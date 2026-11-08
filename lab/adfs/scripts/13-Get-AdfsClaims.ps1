<#
.SYNOPSIS
    Signs the pilot user in to AD FS for the Claims Viewer relying party and
    prints the claims AD FS issued, as JSON. Never prints the token itself.

.DESCRIPTION
    Runs INSIDE DC01 as SYSTEM (lab/scripts/dc/run-on-dc.py).

    Two jobs:
      * "Before" evidence for the cutover: the exact claims the app gets from
        AD FS. lab/adfs/compare/compare_claims.py diffs this JSON against the
        claims the app gets from Entra after the cutover.
      * Real sign-in traffic. Entra's AD FS migration report lists only
        relying parties with sign-ins in the last 30 days. Each run of this
        script is one real AD FS token issuance (AD FS audit events 1200 and
        1202), which the Connect Health agent uploads.

    How: the IdP-initiated sign-on page (switched on by
    11-Add-ClaimsViewerRp.ps1) with forms authentication, from this server to
    itself. The SAML response is decoded in memory. Its signature is checked
    against the primary AD FS token-signing certificate. Only the claim types,
    values, Name ID, issuer and audience are printed.

    Why not through the app in a browser: that is lab/adfs/compare/capture.mjs
    (needs the 443 NSG rule, enable_adfs_https). This script needs no inbound
    port at all.

.PARAMETER FederationServiceName
    e.g. sts.corp.contosohealthlab.com.

.PARAMETER UserName
    The pilot user's UPN.

.PARAMETER UserPassword
    Protected parameter only.

.PARAMETER Count
    How many sign-ins to make (traffic for the report). Default 1.
#>
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', '',
    Justification = 'Run-command parameters arrive as strings. The password is a protected parameter (run-on-dc.py) and becomes a SecureString on the first line that touches it.')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '',
    Justification = 'Used inside Get-AdfsAssertion (script scope); the rule does not follow script-scope use into functions.')]
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$FederationServiceName,
    [Parameter(Mandatory)][string]$UserName,
    [Parameter(Mandatory)][string]$UserPassword,
    [string]$RpIdentifier = 'urn:contoso:claims-viewer',
    [ValidateRange(1, 50)][int]$Count = 1
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
Add-Type -AssemblyName System.Security
Add-Type -AssemblyName System.Web
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$plain = $UserPassword
$UserPassword = $null

$signing = (Get-AdfsCertificate -CertificateType Token-Signing | Where-Object IsPrimary | Select-Object -First 1).Certificate
if (-not $signing) { throw 'No primary AD FS token-signing certificate.' }

function Get-AdfsAssertion {
    $start = "https://$FederationServiceName/adfs/ls/IdpInitiatedSignOn.aspx?loginToRp=$([uri]::EscapeDataString($RpIdentifier))"
    $session = $null
    $form = Invoke-WebRequest -Uri $start -SessionVariable session -UseBasicParsing -MaximumRedirection 5
    $action = [regex]::Match($form.Content, '<form[^>]+id="loginForm"[^>]+action="([^"]+)"').Groups[1].Value
    if (-not $action) { throw 'AD FS did not return its sign-in form (is the IdP-initiated page on?).' }
    $action = [System.Web.HttpUtility]::HtmlDecode($action)
    if ($action -notlike 'https://*') { $action = "https://$FederationServiceName$action" }

    $body = @{ UserName = $UserName; Password = $plain; AuthMethod = 'FormsAuthentication' }
    $post = Invoke-WebRequest -Uri $action -Method Post -Body $body -WebSession $session -UseBasicParsing -MaximumRedirection 5
    $m = [regex]::Match($post.Content, 'name="SAMLResponse"\s+value="([^"]+)"')
    if (-not $m.Success) {
        $err = [regex]::Match($post.Content, 'id="errorText"[^>]*>([^<]+)<').Groups[1].Value
        throw "No SAML response from AD FS. $err"
    }
    [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String([System.Web.HttpUtility]::HtmlDecode($m.Groups[1].Value)))
}

$result = $null
for ($i = 1; $i -le $Count; $i++) {
    $xmlText = Get-AdfsAssertion
    $doc = New-Object System.Xml.XmlDocument
    $doc.PreserveWhitespace = $true
    $doc.XmlResolver = $null
    $doc.LoadXml($xmlText)
    $ns = New-Object System.Xml.XmlNamespaceManager($doc.NameTable)
    $ns.AddNamespace('p', 'urn:oasis:names:tc:SAML:2.0:protocol')
    $ns.AddNamespace('a', 'urn:oasis:names:tc:SAML:2.0:assertion')
    $ns.AddNamespace('ds', 'http://www.w3.org/2000/09/xmldsig#')

    $status = $doc.SelectSingleNode('/p:Response/p:Status/p:StatusCode/@Value', $ns).Value
    if ($status -ne 'urn:oasis:names:tc:SAML:2.0:status:Success') { throw "AD FS status $status" }
    $assertion = $doc.SelectSingleNode('/p:Response/a:Assertion', $ns)
    if (-not $assertion) { throw 'No plain Assertion (an encrypted assertion is not expected: the RP has no encryption certificate).' }

    $sigNode = $assertion.SelectSingleNode('ds:Signature', $ns)
    $valid = $false
    if ($sigNode) {
        $signed = New-Object System.Security.Cryptography.Xml.SignedXml($assertion)
        $signed.LoadXml([System.Xml.XmlElement]$sigNode)
        $valid = $signed.CheckSignature($signing, $true)
    }
    if (-not $valid) { throw 'The assertion signature does not verify against the AD FS token-signing certificate.' }

    $attrs = [ordered]@{}
    foreach ($a in $assertion.SelectNodes('a:AttributeStatement/a:Attribute', $ns)) {
        $attrs[$a.GetAttribute('Name')] = @($a.SelectNodes('a:AttributeValue', $ns) | ForEach-Object { $_.InnerText } | Sort-Object)
    }
    $nameId = $assertion.SelectSingleNode('a:Subject/a:NameID', $ns)
    $result = [ordered]@{
        source         = 'adfs'
        capturedAtUtc  = (Get-Date).ToUniversalTime().ToString('o')
        issuer         = $assertion.SelectSingleNode('a:Issuer', $ns).InnerText
        audience       = $assertion.SelectSingleNode('a:Conditions/a:AudienceRestriction/a:Audience', $ns).InnerText
        signatureValid = $valid
        nameId         = [ordered]@{ value = $nameId.InnerText; format = $nameId.GetAttribute('Format') }
        attributes     = $attrs
        signIns        = $i
    }
}
$plain = $null
$result | ConvertTo-Json -Depth 5
