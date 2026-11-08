<#
.SYNOPSIS
    Adds the one relying party the migration exercise moves: "Contoso Claims
    Viewer" (SAML), with real claim rules, two role groups and a pilot user.

.DESCRIPTION
    Runs INSIDE DC01 as SYSTEM (lab/scripts/dc/run-on-dc.py) after
    10-Install-Adfs.ps1. Idempotent.

    What it creates, and why each piece is there:
      * AD groups GRP-ClaimsViewer-Clinicians and GRP-ClaimsViewer-Admins in
        OU=Workforce. That OU is in Cloud Sync scope, so both groups also
        appear in Entra. The Entra app (modules/apps/claims_viewer.tf) assigns
        its app roles to these SAME groups: one source of truth for who may
        use the app, before and after the cutover.
      * AD user adfs-pilot in OU=Workforce (department Nursing, a member of
        the Clinicians group). Its password is a protected parameter that the
        operator generated into the Keychain (contoso-lab-pw-adfs-pilot). The
        same password then works in Entra, through password hash sync. It is a
        test account, so it has no HR record: the HR reconciliation report
        will list it as an orphan until 19-Remove-Adfs.ps1 deletes it.
      * Relying party trust urn:contoso:claims-viewer, SAML 2.0, assertion
        consumer https://localhost:8443/... (the claims viewer container on
        the operator's Mac, lab/adfs/claims-viewer). Access control policy:
        "Permit specific group" = the two role groups.
      * Issuance transform rules from lab/adfs/claims-viewer.rules.txt (passed
        in as -RulesText; run-on-dc.py sends one script, not a folder). The
        group SIDs are filled in here, because a claim rule matches a group
        by its SID, not by its name.
      * The IdP-initiated sign-on page is switched on, because
        13-Get-AdfsClaims.ps1 signs in through it. Off is the AD FS default;
        19-Remove-Adfs.ps1 removes the whole farm.

.PARAMETER DomainName
    The AD forest root, e.g. corp.contosohealthlab.com.

.PARAMETER UpnSuffix
    The UPN suffix synced users have in Entra, e.g. contosohealthlab.com.

.PARAMETER RulesText
    The content of lab/adfs/claims-viewer.rules.txt.

.PARAMETER PilotPassword
    Password for adfs-pilot. Protected parameter only.

.EXAMPLE
    lab/scripts/dc/run-on-dc.py lab/adfs/scripts/11-Add-ClaimsViewerRp.ps1 \
      --param DomainName=corp.contosohealthlab.com --param UpnSuffix=contosohealthlab.com \
      --param "RulesText=$(cat lab/adfs/claims-viewer.rules.txt)" \
      --secret PilotPassword=keychain:contoso-lab-pw-adfs-pilot
#>
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', '',
    Justification = 'Run-command parameters arrive as strings. The password is a protected parameter (run-on-dc.py) and becomes a SecureString on the first line that touches it.')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingConvertToSecureStringWithPlainText', '',
    Justification = 'The only way to turn a run-command protected parameter into the SecureString/PSCredential these cmdlets need. The plain copy is cleared right after.')]
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$DomainName,
    [Parameter(Mandatory)][string]$UpnSuffix,
    [Parameter(Mandatory)][string]$RulesText,
    [Parameter(Mandatory)][string]$PilotPassword,
    [string]$RpIdentifier = 'urn:contoso:claims-viewer',
    [string]$AcsUrl = 'https://localhost:8443/simplesaml/module.php/saml/sp/saml2-acs.php/default-sp'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
Import-Module ActiveDirectory

function Write-Step([string]$Message) { Write-Output ("[adfs-rp] {0}" -f $Message) }

if (-not (Get-Service adfssrv -ErrorAction SilentlyContinue)) { throw 'AD FS is not installed. Run 10-Install-Adfs.ps1 first.' }
if ($AcsUrl -notlike 'https://*') { throw 'AD FS accepts only https assertion consumer endpoints.' }

$adDomain = Get-ADDomain
if ($adDomain.DNSRoot -ne $DomainName) { throw "This DC is in '$($adDomain.DNSRoot)', not '$DomainName'." }
$domainDn = $adDomain.DistinguishedName
$ou = "OU=Workforce,$domainDn"
$null = Get-ADOrganizationalUnit -Identity $ou   # fails loudly if the OU is missing

# --- Groups ---------------------------------------------------------------------
$groups = [ordered]@{}
foreach ($name in 'GRP-ClaimsViewer-Clinicians', 'GRP-ClaimsViewer-Admins') {
    $g = Get-ADGroup -Filter "SamAccountName -eq '$name'" -SearchBase $ou
    if (-not $g) {
        Write-Step "group $name"
        $g = New-ADGroup -Name $name -SamAccountName $name -GroupScope Global -GroupCategory Security -Path $ou `
            -Description 'AD FS -> Entra migration exercise (lab/adfs). Removed by 19-Remove-Adfs.ps1 -RemoveTestObjects yes.' -PassThru
    }
    $groups[$name] = $g
}

# --- Pilot user -------------------------------------------------------------------
$sam = 'adfs-pilot'
$upn = "$sam@$UpnSuffix"
$pw = ConvertTo-SecureString $PilotPassword -AsPlainText -Force
$PilotPassword = $null
$user = Get-ADUser -Filter "SamAccountName -eq '$sam'"
if (-not $user) {
    Write-Step "user $upn"
    $user = New-ADUser -Name 'AD FS Pilot' -SamAccountName $sam -UserPrincipalName $upn -GivenName 'Pilot' -Surname 'AdfsTest' `
        -EmailAddress $upn -Department 'Nursing' -EmployeeID 'ADFS-PILOT-1' -Path $ou -AccountPassword $pw `
        -Enabled $true -PasswordNeverExpires $true `
        -Description 'Test user for the AD FS -> Entra migration (lab/adfs). No HR record on purpose. Removed by 19-Remove-Adfs.ps1 -RemoveTestObjects yes.-RemoveTestObjects yes.' -PassThru
} else {
    if ($user.DistinguishedName -notlike "*,$ou") { throw "$sam exists outside $ou; refusing to touch it." }
    Set-ADAccountPassword -Identity $user -Reset -NewPassword $pw
}
Add-ADGroupMember -Identity $groups['GRP-ClaimsViewer-Clinicians'] -Members $user

# --- Relying party ------------------------------------------------------------
$rules = $RulesText.Replace('{{CLINICIANS_SID}}', $groups['GRP-ClaimsViewer-Clinicians'].SID.Value).Replace('{{ADMINS_SID}}', $groups['GRP-ClaimsViewer-Admins'].SID.Value)
if ($rules -match '\{\{') { throw 'A {{placeholder}} is left in the claim rules.' }

$netbios = (Get-ADDomain).NetBIOSName
$acp = @{ GroupParameter = @("$netbios\GRP-ClaimsViewer-Clinicians", "$netbios\GRP-ClaimsViewer-Admins") }
$ep = New-AdfsSamlEndpoint -Binding POST -Protocol SAMLAssertionConsumer -Uri $AcsUrl -IsDefault $true -Index 0

$rp = Get-AdfsRelyingPartyTrust -Identifier $RpIdentifier
if (-not $rp) {
    Write-Step "relying party $RpIdentifier"
    Add-AdfsRelyingPartyTrust -Name 'Contoso Claims Viewer' -Identifier $RpIdentifier -SamlEndpoint $ep `
        -AccessControlPolicyName 'Permit specific group' -AccessControlPolicyParameters $acp `
        -IssuanceTransformRules $rules -SignatureAlgorithm 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256' `
        -Notes 'AD FS -> Entra migration exercise (lab/adfs). Removed by 19-Remove-Adfs.ps1 -Apply yes.'
} else {
    Set-AdfsRelyingPartyTrust -TargetIdentifier $RpIdentifier -SamlEndpoint $ep `
        -AccessControlPolicyName 'Permit specific group' -AccessControlPolicyParameters $acp `
        -IssuanceTransformRules $rules
}
Set-AdfsProperties -EnableIdPInitiatedSignonPage $true

$rp = Get-AdfsRelyingPartyTrust -Identifier $RpIdentifier
[pscustomobject]@{
    relyingParty   = $rp.Name
    identifier     = $rp.Identifier -join ','
    acs            = $AcsUrl
    accessPolicy   = $rp.AccessControlPolicyName
    ruleCount      = ([regex]::Matches($rp.IssuanceTransformRules, '=>')).Count
    pilotUser      = $upn
    clinicianSid   = $groups['GRP-ClaimsViewer-Clinicians'].SID.Value
    adminSid       = $groups['GRP-ClaimsViewer-Admins'].SID.Value
    idpInitiated   = (Get-AdfsProperties).EnableIdPInitiatedSignonPage
} | ConvertTo-Json
