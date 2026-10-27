<#
.SYNOPSIS
    Creates the HR inbound provisioning app and its synchronization job
    (API-driven provisioning) and prints the two ids
    Invoke-InboundProvisioning.ps1 needs. Replaces README one-time setup steps
    1 and 3 (portal clicks).

.DESCRIPTION
    -Target AD     "API-driven provisioning to on-premises Active Directory"
                   (hybrid: HR -> AD OU -> Cloud Sync -> Entra; the lab's path)
    -Target Entra  "API-driven provisioning to Microsoft Entra ID" (cloud-only)

    Steps: look the gallery template up by display name -> instantiate it ->
    read the synchronization templates the service offers that app -> create
    the job from it -> print ServicePrincipalId and JobId.

    Idempotent: an existing service principal with -DisplayName is reused, and
    an existing job on it is reused, so re-running is safe. -WhatIf performs
    only the reads and creates nothing.

    NOT done here, because each needs state that exists only later or values
    specific to the forest (README one-time setup step 2):
      * assigning the registered Cloud Sync agent to the AD job
        (04-Install-CloudSyncAgent.ps1 registers it);
      * the custom attribute mappings: the parentDistinguishedName expression
        printed by 02-Configure-Domain.ps1, and hireDate.

    Requires a Microsoft Graph session with Application.ReadWrite.All and
    Synchronization.ReadWrite.All, e.g.
      Connect-MgGraph -TenantId <tenant> -Scopes Application.ReadWrite.All,Synchronization.ReadWrite.All

.PARAMETER Target
    AD (default) or Entra.

.PARAMETER DisplayName
    Display name of the provisioning app to create or reuse.

.EXAMPLE
    ./New-InboundProvisioningApp.ps1 -WhatIf
    ./New-InboundProvisioningApp.ps1 -Target AD
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [ValidateSet('AD', 'Entra')] [string]$Target = 'AD',
    [ValidateNotNullOrEmpty()] [string]$DisplayName = 'Contoso HR Inbound Provisioning'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$templateName = @{
    AD    = 'API-driven provisioning to on-premises Active Directory'
    Entra = 'API-driven provisioning to Microsoft Entra ID'
}[$Target]

function Get-GraphValue([string]$Uri) {
    @((Invoke-MgGraphRequest -Method GET -Uri $Uri).value)
}

function Format-Filter([string]$Expression) { [uri]::EscapeDataString($Expression) }

# 1. Gallery template
# @() at the call site: a function returning a one-item array is unrolled to
# that item, so .Count would count the hashtable's keys instead.
$templates = @(Get-GraphValue ("v1.0/applicationTemplates?`$filter=" + (Format-Filter "displayName eq '$templateName'")))
if ($templates.Count -ne 1) {
    throw "Expected exactly one application template named '$templateName', found $($templates.Count)."
}
$template = $templates[0]
Write-Verbose "Template: $($template.displayName) ($($template.id))"

# 2. Service principal: reuse or instantiate
$sp = Get-GraphValue ("v1.0/servicePrincipals?`$select=id,appId,displayName&`$filter=" + (Format-Filter "displayName eq '$DisplayName'")) |
    Select-Object -First 1

if ($sp) {
    Write-Verbose "Reusing service principal $($sp.id)"
}
elseif ($PSCmdlet.ShouldProcess($DisplayName, "Instantiate '$templateName'")) {
    $body = @{ displayName = $DisplayName } | ConvertTo-Json
    $created = Invoke-MgGraphRequest -Method POST -Uri "v1.0/applicationTemplates/$($template.id)/instantiate" -Body $body -ContentType 'application/json'
    $sp = $created.servicePrincipal

    # A new service principal takes a moment to become readable by the
    # synchronization service.
    $ready = $false
    foreach ($attempt in 1..12) {
        try { Invoke-MgGraphRequest -Method GET -Uri "v1.0/servicePrincipals/$($sp.id)/synchronization/templates" | Out-Null; $ready = $true; break }
        catch { Start-Sleep -Seconds 10 }
    }
    if (-not $ready) { throw "Service principal $($sp.id) was not ready for synchronization after two minutes." }
}

if (-not $sp) {
    Write-Output "WhatIf: would instantiate '$templateName' as '$DisplayName' and create its synchronization job."
    return
}

# 3. Synchronization job: reuse or create from the offered template
$job = Get-GraphValue "v1.0/servicePrincipals/$($sp.id)/synchronization/jobs" | Select-Object -First 1

if (-not $job) {
    $syncTemplates = @(Get-GraphValue "v1.0/servicePrincipals/$($sp.id)/synchronization/templates")
    if ($syncTemplates.Count -lt 1) { throw "The service offers no synchronization template for $($sp.id)." }
    $syncTemplate = $syncTemplates[0]
    if ($PSCmdlet.ShouldProcess($DisplayName, "Create synchronization job from template '$($syncTemplate.id)'")) {
        $body = @{ templateId = $syncTemplate.id } | ConvertTo-Json
        $job = Invoke-MgGraphRequest -Method POST -Uri "v1.0/servicePrincipals/$($sp.id)/synchronization/jobs" -Body $body -ContentType 'application/json'
    }
}

[pscustomobject]@{
    Target             = $Target
    DisplayName        = $DisplayName
    ServicePrincipalId = $sp.id
    JobId              = if ($job) { $job.id } else { $null }
}
