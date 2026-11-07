<#
.SYNOPSIS
    Intune Endpoint Privilege Management (one support-approved app) and
    Windows LAPS for the lab's Intune PC (CH-WIN11-01), as Intune policies.

.DESCRIPTION
    STATUS: BUILT, not run. The lab operator holds DeviceManagementConfiguration.Read.All
    only, so it cannot create Intune policies. A human Intune admin runs this
    script once, with delegated Graph (the same pattern as
    New-IntuneComplianceBaseline.ps1). The setting ids and option ids below were
    read from the tenant's own policy templates on 2026-11-07:
      Elevation settings policy        e7dcaba4-959b-46ed-88f0-16ba39b14fd8_1
      Elevation rules policy           cff02aad-51b1-498d-83ad-81161a393f56_1
      Local admin password solution    adc46e5a-f4aa-4ff6-aeff-4f27bc525796_1

    LICENCE: EPM needs no purchase in this tenant. The SPE_E5 (Microsoft 365 E5)
    trial carries the Intune-EPM service plan, provisioningStatus Success
    (subscribedSkus, read 2026-11-07). The trial ends 2026-11-26. The standard
    user who asks for elevation must hold that E5 licence.

    WHAT IT CREATES
    1. "EPM - Settings (lab)": EPM on; DEFAULT response "Deny all requests", so
       only a file named by a rule can ever be elevated; send elevation data for
       reporting, all endpoint elevations.
    2. "EPM - Rules (lab)": ONE rule, "Process Explorer - support approved":
       file procexp64.exe, matched by its SHA-256 hash (-FileHash), elevation type
       "Support approved", child processes "Deny all". The user right-clicks the
       file, chooses "Run with elevated access", and types a business reason. An
       Intune admin approves or denies it in the Intune admin center
       (Endpoint security > Endpoint Privilege Management > Elevation requests).
       Learn: an approval lets that user run that file elevated "for the next 24
       hours", and there is "no current support for a custom time period or
       cancellation". So "a short time" is 24 hours, fixed by Microsoft.
    3. "LAPS - Intune PC (lab)": Windows LAPS manages the built-in
       Administrator account. Backup directory: Microsoft Entra ID only. Password
       age 7 days, 20 characters, complexity 4 (upper + lower + numbers +
       specials). After someone uses the password: reset it and log the account
       off, after 1 hour.

    WHO APPROVES: an Intune admin who holds the Intune RBAC permission
    "Endpoint Privilege Management Elevation Requests" (view + modify). In the lab
    that is an activation of PIM-Tier1-Intune-Admins (Intune Administrator).

    SCOPES (delegated): DeviceManagementConfiguration.ReadWrite.All, Group.Read.All.
    Reading the LAPS password afterwards needs DeviceLocalCredential.Read.All (and
    an Entra role such as Cloud Device Administrator); this script never reads it.

.PARAMETER UserGroupId
    Entra group of the standard users that may ask for elevation (EPM policies).

.PARAMETER DeviceGroupId
    Entra group that holds CH-WIN11-01 (LAPS policy).

.PARAMETER FileHash
    SHA-256 of the exact procexp64.exe you approve (Get-FileHash on the PC).

.EXAMPLE
    Connect-MgGraph -Scopes 'DeviceManagementConfiguration.ReadWrite.All','Group.Read.All'
    ./New-IntuneEpmAndLaps.ps1 -UserGroupId <id> -DeviceGroupId <id> -FileHash <sha256> -WhatIf
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F-]{36}$')][string]$UserGroupId,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F-]{36}$')][string]$DeviceGroupId,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{64}$')][string]$FileHash,
    [string]$FileName = 'procexp64.exe'
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ctx = Get-MgContext
if (-not $ctx) { throw 'Not connected. Run Connect-MgGraph with the scopes in the help first.' }
foreach ($s in @('DeviceManagementConfiguration.ReadWrite.All', 'Group.Read.All')) {
    if ($ctx.Scopes -notcontains $s) { throw "The Graph session lacks $s." }
}

$base = 'https://graph.microsoft.com/beta/deviceManagement/configurationPolicies'
$p = 'device_vendor_msft_policy_'

function New-Choice([string]$id, [string]$value, [string]$tpl = $null, $children = @()) {
    $o = @{
        '@odata.type'       = '#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance'
        settingDefinitionId = $id
        choiceSettingValue  = @{ value = $value; children = @($children) }
    }
    if ($tpl) { $o.settingInstanceTemplateReference = @{ settingInstanceTemplateId = $tpl } }
    return $o
}
function New-Simple([string]$id, $value, [string]$type = 'String', [string]$tpl = $null) {
    $o = @{
        '@odata.type'       = '#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance'
        settingDefinitionId = $id
        simpleSettingValue  = @{ '@odata.type' = "#microsoft.graph.deviceManagementConfiguration$($type)SettingValue"; value = $value }
    }
    if ($tpl) { $o.settingInstanceTemplateReference = @{ settingInstanceTemplateId = $tpl } }
    return $o
}
function Find-Policy([string]$name) {
    $r = Invoke-MgGraphRequest -Method GET -Uri "$base`?`$filter=name eq '$name'&`$select=id,name"
    return @($r.value) | Select-Object -First 1
}
function Set-Policy([string]$name, [hashtable]$body, [string]$groupId) {
    # Resolve or create the policy first, then check and repair its assignment
    # on EVERY run: a run that created the policy but failed to assign it is
    # finished by the next run, never reported as done.
    $existing = Find-Policy $name
    if ($existing) {
        $id = $existing.id
        Write-Host "Exists, settings left as they are: $name ($id)"
    } else {
        if (-not $PSCmdlet.ShouldProcess($name, 'Create Intune policy')) { return $null }
        $id = (Invoke-MgGraphRequest -Method POST -Uri $base -Body ($body | ConvertTo-Json -Depth 30) -ContentType 'application/json').id
        Write-Host "Created: $name ($id)"
    }
    $current = @((Invoke-MgGraphRequest -Method GET -Uri "$base('$id')/assignments").value)
    $assigned = @($current | Where-Object { $_.target.groupId -eq $groupId }).Count -gt 0
    if (-not $assigned) {
        if (-not $PSCmdlet.ShouldProcess($name, "Assign to group $groupId")) { return $id }
        # /assign replaces the whole list: keep any assignments already there.
        $targets = @($current | ForEach-Object { @{ target = $_.target } }) + @(@{ target = @{ '@odata.type' = '#microsoft.graph.groupAssignmentTarget'; groupId = $groupId } })
        Invoke-MgGraphRequest -Method POST -Uri "$base('$id')/assign" -Body (@{ assignments = $targets } | ConvertTo-Json -Depth 10) -ContentType 'application/json' | Out-Null
        $check = @((Invoke-MgGraphRequest -Method GET -Uri "$base('$id')/assignments").value | Where-Object { $_.target.groupId -eq $groupId })
        if ($check.Count -eq 0) { throw "$name ($id): assignment to $groupId did not stick" }
        Write-Host "Assigned: $name -> $groupId (read back)"
    } else {
        Write-Host "Already assigned: $name -> $groupId"
    }
    return $id
}

# 1. Elevation settings: EPM on, default deny, report all elevations.
$settings = @{
    name              = 'EPM - Settings (lab)'
    description       = 'lab/scripts/intune/New-IntuneEpmAndLaps.ps1. EPM on; default response Deny all; only rule-named files elevate.'
    platforms         = 'windows10'
    technologies      = 'mdm,endpointPrivilegeManagement'
    templateReference = @{ templateId = 'e7dcaba4-959b-46ed-88f0-16ba39b14fd8_1' }
    settings          = @(@{
        settingInstance = (New-Choice "${p}elevationclientsettings_enableepm" "${p}elevationclientsettings_enableepm_1" '58a79a4b-ba9b-4923-a7a5-6dc1a9f638a4' @(
            (New-Choice "${p}elevationclientsettings_defaultelevationresponse" "${p}elevationclientsettings_defaultelevationresponse_0"),
            (New-Choice "${p}elevationclientsettings_senddata" "${p}elevationclientsettings_senddata_1" $null @(
                (New-Choice "${p}elevationclientsettings_reportingscope" "${p}elevationclientsettings_reportingscope_2")))
        ))
    })
}

# 2. One support-approved rule, matched by hash, no elevated children.
$r = "${p}privilegemanagement_elevationrules_{elevationrulename}"
$rule = @{
    name              = 'EPM - Rules (lab)'
    description       = 'lab/scripts/intune/New-IntuneEpmAndLaps.ps1. One file, support approved, 24 h per approval (Microsoft fixed).'
    platforms         = 'windows10'
    technologies      = 'mdm,endpointPrivilegeManagement'
    templateReference = @{ templateId = 'cff02aad-51b1-498d-83ad-81161a393f56_1' }
    settings          = @(@{
        settingInstance = @{
            '@odata.type'                    = '#microsoft.graph.deviceManagementConfigurationGroupSettingCollectionInstance'
            settingDefinitionId              = $r
            settingInstanceTemplateReference = @{ settingInstanceTemplateId = 'ee3d2e5f-6b3d-4cb1-af9b-37b02d3dbae2' }
            groupSettingCollectionValue      = @(@{ children = @(
                (New-Simple "${r}_name" 'Process Explorer - support approved'),
                (New-Simple "${r}_description" 'A standard user asks; an Intune admin approves; 24 hours.'),
                (New-Simple "${r}_filename" $FileName),
                (New-Simple "${r}_filehash" $FileHash.ToUpperInvariant()),
                (New-Choice "${r}_appliesto" "${r}_allusers"),
                (New-Choice "${r}_childprocessbehavior" "${r}_deny"),
                (New-Choice "${r}_ruletype" "${r}_supportarbitrated")
            ) })
        }
    })
}

# 3. Windows LAPS on the Intune PC, backed up to Entra ID.
$l = 'device_vendor_msft_laps_policies_'
$laps = @{
    name              = 'LAPS - Intune PC (lab)'
    description       = 'lab/scripts/intune/New-IntuneEpmAndLaps.ps1. Built-in Administrator; Entra ID backup; 7 days; reset + logoff 1 h after use.'
    platforms         = 'windows10'
    technologies      = 'mdm'
    templateReference = @{ templateId = 'adc46e5a-f4aa-4ff6-aeff-4f27bc525796_1' }
    settings          = @(
        @{ settingInstance = (New-Choice "${l}backupdirectory" "${l}backupdirectory_1" 'a3270f64-e493-499d-8900-90290f61ed8a' @(
            (New-Simple "${l}passwordagedays_aad" 7 'Integer'))) },
        @{ settingInstance = (New-Choice "${l}passwordcomplexity" "${l}passwordcomplexity_4" '8a7459e8-1d1c-458a-8906-7b27d216de52') },
        @{ settingInstance = (New-Simple "${l}passwordlength" 20 'Integer' 'da7a1dbd-caf7-4341-ab63-ece6f994ff02') },
        @{ settingInstance = (New-Choice "${l}postauthenticationactions" "${l}postauthenticationactions_3" 'd9282eb1-d187-42ae-b366-7081f32dcfff') },
        @{ settingInstance = (New-Simple "${l}postauthenticationresetdelay" 1 'Integer' 'a9e21166-4055-4042-9372-efaf3ef41868') }
    )
}

$ids = [ordered]@{
    settings = Set-Policy $settings.name $settings $UserGroupId
    rules    = Set-Policy $rule.name $rule $UserGroupId
    laps     = Set-Policy $laps.name $laps $DeviceGroupId
}
$ids | ConvertTo-Json
Write-Host 'Next: lab/scripts/intune/README.md, section "EPM and LAPS proof" (device sync, request, approval, LAPS read-back).'
