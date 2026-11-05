<#
.SYNOPSIS
    Deploys the ITDR containment playbook (lab/monitoring/playbook-contain.json)
    and grants its managed identity exactly the rights the playbook uses.

.DESCRIPTION
    What the playbook does (see the template metadata): on a NEW High identity
    incident it posts a Teams adaptive card per account and WAITS for a human:
    Contain (revoke sessions + confirm compromised in Identity Protection +
    disable / flag for AD disable), Revoke only, or Reject. Break-glass
    accounts (by OBJECT ID) are refused outright; only a member of the
    containment approver group (-ApproverGroupName) who is not the subject
    can decide - anyone else in the Teams channel is ignored, and an answer
    without a responder identity fails closed; no answer in 4 h means no
    action; every result lands on the Sentinel incident and the ServiceNow
    ticket.

    Why a local script and not the pipeline (same reasoning as
    Deploy-Playbook.ps1): the ServiceNow password must never reach CI, and the
    Graph app-role grants below need a Privileged Role Administrator-level
    human - the CI apply identity deliberately cannot grant Graph permissions.

    NOTHING TRIGGERS THE PLAYBOOK UNTIL Terraform's enable_itdr_containment is
    true AND containment_playbook_id is set to the id this script prints. Run
    it whenever; containment stays dormant until that flag.

    LEAST PRIVILEGE (system-assigned managed identity of the Logic App):
      Microsoft Graph application permissions (app roles):
        User.Read.All               Get user (UPN, sync state) before acting
        AdministrativeUnit.Read.All the account's restricted management AUs: RMAU
                                    members are escalated to a human (app
                                    permissions cannot act on them; verify: the
                                    least-privileged role for this read)
        User.RevokeSessions.All     POST /users/{id}/revokeSignInSessions
        User.EnableDisableAccount.All  PATCH accountEnabled=false
        IdentityRiskyUser.ReadWrite.All  POST identityProtection/riskyUsers/
                                    confirmCompromised (user risk -> High, so
                                    CA006 applies at the next sign-in; Entra
                                    ID P2 - without it the call answers 403)
      Directory role (OPT-IN, -GrantDisableRole) - NOT NEEDED, keep it off:
        the design assumed Graph's sensitive-action rule makes an app-only
        disable need a directory role. RAN - tenant 2026-11-05 (capture-log
        E41): with only the app roles above, PATCH accountEnabled=false on a
        non-admin cloud-only user answered 204. Authentication Administrator
        would add nothing for those targets and a lot of reach (method resets
        and Temporary Access Passes for every non-admin user, R16), so it
        stays off. Admins are never in scope: containing an ADMIN needs
        Privileged Authentication Administrator, which would make this Logic
        App Tier 0 - admin containment stays a human action. (Not tried live:
        Graph's answer for an admin target, by design.) If the switch is ever
        used, it creates a standing role assignment outside PIM:
        role-assigned-outside-pim.kql WILL alert once - expected, record it.
      Azure RBAC:
        Microsoft Sentinel Responder (workspace)  incident comments + entities
        Azure Security Insights app -> Microsoft Sentinel Automation
          Contributor (resource group), so automation rules may run it.
    revokeSignInSessions app-only needed no directory role either (200 on
    the 2026-11-05 drill; Graph v1.0 answers 200 with value true).

    Teams: the approval card is posted by the Teams connector (OAuth API
    connection teams-<playbook>, action PostCardAndWaitForResponse as the
    Flow bot) to the SOC team's Identity-SecOps channel. The SOC team is
    owned by the cloud-only automation account svc-soc-automation, and the
    connection is authorized once AS THAT ACCOUNT
    (authorize-teams-connection.mjs) - never as a person, so no one's
    leaving or password reset silently breaks containment. Re-deploying keeps
    the authorization (no parameter values on the connection).

    Secrets: ServiceNow integration password from Key Vault
    (servicenow-integration-password), passed as an ARM securestring through a
    0600 temp parameters file that is deleted afterwards - same pattern as
    Deploy-Playbook.ps1. Nothing is printed or written to the repo.

.PARAMETER KeyVaultName
    Lab Key Vault holding servicenow-integration-password.

.PARAMETER TeamsGroupId
    Object id of the Team (M365 group) that owns the Identity-SecOps channel.

.PARAMETER TeamsChannelId
    Channel id (19:...@thread.tacv2) for the approval cards.

.PARAMETER ServiceNowInstance
    PDI instance name, e.g. dev123456 (empty = skip ServiceNow).

.PARAMETER ServiceNowUser
    ServiceNow integration user (itil role). Required with -ServiceNowInstance.

.PARAMETER BreakGlassGroupName
    Group whose members are protected from containment (default
    Break-Glass-Admins, modules/groups). Their object ids are baked into the
    playbook parameter protectedObjectIds - the ONLY protection: the
    bg-admin- UPN prefix is log-only (anyone who can rename a user could
    otherwise make a compromised account uncontainable). Re-run this script
    (or -VerifyProtectedList) whenever that membership changes.

.PARAMETER ApproverGroupName
    Group whose members may DECIDE a containment card (default
    ITDR-Containment-Approvers; create it with the SOC leads, role-assignable
    or at least owned by Tier 0). Their object ids become the playbook
    parameter approverObjectIds. Missing or empty group = the playbook
    ignores every answer (fail closed) and this script warns.

.PARAMETER VerifyProtectedList
    Read-only check: compare the deployed playbook's protectedObjectIds and
    approverObjectIds with the current group memberships and report drift.
    Deploys nothing.

.PARAMETER GrantDisableRole
    Also assign the Authentication Administrator directory role to the
    playbook identity (see LEAST PRIVILEGE). Off by default and not needed:
    the disable of a non-admin cloud-only user works without it (E41).

.PARAMETER DirectoryRoleScope
    Scope for -GrantDisableRole: '/' (tenant) or '/administrativeUnits/<id>'.

.EXAMPLE
    Connect-MgGraph -Scopes 'Application.Read.All','AppRoleAssignment.ReadWrite.All','GroupMember.Read.All'
    ./Deploy-ContainmentPlaybook.ps1 -KeyVaultName kv-idlab-7f3a -TeamsGroupId <guid> -TeamsChannelId '19:abc@thread.tacv2' -ServiceNowInstance dev123456 -ServiceNowUser svc.sentinel -WhatIf
#>

#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.Authentication

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '',
    Justification = 'Interactive operator script: coloured progress goes to the host so it never mixes with returned objects; nothing parses this output.')]
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [string]$ResourceGroup = 'rg-identity-lab',
    [string]$WorkspaceName = 'loga-idlab',
    [Parameter(Mandatory)][string]$KeyVaultName,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F-]{36}$')][string]$TeamsGroupId,
    [Parameter(Mandatory)][ValidatePattern('^19:.+@thread\.(tacv2|skype)$')][string]$TeamsChannelId,
    [string]$ServiceNowInstance = '',
    [string]$ServiceNowUser = '',
    [string]$BreakGlassGroupName = 'Break-Glass-Admins',
    [string]$ApproverGroupName = 'ITDR-Containment-Approvers',
    [switch]$VerifyProtectedList,
    [string]$PlaybookName = 'pb-identity-contain',
    [switch]$GrantDisableRole,
    [ValidatePattern('^/$|^/administrativeUnits/[0-9a-fA-F-]{36}$')][string]$DirectoryRoleScope = '/',
    [string]$TemplatePath = (Join-Path $PSScriptRoot '..' '..' 'monitoring' 'playbook-contain.json')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $true   # non-zero az exit = terminating error

$SecurityInsightsAppId = '98785600-1bb7-4fb9-b9fa-19afe2c8a360'   # "Azure Security Insights" (Sentinel automation)
$GraphAppId = '00000003-0000-0000-c000-000000000000'              # Microsoft Graph
$GraphAppRoles = @('User.Read.All', 'AdministrativeUnit.Read.All', 'User.RevokeSessions.All', 'User.EnableDisableAccount.All', 'IdentityRiskyUser.ReadWrite.All')
$graph = 'https://graph.microsoft.com/v1.0'

function Get-VaultSecretOrEmpty([string]$Vault, [string]$Name) {
    # Missing secret = that integration is skipped by the playbook; never silent.
    $PSNativeCommandUseErrorActionPreference = $false
    $v = az keyvault secret show --vault-name $Vault --name $Name --query value -o tsv 2>$null
    if ($LASTEXITCODE -ne 0 -or -not $v) {
        Write-Warning "Key Vault secret '$Name' not readable (missing, or your IP is not in the vault firewall) - ServiceNow will be skipped by the playbook."
        return ''
    }
    return $v
}

function Grant-RoleIfMissing {
    [CmdletBinding(SupportsShouldProcess)]
    param([string]$PrincipalId, [string]$PrincipalType, [string]$Role, [string]$Scope)
    $existing = az role assignment list --assignee $PrincipalId --role $Role --scope $Scope --query '[].id' -o tsv
    if ($existing) { Write-Host "  [=] $Role already granted." -ForegroundColor DarkGray; return }
    if ($PSCmdlet.ShouldProcess($Scope, "grant '$Role' to $PrincipalId")) {
        az role assignment create --assignee-object-id $PrincipalId --assignee-principal-type $PrincipalType `
            --role $Role --scope $Scope -o none
        Write-Host "  [+] Granted $Role." -ForegroundColor Green
    }
}

function Grant-GraphAppRoleIfMissing {
    [CmdletBinding(SupportsShouldProcess)]
    param([string]$PrincipalId, [object]$GraphSp, [string]$RoleValue)
    $role = @($GraphSp.appRoles | Where-Object { $_.value -eq $RoleValue -and $_.allowedMemberTypes -contains 'Application' })[0]
    if (-not $role) { throw "Microsoft Graph has no application permission '$RoleValue'." }
    $have = @((Invoke-MgGraphRequest -Method GET -Uri "$graph/servicePrincipals/$PrincipalId/appRoleAssignments").value |
            Where-Object { $_.appRoleId -eq $role.id -and $_.resourceId -eq $GraphSp.id })
    if ($have) { Write-Host "  [=] Graph $RoleValue already granted." -ForegroundColor DarkGray; return }
    if ($PSCmdlet.ShouldProcess("managed identity $PrincipalId", "grant Graph application permission $RoleValue")) {
        $body = @{ principalId = $PrincipalId; resourceId = $GraphSp.id; appRoleId = $role.id } | ConvertTo-Json
        Invoke-MgGraphRequest -Method POST -Uri "$graph/servicePrincipals/$PrincipalId/appRoleAssignments" -Body $body -ContentType 'application/json' | Out-Null
        Write-Host "  [+] Granted Graph $RoleValue." -ForegroundColor Green
    }
}

# ------------------------------------------------------------------ checks --
if (-not (Test-Path -LiteralPath $TemplatePath)) { throw "Template not found: $TemplatePath" }
if ($ServiceNowInstance -and -not $ServiceNowUser) { throw '-ServiceNowInstance requires -ServiceNowUser (the integration user with the itil role).' }

$requiredScopes = @('Application.Read.All', 'AppRoleAssignment.ReadWrite.All', 'GroupMember.Read.All')
if ($GrantDisableRole) { $requiredScopes += 'RoleManagement.ReadWrite.Directory' }
$ctx = $null; try { $ctx = Get-MgContext } catch { $ctx = $null }
if (-not $ctx) { Write-Host 'Connecting to Microsoft Graph...' -ForegroundColor Yellow; Connect-MgGraph -Scopes $requiredScopes | Out-Null; $ctx = Get-MgContext }
$missingScopes = @($requiredScopes | Where-Object { $ctx.Scopes -and $_ -notin $ctx.Scopes })
if ($missingScopes) { Write-Warning "Current Graph context does not list: $($missingScopes -join ', '). Grants needing them will fail with 403 (Disconnect-MgGraph, then re-run)." }

$workspaceId = az monitor log-analytics workspace show -g $ResourceGroup -n $WorkspaceName --query id -o tsv
$rgId = az group show -n $ResourceGroup --query id -o tsv

function Get-GroupMemberId([string]$GroupName) {
    # Object ids of a group's direct members ($null = group not found).
    $g = @((Invoke-MgGraphRequest -Method GET -Uri "$graph/groups?`$filter=displayName eq '$GroupName'&`$select=id").value)[0]
    if (-not $g) { return $null }
    return @((Invoke-MgGraphRequest -Method GET -Uri "$graph/groups/$($g.id)/members?`$select=id").value | ForEach-Object { $_.id })
}

# Break-glass members are protected by OBJECT ID only: a UPN prefix can be
# given to any account by whoever can rename users.
Write-Host "[1/5] Resolving protected accounts ($BreakGlassGroupName) and approvers ($ApproverGroupName)" -ForegroundColor Cyan
$protectedIds = Get-GroupMemberId $BreakGlassGroupName
if ($null -eq $protectedIds) {
    Write-Warning "Group '$BreakGlassGroupName' not found - NO account is protected from containment (the bg-admin- UPN prefix is log-only). Fix before enabling containment."
    $protectedIds = @()
}
else { Write-Host "  $(@($protectedIds).Count) break-glass member(s) protected by object id." -ForegroundColor Green }
$approverIds = Get-GroupMemberId $ApproverGroupName
if ($null -eq $approverIds -or @($approverIds).Count -eq 0) {
    Write-Warning "Approver group '$ApproverGroupName' is missing or empty - the playbook will IGNORE every answer (fail closed) until it has members and this script is re-run."
    $approverIds = @()
}
else { Write-Host "  $(@($approverIds).Count) containment approver(s) by object id." -ForegroundColor Green }

if ($VerifyProtectedList) {
    # Drift check only: the deployed parameters vs the groups right now.
    $deployed = az resource show -g $ResourceGroup -n $PlaybookName --resource-type Microsoft.Logic/workflows --query properties.parameters -o json | ConvertFrom-Json
    $drift = $false
    foreach ($pair in @(@('protectedObjectIds', $protectedIds), @('approverObjectIds', $approverIds))) {
        $have = @($deployed.($pair[0]).value | Sort-Object)
        $want = @($pair[1] | Sort-Object)
        if (($want -join ',') -ne ($have -join ',')) {
            Write-Warning "$($pair[0]): deployed list differs from the group membership - re-run this script to refresh it."
            $drift = $true
        }
        else { Write-Host "  [=] $($pair[0]) matches the group." -ForegroundColor Green }
    }
    if ($drift) { exit 1 }
    return
}

Write-Host "[2/5] Reading the ServiceNow secret from Key Vault '$KeyVaultName'" -ForegroundColor Cyan
$snowPassword = if ($ServiceNowInstance) { Get-VaultSecretOrEmpty -Vault $KeyVaultName -Name 'servicenow-integration-password' } else { '' }
if ($ServiceNowInstance -and -not $snowPassword) { $ServiceNowInstance = ''; $ServiceNowUser = '' }

Write-Host "[3/5] Deploying $PlaybookName" -ForegroundColor Cyan
$paramFile = New-TemporaryFile
$out = $null
try {
    chmod 600 $paramFile.FullName
    @{
        '$schema'      = 'https://schema.management.azure.com/schemas/2019-04-01/deploymentParameters.json#'
        contentVersion = '1.0.0.0'
        parameters     = @{
            playbookName         = @{ value = $PlaybookName }
            teamsGroupId         = @{ value = $TeamsGroupId }
            teamsChannelId       = @{ value = $TeamsChannelId }
            protectedUpnPrefixes = @{ value = @('bg-admin-') }
            protectedObjectIds   = @{ value = @($protectedIds) }
            approverObjectIds    = @{ value = @($approverIds) }
            snowInstance         = @{ value = $ServiceNowInstance }
            snowUser             = @{ value = $ServiceNowUser }
            snowPassword         = @{ value = $snowPassword }
        }
    } | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $paramFile.FullName -NoNewline

    if ($PSCmdlet.ShouldProcess($ResourceGroup, "deploy $PlaybookName")) {
        $out = az deployment group create -g $ResourceGroup -n "deploy-$PlaybookName" `
            --template-file $TemplatePath --parameters "@$($paramFile.FullName)" `
            --query properties.outputs -o json | ConvertFrom-Json
    }
}
finally {
    Remove-Item -LiteralPath $paramFile.FullName -Force -ErrorAction SilentlyContinue
    $snowPassword = $null
}
if (-not $out) { Write-Host 'WhatIf: stopping before role grants (the managed identity does not exist yet).' -ForegroundColor Yellow; return }

$playbookId = $out.playbookId.value
$principalId = $out.principalId.value

Write-Host '[4/5] Azure RBAC' -ForegroundColor Cyan
Grant-RoleIfMissing -PrincipalId $principalId -PrincipalType ServicePrincipal -Role 'Microsoft Sentinel Responder' -Scope $workspaceId
$siObjectId = az ad sp show --id $SecurityInsightsAppId --query id -o tsv
Grant-RoleIfMissing -PrincipalId $siObjectId -PrincipalType ServicePrincipal -Role 'Microsoft Sentinel Automation Contributor' -Scope $rgId

Write-Host '[5/5] Microsoft Graph permissions for the managed identity' -ForegroundColor Cyan
$graphSp = @((Invoke-MgGraphRequest -Method GET -Uri "$graph/servicePrincipals?`$filter=appId eq '$GraphAppId'&`$select=id,appRoles").value)[0]
foreach ($r in $GraphAppRoles) { Grant-GraphAppRoleIfMissing -PrincipalId $principalId -GraphSp $graphSp -RoleValue $r }

if ($GrantDisableRole) {
    $roleDef = @((Invoke-MgGraphRequest -Method GET -Uri "$graph/roleManagement/directory/roleDefinitions?`$filter=displayName eq 'Authentication Administrator'&`$select=id").value)[0]
    $existing = @((Invoke-MgGraphRequest -Method GET -Uri "$graph/roleManagement/directory/roleAssignments?`$filter=principalId eq '$principalId'").value |
            Where-Object { $_.roleDefinitionId -eq $roleDef.id -and $_.directoryScopeId -eq $DirectoryRoleScope })
    if ($existing) { Write-Host '  [=] Authentication Administrator already assigned.' -ForegroundColor DarkGray }
    elseif ($PSCmdlet.ShouldProcess("managed identity $principalId", "assign Authentication Administrator at $DirectoryRoleScope (standing - role-assigned-outside-pim.kql will alert once)")) {
        $body = @{ principalId = $principalId; roleDefinitionId = $roleDef.id; directoryScopeId = $DirectoryRoleScope } | ConvertTo-Json
        Invoke-MgGraphRequest -Method POST -Uri "$graph/roleManagement/directory/roleAssignments" -Body $body -ContentType 'application/json' | Out-Null
        Write-Host "  [+] Authentication Administrator assigned at '$DirectoryRoleScope'." -ForegroundColor Green
    }
}
else {
    Write-Host '  No directory role (the default): the disable works for non-admin cloud-only users without one (E41, 2026-11-05).' -ForegroundColor DarkGray
}

Write-Host "`nPlaybook deployed: $playbookId" -ForegroundColor Green
Write-Host @"
Human steps left (tenant time):
  1. Authorize the Teams connection once, as svc-soc-automation (the SOC team owner, never a person):
     node lab/scripts/monitoring/authorize-teams-connection.mjs $($out.teamsConnectionName.value)
     (or portal > API connections > $($out.teamsConnectionName.value) > Edit API connection > Authorize, signed in as that account).
  2. Terraform: containment_playbook_id = "$playbookId" and enable_itdr_containment = true
     (needs enable_sentinel + enable_itdr_detections), then apply.
  3. Drill: run the playbook from a test High incident (Sentinel: Run playbook) and answer the card as a lab test user:
     node lab/scripts/monitoring/answer-teams-card.mjs --as <test upn> --incident <n> --choice reject|contain
     Capture the card, the incident comment and the ServiceNow work note as evidence.
"@ -ForegroundColor Cyan
