<#
.SYNOPSIS
    Deploys the Sentinel response playbook (lab/monitoring/playbook-notify.json):
    incident -> Teams adaptive card + ServiceNow incident + ticket number
    commented back on the Sentinel incident. Pulls its secrets from Key Vault
    at deploy time and grants the two roles the playbook needs.

.DESCRIPTION
    Why a script and not the pipeline: the playbook carries two secrets - the
    Teams Workflows webhook URL (anyone holding it can post to the channel)
    and the ServiceNow integration user's password. The CI identities must
    never hold those, so this runs LOCALLY as the operator (whose IP the Key
    Vault firewall admits), reads the secrets from Key Vault, passes them as
    ARM securestring parameters through a short-lived 0600 parameters file,
    and deletes the file.

    Before running, store the secrets yourself (you type them; nothing here
    prompts or echoes them):
        az keyvault secret set --vault-name <kv> --name teams-webhook-url              --value '<url>'
        az keyvault secret set --vault-name <kv> --name servicenow-integration-password --value '<pw>'

    ROLES GRANTED (Owner / User Access Administrator required - the operator):
      * playbook managed identity  -> Microsoft Sentinel Responder (workspace)
        so it can comment on incidents through the managed-identity connection.
      * "Azure Security Insights" first-party app -> Microsoft Sentinel
        Automation Contributor (resource group) so automation rules may run
        the playbook.

    Then put the printed playbook id into Terraform (TF_SENTINEL_PLAYBOOK_ID /
    sentinel_playbook_id) so modules/monitoring creates the automation rule.

.PARAMETER ResourceGroup
    Resource group of the lab (default rg-identity-lab).

.PARAMETER WorkspaceName
    Log Analytics workspace with Sentinel (default loga-idlab).

.PARAMETER KeyVaultName
    Lab Key Vault holding teams-webhook-url / servicenow-integration-password.

.PARAMETER ServiceNowInstance
    PDI instance name, e.g. dev123456 (empty = skip ServiceNow).

.PARAMETER ServiceNowUser
    ServiceNow integration user (with the itil role). Required with -ServiceNowInstance.

.EXAMPLE
    ./Deploy-Playbook.ps1 -KeyVaultName kv-idlab-7f3a -ServiceNowInstance dev123456 -ServiceNowUser svc.sentinel
#>

#Requires -Version 7.0

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '',
    Justification = 'Interactive operator script: coloured progress goes to the host so it never mixes with returned objects; nothing parses this output.')]
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$ResourceGroup = 'rg-identity-lab',
    [string]$WorkspaceName = 'loga-idlab',
    [Parameter(Mandatory)][string]$KeyVaultName,
    [string]$ServiceNowInstance = '',
    [string]$ServiceNowUser = '',
    [string]$PlaybookName = 'pb-identity-notify',
    [string]$TemplatePath = (Join-Path $PSScriptRoot '..' '..' 'monitoring' 'playbook-notify.json')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $true   # non-zero az exit = terminating error

# First-party "Azure Security Insights" application (Sentinel automation engine).
$SecurityInsightsAppId = '98785600-1bb7-4fb9-b9fa-19afe2c8a360'

function Get-VaultSecretOrEmpty([string]$Name) {
    # A missing secret is allowed (that integration is skipped), so a non-zero
    # az exit must not be terminating here - but it is never silent either.
    $PSNativeCommandUseErrorActionPreference = $false
    $v = az keyvault secret show --vault-name $KeyVaultName --name $Name --query value -o tsv 2>$null
    if ($LASTEXITCODE -ne 0 -or -not $v) {
        Write-Warning "Key Vault secret '$Name' not readable (missing, or your IP is not in the vault firewall) - that integration will be skipped by the playbook."
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

if (-not (Test-Path -LiteralPath $TemplatePath)) { throw "Template not found: $TemplatePath" }
if ($ServiceNowInstance -and -not $ServiceNowUser) { throw '-ServiceNowInstance requires -ServiceNowUser (the integration user with the itil role).' }
$workspaceId = az monitor log-analytics workspace show -g $ResourceGroup -n $WorkspaceName --query id -o tsv
$rgId = az group show -n $ResourceGroup --query id -o tsv

Write-Host "[1/3] Reading playbook secrets from Key Vault '$KeyVaultName'" -ForegroundColor Cyan
$teamsUrl = Get-VaultSecretOrEmpty 'teams-webhook-url'
$snowPassword = if ($ServiceNowInstance) { Get-VaultSecretOrEmpty 'servicenow-integration-password' } else { '' }
if ($ServiceNowInstance -and -not $snowPassword) {
    # The playbook gates ServiceNow on snowInstance only, so blank it (and the user) to make
    # the "skipped" warning true instead of a blank-password Basic auth that fails every run.
    $ServiceNowInstance = ''; $ServiceNowUser = ''
}

Write-Host "[2/3] Deploying $PlaybookName" -ForegroundColor Cyan
$paramFile = New-TemporaryFile
try {
    chmod 600 $paramFile.FullName
    @{
        '$schema'      = 'https://schema.management.azure.com/schemas/2019-04-01/deploymentParameters.json#'
        contentVersion = '1.0.0.0'
        parameters     = @{
            playbookName    = @{ value = $PlaybookName }
            teamsWebhookUrl = @{ value = $teamsUrl }
            snowInstance    = @{ value = $ServiceNowInstance }
            snowUser        = @{ value = $ServiceNowUser }
            snowPassword    = @{ value = $snowPassword }
        }
    } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $paramFile.FullName -NoNewline

    if (-not $PSCmdlet.ShouldProcess($ResourceGroup, "deploy $PlaybookName")) { return }
    $out = az deployment group create -g $ResourceGroup -n "deploy-$PlaybookName" `
        --template-file $TemplatePath --parameters "@$($paramFile.FullName)" `
        --query properties.outputs -o json | ConvertFrom-Json
}
finally {
    Remove-Item -LiteralPath $paramFile.FullName -Force -ErrorAction SilentlyContinue
    $teamsUrl = $null; $snowPassword = $null
}

$playbookId = $out.playbookId.value
$principalId = $out.principalId.value

Write-Host "[3/3] Role assignments" -ForegroundColor Cyan
Grant-RoleIfMissing -PrincipalId $principalId -PrincipalType ServicePrincipal -Role 'Microsoft Sentinel Responder' -Scope $workspaceId
$siObjectId = az ad sp show --id $SecurityInsightsAppId --query id -o tsv
Grant-RoleIfMissing -PrincipalId $siObjectId -PrincipalType ServicePrincipal -Role 'Microsoft Sentinel Automation Contributor' -Scope $rgId

Write-Host "`nPlaybook deployed: $playbookId" -ForegroundColor Green
Write-Host "Next: set GitHub variable TF_SENTINEL_PLAYBOOK_ID (or sentinel_playbook_id in terraform.tfvars) to that id, so modules/monitoring creates the automation rule." -ForegroundColor Cyan
