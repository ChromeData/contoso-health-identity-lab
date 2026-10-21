# Shared helpers for the lab's Pester 5 tests. Dot-source from BeforeAll:
#     . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
#
# Two ways the tests reach the code under test, chosen per script:
#   * Whole-script runs (02/03/04/06, Set-AuthenticationMethodsPolicy): the
#     script is invoked with `&` and every Graph call is answered by a Pester
#     Mock. Mocks of the REAL Microsoft Graph cmdlets copy their parameter
#     metadata, so a script calling a cmdlet with a parameter that does not
#     exist fails the test - a cheap guard against SDK drift.
#   * Pure functions (07/08/drill): Get-ScriptFunctionBlock pulls the
#     function definitions out of the script's syntax tree, so the KPI and
#     readiness maths are tested without running the script body (no Graph
#     connection, no files written).
# Nothing here talks to a tenant.

Set-StrictMode -Version Latest

$script:LabPowerShellRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))

function Get-LabScriptPath {
    param([Parameter(Mandatory)][string]$RelativePath)
    return Join-Path $script:LabPowerShellRoot $RelativePath
}

function Get-ScriptFunctionBlock {
    # Returns a scriptblock holding the script's TOP-LEVEL function definitions
    # (nested helpers come along inside their parent). Dot-source the result:
    #     . (Get-ScriptFunctionBlock -Path $p)
    param([Parameter(Mandatory)][string]$Path, [string[]]$Name = @())
    $tokens = $null; $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$errors)
    if ($errors) { throw "Parse errors in ${Path}: $($errors[0].Message)" }
    $defs = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $false)
    if ($Name) { $defs = @($defs | Where-Object { $_.Name -in $Name }) }
    return [scriptblock]::Create((@($defs | ForEach-Object { $_.Extent.Text }) -join [Environment]::NewLine))
}

function New-MgContextStub {
    # What Get-MgContext returns, with every scope a script might check, so the
    # "missing scope" warning stays quiet unless a test wants it.
    param([string[]]$Scopes = @(
            'User.ReadWrite.All', 'Organization.Read.All', 'GroupMember.ReadWrite.All', 'Group.Read.All',
            'EntitlementManagement.ReadWrite.All', 'Directory.Read.All', 'User.RevokeSessions.All',
            'AppRoleAssignment.ReadWrite.All', 'Application.Read.All', 'Synchronization.ReadWrite.All',
            'Policy.Read.All', 'Policy.ReadWrite.AuthenticationMethod', 'AuditLog.Read.All',
            'RoleManagement.Read.Directory'))
    return [pscustomobject]@{ Scopes = $Scopes; TenantId = '11111111-1111-1111-1111-111111111111'; Account = 'tester@contoso.test' }
}

function New-GraphPage {
    # One Graph collection page as Invoke-MgGraphRequest -OutputType HashTable returns it.
    param([object[]]$Value = @(), [string]$NextLink = '')
    $p = @{ value = @($Value) }
    if ($NextLink) { $p['@odata.nextLink'] = $NextLink }
    return $p
}
