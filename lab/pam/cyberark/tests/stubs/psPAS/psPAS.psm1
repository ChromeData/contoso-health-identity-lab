<#
  A stub CyberArk vault, standing in for psPAS. NOT CyberArk.

  Named psPAS on purpose: placed first on PSModulePath it shadows the real
  module, so `Import-Module psPAS` inside the scripts resolves here and the
  scripts under test run unmodified.

  The vault is described by a JSON file at $env:STUB_TENANT. Every write is
  appended to $env:STUB_WRITES (one JSON line, with every permission passed),
  so tests can assert what a script tried to change, and that it tried
  nothing.

  WHAT CHANGED FROM THE EARLIER LAB'S STUB (each one hid a real bug):
    * Parameters copy psPAS 8.2.0's real names and types: the 22 permissions
      are [boolean], and there is NO catch-all ValueFromRemainingArguments.
      The old stub swallowed any unknown parameter, so New-LabSafe.ps1's
      `@($roleMap[$m.role])` (an array, not a splat) and permission names the
      stub did not declare passed silently. A wrong name now fails here, as it
      would against the real module.
    * A safe that does not exist THROWS, the way psPAS does: psPAS raises a
      terminating error ($PSCmdlet.ThrowTerminatingError) whose message starts
      "[<HTTP status>]" and whose TargetObject is the original web error
      (psPAS 8.2.0, psPAS/Private/Invoke-PASRestMethod.ps1). The old stub
      returned $null, so the reconciler's "missing safe" path passed tests.
      Against a vault that answers a missing safe with an HTTP error, the old
      reconciler would have stopped at the first missing safe instead:
      -ErrorAction SilentlyContinue does not suppress a terminating error
      (checked in pwsh 7.6.1, 2026-11-06).
    * Any read or write can be made to fail with a status ("fail":
      {"Get-PASSafeMember": 500}) so tests can prove a failure stops the run
      with the "could not run" code instead of reading as drift.

  WHAT IT DOES NOT PROVE: anything about a real vault: paging, the real
  objects psPAS returns, predefined members, or the API's error codes.
#>

Set-StrictMode -Version Latest

function script:Get-Tenant {
    if (-not $env:STUB_TENANT -or -not (Test-Path -LiteralPath $env:STUB_TENANT)) {
        throw 'stub psPAS: STUB_TENANT is not set to a tenant JSON file'
    }
    Get-Content -Raw -LiteralPath $env:STUB_TENANT | ConvertFrom-Json -AsHashtable
}

function script:Write-StubWrite {
    param([string]$Cmdlet, [hashtable]$Params)
    if (-not $env:STUB_WRITES) { return }
    $entry = [ordered]@{ cmdlet = $Cmdlet; params = $Params }
    Add-Content -LiteralPath $env:STUB_WRITES -Value ($entry | ConvertTo-Json -Compress -Depth 6)
}

function script:Stop-LikePsPas {
    # Same shape as psPAS: message "[<status>] ...", ErrorId, TargetObject
    # carrying the HTTP status on .Exception.Response.StatusCode.
    param($Cmdlet, [int]$Status, [string]$Message)
    $target = [pscustomobject]@{ Exception = [pscustomobject]@{ Response = [pscustomobject]@{ StatusCode = $Status } } }
    $Cmdlet.ThrowTerminatingError([System.Management.Automation.ErrorRecord]::new(
            [System.Exception]::new("[$Status] $Message"), "STUB$Status",
            [System.Management.Automation.ErrorCategory]::NotSpecified, $target))
}

function script:Test-InjectedFailure {
    param($Cmdlet, [string]$Name)
    $t = Get-Tenant
    if ($t.ContainsKey('fail') -and $t.fail.ContainsKey($Name)) {
        Stop-LikePsPas $Cmdlet ([int]$t.fail[$Name]) "stub: injected failure for $Name"
    }
}

function script:Get-BoundPermission {
    param([hashtable]$Bound)
    $p = @{}
    foreach ($k in $Bound.Keys) { if ($k -notin 'SafeName', 'MemberName') { $p[$k] = $Bound[$k] } }
    $p
}

function Get-PASSession {
    [CmdletBinding()] param()
    [pscustomobject]@{ User = 'stub'; BaseURI = 'https://stub.invalid' }
}

function Get-PASSafe {
    [CmdletBinding()]
    param([string]$SafeName)
    Test-InjectedFailure $PSCmdlet 'Get-PASSafe'
    $safe = @((Get-Tenant).safes) | Where-Object { $_.safeName -eq $SafeName }
    if (-not $safe) { Stop-LikePsPas $PSCmdlet 404 "stub: safe $SafeName was not found" }
    [pscustomobject]$safe
}

function Get-PASSafeMember {
    [CmdletBinding()]
    param([string]$SafeName)
    Test-InjectedFailure $PSCmdlet 'Get-PASSafeMember'
    $t = Get-Tenant
    if (-not $t.members.ContainsKey($SafeName)) { return }
    foreach ($m in @($t.members[$SafeName])) {
        [pscustomobject]@{ MemberName = $m.MemberName; Permissions = [pscustomobject]$m.Permissions }
    }
}

function Get-PASAccount {
    [CmdletBinding()]
    param([string]$safeName, [string]$search)
    Test-InjectedFailure $PSCmdlet 'Get-PASAccount'
    @((Get-Tenant).accounts) | Where-Object { $_ -and $_.safeName -eq $safeName } | ForEach-Object { [pscustomobject]$_ }
}

function Add-PASSafe {
    [CmdletBinding()]
    param([string]$SafeName, [string]$Description, [string]$ManagingCPM)
    Test-InjectedFailure $PSCmdlet 'Add-PASSafe'
    Write-StubWrite 'Add-PASSafe' @{ SafeName = $SafeName; ManagingCPM = $ManagingCPM }
}

function Add-PASSafeMember {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$SafeName, [Parameter(Mandatory)][string]$MemberName,
        [boolean]$UseAccounts, [boolean]$RetrieveAccounts, [boolean]$ListAccounts, [boolean]$AddAccounts,
        [boolean]$UpdateAccountContent, [boolean]$UpdateAccountProperties,
        [boolean]$InitiateCPMAccountManagementOperations, [boolean]$SpecifyNextAccountContent,
        [boolean]$RenameAccounts, [boolean]$DeleteAccounts, [boolean]$UnlockAccounts, [boolean]$ManageSafe,
        [boolean]$ManageSafeMembers, [boolean]$BackupSafe, [boolean]$ViewAuditLog, [boolean]$ViewSafeMembers,
        [boolean]$requestsAuthorizationLevel1, [boolean]$requestsAuthorizationLevel2,
        [boolean]$AccessWithoutConfirmation, [boolean]$CreateFolders, [boolean]$DeleteFolders,
        [boolean]$MoveAccountsAndFolders
    )
    Test-InjectedFailure $PSCmdlet 'Add-PASSafeMember'
    Write-StubWrite 'Add-PASSafeMember' @{ SafeName = $SafeName; MemberName = $MemberName; Permissions = (Get-BoundPermission $PSBoundParameters) }
}

function Set-PASSafeMember {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$SafeName, [Parameter(Mandatory)][string]$MemberName,
        [boolean]$UseAccounts, [boolean]$RetrieveAccounts, [boolean]$ListAccounts, [boolean]$AddAccounts,
        [boolean]$UpdateAccountContent, [boolean]$UpdateAccountProperties,
        [boolean]$InitiateCPMAccountManagementOperations, [boolean]$SpecifyNextAccountContent,
        [boolean]$RenameAccounts, [boolean]$DeleteAccounts, [boolean]$UnlockAccounts, [boolean]$ManageSafe,
        [boolean]$ManageSafeMembers, [boolean]$BackupSafe, [boolean]$ViewAuditLog, [boolean]$ViewSafeMembers,
        [boolean]$requestsAuthorizationLevel1, [boolean]$requestsAuthorizationLevel2,
        [boolean]$AccessWithoutConfirmation, [boolean]$CreateFolders, [boolean]$DeleteFolders,
        [boolean]$MoveAccountsAndFolders
    )
    Test-InjectedFailure $PSCmdlet 'Set-PASSafeMember'
    Write-StubWrite 'Set-PASSafeMember' @{ SafeName = $SafeName; MemberName = $MemberName; Permissions = (Get-BoundPermission $PSBoundParameters) }
}

function Add-PASAccount {
    [CmdletBinding()]
    param([string]$SafeName, [string]$platformID, [string]$address, [string]$userName, [string]$secretType)
    Test-InjectedFailure $PSCmdlet 'Add-PASAccount'
    Write-StubWrite 'Add-PASAccount' @{ SafeName = $SafeName; userName = $userName; address = $address; platformID = $platformID }
}

# Deliberately NOT defined: Remove-PASSafe, Remove-PASSafeMember,
# Remove-PASAccount. A deletion path added to a script fails here with
# "not recognized" instead of silently revoking access in a test.

Export-ModuleMember -Function Get-PASSession, Get-PASSafe, Get-PASSafeMember, Get-PASAccount,
Add-PASSafe, Add-PASSafeMember, Set-PASSafeMember, Add-PASAccount
