<#
.SYNOPSIS
    Creates the cloud-only adm- admin accounts listed in lab/iga/admin-accounts.json
    and puts them (and the build account) in the standing Admin-Accounts group,
    the admin passkey target. Idempotent; -WhatIf; -RenderOnly needs no tenant.

.DESCRIPTION
    iam-standard: admin work is done from a SEPARATE cloud-only account,
    adm-first.last@<tenant>.onmicrosoft.com, never from the HR-synced
    workforce account. This script is the only place those accounts are made.

    PER REGISTER ROW
      1. The owner's WORKFORCE account must exist, be enabled and match the
         row's ownerEmployeeId (HR provisioned it). A missing, disabled or
         ambiguous owner is a FAIL for that row: an admin account nobody owns
         is an orphan from day one.
      2. adm-<first.last>@<OnMicrosoftDomain>:
           missing   -> created cloud-only: accountEnabled, displayName
                        "ADM <owner>", employeeType "Admin account", a random
                        64-character password that is generated in memory and
                        DISCARDED (nobody knows it; first sign-in is a one-time
                        Temporary Access Pass, then an issued passkey), no
                        usageLocation, no licence, no mailbox.
           exists    -> refused if it is synced from AD (an admin account must
                        be cloud-only); WARN if it holds a licence.
      3. Manager = the owner's workforce account (the leaver process and the
         privileged review see who the admin account belongs to).
      4. Member of Admin-Accounts (modules/groups; role-assignable, standing,
         holds no role): the admin passkey profile and registration campaign
         target in Set-AuthenticationMethodsPolicy.ps1. A PIM group cannot be
         that target - eligible people are only in it during an activation,
         which needs the passkey first.

    -BuildAccountUpn: the build account (admin@<tenant>) is added to
    Admin-Accounts too (refused if synced), so its admin passkey keeps working
    until Convert-BuildAccountToEligible.ps1 turns it eligible.

    WHAT IT DOES NOT DO: grant any role or eligibility (eligibleFor in the
    register is the reviewed intent; Set-PimGroupEligibility.ps1 and
    Set-DirectoryRolePimPolicies.ps1 grant it), issue the TAP (a credential:
    07-Passwordless-Rollout.ps1 -IssueTapFor, by a Privileged Authentication
    Administrator, delivered in person), or delete anything.

.PREREQUISITES
    * Terraform envs/dev applied with enable_premium (Admin-Accounts exists).
    * The owners exist in Entra (HR provisioning: mock-hr/hr_feed.csv
      Information Technology rows).
    * Signed-in roles: User Administrator (create users, set manager) and
      Privileged Role Administrator (membership of a role-assignable group).

.GRAPH SCOPES  (delegated; admin consent)
    User.ReadWrite.All                   read owners, create admin accounts, set manager
    GroupMember.ReadWrite.All            add members
    RoleManagement.ReadWrite.Directory   required to change a role-assignable group's members

.PARAMETER RegisterPath
    Default lab/iga/admin-accounts.json.

.PARAMETER OnMicrosoftDomain
    The tenant's *.onmicrosoft.com domain (admin accounts never use the
    federated/custom domain).

.PARAMETER BuildAccountUpn
    Also add the build account to Admin-Accounts.

.PARAMETER GroupMailNickname
    Default admin-accounts (Terraform contract).

.PARAMETER RenderOnly
    Validate the register and print the plan. No Graph module or tenant.

.EXAMPLE
    ./New-AdminAccounts.ps1 -OnMicrosoftDomain '<tenant>.onmicrosoft.com' -RenderOnly
.EXAMPLE
    Connect-MgGraph -Scopes 'User.ReadWrite.All','GroupMember.ReadWrite.All','RoleManagement.ReadWrite.Directory'
    ./New-AdminAccounts.ps1 -OnMicrosoftDomain '<tenant>.onmicrosoft.com' -BuildAccountUpn 'admin@<tenant>.onmicrosoft.com' -WhatIf

.NOTES
    TENANT-TIME: nothing here has run against Entra.
    verify: POST /users accepts employeeType "Admin account" (free text in
      v1.0) and a password the caller immediately forgets with
      forceChangePasswordNextSignIn = true (the TAP sign-in then registers the
      passkey; the password is never used).
    verify: POST /groups/{id}/members/$ref on a role-assignable group needs
      RoleManagement.ReadWrite.Directory in addition to GroupMember.ReadWrite.All
      (Learn: role-assignable group membership), and a Privileged Role
      Administrator caller.

.WHAT IT DEMONSTRATES
    Separate admin identities as code: owned by a named person, cloud-only,
    no password anyone knows, no mailbox to phish, and always inside the
    standing passkey target so phishing-resistant step-up can be enforced
    without locking them out.
#>

#Requires -Version 7.0

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$RegisterPath = (Join-Path $PSScriptRoot '..' '..' '..' 'iga' 'admin-accounts.json'),

    [Parameter(Mandatory)]
    [ValidatePattern('^[A-Za-z0-9-]+\.onmicrosoft\.com$', ErrorMessage = 'OnMicrosoftDomain must look like <tenant>.onmicrosoft.com')]
    [string]$OnMicrosoftDomain,

    [Parameter()]
    [ValidatePattern('^$|^[^@\s]+@[^@\s]+\.[^@\s]+$', ErrorMessage = 'BuildAccountUpn must be a UPN.')]
    [string]$BuildAccountUpn = '',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$GroupMailNickname = 'admin-accounts',

    [Parameter()]
    [switch]$RenderOnly
)

# Operator console output. Write-Host on purpose (colour, -NoNewline); every
# script-level status line goes through here, so the analyzer suppression is
# scoped to this one function, never to the file.
function Write-Console {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'Interactive operator console (colour, -NoNewline): status lines for the person running the script, not pipeline data.')]
    param()
    Write-Host @args
}

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$graph = 'https://graph.microsoft.com/v1.0'

# =============================================================================
# PURE FUNCTIONS (tests/New-AdminAccounts.Tests.ps1)
# =============================================================================
function Test-AdminAccountRegister {
    # Every reason the register must not be applied. Empty = safe.
    param([Parameter(Mandatory)]$Register)
    $errs = [System.Collections.Generic.List[string]]::new()
    $rows = @($(if ($Register -is [System.Collections.IDictionary] -and $Register.Contains('accounts')) { $Register['accounts'] }) | Where-Object { $_ })
    if ($rows.Count -eq 0) { $errs.Add('accounts is empty or missing.'); return $errs.ToArray() }
    $seen = @{}; $owners = @{}
    foreach ($r in $rows) {
        $a = [string]$r['adminAccount']; $o = [string]$r['ownerEmployeeId']
        if ($a -notmatch '^adm-[a-z]+(-[a-z]+)*(\.[a-z]+(-[a-z]+)*)+$') { $errs.Add("adminAccount '$a' must be adm-first.last (lower case).") }
        if ($a -match '(?i)^bg-admin|break-?glass') { $errs.Add("adminAccount '$a' looks like a break-glass account; those are Terraform-owned (modules/groups).") }
        if ($seen.ContainsKey($a)) { $errs.Add("adminAccount '$a' is listed twice.") } else { $seen[$a] = 1 }
        if ($o -notmatch '^\d+$') { $errs.Add("adminAccount '$a': ownerEmployeeId '$o' must be the HR employeeId.") }
        elseif ($owners.ContainsKey($o)) { $errs.Add("ownerEmployeeId '$o' owns more than one admin account (one per person).") } else { $owners[$o] = 1 }
        foreach ($g in @($r['eligibleFor'] | Where-Object { $_ })) {
            if ([string]$g -notmatch '^(pim-tier[01]-[a-z0-9-]+|privileged-iam-admins)$') { $errs.Add("adminAccount '$a': eligibleFor '$g' is not a PIM-for-Groups group (pim-tier0-*, pim-tier1-*, privileged-iam-admins).") }
        }
    }
    return $errs.ToArray()
}

function Get-AdminAccountUpn {
    param([Parameter(Mandatory)][string]$AdminAccount, [Parameter(Mandatory)][string]$Domain)
    return "$AdminAccount@$Domain".ToLowerInvariant()
}

function Get-UnknownPassword {
    # 64 random characters from a CSPRNG, meeting the Entra complexity rule.
    # Returned to the caller only to be sent once and dropped; never printed,
    # logged or stored (the account signs in with a TAP, then a passkey).
    $sets = @('ABCDEFGHJKLMNPQRSTUVWXYZ', 'abcdefghijkmnopqrstuvwxyz', '23456789', '!#%*+-=?@^_')
    $all = -join $sets
    $chars = [System.Collections.Generic.List[char]]::new()
    foreach ($set in $sets) { $chars.Add($set[[System.Security.Cryptography.RandomNumberGenerator]::GetInt32($set.Length)]) }
    while ($chars.Count -lt 64) { $chars.Add($all[[System.Security.Cryptography.RandomNumberGenerator]::GetInt32($all.Length)]) }
    for ($i = $chars.Count - 1; $i -gt 0; $i--) { $j = [System.Security.Cryptography.RandomNumberGenerator]::GetInt32($i + 1); $t = $chars[$i]; $chars[$i] = $chars[$j]; $chars[$j] = $t }
    return -join $chars
}

function ConvertTo-AdminUserBody {
    # POST /users body for one admin account (the password is passed in, not made here).
    param([Parameter(Mandatory)][string]$Upn, [Parameter(Mandatory)][string]$OwnerDisplayName, [Parameter(Mandatory)][string]$InitialSecret)
    return [ordered]@{
        accountEnabled    = $true
        displayName       = "ADM $OwnerDisplayName"
        mailNickname      = ($Upn -split '@')[0]
        userPrincipalName = $Upn
        employeeType      = 'Admin account'
        passwordProfile   = [ordered]@{ forceChangePasswordNextSignIn = $true; password = $InitialSecret }
    }
}

# =============================================================================
# SCRIPT BODY
# =============================================================================
if (-not (Test-Path -LiteralPath $RegisterPath -PathType Leaf)) { throw "Register not found: $RegisterPath" }
$register = Get-Content -LiteralPath $RegisterPath -Raw | ConvertFrom-Json -AsHashtable
$problems = @(Test-AdminAccountRegister -Register $register)
if ($problems.Count) {
    foreach ($p in $problems) { Write-Warning "  REGISTER ERROR: $p" }
    throw "admin-accounts.json is not safe to apply ($($problems.Count) error(s)). Nothing was sent."
}
$rows = @($register['accounts'] | Where-Object { $_ })
Write-Console "Admin accounts ($($rows.Count)) -> Admin-Accounts ($GroupMailNickname)" -ForegroundColor Cyan
foreach ($r in $rows) {
    Write-Console ("  {0,-40} owner {1} ({2}); intended eligibility: {3}{4}" -f (Get-AdminAccountUpn $r['adminAccount'] $OnMicrosoftDomain), $r['owner'], $r['ownerEmployeeId'],
        $(if (@($r['eligibleFor']).Count) { @($r['eligibleFor']) -join ', ' } else { 'none' }), $(if ($r['globalAdminEligible'] -eq $true) { ' + Global Administrator' } else { '' })) -ForegroundColor DarkGray
}
if ($BuildAccountUpn) { Write-Console "  build account $BuildAccountUpn -> Admin-Accounts only" -ForegroundColor DarkGray }
if ($RenderOnly) { return }

# ---- Graph ------------------------------------------------------------------
if (-not (Get-Command Invoke-MgGraphRequest -ErrorAction SilentlyContinue)) { throw 'Microsoft.Graph.Authentication is required, or use -RenderOnly.' }
$requiredScopes = @('User.ReadWrite.All', 'GroupMember.ReadWrite.All', 'RoleManagement.ReadWrite.Directory')
$ctx = $null; try { $ctx = Get-MgContext } catch { Write-Verbose "Get-MgContext failed: $($_.Exception.Message)"; $ctx = $null }
if (-not $ctx) { Write-Console 'Connecting to Microsoft Graph...' -ForegroundColor Yellow; Connect-MgGraph -Scopes $requiredScopes -NoWelcome; $ctx = Get-MgContext }
$missingScopes = @($requiredScopes | Where-Object { $ctx.Scopes -and $_ -notin $ctx.Scopes })
if ($missingScopes) { Write-Warning "Current Graph context does not list: $($missingScopes -join ', '). Calls needing them will return 403." }

function Invoke-Graph {
    param([string]$Method = 'GET', [Parameter(Mandatory)][string]$Uri, $Body = $null)
    if ($null -ne $Body) { return Invoke-MgGraphRequest -Method $Method -Uri $Uri -Body ($Body | ConvertTo-Json -Depth 10) -ContentType 'application/json' -OutputType HashTable }
    return Invoke-MgGraphRequest -Method $Method -Uri $Uri -OutputType HashTable
}
function Get-GraphCollection {
    param([Parameter(Mandatory)][string]$Uri)
    $items = [System.Collections.Generic.List[object]]::new(); $next = $Uri
    while ($next) {
        $page = Invoke-MgGraphRequest -Method GET -Uri $next -OutputType HashTable
        foreach ($v in @($page['value'])) { if ($null -ne $v) { $items.Add($v) } }
        $next = if ($page.Contains('@odata.nextLink')) { $page['@odata.nextLink'] } else { $null }
    }
    return $items.ToArray()
}
function Find-User {
    # One user by UPN, or $null when it does not exist (any other error throws).
    param([Parameter(Mandatory)][string]$Upn)
    $f = [uri]::EscapeDataString("userPrincipalName eq '$($Upn.Replace("'", "''"))'")
    return @(Get-GraphCollection -Uri "$graph/users?`$filter=$f&`$select=id,userPrincipalName,accountEnabled,onPremisesSyncEnabled,assignedLicenses") | Select-Object -First 1
}

$results = [System.Collections.Generic.List[object]]::new()
function Add-Result {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'Interactive operator console (colour, -NoNewline): status lines for the person running the script, not pipeline data.')]
    param([string]$Account, [ValidateSet('PASS', 'WARN', 'FAIL', 'INFO')][string]$Status, [string]$Detail)
    $results.Add([pscustomobject]@{ Account = $Account; Status = $Status; Detail = $Detail })
    Write-Host ("  [{0}] {1} - {2}" -f $Status, $Account, $Detail) -ForegroundColor @{ PASS = 'Green'; WARN = 'Yellow'; FAIL = 'Red'; INFO = 'DarkGray' }[$Status]
}

$gf = [uri]::EscapeDataString("mailNickname eq '$GroupMailNickname'")
$group = @(Get-GraphCollection -Uri "$graph/groups?`$filter=$gf&`$select=id,displayName,isAssignableToRole,groupTypes")
if ($group.Count -ne 1) { throw "Group '$GroupMailNickname' found $($group.Count) time(s); apply Terraform envs/dev (enable_premium, modules/groups Admin-Accounts) first. Nothing was sent." }
$group = $group[0]
if ($group['isAssignableToRole'] -ne $true -or @($group['groupTypes']) -contains 'DynamicMembership') { throw "'$GroupMailNickname' must be a role-assignable ASSIGNED group (only Privileged Role Administrators may change who is in the admin passkey target). Nothing was sent." }
$memberIds = @(Get-GraphCollection -Uri "$graph/groups/$($group['id'])/members?`$select=id" | ForEach-Object { [string]$_['id'] })

function Add-ToAdminGroup {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param([string]$Label, [string]$UserId)
    if ($UserId -in $memberIds) { Add-Result $Label 'PASS' 'already in Admin-Accounts'; return }
    if ($PSCmdlet.ShouldProcess($Label, 'add to Admin-Accounts (admin passkey target)')) {
        Invoke-Graph -Method POST -Uri "$graph/groups/$($group['id'])/members/`$ref" -Body @{ '@odata.id' = "$graph/directoryObjects/$UserId" } | Out-Null
        Add-Result $Label 'PASS' 'added to Admin-Accounts'
    }
    else { Add-Result $Label 'INFO' 'would add to Admin-Accounts' }
}

Write-Console "`nApplying" -ForegroundColor Cyan
foreach ($r in $rows) {
    $upn = Get-AdminAccountUpn $r['adminAccount'] $OnMicrosoftDomain
    try {
        # 1. Owner: the HR-provisioned workforce account.
        $of = [uri]::EscapeDataString("employeeId eq '$([string]$r['ownerEmployeeId'])'")
        $owners = @(Get-GraphCollection -Uri "$graph/users?`$filter=$of&`$select=id,displayName,userPrincipalName,accountEnabled")
        if ($owners.Count -ne 1) { Add-Result $upn 'FAIL' "owner employeeId $($r['ownerEmployeeId']) matches $($owners.Count) user(s) - HR must provision the person first (one match). Not created."; continue }
        $owner = $owners[0]
        if ($owner['accountEnabled'] -eq $false) { Add-Result $upn 'FAIL' "owner $($owner['userPrincipalName']) is disabled (leaver?) - an admin account must not outlive its owner. Not created; disable the admin account if it exists."; continue }

        # 2. The admin account itself.
        $adm = Find-User -Upn $upn
        if ($adm) {
            if ($adm['onPremisesSyncEnabled'] -eq $true) { Add-Result $upn 'FAIL' 'exists but is SYNCED from AD: an admin account must be cloud-only (a compromised AD would own it). Not touched.'; continue }
            if (@($adm['assignedLicenses'] | Where-Object { $_ }).Count) { Add-Result $upn 'WARN' 'holds a licence: an admin account has no mailbox or apps - remove it' }
            Add-Result $upn 'PASS' 'exists, cloud-only'
        }
        elseif ($PSCmdlet.ShouldProcess($upn, "create cloud-only admin account for $($owner['displayName']) (no known password)")) {
            # The password exists only inside this call: never printed, logged or returned.
            $adm = Invoke-Graph -Method POST -Uri "$graph/users" -Body (ConvertTo-AdminUserBody -Upn $upn -OwnerDisplayName ([string]$owner['displayName']) -InitialSecret (Get-UnknownPassword))
            Add-Result $upn 'PASS' 'created cloud-only (no licence, no known password; issue a one-time TAP in person to register an issued passkey)'
        }
        else { Add-Result $upn 'INFO' 'would create (cloud-only, no licence, no known password)'; continue }

        # 3. Manager = owner's workforce account.
        if ($PSCmdlet.ShouldProcess($upn, "set manager $($owner['userPrincipalName'])")) {
            Invoke-Graph -Method PUT -Uri "$graph/users/$($adm['id'])/manager/`$ref" -Body @{ '@odata.id' = "$graph/users/$($owner['id'])" } | Out-Null
        }
        # 4. Standing admin passkey target.
        Add-ToAdminGroup -Label $upn -UserId ([string]$adm['id'])
    }
    catch { Add-Result $upn 'FAIL' $_.Exception.Message }
}

if ($BuildAccountUpn) {
    try {
        $b = Find-User -Upn $BuildAccountUpn
        if (-not $b) { Add-Result $BuildAccountUpn 'FAIL' 'build account not found' }
        elseif ($b['onPremisesSyncEnabled'] -eq $true) { Add-Result $BuildAccountUpn 'FAIL' 'build account is SYNCED from AD - an admin account must be cloud-only' }
        else { Add-ToAdminGroup -Label "$BuildAccountUpn (build account)" -UserId ([string]$b['id']) }
    }
    catch { Add-Result $BuildAccountUpn 'FAIL' $_.Exception.Message }
}

$fails = @($results | Where-Object Status -eq 'FAIL').Count
Write-Console "`nAdmin accounts: $fails FAIL, $(@($results | Where-Object Status -eq 'WARN').Count) WARN" -ForegroundColor $(if ($fails) { 'Red' } else { 'Green' })
Write-Console 'Next: TAP in person -> register an issued key model -> Set-AuthenticationMethodsPolicy.ps1 (checks the target) -> Set-PimGroupEligibility.ps1 for each eligibleFor.' -ForegroundColor Cyan
$results.ToArray()
if ($fails) { exit 1 }
