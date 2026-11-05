<#
.SYNOPSIS
    Creates the cloud-only adm- admin accounts listed in lab/iga/admin-accounts.json
    and puts them (and the build account) in the standing Admin-Accounts group,
    the admin passkey target. Idempotent; -WhatIf; -RenderOnly needs no tenant.

.DESCRIPTION
    iam-standard: admin work is done from a SEPARATE cloud-only account,
    adm-first.last@<tenant>.onmicrosoft.com, never from the HR-synced
    workforce account. This script is the only place those accounts are made.

    PER REGISTER ROW (a row names EITHER an HR owner OR a sponsor)
      1. Owner row (ownerEmployeeId): the owner's WORKFORCE account must
         exist, be enabled and match the row's ownerEmployeeId (HR
         provisioned it). A missing, disabled or ambiguous owner is a FAIL
         for that row: an admin account nobody owns is an orphan from day one.
         Sponsor row (sponsorUpn, for an account no HR record owns - the demo
         presenter): the sponsor must exist exactly once, be enabled and be a
         Member (not a guest); otherwise FAIL, not created. Such a row is a
         function account (adm-<word>, no first.last), carries its own
         displayName and may only be eligible for read-only groups
         (pim-demo-readers): with no HR record, no leaver event ever ends it,
         so it never gets write power.
      2. adm-<first.last>@<OnMicrosoftDomain>:
           missing   -> created cloud-only: accountEnabled, displayName
                        "ADM <owner>" (sponsor row: the register's
                        displayName), employeeType "Admin account", a random
                        64-character password that is generated in memory and
                        DISCARDED (nobody knows it; first sign-in is a one-time
                        Temporary Access Pass, then an issued passkey), no
                        usageLocation, no licence, no mailbox.
           exists    -> refused if it is synced from AD (an admin account must
                        be cloud-only); WARN if it holds a licence, or (sponsor
                        row) if its displayName differs from the register -
                        an existing account is never renamed here.
      3. Owner row: manager = the owner's workforce account (the leaver
         process and the privileged review see who the admin account belongs
         to). Sponsor row: no manager; the sponsor is added to the account's
         sponsors relationship (POST /users/{id}/sponsors/$ref) unless it is
         already there. A failed sponsors READ is a FAIL, never "not set yet".
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
    Sponsors (Learn, read 2026-11-05):
      https://learn.microsoft.com/en-us/graph/api/user-post-sponsors
        POST /users/{id}/sponsors/$ref, body {"@odata.id":
        "https://graph.microsoft.com/v1.0/users/{sponsor id}"}, 204 No
        Content; least privileged User.ReadWrite.All (delegated: User
        Administrator or Directory Writers).
      https://learn.microsoft.com/en-us/graph/api/user-list-sponsors
        GET /users/{id}/sponsors ($select supported); User.Read.All.
      Learn describes sponsors for guests; the relationship is on every user
      (adm-labops already carries one, capture E95). verify: the first
      sponsor row run reads the sponsor back.
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
    # Read-only PIM groups a sponsor row (no HR owner) may be eligible for.
    $readOnlyGroups = @('pim-demo-readers')
    $errs = [System.Collections.Generic.List[string]]::new()
    $rows = @($(if ($Register -is [System.Collections.IDictionary] -and $Register.Contains('accounts')) { $Register['accounts'] }) | Where-Object { $_ })
    if ($rows.Count -eq 0) { $errs.Add('accounts is empty or missing.'); return $errs.ToArray() }
    $seen = @{}; $owners = @{}
    foreach ($r in $rows) {
        $a = [string]$r['adminAccount']; $o = [string]$r['ownerEmployeeId']; $sp = [string]$r['sponsorUpn']
        $sponsored = $sp -ne ''
        if ($a -match '(?i)^bg-admin|break-?glass') { $errs.Add("adminAccount '$a' looks like a break-glass account; those are Terraform-owned (modules/groups).") }
        if ($seen.ContainsKey($a)) { $errs.Add("adminAccount '$a' is listed twice.") } else { $seen[$a] = 1 }
        if ($sponsored -and $o -ne '') { $errs.Add("adminAccount '$a' names both an HR owner (ownerEmployeeId) and a sponsor (sponsorUpn): one or the other.") }
        elseif ($sponsored) {
            # No HR owner: a function account, never shaped like a person's.
            if ($a -cnotmatch '^adm-[a-z]+(-[a-z]+)*$') { $errs.Add("adminAccount '$a': a sponsored account (no HR owner) must be adm-<function> (lower case, no first.last - that shape is reserved for a person HR owns).") }
            if ($sp -notmatch '^[^@\s]+@[^@\s]+\.[^@\s]+$') { $errs.Add("adminAccount '$a': sponsorUpn '$sp' must be a user principal name.") }
            elseif ($sp -match '(?i)^(adm-|bg-admin)') { $errs.Add("adminAccount '$a': sponsorUpn '$sp' is an admin or break-glass account; the sponsor is the person who answers for it.") }
            if ([string]::IsNullOrWhiteSpace([string]$r['displayName']) -or [string]$r['displayName'] -notmatch '^[\x20-\x7E]{1,64}$') { $errs.Add("adminAccount '$a': a sponsored account needs a displayName (printable ASCII, at most 64 characters): there is no owner to name it after.") }
            if ($r['globalAdminEligible'] -eq $true) { $errs.Add("adminAccount '$a': a sponsored account (no HR owner, no leaver event) is never Global Administrator eligible.") }
            foreach ($g in @($r['eligibleFor'] | Where-Object { $_ })) {
                if ([string]$g -notin $readOnlyGroups) { $errs.Add("adminAccount '$a': a sponsored account may only be eligible for read-only groups ($($readOnlyGroups -join ', ')), not '$g'.") }
            }
        }
        else {
            if ($a -notmatch '^adm-[a-z]+(-[a-z]+)*(\.[a-z]+(-[a-z]+)*)+$') { $errs.Add("adminAccount '$a' must be adm-first.last (lower case).") }
            if ($o -notmatch '^\d+$') { $errs.Add("adminAccount '$a': ownerEmployeeId '$o' must be the HR employeeId (or name a sponsorUpn for an account no HR record owns).") }
            elseif ($owners.ContainsKey($o)) { $errs.Add("ownerEmployeeId '$o' owns more than one admin account (one per person).") } else { $owners[$o] = 1 }
            if ($r.Contains('displayName')) { $errs.Add("adminAccount '$a': displayName is only for sponsored rows; an owned account is named 'ADM <owner>'.") }
        }
        foreach ($g in @($r['eligibleFor'] | Where-Object { $_ })) {
            if ([string]$g -notmatch '^(pim-tier[01]-[a-z0-9-]+|privileged-iam-admins|pim-demo-readers)$') { $errs.Add("adminAccount '$a': eligibleFor '$g' is not a PIM-for-Groups group (pim-tier0-*, pim-tier1-*, privileged-iam-admins, pim-demo-readers).") }
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
    # Owner row: "ADM <owner>". Sponsor row: the register's displayName.
    param([Parameter(Mandatory)][string]$Upn, [string]$OwnerDisplayName = '', [string]$DisplayName = '', [Parameter(Mandatory)][string]$InitialSecret)
    if ($DisplayName -eq '' -and $OwnerDisplayName -eq '') { throw "ConvertTo-AdminUserBody: $Upn needs an owner display name or its own displayName." }
    return [ordered]@{
        accountEnabled    = $true
        displayName       = $(if ($DisplayName -ne '') { $DisplayName } else { "ADM $OwnerDisplayName" })
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
    $who = if ([string]$r['sponsorUpn'] -ne '') { "sponsor $($r['sponsorUpn']) (no HR owner)" } else { "owner $($r['owner']) ($($r['ownerEmployeeId']))" }
    Write-Console ("  {0,-40} {1}; intended eligibility: {2}{3}" -f (Get-AdminAccountUpn $r['adminAccount'] $OnMicrosoftDomain), $who,
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
    return @(Get-GraphCollection -Uri "$graph/users?`$filter=$f&`$select=id,displayName,userPrincipalName,userType,accountEnabled,onPremisesSyncEnabled,assignedLicenses") | Select-Object -First 1
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
        $sponsorUpn = [string]$r['sponsorUpn']
        if ($sponsorUpn -ne '') {
            # 1. Sponsor row: the person who answers for an account no HR record owns.
            $owner = Find-User -Upn $sponsorUpn
            if (-not $owner) { Add-Result $upn 'FAIL' "sponsor $sponsorUpn not found - an admin account needs someone who answers for it. Not created."; continue }
            if ($owner['accountEnabled'] -eq $false) { Add-Result $upn 'FAIL' "sponsor $sponsorUpn is disabled - an admin account must not outlive its sponsor. Not created; disable the admin account if it exists."; continue }
            if ([string]$owner['userType'] -ne 'Member') { Add-Result $upn 'FAIL' "sponsor $sponsorUpn is not a Member user (userType '$($owner['userType'])') - a guest cannot answer for an admin account. Not created."; continue }
            $label = [string]$r['displayName']
        }
        else {
            # 1. Owner row: the HR-provisioned workforce account.
            $of = [uri]::EscapeDataString("employeeId eq '$([string]$r['ownerEmployeeId'])'")
            $owners = @(Get-GraphCollection -Uri "$graph/users?`$filter=$of&`$select=id,displayName,userPrincipalName,accountEnabled")
            if ($owners.Count -ne 1) { Add-Result $upn 'FAIL' "owner employeeId $($r['ownerEmployeeId']) matches $($owners.Count) user(s) - HR must provision the person first (one match). Not created."; continue }
            $owner = $owners[0]
            if ($owner['accountEnabled'] -eq $false) { Add-Result $upn 'FAIL' "owner $($owner['userPrincipalName']) is disabled (leaver?) - an admin account must not outlive its owner. Not created; disable the admin account if it exists."; continue }
            $label = [string]$owner['displayName']
        }

        # 2. The admin account itself (it may already exist: created earlier,
        #    or by another operator run - never renamed or recreated here).
        $adm = Find-User -Upn $upn
        if ($adm) {
            if ($adm['onPremisesSyncEnabled'] -eq $true) { Add-Result $upn 'FAIL' 'exists but is SYNCED from AD: an admin account must be cloud-only (a compromised AD would own it). Not touched.'; continue }
            if (@($adm['assignedLicenses'] | Where-Object { $_ }).Count) { Add-Result $upn 'WARN' 'holds a licence: an admin account has no mailbox or apps - remove it' }
            if ($sponsorUpn -ne '' -and $adm.Contains('displayName') -and [string]$adm['displayName'] -ne $label) { Add-Result $upn 'WARN' "display name is '$($adm['displayName'])', the register says '$label' (not changed here)" }
            Add-Result $upn 'PASS' 'exists, cloud-only'
        }
        elseif ($PSCmdlet.ShouldProcess($upn, "create cloud-only admin account '$label' (no known password)")) {
            # The password exists only inside this call: never printed, logged or returned.
            $userBody = if ($sponsorUpn -ne '') { ConvertTo-AdminUserBody -Upn $upn -DisplayName $label -InitialSecret (Get-UnknownPassword) } else { ConvertTo-AdminUserBody -Upn $upn -OwnerDisplayName $label -InitialSecret (Get-UnknownPassword) }
            $adm = Invoke-Graph -Method POST -Uri "$graph/users" -Body $userBody
            $userBody = $null
            Add-Result $upn 'PASS' 'created cloud-only (no licence, no known password; issue a one-time TAP in person to register an issued passkey)'
        }
        else { Add-Result $upn 'INFO' 'would create (cloud-only, no licence, no known password)'; continue }

        if ($sponsorUpn -ne '') {
            # 3. Sponsor row: sponsors relationship, not a manager. A failed
            #    read throws (caught below as FAIL): never "not set yet".
            $sponsorIds = @(Get-GraphCollection -Uri "$graph/users/$($adm['id'])/sponsors?`$select=id" | ForEach-Object { [string]$_['id'] })
            if ([string]$owner['id'] -in $sponsorIds) { Add-Result $upn 'PASS' "sponsor $sponsorUpn already set" }
            elseif ($PSCmdlet.ShouldProcess($upn, "add sponsor $sponsorUpn")) {
                Invoke-Graph -Method POST -Uri "$graph/users/$($adm['id'])/sponsors/`$ref" -Body @{ '@odata.id' = "$graph/users/$($owner['id'])" } | Out-Null
                Add-Result $upn 'PASS' "sponsor $sponsorUpn added"
            }
            else { Add-Result $upn 'INFO' "would add sponsor $sponsorUpn" }
        }
        # 3. Owner row: manager = owner's workforce account.
        elseif ($PSCmdlet.ShouldProcess($upn, "set manager $($owner['userPrincipalName'])")) {
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
