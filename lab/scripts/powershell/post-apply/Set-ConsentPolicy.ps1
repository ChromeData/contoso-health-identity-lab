<#
.SYNOPSIS
    Locks down app consent. Users can consent only to apps from VERIFIED
    publishers (or apps registered in this tenant) and only to permissions
    classified LOW impact. Or, with -UserConsent Disabled, they can't consent
    at all. Everything else goes through the admin consent workflow, reviewed
    by a named group. Idempotent; fails closed before any change.

.DESCRIPTION
    Consent phishing (OWASP NHI3, "illicit consent grant") is a token-theft
    path that never touches a password or MFA. A user clicks "Accept" on a
    malicious multi-tenant app and hands it Mail.Read or Files.ReadWrite.All.
    The default Entra setting lets users consent to any permission that doesn't
    need admin consent, for any app. This script closes that in three steps:

      1. USER CONSENT  authorizationPolicy.defaultUserRolePermissions.
                       permissionGrantPoliciesAssigned:
                         VerifiedPublishersLowRisk -> ManagePermissionGrantsForSelf.microsoft-user-default-low
                         Disabled                  -> no ManagePermissionGrantsForSelf.* policy
                       Any ManagePermissionGrantsForOwnedResource.* entries
                       (group/team owner and developer consent) are KEPT, as
                       Microsoft's guidance requires. verify: newer tenants
                       also offer a Microsoft-managed policy
                       (microsoft-user-default-recommended); the lab pins the
                       explicit low-impact policy so the behaviour is
                       reviewable in code.
      2. LOW IMPACT    the delegated permissions users may still consent to,
                       classified 'low' on the Microsoft Graph service principal:
                       openid, profile, email, offline_access, User.Read (the
                       sign-in minimum). Skipped when consent is Disabled.
      3. ADMIN CONSENT the admin consent request workflow: on, notifications and
                       reminders on, requests expire after -RequestDurationInDays,
                       reviewers = the App-Consent-Reviewers group (transitive
                       user members) plus any -ReviewerUserPrincipalNames.

    FAIL CLOSED: every input (reviewer group, reviewer users, the Graph service
    principal and the permission ids) is resolved BEFORE the first write. A
    missing input stops the script with nothing changed, so it can never
    disable user consent and then fail to enable the admin workflow.

    REVIEWERS DON'T GAIN PRIVILEGE: a reviewer can view, deny or block a
    request, but approving still needs a role that can grant the consent.
    Microsoft says only Global Administrators can approve requests for
    Microsoft Graph APPLICATION permissions. verify: that statement on
    learn.microsoft.com/entra/identity/enterprise-apps/configure-admin-consent-workflow
    and which roles can approve delegated-permission requests. Reviewer
    members should be PIM-eligible for Cloud Application Administrator.

    Existing grants are not touched: the policy only governs FUTURE consent.
    Review existing tenant-wide grants with 06-NHI-Inventory.ps1
    (THIRDPARTY-CONSENT / DELEGATED-TENANTWIDE findings).

    STATUS: not run against a tenant. -OfflinePreview prints all three request
    bodies with placeholder ids.

.PREREQUISITES
    * The reviewer group exists. Terraform should create 'App-Consent-Reviewers'
      (mailNickname app-consent-reviewers) behind its staging flag. Until then,
      pass -ReviewerUserPrincipalNames instead.
    * Roles: Privileged Role Administrator (user consent settings via Graph);
      Cloud Application Administrator (classifications + admin consent
      workflow). The admin-center blades ask for Global Administrator.

.GRAPH SCOPES  (delegated; admin-consent)
    Policy.Read.All                   read current settings
    Policy.ReadWrite.Authorization    authorizationPolicy (user consent)
    Policy.ReadWrite.PermissionGrant  delegatedPermissionClassifications
    Policy.ReadWrite.ConsentRequest   adminConsentRequestPolicy
    Application.Read.All              Microsoft Graph SP + its delegated scopes
    Group.Read.All, User.Read.All     resolve reviewers

.PARAMETER UserConsent
    VerifiedPublishersLowRisk (default) or Disabled.

.PARAMETER LowImpactPermissions
    Microsoft Graph delegated permissions to classify as low impact.

.PARAMETER ReviewerGroupMailNickname
    Group whose transitive user members review admin consent requests.
    Default app-consent-reviewers. Pass '' to use only -ReviewerUserPrincipalNames.

.PARAMETER ReviewerUserPrincipalNames
    Extra individual reviewers.

.PARAMETER RequestDurationInDays
    Days before an unanswered request expires. Default 14.

.PARAMETER OfflinePreview
    No connection: print the request bodies with placeholder ids.

.EXAMPLE
    ./Set-ConsentPolicy.ps1 -OfflinePreview

.EXAMPLE
    Connect-MgGraph -Scopes 'Policy.Read.All','Policy.ReadWrite.Authorization','Policy.ReadWrite.PermissionGrant','Policy.ReadWrite.ConsentRequest','Application.Read.All','Group.Read.All','User.Read.All'
    ./Set-ConsentPolicy.ps1 -WhatIf
    ./Set-ConsentPolicy.ps1
#>

#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter()]
    [ValidateSet('VerifiedPublishersLowRisk', 'Disabled')]
    [string]$UserConsent = 'VerifiedPublishersLowRisk',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string[]]$LowImpactPermissions = @('openid', 'profile', 'email', 'offline_access', 'User.Read'),

    [Parameter()]
    [string]$ReviewerGroupMailNickname = 'app-consent-reviewers',

    [Parameter()]
    [string[]]$ReviewerUserPrincipalNames = @(),

    [Parameter()]
    [ValidateRange(1, 30)]
    [int]$RequestDurationInDays = 14,

    [Parameter()]
    [switch]$OfflinePreview
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
$GraphAppId = '00000003-0000-0000-c000-000000000000'
$selfPrefix = 'ManagePermissionGrantsForSelf.'
$desiredSelfPolicy = if ($UserConsent -eq 'VerifiedPublishersLowRisk') { 'ManagePermissionGrantsForSelf.microsoft-user-default-low' } else { $null }

function Get-Value($Object, [string[]]$Path) {
    $cur = $Object
    foreach ($p in $Path) {
        if ($null -eq $cur) { return $null }
        if ($cur -is [System.Collections.IDictionary]) { $cur = $cur[$p] }
        elseif ($cur.PSObject.Properties[$p]) { $cur = $cur.$p }
        else { return $null }
    }
    return $cur
}

# Lookups use Select-Object -First 1, never @(...)[0]: under StrictMode an
# empty result makes [0] throw 'Index was outside the bounds of the array'
# instead of reaching the friendly 'not found' message.
$results = [System.Collections.Generic.List[object]]::new()
function Add-Result([string]$Setting, [string]$Status, [string]$Detail = '') {
    $results.Add([pscustomobject]@{ Setting = $Setting; Status = $Status; Detail = $Detail })
}

# ===========================================================================
# 0. CONNECT + RESOLVE EVERY INPUT (nothing is written until all resolve)
# ===========================================================================
if ($OfflinePreview) {
    Write-Console 'OFFLINE PREVIEW - no Graph connection; ids are placeholders resolved at runtime on a real run.' -ForegroundColor DarkYellow
    $reviewerQueries = @()
    if ($ReviewerGroupMailNickname) { $reviewerQueries += "/groups/<groupId: $ReviewerGroupMailNickname>/transitiveMembers/microsoft.graph.user" }
    foreach ($upn in $ReviewerUserPrincipalNames) { $reviewerQueries += "/users/<userId: $upn>" }
    if (-not $reviewerQueries.Count) { throw 'No reviewers: pass -ReviewerGroupMailNickname or -ReviewerUserPrincipalNames. An admin consent workflow with no reviewers is a dead end for users.' }
    $currentAssigned = @('ManagePermissionGrantsForSelf.microsoft-user-default-legacy', 'ManagePermissionGrantsForOwnedResource.microsoft-dynamically-managed-permissions-for-team', 'ManagePermissionGrantsForOwnedResource.microsoft-dynamically-managed-permissions-for-chat')
    Write-Console "  (preview assumes the Entra default: $($currentAssigned -join ', '))" -ForegroundColor DarkGray
    $currentDefaultPerms = [ordered]@{ permissionGrantPoliciesAssigned = $currentAssigned }
    $scopeIds = @{}; foreach ($n in $LowImpactPermissions) { $scopeIds[$n] = "<scopeId: $n>" }
    $graphSpId = '<Microsoft Graph servicePrincipal id>'
    $existingClass = @()
    $currentAcr = @{ isEnabled = $false; notifyReviewers = $false; remindersEnabled = $false; requestDurationInDays = 30; reviewers = @() }
}
else {
    $requiredScopes = @('Policy.Read.All', 'Policy.ReadWrite.Authorization', 'Policy.ReadWrite.PermissionGrant',
        'Policy.ReadWrite.ConsentRequest', 'Application.Read.All', 'Group.Read.All', 'User.Read.All')
    $ctx = $null; try { $ctx = Get-MgContext } catch { $ctx = $null }
    if (-not $ctx) { Write-Console 'Connecting to Microsoft Graph...' -ForegroundColor Yellow; Connect-MgGraph -Scopes $requiredScopes; $ctx = Get-MgContext }
    $missingScopes = @($requiredScopes | Where-Object { $ctx.Scopes -and $_ -notin $ctx.Scopes })
    if ($missingScopes) { Write-Warning "Current Graph context does not list: $($missingScopes -join ', '). Calls needing them return 403 (Disconnect-MgGraph, then re-run to reconnect with all scopes)." }

    $reviewerQueries = @()
    if ($ReviewerGroupMailNickname) {
        $grp = @((Invoke-MgGraphRequest -Method GET -Uri "$graph/groups?`$filter=mailNickname eq '$ReviewerGroupMailNickname'&`$select=id,displayName,isAssignableToRole").value) | Select-Object -First 1
        if (-not $grp) {
            throw "Reviewer group '$ReviewerGroupMailNickname' not found. Apply Terraform with the NHI governance staging flag (creates App-Consent-Reviewers), or pass -ReviewerGroupMailNickname '' -ReviewerUserPrincipalNames <upn>. Nothing was changed."
        }
        # verify: group reviewer query format for adminConsentRequestPolicy
        # (accessReviewReviewerScope; transitive user members of the group).
        $reviewerQueries += "/groups/$($grp['id'])/transitiveMembers/microsoft.graph.user"
        Write-Console "Reviewer group: $($grp['displayName']) ($($grp['id']))" -ForegroundColor Cyan
    }
    foreach ($upn in $ReviewerUserPrincipalNames) {
        $u = @((Invoke-MgGraphRequest -Method GET -Uri "$graph/users?`$filter=userPrincipalName eq '$upn'&`$select=id,accountEnabled").value) | Select-Object -First 1
        if (-not $u) { throw "Reviewer '$upn' not found. Nothing was changed." }
        if (-not $u['accountEnabled']) { throw "Reviewer '$upn' is disabled. Nothing was changed." }
        $reviewerQueries += "/users/$($u['id'])"
    }
    if (-not $reviewerQueries.Count) { throw 'No reviewers: pass -ReviewerGroupMailNickname or -ReviewerUserPrincipalNames. Nothing was changed.' }

    # authorizationPolicy: v1.0 returns the single object; older responses
    # wrapped it in 'value'. Accept both.
    $authz = Invoke-MgGraphRequest -Method GET -Uri "$graph/policies/authorizationPolicy"
    if ($authz.Contains('value')) { $authz = @($authz['value']) | Select-Object -First 1 }
    $currentDefaultPerms = Get-Value $authz @('defaultUserRolePermissions')
    $currentAssigned = @(Get-Value $currentDefaultPerms @('permissionGrantPoliciesAssigned') | Where-Object { $_ })

    $scopeIds = @{}; $graphSpId = ''; $existingClass = @()
    if ($desiredSelfPolicy) {
        $gsp = Invoke-MgGraphRequest -Method GET -Uri "$graph/servicePrincipals(appId='$GraphAppId')?`$select=id,oauth2PermissionScopes"
        $graphSpId = [string]$gsp['id']
        foreach ($n in $LowImpactPermissions) {
            $scope = @($gsp['oauth2PermissionScopes']) | Where-Object { $_['value'] -eq $n } | Select-Object -First 1
            if (-not $scope) { throw "Delegated permission '$n' not found on Microsoft Graph. Nothing was changed." }
            if ("$($scope['type'])" -eq 'Admin') { throw "'$n' requires admin consent and can't be classified low impact. Nothing was changed." }
            $scopeIds[$n] = [string]$scope['id']
        }
        $existingClass = @((Invoke-MgGraphRequest -Method GET -Uri "$graph/servicePrincipals/$graphSpId/delegatedPermissionClassifications").value)
    }
    $currentAcr = Invoke-MgGraphRequest -Method GET -Uri "$graph/policies/adminConsentRequestPolicy"
}

# ===========================================================================
# 1. USER CONSENT
# ===========================================================================
Write-Console "`n[1/3] User consent -> $UserConsent" -ForegroundColor Cyan
# Keep everything that isn't a 'for self' policy (owned-resource / developer
# consent), then add the one we want.
$kept = @($currentAssigned | Where-Object { -not $_.StartsWith($selfPrefix, [System.StringComparison]::OrdinalIgnoreCase) })
$desiredAssigned = @($kept) + @($desiredSelfPolicy | Where-Object { $_ })
$sameSet = (@($currentAssigned | ForEach-Object { $_.ToLowerInvariant() } | Sort-Object) -join '|') -eq (@($desiredAssigned | ForEach-Object { $_.ToLowerInvariant() } | Sort-Object) -join '|')
# Send the whole defaultUserRolePermissions object back so the other user
# defaults (allowedToCreateApps, allowedToCreateSecurityGroups, ...) are
# re-sent unchanged instead of depending on PATCH merge behaviour.
$newDefaultPerms = [ordered]@{}
if ($currentDefaultPerms -is [System.Collections.IDictionary]) { foreach ($k in $currentDefaultPerms.Keys) { if ($k -notlike '@odata.*') { $newDefaultPerms[$k] = $currentDefaultPerms[$k] } } }
$newDefaultPerms['permissionGrantPoliciesAssigned'] = $desiredAssigned
$authzBody = @{ defaultUserRolePermissions = $newDefaultPerms } | ConvertTo-Json -Depth 6
if ($OfflinePreview) {
    Write-Console "PATCH $graph/policies/authorizationPolicy" -ForegroundColor DarkGray; $authzBody | Out-Host
    Add-Result 'User consent' 'preview' ($desiredAssigned -join ', ')
}
elseif ($sameSet) {
    Write-Console '  [=] Already set.' -ForegroundColor DarkGray
    Add-Result 'User consent' 'unchanged' ($desiredAssigned -join ', ')
}
elseif ($PSCmdlet.ShouldProcess('authorizationPolicy', "permissionGrantPoliciesAssigned = $($desiredAssigned -join ', ')")) {
    Invoke-MgGraphRequest -Method PATCH -Uri "$graph/policies/authorizationPolicy" -Body $authzBody -ContentType 'application/json' | Out-Null
    Write-Console "  [+] Was: $($currentAssigned -join ', ')" -ForegroundColor Green
    Add-Result 'User consent' 'updated' ($desiredAssigned -join ', ')
}
else { Add-Result 'User consent' 'whatif' ($desiredAssigned -join ', ') }

# ===========================================================================
# 2. LOW-IMPACT PERMISSION CLASSIFICATIONS
# ===========================================================================
Write-Console "`n[2/3] Low-impact permission classifications" -ForegroundColor Cyan
if (-not $desiredSelfPolicy) {
    Write-Console '  [skip] User consent is Disabled; classifications have no effect.' -ForegroundColor DarkGray
    Add-Result 'Low-impact classifications' 'skipped' 'user consent disabled'
}
else {
    foreach ($n in $LowImpactPermissions) {
        $existing = @($existingClass) | Where-Object { [string]$_['permissionId'] -eq $scopeIds[$n] -or [string]$_['permissionName'] -eq $n } | Select-Object -First 1
        if ($existing -and "$($existing['classification'])" -eq 'low') {
            Add-Result "Classify $n" 'unchanged' 'low'
            continue
        }
        if ($existing) {
            # Someone classified it medium/high on purpose: don't downgrade silently.
            Write-Warning "  '$n' is classified '$($existing['classification'])'; leaving it. Users can't consent to it under microsoft-user-default-low."
            Add-Result "Classify $n" 'KEPT-EXISTING' "$($existing['classification'])"
            continue
        }
        $classBody = @{ permissionId = $scopeIds[$n]; permissionName = $n; classification = 'low' } | ConvertTo-Json
        if ($OfflinePreview) {
            Write-Console "POST $graph/servicePrincipals/$graphSpId/delegatedPermissionClassifications" -ForegroundColor DarkGray; $classBody | Out-Host
            Add-Result "Classify $n" 'preview' 'low'
        }
        elseif ($PSCmdlet.ShouldProcess("Microsoft Graph delegated permission '$n'", "classify low impact")) {
            Invoke-MgGraphRequest -Method POST -Uri "$graph/servicePrincipals/$graphSpId/delegatedPermissionClassifications" -Body $classBody -ContentType 'application/json' | Out-Null
            Write-Console "  [+] $n -> low" -ForegroundColor Green
            Add-Result "Classify $n" 'created' 'low'
        }
        else { Add-Result "Classify $n" 'whatif' 'low' }
    }
}

# ===========================================================================
# 3. ADMIN CONSENT WORKFLOW
# ===========================================================================
Write-Console "`n[3/3] Admin consent workflow" -ForegroundColor Cyan
$acr = [ordered]@{
    isEnabled             = $true
    notifyReviewers       = $true
    remindersEnabled      = $true
    requestDurationInDays = $RequestDurationInDays
    reviewers             = @($reviewerQueries | ForEach-Object { [ordered]@{ query = $_; queryType = 'MicrosoftGraph' } })
}
$acrBody = $acr | ConvertTo-Json -Depth 5
$curReviewers = @(@(Get-Value $currentAcr @('reviewers')) | Where-Object { $_ } | ForEach-Object { [string](Get-Value $_ @('query')) } | Sort-Object)
$acrSame = [bool](Get-Value $currentAcr @('isEnabled')) -and [bool](Get-Value $currentAcr @('notifyReviewers')) -and
[bool](Get-Value $currentAcr @('remindersEnabled')) -and ([int](Get-Value $currentAcr @('requestDurationInDays')) -eq $RequestDurationInDays) -and
(($curReviewers -join '|') -eq (@($reviewerQueries | Sort-Object) -join '|'))
if ($OfflinePreview) {
    Write-Console "PUT $graph/policies/adminConsentRequestPolicy" -ForegroundColor DarkGray; $acrBody | Out-Host
    Add-Result 'Admin consent workflow' 'preview' "$($reviewerQueries.Count) reviewer scope(s), $RequestDurationInDays d"
}
elseif ($acrSame) {
    Write-Console '  [=] Already enabled with the same reviewers and expiry.' -ForegroundColor DarkGray
    Add-Result 'Admin consent workflow' 'unchanged'
}
elseif ($PSCmdlet.ShouldProcess('adminConsentRequestPolicy', "enable; reviewers: $($reviewerQueries -join ', ')")) {
    # PUT replaces the whole policy, which is why every field is sent.
    Invoke-MgGraphRequest -Method PUT -Uri "$graph/policies/adminConsentRequestPolicy" -Body $acrBody -ContentType 'application/json' | Out-Null
    Write-Console '  [+] Enabled (Microsoft: can take up to an hour to take effect).' -ForegroundColor Green
    Add-Result 'Admin consent workflow' 'updated' "$($reviewerQueries.Count) reviewer scope(s), $RequestDurationInDays d"
}
else { Add-Result 'Admin consent workflow' 'whatif' }

# ===========================================================================
# 4. VERIFY (read back) + REPORT
# ===========================================================================
$failed = 0
if (-not $OfflinePreview -and -not $WhatIfPreference -and @($results | Where-Object Status -in 'updated', 'created').Count) {
    $authzNow = Invoke-MgGraphRequest -Method GET -Uri "$graph/policies/authorizationPolicy"
    if ($authzNow.Contains('value')) { $authzNow = @($authzNow['value']) | Select-Object -First 1 }
    $assignedNow = @(Get-Value $authzNow @('defaultUserRolePermissions', 'permissionGrantPoliciesAssigned'))
    $selfNow = @($assignedNow | Where-Object { $_ -and $_.StartsWith($selfPrefix, [System.StringComparison]::OrdinalIgnoreCase) })
    $consentOk = if ($desiredSelfPolicy) { $selfNow.Count -eq 1 -and $selfNow[0] -ieq $desiredSelfPolicy } else { $selfNow.Count -eq 0 }
    if (-not $consentOk) { Write-Warning "Read-back: user consent policies are '$($selfNow -join ', ')'."; $failed++ }
    $acrNow = Invoke-MgGraphRequest -Method GET -Uri "$graph/policies/adminConsentRequestPolicy"
    if (-not $acrNow['isEnabled']) { Write-Warning 'Read-back: admin consent workflow is not enabled yet (allow up to an hour, then re-run).'; $failed++ }
}

Write-Console "`nConsent settings:" -ForegroundColor Cyan
$results | Format-Table -AutoSize | Out-Host
if ($failed) { exit 1 }
if (-not $OfflinePreview) {
    Write-Console 'Test: as a non-admin user, open a consent URL for an unverified multi-tenant app; you should get "Need admin approval" with a request button, and the reviewers get an email.' -ForegroundColor Cyan
}
