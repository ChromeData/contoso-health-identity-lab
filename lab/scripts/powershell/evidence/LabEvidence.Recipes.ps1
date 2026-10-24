# =============================================================================
# LabEvidence.Recipes.ps1 - dot-sourced by LabEvidence.psm1. The capture
# recipes a plan step names (evidence/LabDayPlan.psd1, Capture = ...): each
# one GET-only Graph read, Log Analytics query, ARM read, gh read or local
# file copy into the capture folder. Never throws: a failed read is an item
# with status failed in the manifest.
# =============================================================================

Set-StrictMode -Version Latest

# Graph scopes each recipe reads with (delegated). verify: least privilege on
# Learn for subscriptions (/directory/subscriptions) and the PIM-for-Groups
# policy reads.
$script:RecipeScopes = @{
    'ca-policies'                = @('Policy.Read.All')
    'auth-contexts'              = @('Policy.Read.All')
    'pim-group-policies'         = @('Group.Read.All', 'RoleManagementPolicy.Read.AzureADGroup')
    'pim-group-eligibility'      = @('Group.Read.All', 'PrivilegedEligibilitySchedule.Read.AzureADGroup')
    'pim-group-activations'      = @('Group.Read.All', 'PrivilegedAssignmentSchedule.Read.AzureADGroup')
    'directory-role-pim'         = @('RoleManagementPolicy.Read.Directory', 'RoleEligibilitySchedule.Read.Directory', 'RoleAssignmentSchedule.Read.Directory')
    'admin-units'                = @('AdministrativeUnit.Read.All', 'RoleManagement.Read.Directory')
    'access-packages'            = @('EntitlementManagement.Read.All')
    'access-package-assignments' = @('EntitlementManagement.Read.All')
    'assignment-requests'        = @('EntitlementManagement.Read.All')
    'lifecycle-workflows'        = @('LifecycleWorkflows.Read.All')
    'access-reviews'             = @('AccessReview.Read.All')
    'auth-methods-policy'        = @('Policy.Read.All')
    'consent-policies'           = @('Policy.Read.All')
    'external-collab'            = @('Policy.Read.All', 'EntitlementManagement.Read.All')
    'app-management-policy'      = @('Policy.Read.All')
    'subscriptions'              = @('Organization.Read.All', 'LicenseAssignment.Read.All')
    'sign-ins'                   = @('AuditLog.Read.All', 'Directory.Read.All')
    'directory-audits'           = @('AuditLog.Read.All', 'Directory.Read.All')
    'provisioning-logs'          = @('AuditLog.Read.All', 'Directory.Read.All')
    'risk-detections'            = @('IdentityRiskEvent.Read.All')
    'risky-users'                = @('IdentityRiskyUser.Read.All')
    'managed-devices'            = @('DeviceManagementManagedDevices.Read.All')
    # az (Log Analytics / ARM) and gh: no Graph scope; az login and gh auth.
    'la'                         = @()
    'incidents'                  = @()
    'sentinel-rules'             = @()
    'evidence-store'             = @()
    'logic-apps'                 = @()
    'logic-app-runs'             = @()
    'azure-pim'                  = @()
    'pipeline'                   = @()
    'open-prs'                   = @()
    'files'                      = @()
}

# =============================================================================
# Recipes
# =============================================================================
function Get-LabCaptureRecipeName {
    [CmdletBinding()]
    [OutputType([string[]])]
    param()
    return @($script:RecipeScopes.Keys | Sort-Object)
}

function Get-LabCaptureScope {
    # The union of Graph scopes a set of capture specs reads with.
    [CmdletBinding()]
    [OutputType([string[]])]
    param([AllowEmptyCollection()][object[]]$Specs = @())
    $all = foreach ($s in @($Specs)) { if ($s -and $script:RecipeScopes.ContainsKey([string]$s['Recipe'])) { $script:RecipeScopes[[string]$s['Recipe']] } }
    return @($all | Where-Object { $_ } | Sort-Object -Unique)
}

function Test-LabCaptureItemOk {
    # True when this capture already holds an 'ok' item of that name: a read
    # that depends on an earlier one (decisions on definitions, links on
    # packages) is recorded as failed, never as an empty 'ok', when the
    # earlier read failed.
    param([Parameter(Mandatory)]$Context, [Parameter(Mandatory)][string]$Name)
    return [bool]@($Context.Items | Where-Object { $_['name'] -eq $Name -and $_['status'] -eq 'ok' }).Count
}

function Get-LabPimGroup {
    # The PIM-governed groups: the tier groups (mailNickname pim-tier*) and
    # privileged-iam-admins (the Terraform contract). Display names and
    # mailNicknames are lab-defined; ids stay in raw/.
    param([Parameter(Mandatory)]$Context)
    if ($Context.Cache.ContainsKey('pimGroups')) { return $Context.Cache['pimGroups'] }
    $groups = [System.Collections.Generic.List[object]]::new()
    foreach ($f in @("startswith(mailNickname,'pim-tier')", "mailNickname eq 'privileged-iam-admins'")) {
        $r = Get-LabGraphResult -Uri "$script:Graph/groups?`$filter=$([uri]::EscapeDataString($f))&`$select=id,displayName,mailNickname"
        foreach ($g in @($r.Items)) { $groups.Add($g) }
    }
    $Context.Cache['pimGroups'] = $groups.ToArray()
    return $Context.Cache['pimGroups']
}

function Invoke-LabPerGroupRecipe {
    # One Graph read per PIM group: $filter = -FilterTemplate with {id} set
    # to the group id (escaped after the substitution), then -Query.
    param([Parameter(Mandatory)]$Context, [Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$FilterTemplate, [string]$Query = '', [Parameter(Mandatory)][string]$Source, [scriptblock]$Summarize, [string]$SinceProperty = '', [AllowNull()][Nullable[datetime]]$WindowStartUtc = $null)
    try {
        $groups = @(Get-LabPimGroup -Context $Context)
        $out = [System.Collections.Generic.List[object]]::new()
        $all = [System.Collections.Generic.List[object]]::new()
        foreach ($g in $groups) {
            $filter = [uri]::EscapeDataString($FilterTemplate.Replace('{id}', [string]$g['id']))
            $uri = '{0}{1}?$filter={2}{3}' -f $script:Graph, $Path, $filter, $Query
            $r = Get-LabGraphResult -Uri $uri
            $rows = @($r.Items)
            if ($SinceProperty -and $WindowStartUtc) { $rows = @($rows | Where-Object { Test-LabSince -Value $_[$SinceProperty] -Since ([datetime]$WindowStartUtc) }) }
            foreach ($x in $rows) { $all.Add($x) }
            $out.Add([ordered]@{ group = [string]$g['displayName']; mailNickname = [string]$g['mailNickname']; groupId = [string]$g['id']; truncated = $r.Truncated; value = $rows })
        }
        $file = Save-LabCaptureText -Context $Context -Name $Name -Text (ConvertTo-Json -InputObject $out.ToArray() -Depth 40)
        $summary = [ordered]@{ groups = $groups.Count }
        if ($Summarize) { $summary['rows'] = & $Summarize $all.ToArray() }
        Add-LabCaptureItem -Context $Context -Name $Name -Status 'ok' -File $file -Source $Source -Count $all.Count -Summary $summary -WindowStartUtc $WindowStartUtc
    }
    catch { Add-LabCaptureItem -Context $Context -Name $Name -Status 'failed' -Source $Source -Reason $_.Exception.Message -WindowStartUtc $WindowStartUtc }
}

function Get-LabWorkspace {
    # The Log Analytics workspace (resource id + customerId), once per capture.
    param([Parameter(Mandatory)]$Context)
    if ($Context.Cache.ContainsKey('workspace')) { return $Context.Cache['workspace'] }
    $rg = [string]$Context.Settings['ResourceGroup']; $ws = [string]$Context.Settings['WorkspaceName']
    if (-not $rg -or -not $ws) { throw 'ResourceGroup and WorkspaceName are needed for Log Analytics captures (settings file).' }
    $w = Invoke-LabAzJson -ArgumentList @('monitor', 'log-analytics', 'workspace', 'show', '-g', $rg, '-n', $ws)
    if (-not $w -or -not $w['customerId']) { throw 'the workspace has no customerId (az monitor log-analytics workspace show).' }
    $Context.Cache['workspace'] = $w
    return $w
}

function Get-LabSubscriptionId {
    param([Parameter(Mandatory)]$Context)
    if (-not $Context.Cache.ContainsKey('subscription')) {
        $a = Invoke-LabAzJson -ArgumentList @('account', 'show')
        if (-not $a -or -not $a['id']) { throw 'az account show returned no subscription (az login).' }
        $Context.Cache['subscription'] = [string]$a['id']
    }
    return $Context.Cache['subscription']
}

function Save-LabLaQuery {
    <#
    One Log Analytics query (the query API, through az rest) over the
    window, into raw/<Name>.json with the KQL beside it as raw/<Name>.kql.
    #>
    param([Parameter(Mandatory)]$Context, [Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][string]$Query, [Parameter(Mandatory)][datetime]$WindowStartUtc)
    $source = "Log Analytics query API (KQL in raw/$((Get-LabSafeFileName -Name $Name)).kql)"
    try {
        $ws = Get-LabWorkspace -Context $Context
        $tmp = New-TemporaryFile
        try {
            $span = '{0}/{1}' -f (Format-LabGraphTime -Utc $WindowStartUtc), (Format-LabGraphTime -Utc $Context.NowUtc)
            @{ query = $Query; timespan = $span } | ConvertTo-Json -Compress | Set-Content -LiteralPath $tmp.FullName -Encoding utf8NoBOM
            $resp = Invoke-LabAzJson -ArgumentList @('rest', '--method', 'post', '--url', "https://api.loganalytics.io/v1/workspaces/$($ws['customerId'])/query", '--resource', 'https://api.loganalytics.io', '--body', "@$($tmp.FullName)")
        }
        finally { Remove-Item -LiteralPath $tmp.FullName -Force -ErrorAction SilentlyContinue }
        $null = Save-LabCaptureText -Context $Context -Name $Name -Text $Query -Extension '.kql'
        $file = Save-LabCaptureText -Context $Context -Name $Name -Text (ConvertTo-Json -InputObject $resp -Depth 40)
        $rows = 0
        if ($resp -and $resp['tables']) { $t = @($resp['tables'])[0]; if ($t -and $t['rows']) { $rows = @($t['rows']).Count } }
        Add-LabCaptureItem -Context $Context -Name $Name -Status 'ok' -File $file -Source $source -Count $rows -WindowStartUtc $WindowStartUtc
    }
    catch { Add-LabCaptureItem -Context $Context -Name $Name -Status 'failed' -Source $source -Reason $_.Exception.Message -WindowStartUtc $WindowStartUtc }
}

function Save-LabArmGet {
    # One ARM GET (az rest) into raw/<Name>.json.
    param([Parameter(Mandatory)]$Context, [Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][string]$Url, [Parameter(Mandatory)][string]$Source, [scriptblock]$Summarize, [string]$SinceProperty = '', [AllowNull()][Nullable[datetime]]$WindowStartUtc = $null)
    try {
        $resp = Invoke-LabAzJson -ArgumentList @('rest', '--method', 'get', '--url', $Url)
        $rows = if ($resp -and $resp.Contains('value')) { @($resp['value']) } elseif ($resp) { @($resp) } else { @() }
        if ($SinceProperty -and $WindowStartUtc) {
            $rows = @($rows | Where-Object { $v = $_; foreach ($p in $SinceProperty -split '\.') { if ($v -is [System.Collections.IDictionary]) { $v = $v[$p] } else { $v = $null } }; Test-LabSince -Value $v -Since ([datetime]$WindowStartUtc) })
        }
        $file = Save-LabCaptureText -Context $Context -Name $Name -Text (ConvertTo-Json -InputObject $rows -Depth 40)
        $summary = if ($Summarize) { & $Summarize $rows } else { $null }
        Add-LabCaptureItem -Context $Context -Name $Name -Status 'ok' -File $file -Source $Source -Count $rows.Count -Summary $summary -WindowStartUtc $WindowStartUtc
    }
    catch { Add-LabCaptureItem -Context $Context -Name $Name -Status 'failed' -Source $Source -Reason $_.Exception.Message -WindowStartUtc $WindowStartUtc }
}

function Save-LabGhJson {
    param([Parameter(Mandatory)]$Context, [Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][string[]]$ArgumentList, [Parameter(Mandatory)][string]$Source)
    $wd = if ($Context.LabRoot) { Split-Path -Parent $Context.LabRoot } else { '' }
    $r = Invoke-LabNativeCommand -FilePath 'gh' -ArgumentList $ArgumentList -WorkingDirectory $wd
    if ($r.ExitCode -ne 0) { throw "$Source failed: $($r.StdErr)" }
    $data = if (([string]$r.StdOut).Trim()) { $r.StdOut | ConvertFrom-Json -AsHashtable -Depth 64 } else { @() }
    $null = Save-LabCaptureText -Context $Context -Name $Name -Text (ConvertTo-Json -InputObject $data -Depth 40)
    return $data
}

function Save-LabPipeline {
    <#
    The Terraform record from the pipeline itself (GitHub Actions, the
    repository of this clone): the PR merged in the window with its comments
    (the plan comment), the terraform-plan and terraform-apply runs in the
    window, and the newest run log of each. Read-only gh verbs only.
    #>
    param([Parameter(Mandatory)]$Context, [Parameter(Mandatory)][datetime]$WindowStartUtc)
    $since = $WindowStartUtc
    $summary = [ordered]@{}
    try {
        $prs = @(Save-LabGhJson -Context $Context -Name 'prs-merged' -Source 'gh pr list --state merged' -ArgumentList @('pr', 'list', '--state', 'merged', '--limit', '10', '--json', 'number,title,mergedAt,url,headRefName'))
        $inWindow = @($prs | Where-Object { Test-LabSince -Value $_['mergedAt'] -Since $since } | Sort-Object { [datetime]$_['mergedAt'] } -Descending)
        $summary['prsMergedInWindow'] = $inWindow.Count
        if ($inWindow.Count) {
            $n = [string]$inWindow[0]['number']
            $null = Save-LabGhJson -Context $Context -Name "pr-$n" -Source 'gh pr view {number}' -ArgumentList @('pr', 'view', $n, '--json', 'number,title,url,mergedAt,comments,reviews,files')
        }
        foreach ($wf in @('terraform-plan', 'terraform-apply')) {
            $runs = @(Save-LabGhJson -Context $Context -Name "runs-$wf" -Source "gh run list --workflow $wf.yml" -ArgumentList @('run', 'list', '--workflow', "$wf.yml", '--limit', '10', '--json', 'databaseId,displayTitle,event,headBranch,status,conclusion,createdAt,url'))
            $recent = @($runs | Where-Object { Test-LabSince -Value $_['createdAt'] -Since $since } | Sort-Object { [datetime]$_['createdAt'] } -Descending)
            $summary["$wf-runs"] = $recent.Count
            if ($recent.Count) {
                $summary["$wf-latest"] = "$($recent[0]['status'])/$($recent[0]['conclusion'])"
                $id = [string]$recent[0]['databaseId']
                $wd = if ($Context.LabRoot) { Split-Path -Parent $Context.LabRoot } else { '' }
                $log = Invoke-LabNativeCommand -FilePath 'gh' -ArgumentList @('run', 'view', $id, '--log') -WorkingDirectory $wd
                if ($log.ExitCode -eq 0) { $null = Save-LabCaptureText -Context $Context -Name "$wf-run-log" -Text $log.StdOut -Extension '.log' }
                else { $summary["$wf-log"] = 'unavailable (a run still in progress has no log yet)' }
            }
        }
        $status = if ($inWindow.Count -or $summary['terraform-apply-runs']) { 'ok' } else { 'absent' }
        $reason = if ($status -eq 'absent') { 'no merged PR and no apply run since the step started' } else { '' }
        Add-LabCaptureItem -Context $Context -Name 'pipeline' -Status $status -File 'raw/' -Source 'GitHub Actions: merged PR + terraform-plan / terraform-apply runs (gh, read-only)' -Summary $summary -Reason $reason -WindowStartUtc $since
    }
    catch { Add-LabCaptureItem -Context $Context -Name 'pipeline' -Status 'failed' -Source 'GitHub Actions (gh, read-only)' -Reason $_.Exception.Message -WindowStartUtc $since }
}

function Save-LabFileCopy {
    # Copies the files a script wrote in the window (Path: a glob relative to
    # the lab root) into raw/files/<Name>/, with any .sha256 sidecar.
    param([Parameter(Mandatory)]$Context, [Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][datetime]$WindowStartUtc)
    $source = "local files: lab/$Path"
    try {
        if (-not $Context.LabRoot) { throw 'no lab root' }
        $files = @(Get-ChildItem -Path (Join-Path $Context.LabRoot $Path) -File -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTimeUtc -ge $WindowStartUtc.ToUniversalTime() })
        if (-not $files.Count) { Add-LabCaptureItem -Context $Context -Name $Name -Status 'absent' -Source $source -Reason 'no matching file written in the window' -WindowStartUtc $WindowStartUtc; return }
        $dest = Join-Path $Context.Raw 'files' (Get-LabSafeFileName -Name $Name)
        New-Item -ItemType Directory -Path $dest -Force | Out-Null
        foreach ($f in $files) {
            $target = Join-Path $dest $f.Name
            if (Test-Path -LiteralPath $target) { $target = Join-Path $dest "$($f.Directory.Name)-$($f.Name)" }
            Copy-Item -LiteralPath $f.FullName -Destination $target
        }
        Add-LabCaptureItem -Context $Context -Name $Name -Status 'ok' -File "raw/files/$(Get-LabSafeFileName -Name $Name)/" -Source $source -Count $files.Count -WindowStartUtc $WindowStartUtc
    }
    catch { Add-LabCaptureItem -Context $Context -Name $Name -Status 'failed' -Source $source -Reason $_.Exception.Message -WindowStartUtc $WindowStartUtc }
}

function Add-LabCaptureFile {
    # A transcript (or any local file) into raw/<Subfolder>/.
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Context, [Parameter(Mandatory)][string]$Path, [string]$Subfolder = 'transcripts')
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { Add-LabCaptureItem -Context $Context -Name (Split-Path -Leaf $Path) -Status 'absent' -Source $Subfolder -Reason 'file not found'; return }
    $dest = Join-Path $Context.Raw $Subfolder
    New-Item -ItemType Directory -Path $dest -Force | Out-Null
    Copy-Item -LiteralPath $Path -Destination (Join-Path $dest (Split-Path -Leaf $Path))
    Add-LabCaptureItem -Context $Context -Name (Split-Path -Leaf $Path) -Status 'ok' -File "raw/$Subfolder/$(Split-Path -Leaf $Path)" -Source 'console transcript of the script run (the script''s own output)'
}

function Invoke-LabCaptureRecipe {
    <#
    Runs one capture spec (@{ Recipe = ...; Name; User; Service; Query;
    Workflow; Path; LookbackHours }) into the capture. Never throws: a
    failure is an item with status 'failed'. A spec whose placeholders the
    day runner could not fill arrives with Unresolved = the reason.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Context, [Parameter(Mandatory)][hashtable]$Spec)
    $recipe = [string]$Spec['Recipe']
    $label = if ($Spec['Name']) { [string]$Spec['Name'] } else { $recipe }
    $since = Get-LabWindowStart -Context $Context -Spec $Spec
    if ($Spec['Unresolved']) { Add-LabCaptureItem -Context $Context -Name $label -Status 'failed' -Source $recipe -Reason "not run: $($Spec['Unresolved'])" -WindowStartUtc $since; return }
    $g = $script:Graph
    $t = Format-LabGraphTime -Utc $since
    $esc = { param($f) [uri]::EscapeDataString($f) }
    try {
        switch ($recipe) {
            'ca-policies' {
                $null = Save-LabGraphItem -Context $Context -Name $label -Uri "$g/identity/conditionalAccess/policies" -Source 'GET v1.0 /identity/conditionalAccess/policies' -Summarize { param($i) Get-LabCaSummary -Items $i }
            }
            'auth-contexts' {
                $null = Save-LabGraphItem -Context $Context -Name $label -Uri "$g/identity/conditionalAccess/authenticationContextClassReferences" -Source 'GET v1.0 /identity/conditionalAccess/authenticationContextClassReferences' -Summarize { param($i) $h = [ordered]@{}; foreach ($c in $i) { $h[[string]$c['id']] = [bool]$c['isAvailable'] }; $h }
            }
            'pim-group-policies' {
                # verify: $expand=policy($expand=rules) on the assignment list.
                Invoke-LabPerGroupRecipe -Context $Context -Name $label -Path '/policies/roleManagementPolicyAssignments' -FilterTemplate "scopeId eq '{id}' and scopeType eq 'Group'" -Query '&$expand=policy($expand=rules)' -Source "GET v1.0 /policies/roleManagementPolicyAssignments?`$filter=scopeId eq '{group}' and scopeType eq 'Group'&`$expand=policy(`$expand=rules), per PIM group"
            }
            'pim-group-eligibility' {
                Invoke-LabPerGroupRecipe -Context $Context -Name $label -Path '/identityGovernance/privilegedAccess/group/eligibilitySchedules' -FilterTemplate "groupId eq '{id}'" -Source "GET v1.0 /identityGovernance/privilegedAccess/group/eligibilitySchedules?`$filter=groupId eq '{group}', per PIM group" -Summarize { param($i) Get-LabScheduleSummary -Items $i }
            }
            'pim-group-activations' {
                Invoke-LabPerGroupRecipe -Context $Context -Name "$label-requests" -Path '/identityGovernance/privilegedAccess/group/assignmentScheduleRequests' -FilterTemplate "groupId eq '{id}'" -Source "GET v1.0 /identityGovernance/privilegedAccess/group/assignmentScheduleRequests?`$filter=groupId eq '{group}', in the window" -SinceProperty 'createdDateTime' -WindowStartUtc $since -Summarize { param($i) Get-LabCountBy -Items $i -Key { param($r) "$($r['action'])/$($r['status'])" } }
                Invoke-LabPerGroupRecipe -Context $Context -Name "$label-instances" -Path '/identityGovernance/privilegedAccess/group/assignmentScheduleInstances' -FilterTemplate "groupId eq '{id}'" -Source "GET v1.0 /identityGovernance/privilegedAccess/group/assignmentScheduleInstances?`$filter=groupId eq '{group}'" -Summarize { param($i) Get-LabCountBy -Items $i -Key { param($r) [string]$r['assignmentType'] } }
            }
            'directory-role-pim' {
                $ga = $script:GlobalAdminRoleId
                $null = Save-LabGraphItem -Context $Context -Name "$label-policy" -Uri "$g/policies/roleManagementPolicyAssignments?`$filter=$(& $esc "scopeId eq '/' and scopeType eq 'DirectoryRole' and roleDefinitionId eq '$ga'")&`$expand=policy(`$expand=rules)" -Source "GET v1.0 /policies/roleManagementPolicyAssignments?`$filter=scopeId eq '/' and scopeType eq 'DirectoryRole' and roleDefinitionId eq '<Global Administrator>'&`$expand=policy(`$expand=rules)"
                $null = Save-LabGraphItem -Context $Context -Name "$label-eligible" -Uri "$g/roleManagement/directory/roleEligibilitySchedules?`$filter=$(& $esc "roleDefinitionId eq '$ga'")" -Source "GET v1.0 /roleManagement/directory/roleEligibilitySchedules?`$filter=roleDefinitionId eq '<Global Administrator>'" -Summarize { param($i) Get-LabScheduleSummary -Items $i }
                $null = Save-LabGraphItem -Context $Context -Name "$label-active" -Uri "$g/roleManagement/directory/roleAssignmentSchedules?`$filter=$(& $esc "roleDefinitionId eq '$ga'")" -Source "GET v1.0 /roleManagement/directory/roleAssignmentSchedules?`$filter=roleDefinitionId eq '<Global Administrator>'" -Summarize { param($i) Get-LabScheduleSummary -Items $i }
            }
            'admin-units' {
                $aus = @(Save-LabGraphItem -Context $Context -Name "$label-list" -Uri "$g/directory/administrativeUnits?`$select=id,displayName,membershipType,membershipRule,isMemberManagementRestricted" -Source 'GET v1.0 /directory/administrativeUnits' -Summarize { param($i) Get-LabCountBy -Items $i -Key { param($a) [string]$a['displayName'] } })
                foreach ($au in @($aus | Where-Object { [string]$_['displayName'] -in @('AU-Workforce-Standard', 'RMAU-VIP') })) {
                    $n = Get-LabSafeFileName -Name ([string]$au['displayName']).ToLowerInvariant()
                    $id = [uri]::EscapeDataString([string]$au['id'])
                    $null = Save-LabGraphItem -Context $Context -Name "$label-$n-members" -Uri "$g/directory/administrativeUnits/$id/members?`$select=id,userPrincipalName,displayName" -Source 'GET v1.0 /directory/administrativeUnits/{au}/members'
                    $null = Save-LabGraphItem -Context $Context -Name "$label-$n-role-assignments" -Uri "$g/roleManagement/directory/roleAssignments?`$filter=$(& $esc "directoryScopeId eq '/administrativeUnits/$([string]$au['id'])'")" -Source "GET v1.0 /roleManagement/directory/roleAssignments?`$filter=directoryScopeId eq '/administrativeUnits/{au}'"
                }
            }
            'access-packages' {
                # verify: $expand=assignmentPolicies on the v1.0 list.
                $pkgs = @(Save-LabGraphItem -Context $Context -Name $label -Uri "$g/identityGovernance/entitlementManagement/accessPackages?`$expand=assignmentPolicies" -Source 'GET v1.0 /identityGovernance/entitlementManagement/accessPackages?$expand=assignmentPolicies' -Summarize {
                        param($i)
                        $h = [ordered]@{}
                        foreach ($p in $i) { $h[[string]$p['displayName']] = [ordered]@{ policies = @($p['assignmentPolicies'] | Where-Object { $_ }).Count; automatic = [bool](@($p['assignmentPolicies'] | Where-Object { $_ -and $_['automaticRequestSettings'] }).Count) } }
                        $h
                    })
                $linkSource = 'GET v1.0 /identityGovernance/entitlementManagement/accessPackages/{package}/incompatibleAccessPackages, per package'
                if (-not (Test-LabCaptureItemOk -Context $Context -Name $label)) {
                    Add-LabCaptureItem -Context $Context -Name "$label-incompatible" -Status 'failed' -Source $linkSource -Reason 'not read: the access package list could not be read'
                }
                else {
                    $links = [System.Collections.Generic.List[object]]::new()
                    foreach ($p in $pkgs) {
                        $r = Get-LabGraphResult -Uri "$g/identityGovernance/entitlementManagement/accessPackages/$([uri]::EscapeDataString([string]$p['id']))/incompatibleAccessPackages?`$select=id,displayName"
                        $links.Add([ordered]@{ accessPackage = [string]$p['displayName']; incompatibleWith = @($r.Items | ForEach-Object { [string]$_['displayName'] }) })
                    }
                    $file = Save-LabCaptureText -Context $Context -Name "$label-incompatible" -Text (ConvertTo-Json -InputObject $links.ToArray() -Depth 10)
                    Add-LabCaptureItem -Context $Context -Name "$label-incompatible" -Status 'ok' -File $file -Source $linkSource -Count $links.Count -Summary ([ordered]@{ packagesWithLinks = @($links | Where-Object { @($_['incompatibleWith']).Count }).Count })
                }
            }
            'access-package-assignments' {
                $null = Save-LabGraphItem -Context $Context -Name $label -Uri "$g/identityGovernance/entitlementManagement/assignments?`$expand=target,accessPackage,assignmentPolicy" -Source 'GET v1.0 /identityGovernance/entitlementManagement/assignments?$expand=target,accessPackage,assignmentPolicy' -Summarize { param($i) Get-LabCountBy -Items $i -Key { param($a) "$(if ($a['accessPackage']) { $a['accessPackage']['displayName'] })/$($a['state'])" } }
            }
            'assignment-requests' {
                $null = Save-LabGraphItem -Context $Context -Name $label -Uri "$g/identityGovernance/entitlementManagement/assignmentRequests?`$expand=accessPackage,requestor" -Source 'GET v1.0 /identityGovernance/entitlementManagement/assignmentRequests, in the window' -SinceProperty 'createdDateTime' -WindowStartUtc $since -Summarize { param($i) Get-LabCountBy -Items $i -Key { param($r) "$($r['requestType'])/$($r['state'])/$($r['status'])" } }
            }
            'lifecycle-workflows' {
                $null = Save-LabGraphItem -Context $Context -Name $label -Uri "$g/identityGovernance/lifecycleWorkflows/workflows" -Source 'GET v1.0 /identityGovernance/lifecycleWorkflows/workflows' -Summarize { param($i) Get-LabCountBy -Items $i -Key { param($w) "$($w['category'])/enabled=$($w['isEnabled'])" } }
            }
            'access-reviews' {
                $defs = @(Save-LabGraphItem -Context $Context -Name "$label-definitions" -Uri "$g/identityGovernance/accessReviews/definitions" -Source 'GET v1.0 /identityGovernance/accessReviews/definitions' -Summarize { param($i) Get-LabCountBy -Items $i -Key { param($d) [string]$d['status'] } })
                $decSource = 'GET v1.0 /identityGovernance/accessReviews/definitions/{definition}/instances/{instance}/decisions'
                if (-not (Test-LabCaptureItemOk -Context $Context -Name "$label-definitions")) {
                    Add-LabCaptureItem -Context $Context -Name "$label-decisions" -Status 'failed' -Source $decSource -Reason 'not read: the review definitions could not be read'
                }
                else {
                    $all = [System.Collections.Generic.List[object]]::new()
                    foreach ($d in $defs) {
                        $did = [uri]::EscapeDataString([string]$d['id'])
                        foreach ($inst in @((Get-LabGraphResult -Uri "$g/identityGovernance/accessReviews/definitions/$did/instances").Items)) {
                            $iid = [uri]::EscapeDataString([string]$inst['id'])
                            $dec = @((Get-LabGraphResult -Uri "$g/identityGovernance/accessReviews/definitions/$did/instances/$iid/decisions").Items)
                            $all.Add([ordered]@{ definition = [string]$d['displayName']; instanceStatus = [string]$inst['status']; decisions = $dec })
                        }
                    }
                    $file = Save-LabCaptureText -Context $Context -Name "$label-decisions" -Text (ConvertTo-Json -InputObject $all.ToArray() -Depth 40)
                    $flat = @($all | ForEach-Object { $_['decisions'] } | Where-Object { $_ })
                    Add-LabCaptureItem -Context $Context -Name "$label-decisions" -Status 'ok' -File $file -Source $decSource -Count $flat.Count -Summary (Get-LabCountBy -Items $flat -Key { param($x) "$($x['decision'])/$($x['applyResult'])" })
                }
            }
            'auth-methods-policy' {
                $null = Save-LabGraphItem -Context $Context -Name $label -Uri "$g/policies/authenticationMethodsPolicy" -Source 'GET v1.0 /policies/authenticationMethodsPolicy' -Summarize { param($i) $h = [ordered]@{}; foreach ($c in @($i[0]['authenticationMethodConfigurations'])) { if ($c) { $h[[string]$c['id']] = [string]$c['state'] } }; $h }
            }
            'consent-policies' {
                $null = Save-LabGraphItem -Context $Context -Name "$label-authorization" -Uri "$g/policies/authorizationPolicy" -Source 'GET v1.0 /policies/authorizationPolicy'
                $null = Save-LabGraphItem -Context $Context -Name "$label-admin-consent" -Uri "$g/policies/adminConsentRequestPolicy" -Source 'GET v1.0 /policies/adminConsentRequestPolicy' -Summarize { param($i) [ordered]@{ isEnabled = [bool]$i[0]['isEnabled'] } }
            }
            'external-collab' {
                $null = Save-LabGraphItem -Context $Context -Name "$label-authorization" -Uri "$g/policies/authorizationPolicy" -Source 'GET v1.0 /policies/authorizationPolicy' -Summarize { param($i) [ordered]@{ allowInvitesFrom = [string]$i[0]['allowInvitesFrom'] } }
                $null = Save-LabGraphItem -Context $Context -Name "$label-cross-tenant-default" -Uri "$g/policies/crossTenantAccessPolicy/default" -Source 'GET v1.0 /policies/crossTenantAccessPolicy/default'
                $null = Save-LabGraphItem -Context $Context -Name "$label-authentication-flows" -Uri "$g/policies/authenticationFlowsPolicy" -Source 'GET v1.0 /policies/authenticationFlowsPolicy'
                $null = Save-LabGraphItem -Context $Context -Name "$label-connected-organizations" -Uri "$g/identityGovernance/entitlementManagement/connectedOrganizations" -Source 'GET v1.0 /identityGovernance/entitlementManagement/connectedOrganizations' -Summarize { param($i) Get-LabCountBy -Items $i -Key { param($o) [string]$o['state'] } }
            }
            'app-management-policy' {
                $null = Save-LabGraphItem -Context $Context -Name $label -Uri "$g/policies/defaultAppManagementPolicy" -Source 'GET v1.0 /policies/defaultAppManagementPolicy' -Summarize { param($i) [ordered]@{ isEnabled = [bool]$i[0]['isEnabled'] } }
            }
            'subscriptions' {
                $null = Save-LabGraphItem -Context $Context -Name "$label-company" -Uri "$g/directory/subscriptions" -Source 'GET v1.0 /directory/subscriptions' -Summarize {
                    param($i)
                    @($i | ForEach-Object { [ordered]@{ sku = [string]$_['skuPartNumber']; isTrial = [bool]$_['isTrial']; status = [string]$_['status']; nextLifecycleDateTime = [string]$_['nextLifecycleDateTime'] } })
                }
                $null = Save-LabGraphItem -Context $Context -Name "$label-skus" -Uri "$g/subscribedSkus" -Source 'GET v1.0 /subscribedSkus' -Summarize { param($i) Get-LabCountBy -Items $i -Key { param($s) "$($s['skuPartNumber'])/$($s['capabilityStatus'])" } }
            }
            'sign-ins' {
                $f = "createdDateTime ge $t"
                $src = "GET v1.0 /auditLogs/signIns?`$filter=createdDateTime ge {window start}"
                if ($Spec['User']) { $f += " and userPrincipalName eq '$(([string]$Spec['User']).Replace("'", "''"))'"; $src += " and userPrincipalName eq '{test or admin account}'" }
                $null = Save-LabGraphItem -Context $Context -Name $label -Uri "$g/auditLogs/signIns?`$filter=$(& $esc $f)&`$top=500" -Source $src -MaxPages 10 -WindowStartUtc $since -Summarize { param($i) Get-LabSignInSummary -Items $i }
            }
            'directory-audits' {
                $f = "activityDateTime ge $t"
                $src = "GET v1.0 /auditLogs/directoryAudits?`$filter=activityDateTime ge {window start}"
                if ($Spec['Service']) { $f += " and loggedByService eq '$([string]$Spec['Service'])'"; $src += " and loggedByService eq '$([string]$Spec['Service'])'" }
                $null = Save-LabGraphItem -Context $Context -Name $label -Uri "$g/auditLogs/directoryAudits?`$filter=$(& $esc $f)&`$top=500" -Source $src -MaxPages 10 -WindowStartUtc $since -Summarize { param($i) Get-LabCountBy -Items $i -Key { param($a) [string]$a['activityDisplayName'] } }
            }
            'provisioning-logs' {
                $null = Save-LabGraphItem -Context $Context -Name $label -Uri "$g/auditLogs/provisioning?`$filter=$(& $esc "activityDateTime ge $t")&`$top=500" -Source "GET v1.0 /auditLogs/provisioning?`$filter=activityDateTime ge {window start}" -MaxPages 10 -WindowStartUtc $since -Summarize { param($i) Get-LabCountBy -Items $i -Key { param($p) "$($p['provisioningAction'])/$(if ($p['provisioningStatusInfo']) { $p['provisioningStatusInfo']['status'] })" } }
            }
            'risk-detections' {
                $null = Save-LabGraphItem -Context $Context -Name $label -Uri "$g/identityProtection/riskDetections?`$filter=$(& $esc "detectedDateTime ge $t")" -Source "GET v1.0 /identityProtection/riskDetections?`$filter=detectedDateTime ge {window start}" -WindowStartUtc $since -Summarize { param($i) Get-LabCountBy -Items $i -Key { param($d) "$($d['riskEventType'])/$($d['riskLevel'])/$($d['riskState'])" } }
            }
            'risky-users' {
                $null = Save-LabGraphItem -Context $Context -Name $label -Uri "$g/identityProtection/riskyUsers" -Source 'GET v1.0 /identityProtection/riskyUsers' -Summarize { param($i) Get-LabCountBy -Items $i -Key { param($u) "$($u['riskLevel'])/$($u['riskState'])" } }
            }
            'managed-devices' {
                $null = Save-LabGraphItem -Context $Context -Name $label -Uri "$g/deviceManagement/managedDevices?`$select=deviceName,complianceState,operatingSystem,osVersion,lastSyncDateTime,managedDeviceOwnerType" -Source 'GET v1.0 /deviceManagement/managedDevices' -Summarize { param($i) Get-LabCountBy -Items $i -Key { param($d) [string]$d['complianceState'] } }
            }
            'la' {
                if (-not $Spec['Query']) { throw "the 'la' recipe needs a Query" }
                Save-LabLaQuery -Context $Context -Name $label -Query ([string]$Spec['Query']) -WindowStartUtc $since
            }
            'incidents' {
                Save-LabLaQuery -Context $Context -Name "$label-incidents" -WindowStartUtc $since -Query 'SecurityIncident | summarize arg_max(LastModifiedTime, *) by IncidentNumber | project IncidentNumber, Title, Severity, Status, Classification, CreatedTime, ClosedTime, AlertIds, Labels, IncidentUrl'
                Save-LabLaQuery -Context $Context -Name "$label-alerts" -WindowStartUtc $since -Query 'SecurityAlert | project TimeGenerated, AlertName, AlertSeverity, ProviderName, Status, SystemAlertId, Entities'
            }
            'sentinel-rules' {
                $ws = Get-LabWorkspace -Context $Context
                Save-LabArmGet -Context $Context -Name $label -Url "https://management.azure.com$($ws['id'])/providers/Microsoft.SecurityInsights/alertRules?api-version=2023-02-01" -Source 'ARM GET {workspace}/providers/Microsoft.SecurityInsights/alertRules' -Summarize { param($i) Get-LabCountBy -Items $i -Key { param($r) "$($r['kind'])/enabled=$(if ($r['properties']) { $r['properties']['enabled'] })" } }
            }
            'evidence-store' {
                $acct = [string]$Context.Settings['EvidenceStorageAccount']
                if (-not $acct) { throw 'EvidenceStorageAccount is not in the settings file.' }
                $a = Invoke-LabAzJson -ArgumentList @('storage', 'account', 'show', '-n', $acct)
                $file = Save-LabCaptureText -Context $Context -Name $label -Text (ConvertTo-Json -InputObject $a -Depth 40)
                $imm = if ($a -and $a['immutableStorageWithVersioning']) { $a['immutableStorageWithVersioning'] } else { @{} }
                $pol = if ($imm -is [System.Collections.IDictionary] -and $imm['immutabilityPolicy']) { $imm['immutabilityPolicy'] } else { @{} }
                Add-LabCaptureItem -Context $Context -Name $label -Status 'ok' -File $file -Source 'az storage account show (the WORM evidence store)' -Summary ([ordered]@{
                        allowSharedKeyAccess = $a['allowSharedKeyAccess']; publicNetworkAccess = [string]$a['publicNetworkAccess']; minimumTlsVersion = [string]$a['minimumTlsVersion']
                        versionLevelImmutability = $imm['enabled']; immutabilityState = [string]$pol['state']; immutabilityDays = $pol['immutabilityPeriodSinceCreationInDays']
                    })
            }
            'logic-apps' {
                $rg = [string]$Context.Settings['ResourceGroup']
                $l = @(Invoke-LabAzJson -ArgumentList @('resource', 'list', '-g', $rg, '--resource-type', 'Microsoft.Logic/workflows'))
                $file = Save-LabCaptureText -Context $Context -Name $label -Text (ConvertTo-Json -InputObject $l -Depth 40)
                Add-LabCaptureItem -Context $Context -Name $label -Status 'ok' -File $file -Source 'az resource list --resource-type Microsoft.Logic/workflows (the playbooks)' -Count $l.Count -Summary (Get-LabCountBy -Items $l -Key { param($r) [string]$r['name'] })
            }
            'logic-app-runs' {
                $wf = [string]$Spec['Workflow']
                if ($wf -notmatch '^[A-Za-z0-9-]{1,80}$') { throw "the 'logic-app-runs' recipe needs a Workflow name" }
                $sub = Get-LabSubscriptionId -Context $Context
                Save-LabArmGet -Context $Context -Name $label -Url "https://management.azure.com/subscriptions/$sub/resourceGroups/$([string]$Context.Settings['ResourceGroup'])/providers/Microsoft.Logic/workflows/$wf/runs?api-version=2016-06-01" -Source "ARM GET .../Microsoft.Logic/workflows/$wf/runs, in the window" -SinceProperty 'properties.startTime' -WindowStartUtc $since -Summarize { param($i) Get-LabCountBy -Items $i -Key { param($r) if ($r['properties']) { [string]$r['properties']['status'] } } }
            }
            'azure-pim' {
                $sub = Get-LabSubscriptionId -Context $Context
                $scope = "https://management.azure.com/subscriptions/$sub/resourceGroups/$([string]$Context.Settings['ResourceGroup'])/providers/Microsoft.Authorization"
                Save-LabArmGet -Context $Context -Name "$label-eligible" -Url "$scope/roleEligibilityScheduleInstances?api-version=2020-10-01" -Source 'ARM GET {resource group}/providers/Microsoft.Authorization/roleEligibilityScheduleInstances'
                Save-LabArmGet -Context $Context -Name "$label-active" -Url "$scope/roleAssignmentScheduleInstances?api-version=2020-10-01" -Source 'ARM GET {resource group}/providers/Microsoft.Authorization/roleAssignmentScheduleInstances' -Summarize { param($i) Get-LabCountBy -Items $i -Key { param($r) if ($r['properties']) { [string]$r['properties']['assignmentType'] } } }
            }
            'pipeline' { Save-LabPipeline -Context $Context -WindowStartUtc $since }
            'open-prs' {
                $prs = @(Save-LabGhJson -Context $Context -Name $label -Source 'gh pr list --state open' -ArgumentList @('pr', 'list', '--state', 'open', '--limit', '20', '--json', 'number,title,url,createdAt,headRefName'))
                Add-LabCaptureItem -Context $Context -Name $label -Status 'ok' -File "raw/$(Get-LabSafeFileName -Name $label).json" -Source 'gh pr list --state open (read-only)' -Count $prs.Count
            }
            'files' {
                if (-not $Spec['Path']) { throw "the 'files' recipe needs a Path" }
                Save-LabFileCopy -Context $Context -Name $label -Path ([string]$Spec['Path']) -WindowStartUtc $since
            }
            default { throw "unknown capture recipe '$recipe'" }
        }
    }
    catch { Add-LabCaptureItem -Context $Context -Name $label -Status 'failed' -Source $recipe -Reason $_.Exception.Message -WindowStartUtc $since }
}
