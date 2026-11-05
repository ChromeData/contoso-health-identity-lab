# Pester 5 tests for Export-EvidencePack.ps1 - the parts added for the
# senior-scope build: PIM tier groups join the PIM artifacts when they exist,
# and the companion evidence other scripts wrote under lab/evidence is hashed
# into the SAME manifest (absent = listed as absent, offline-mock = never);
# and the pipeline path evidence-pack.yml uses (-UseAzureCliToken app-only as
# EVIDENCE, token never printed, -GeneratedBy in the manifest, EVIDENCE's
# Terraform roles cover every scope the script checks).
# Every Graph call is mocked; no tenant is contacted.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    $script:Pack = Get-LabScriptPath 'Export-EvidencePack.ps1'

    function Set-PackMocks {
        param([string[]]$TierGroups = @())
        $global:PackTest = @{ Tiers = $TierGroups; GroupLookups = [System.Collections.Generic.List[string]]::new(); Requests = [System.Collections.Generic.List[string]]::new() }
        Mock Write-Host {}
        Mock Get-MgContext { New-MgContextStub -Scopes @('RoleManagement.Read.Directory', 'PrivilegedAssignmentSchedule.Read.AzureADGroup', 'AccessReview.Read.All', 'Policy.Read.All', 'AuditLog.Read.All', 'Directory.Read.All') }
        Mock Connect-MgGraph { throw 'tests must never connect' }
        Mock Invoke-MgGraphRequest {
            $u = [uri]::UnescapeDataString("$Uri"); $t = $global:PackTest
            if ($u -match "groups\?\`$filter=mailNickname eq '(?<n>[^']+)'") {
                $n = $Matches.n; $t.GroupLookups.Add($n)
                $known = @('privileged-iam-admins', 'break-glass-admins') + $t.Tiers
                return @{ value = @(if ($n -in $known) { @{ id = "gid-$n"; displayName = $n } }) }
            }
            if ($u -like '*/beta/roleManagement/directory/roleDefinitions*') { return @{ value = @(@{ id = '62e90394-69f5-4237-9190-012177145e10'; templateId = '62e90394-69f5-4237-9190-012177145e10' }) } }
            if ($u -like '*/privilegedAccess/group/*') { $t.Requests.Add($u); return @{ value = @() } }
            throw "unexpected Graph call in test: $Method $u"
        }
        foreach ($c in 'Get-MgRoleManagementDirectoryRoleAssignmentScheduleRequest', 'Get-MgRoleManagementDirectoryRoleAssignmentScheduleInstance',
            'Get-MgAuditLogDirectoryAudit', 'Get-MgIdentityGovernanceAccessReviewDefinition', 'Get-MgIdentityConditionalAccessPolicy',
            'Get-MgReportAuthenticationMethodUserRegistrationDetail', 'Get-MgRoleManagementDirectoryRoleAssignment') {
            Mock $c { @() }
        }
    }
}

AfterAll { Remove-Variable -Name PackTest, PackFakeToken, PackEvidenceRoles -Scope Global -ErrorAction SilentlyContinue }

Describe 'Export-EvidencePack.ps1 - tier groups + companion evidence' {
    BeforeEach {
        $script:ev = Join-Path $TestDrive ("ev-" + [guid]::NewGuid().ToString('N').Substring(0, 6))
        $script:out = Join-Path $ev 'out'
        New-Item -ItemType Directory -Path (Join-Path $out 'offline-mock'), (Join-Path $ev 'kpis'), (Join-Path $ev 'assessments' '20261101T100000Z-before'), (Join-Path $ev 'assessments' '20261102T100000Z-before'), (Join-Path $ev 'assessments' '20261103T100000Z-before'), (Join-Path $out 'itdr') -Force | Out-Null
        '{"source":"tenant"}' | Set-Content (Join-Path $out 'nhi_inventory.json')
        '{"source":"offline-mock"}' | Set-Content (Join-Path $out 'offline-mock' 'nhi_inventory.json')
        '{"kpi":1}' | Set-Content (Join-Path $ev 'kpis' '20261101T100000Z.json')
        '{"source":{"kind":"tenant"}}' | Set-Content (Join-Path $ev 'assessments' '20261101T100000Z-before' 'summary.json')
        '{"source":{"kind":"non-tenant","detail":"non-tenant: scubaGear: sample"}}' | Set-Content (Join-Path $ev 'assessments' '20261102T100000Z-before' 'summary.json')
        '{"s":1}' | Set-Content (Join-Path $ev 'assessments' '20261103T100000Z-before' 'summary.json')
        '{"x":1}' | Set-Content (Join-Path $out 'itdr' 'ad-containment-1-alice-20261101T100000Z.json')
    }

    It 'adds each PIM tier group that exists to the PIM artifacts (and quietly skips the rest)' {
        Set-PackMocks -TierGroups @('pim-tier1-helpdesk')
        Mock Write-Warning {}
        $null = & $Pack -OutputDirectory $out -EvidenceRoot $ev
        $global:PackTest.GroupLookups | Should -Contain 'pim-tier0-security-admins'
        @($global:PackTest.Requests | Where-Object { $_ -match "groupId eq 'gid-pim-tier1-helpdesk'" }).Count | Should -BeGreaterThan 0
        Should -Invoke Write-Warning -Times 0 -ParameterFilter { $Message -match 'pim-tier0' }
    }

    It '-SkipPimTierGroups looks none of them up' {
        Set-PackMocks
        $null = & $Pack -OutputDirectory $out -EvidenceRoot $ev -SkipPimTierGroups
        @($global:PackTest.GroupLookups | Where-Object { $_ -like 'pim-tier*' }).Count | Should -Be 0
    }

    It 'hashes companion evidence into the manifest, lists missing kinds as absent, never includes offline-mock' {
        Set-PackMocks
        $null = & $Pack -OutputDirectory $out -EvidenceRoot $ev
        $m = Get-Content (Join-Path $out 'manifest.json') -Raw | ConvertFrom-Json
        $comp = @($m.artifacts | Where-Object { $_.PSObject.Properties['source'] -and $_.source -eq 'companion' })
        $ok = @($comp | Where-Object status -eq 'ok' | ForEach-Object file)
        $ok | Should -Contain 'out/nhi_inventory.json'
        $ok | Should -Contain 'kpis/20261101T100000Z.json'
        $ok | Should -Contain 'assessments/20261101T100000Z-before/summary.json'
        $ok | Should -Contain 'out/itdr/ad-containment-1-alice-20261101T100000Z.json'
        @($ok | Where-Object { $_ -like '*offline-mock*' }).Count | Should -Be 0
        ($comp | Where-Object file -eq 'out/nhi_inventory.json').sha256 | Should -Be (Get-FileHash (Join-Path $out 'nhi_inventory.json') -Algorithm SHA256).Hash
        @($comp | Where-Object status -eq 'absent' | ForEach-Object file) | Should -Contain 'drills/*.json'
        # itdr records must not be picked up by any other pattern.
        @($ok | Where-Object { $_ -like 'out/itdr/*' }).Count | Should -Be 1
    }

    It 'hashes an assessment summary in only when it records a tenant run (never the CISA sample or a fixture)' {
        Set-PackMocks
        Mock Write-Warning {}
        $null = & $Pack -OutputDirectory $out -EvidenceRoot $ev
        $m = Get-Content (Join-Path $out 'manifest.json') -Raw | ConvertFrom-Json
        $a = @($m.artifacts | Where-Object { $_.file -like 'assessments/*' })
        ($a | Where-Object file -eq 'assessments/20261101T100000Z-before/summary.json').status | Should -Be 'ok'
        foreach ($f in 'assessments/20261102T100000Z-before/summary.json', 'assessments/20261103T100000Z-before/summary.json') {
            $row = $a | Where-Object file -eq $f
            $row.status | Should -Be 'not-tenant'
            $row.sha256 | Should -BeNullOrEmpty
        }
        Should -Invoke Write-Warning -Times 2 -ParameterFilter { $Message -match 'NOT a tenant run' }
    }
}

Describe 'Export-EvidencePack.ps1 - PIM activation history (read-only: PIM-for-Groups requests + the directory audit log)' {
    # Learn names RoleAssignmentSchedule.ReadWrite.Directory as the least
    # privileged permission for LIST roleAssignmentScheduleRequests, and the
    # live EVIDENCE runs were refused it (PermissionScopeNotGranted). The
    # directory-role history is read from directoryAudits (AuditLog.Read.All).
    BeforeEach {
        $script:out = Join-Path $TestDrive ("pim-" + [guid]::NewGuid().ToString('N').Substring(0, 6))
        New-Item -ItemType Directory -Path $out -Force | Out-Null
        Set-PackMocks
        function New-AuditRow([string]$Category, [string]$Role, [string]$Group, [string]$User, [string]$Why, [string]$RequestId) {
            $targets = @([pscustomobject]@{ Type = 'Role'; DisplayName = $Role })
            if ($Group) { $targets += [pscustomobject]@{ Type = 'Other'; DisplayName = $Group; Id = "gid-$Group" } }
            $targets += [pscustomobject]@{ Type = 'User'; DisplayName = $User }
            [pscustomobject]@{
                Id = [guid]::NewGuid().ToString(); Category = $Category; Result = 'success'
                ActivityDisplayName = 'Add member to role completed (PIM activation)'; ActivityDateTime = [datetime]'2026-11-01T10:00:00Z'
                InitiatedBy = [pscustomobject]@{ User = [pscustomobject]@{ Id = "uid-$User"; DisplayName = $User; UserPrincipalName = "$User@contoso.test" } }
                TargetResources = $targets
                AdditionalDetails = @(
                    [pscustomobject]@{ Key = 'RoleAssignmentRequestId'; Value = $RequestId }, [pscustomobject]@{ Key = 'Justification'; Value = $Why },
                    [pscustomobject]@{ Key = 'StartTime'; Value = '2026-11-01T10:00:00Z' }, [pscustomobject]@{ Key = 'ExpirationTime'; Value = '2026-11-01T12:00:00Z' },
                    [pscustomobject]@{ Key = 'IsAuthenticatedWithMfa'; Value = 'True' }) + @(if ($Group) { [pscustomobject]@{ Key = 'ResourceOriginId'; Value = "gid-$Group" } })
            }
        }
        Mock Get-MgAuditLogDirectoryAudit -ParameterFilter { $Filter -like "*Add member to role completed (PIM activation)*" } {
            New-AuditRow -Category 'RoleManagement' -Role 'Global Administrator' -User 'adm-test' -Why 'CHG-1: break a stuck sync' -RequestId 'req-role-1'
            # Also returned by the PIM-for-Groups requests API below: must not be counted twice.
            New-AuditRow -Category 'GroupManagement' -Role 'Member' -Group 'privileged-iam-admins' -User 'adm-other' -Why 'INC-2' -RequestId 'req-grp-1'
            # No longer in the requests API: added from the audit log.
            New-AuditRow -Category 'GroupManagement' -Role 'Member' -Group 'privileged-iam-admins' -User 'adm-third' -Why 'INC-3' -RequestId 'req-grp-old'
            # A group this pack does not cover (-SkipPimTierGroups): never added.
            New-AuditRow -Category 'GroupManagement' -Role 'Member' -Group 'pim-tier1-helpdesk' -User 'adm-fourth' -Why 'INC-4' -RequestId 'req-grp-tier'
        }
        Mock Invoke-MgGraphRequest -ParameterFilter { "$Uri" -like '*privilegedAccess/group/assignmentScheduleRequests*' } {
            @{ value = @(@{ id = 'req-grp-1'; action = 'selfActivate'; accessId = 'member'; principalId = 'uid-adm-other'; principal = @{ displayName = 'adm-other' }
                        status = 'Provisioned'; justification = 'INC-2'; createdDateTime = '2026-11-01T09:00:00Z'
                        scheduleInfo = @{ startDateTime = '2026-11-01T09:00:00Z'; expiration = @{ endDateTime = '2026-11-01T13:00:00Z' } }; ticketInfo = @{ ticketNumber = 'INC-2' } }) }
        }
    }

    It 'adds a tier group''s audit-log activation when the pack covers the tier groups' {
        Set-PackMocks -TierGroups @('pim-tier1-helpdesk')
        $null = & $Pack -OutputDirectory $out -EvidenceRoot $out
        $rows = @(Get-Content (Join-Path $out 'pim_activation_history.json') -Raw | ConvertFrom-Json)
        ($rows | Where-Object requestId -eq 'req-grp-tier').role | Should -Be 'pim-tier1-helpdesk (member)'
    }

    It 'never lists roleAssignmentScheduleRequests (its least-privileged permission is ReadWrite)' {
        $null = & $Pack -OutputDirectory $out -EvidenceRoot $out -SkipPimTierGroups
        Should -Invoke Get-MgRoleManagementDirectoryRoleAssignmentScheduleRequest -Times 0
        (Get-Content -LiteralPath $Pack -Raw) | Should -Not -Match 'Get-MgRoleManagementDirectoryRoleAssignmentScheduleRequest\s'
        $m = Get-Content (Join-Path $out 'manifest.json') -Raw | ConvertFrom-Json
        ($m.artifacts | Where-Object file -eq 'pim_activation_history.json').status | Should -Be 'ok'
    }

    It 'merges: directory-role activations and aged-out group activations from the audit log, each request once' {
        $null = & $Pack -OutputDirectory $out -EvidenceRoot $out -SkipPimTierGroups
        $rows = @(Get-Content (Join-Path $out 'pim_activation_history.json') -Raw | ConvertFrom-Json)
        $rows.Count | Should -Be 3
        @($rows | Where-Object requestId -eq 'req-grp-1').Count | Should -Be 1
        ($rows | Where-Object requestId -eq 'req-grp-1').source | Should -Be 'PIM requests API'
        ($rows | Where-Object requestId -eq 'req-grp-1').ticketNumber | Should -Be 'INC-2'
        # The kept requests-API row takes the audit log's MFA answer (not lost in the de-duplication).
        ($rows | Where-Object requestId -eq 'req-grp-1').mfa | Should -Be 'True'
        @($rows | Where-Object requestId -eq 'req-grp-tier').Count | Should -Be 0
        $old = $rows | Where-Object requestId -eq 'req-grp-old'
        $old.elevationType | Should -Be 'PIM for Groups'
        $old.role | Should -Be 'privileged-iam-admins (member)'
        $old.source | Should -Be 'directory audit log'
        $r = $rows | Where-Object requestId -eq 'req-role-1'
        $r.elevationType | Should -Be 'PIM for roles'
        $r.role | Should -Be 'Global Administrator'
        $r.principal | Should -Be 'adm-test'
        $r.justification | Should -Be 'CHG-1: break a stuck sync'
        ([datetime]$r.expiration).ToUniversalTime() | Should -Be ([datetime]::new(2026, 11, 1, 12, 0, 0, [DateTimeKind]::Utc))
        $r.mfa | Should -Be 'True'
        Should -Invoke Get-MgAuditLogDirectoryAudit -Times 1 -Exactly -ParameterFilter { $Filter -like "loggedByService eq 'PIM' and activityDisplayName eq*" }
    }
}

Describe 'Export-EvidencePack.ps1 -UseAzureCliToken (app-only as EVIDENCE, evidence-pack.yml)' {
    BeforeAll {
        # EVIDENCE's Graph roles, read from the Terraform default.
        $vt = Get-Content -LiteralPath (Join-Path $PSScriptRoot '..' '..' '..' 'terraform' 'modules' 'pipeline-identity' 'variables.tf') -Raw
        $block = [regex]::Match($vt, '(?s)variable "evidence_graph_roles"\s*\{.*?default\s*=\s*\[(?<list>.*?)\]').Groups['list'].Value
        $global:PackEvidenceRoles = @([regex]::Matches(($block -replace '(?m)#.*$', ''), '"([^"]+)"') | ForEach-Object { $_.Groups[1].Value })
        $global:PackFakeToken = 'eyFAKE.evidence-token.never-printed'
    }
    BeforeEach {
        $script:ev = Join-Path $TestDrive ("app-" + [guid]::NewGuid().ToString('N').Substring(0, 6))
        $script:out = Join-Path $ev 'out'
        New-Item -ItemType Directory -Path $out -Force | Out-Null
        $script:SavedGha = $env:GITHUB_ACTIONS
        $env:GITHUB_ACTIONS = $null
        Set-PackMocks
        $global:PackOut = [System.Collections.Generic.List[string]]::new()
        Mock Write-Host { $global:PackOut.Add([string]$Object) }
        Mock az { $global:LASTEXITCODE = 0; $global:PackFakeToken }
        Mock Connect-MgGraph {}
        Mock Get-MgContext { [pscustomobject]@{ Scopes = $global:PackEvidenceRoles; TenantId = '11111111-1111-1111-1111-111111111111'; Account = $null; AuthType = 'UserProvidedAccessToken' } }
    }
    AfterEach { $env:GITHUB_ACTIONS = $script:SavedGha; Remove-Variable -Name PackOut -Scope Global -ErrorAction SilentlyContinue }

    It 'EVIDENCE''s Terraform roles are exactly the scopes the script checks (read-only, nothing missing)' {
        $line = (Get-Content -LiteralPath $script:Pack -Raw) -replace '\r', ''
        $req = [regex]::Match($line, "(?s)\`$requiredScopes = @\((?<l>.*?)\)").Groups['l'].Value
        $required = @([regex]::Matches($req, "'([^']+)'") | ForEach-Object { $_.Groups[1].Value })
        $required.Count | Should -Be 7
        @($required | Sort-Object) | Should -Be @($global:PackEvidenceRoles | Sort-Object)
        foreach ($r in $global:PackEvidenceRoles) { $r | Should -Match '\.Read(\.|$)' }
    }

    It 'signs in with the Azure CLI token (SecureString), never prints it, records -GeneratedBy' {
        $m = & $Pack -OutputDirectory $out -EvidenceRoot $ev -UseAzureCliToken -GeneratedBy 'EVIDENCE app, GitHub Actions run 42 (commit abc1234)' -WarningVariable wv -WarningAction SilentlyContinue
        Should -Invoke az -Times 1 -Exactly -ParameterFilter { $args -contains 'get-access-token' -and $args -contains 'ms-graph' }
        Should -Invoke Connect-MgGraph -Times 1 -Exactly -ParameterFilter { $AccessToken -is [securestring] -and [System.Net.NetworkCredential]::new('', $AccessToken).Password -eq $global:PackFakeToken }
        Should -Invoke Connect-MgGraph -Times 0 -ParameterFilter { $Scopes }
        ($global:PackOut -join "`n") | Should -Not -Match ([regex]::Escape($global:PackFakeToken))
        ($wv -join "`n") | Should -Not -Match 'does not list'
        $m.evidencePack.generatedBy | Should -Be 'EVIDENCE app, GitHub Actions run 42 (commit abc1234)'
        $disk = Get-Content (Join-Path $out 'manifest.json') -Raw | ConvertFrom-Json
        $disk.evidencePack.generatedBy | Should -Be 'EVIDENCE app, GitHub Actions run 42 (commit abc1234)'
        @($disk.artifacts | Where-Object { -not $_.PSObject.Properties['source'] -and $_.file -like '*.json' }).Count | Should -Be 7
    }

    It 'masks the token in GitHub Actions (::add-mask::) - the only line that ever carries it' {
        $env:GITHUB_ACTIONS = 'true'
        $null = & $Pack -OutputDirectory $out -EvidenceRoot $ev -UseAzureCliToken -WarningAction SilentlyContinue
        $hits = @($global:PackOut | Where-Object { $_ -match [regex]::Escape($global:PackFakeToken) })
        $hits.Count | Should -Be 1
        $hits[0] | Should -BeExactly "::add-mask::$($global:PackFakeToken)"
    }

    It 'stops before any Graph call when the Azure CLI has no session' {
        Mock az { $global:LASTEXITCODE = 1 }
        { & $Pack -OutputDirectory $out -EvidenceRoot $ev -UseAzureCliToken } | Should -Throw '*No Microsoft Graph token from the Azure CLI*'
        Should -Invoke Invoke-MgGraphRequest -Times 0
        Test-Path (Join-Path $out 'manifest.json') | Should -BeFalse
    }
}

Describe 'Export-EvidencePack.ps1 - SUMMARY.md states computed facts, never fixed claims' {
    # The old template said "Standing privileged humans = break-glass only" and
    # "Every app ... has an owner" whatever the records held. Live (2026-11-05)
    # the build account held a standing Global Administrator and 8 of 19 robot
    # identities had no owner (capture-log E70, E72).
    BeforeAll {
        . (Get-ScriptFunctionBlock -Path $script:Pack -Name 'Get-SummaryValue', 'Get-EvidenceRecordText', 'ConvertTo-EvidenceSummaryMarkdown', 'Get-CompanionFact')
        function New-RoleRow([string]$Id, [string]$Type, [bool]$Bg, [string]$Assign = 'Assigned', [string]$Member = 'Direct', $End = $null) {
            [pscustomobject]@{ source = 'Directory role'; role = 'Global Administrator'; isPrivileged = $true; principalId = $Id; principal = "Person $Id"
                principalType = $Type; isBreakGlass = $Bg; assignmentType = $Assign; memberType = $Member; endDateTime = $End }
        }
    }

    It 'the script carries none of the old fixed claims' {
        $text = Get-Content -LiteralPath $script:Pack -Raw
        $text | Should -Not -Match 'Standing privileged humans = break-glass only'
        $text | Should -Not -Match 'has an owner, a known credential type'
        $text | Should -Not -Match 'approved -- no standing admin'
    }

    It 'a non-break-glass user with a standing privileged role is reported as such, by count, never by name' {
        $rec = @{ 'pim_active_assignments.json' = @{ status = 'ok'; error = $null; data = @(
                    (New-RoleRow -Id 'u-build' -Type '#microsoft.graph.user' -Bg $false),
                    (New-RoleRow -Id 'g-bg' -Type '#microsoft.graph.group' -Bg $true),
                    (New-RoleRow -Id 'g-tier0' -Type '#microsoft.graph.group' -Bg $false),
                    (New-RoleRow -Id 'u-jit' -Type '#microsoft.graph.user' -Bg $false -Assign 'Activated')) } }
        $t = Get-EvidenceRecordText -Name 'pim_active_assignments.json' -Records $rec
        $t | Should -Match '1 user account\(s\) outside break-glass assigned directly \(1 with no end date\), 1 break-glass principal\(s\), 1 group\(s\), 0 service principal\(s\)'
        $t | Should -Match 'activated just in time right now: 1'
        $t | Should -Match 'Not zero standing admin'
        $md = ConvertTo-EvidenceSummaryMarkdown -Records $rec
        $md | Should -Not -Match 'Person u-build|u-build'
        $md | Should -Not -Match 'break-glass only'
    }

    It 'says so only when no user outside break-glass holds a standing privileged role' {
        $rec = @{ 'pim_active_assignments.json' = @{ status = 'ok'; error = $null; data = @((New-RoleRow -Id 'bg1' -Type '#microsoft.graph.user' -Bg $true), (New-RoleRow -Id 'g1' -Type '#microsoft.graph.group' -Bg $false)) } }
        $t = Get-EvidenceRecordText -Name 'pim_active_assignments.json' -Records $rec
        $t | Should -Match '0 user account\(s\) outside break-glass'
        $t | Should -Match 'No user account outside break-glass holds a standing privileged role by direct assignment; access through groups is counted separately'
    }

    It 'Assigned is "standing", not "permanent": an end date is counted; users holding a role through a group are counted apart' {
        $rec = @{ 'pim_active_assignments.json' = @{ status = 'ok'; data = @(
                    (New-RoleRow -Id 'u-temp' -Type '#microsoft.graph.user' -Bg $false -End '2026-12-01T00:00:00Z'),
                    (New-RoleRow -Id 'u-viagroup' -Type '#microsoft.graph.user' -Bg $false -Member 'Group')) } }
        $t = Get-EvidenceRecordText -Name 'pim_active_assignments.json' -Records $rec
        $t | Should -Match '1 user account\(s\) outside break-glass assigned directly \(0 with no end date\)'
        $t | Should -Match 'through a group: 1'
        $t | Should -Not -Match 'permanent'
    }

    It 'activation requests are split by outcome; only granted ones count as elevations' {
        $rows = @(
            [pscustomobject]@{ elevationType = 'PIM for Groups'; status = 'Provisioned'; justification = 'INC-1'; mfa = $null },
            [pscustomobject]@{ elevationType = 'PIM for Groups'; status = 'Denied'; justification = 'INC-2'; mfa = $null },
            [pscustomobject]@{ elevationType = 'PIM for Groups'; status = 'PendingApproval'; justification = 'INC-3'; mfa = $null },
            [pscustomobject]@{ elevationType = 'PIM for roles'; status = 'success (Add member to role completed (PIM activation))'; justification = 'CHG-1'; mfa = 'True' })
        $t = Get-EvidenceRecordText -Name 'pim_activation_history.json' -Records @{ 'pim_activation_history.json' = @{ status = 'ok'; data = $rows } }
        $t | Should -Match '4 activation request\(s\): 2 granted, 1 pending, 1 denied'
        $t | Should -Match 'Of the granted: 1 through PIM for Groups, 1 through PIM for directory roles; 2 with a justification; 1 with MFA'
    }

    It 'MFA registration points to the Conditional Access file for who must use MFA' {
        $t = Get-EvidenceRecordText -Name 'mfa_registration_coverage.json' -Records @{ 'mfa_registration_coverage.json' = @{ status = 'ok'; data = @([pscustomobject]@{ _summary = $true; totalUsers = 20; mfaRegistered = 2; coveragePercent = 10 }) } }
        $t | Should -Match '2 of 20 users registered for MFA \(10%\)'
        $t | Should -Match 'conditional_access_policies\.json'
    }

    It 'an incomplete NHI run is shown as a minimum, never as clean' {
        $md = ConvertTo-EvidenceSummaryMarkdown -Companion @([pscustomobject]@{ file = 'nhi/x/nhi-summary.json'; status = 'ok'; source = 'companion' }) -Nhi @{ file = 'nhi/x/nhi-summary.json'; generatedAtUtc = 'x'; nhiCount = 19; orphanedNhi = 0; tierZeroNhi = 2; expired = 0; complete = $false }
        $md | Should -Match 'Incomplete run: a data source failed, so these counts are a minimum'
    }

    It 'a failed or missing record is stated as failed or missing, never as clean' {
        $rec = @{ 'pim_activation_history.json' = @{ status = 'failed'; error = 'PermissionScopeNotGranted'; data = @() } }
        Get-EvidenceRecordText -Name 'pim_activation_history.json' -Records $rec | Should -Match 'Could not be collected'
        Get-EvidenceRecordText -Name 'conditional_access_policies.json' -Records $rec | Should -Be 'Not collected in this run.'
    }

    It 'counts Conditional Access states and flags a policy that does not exclude break-glass' {
        $rows = @([pscustomobject]@{ state = 'enabled'; excludesBreakGlass = $true }, [pscustomobject]@{ state = 'enabledForReportingButNotEnforced'; excludesBreakGlass = $false })
        $t = Get-EvidenceRecordText -Name 'conditional_access_policies.json' -Records @{ 'conditional_access_policies.json' = @{ status = 'ok'; data = $rows } }
        $t | Should -Match '2 Conditional Access policies: 1 enforced, 1 report-only, 0 off\. 1 of 2 exclude the break-glass group; \*\*1 do not\*\*'
    }

    It 'NHI ownership comes from the newest tenant inventory; with none, the row says absent' {
        $comp = @([pscustomobject]@{ file = 'nhi/20261105T101425Z/nhi-summary.json'; status = 'ok'; source = 'companion' })
        $md = ConvertTo-EvidenceSummaryMarkdown -Companion $comp -Nhi @{ file = 'nhi/20261105T101425Z/nhi-summary.json'; generatedAtUtc = '2026-11-05T10:14:25Z'; nhiCount = 19; orphanedNhi = 8; tierZeroNhi = 2; expired = 0 }
        $md | Should -Match '19 non-human identities; \*\*8 without an accountable owner\*\*'
        $md | Should -Not -Match 'has an owner'
        $none = ConvertTo-EvidenceSummaryMarkdown -Companion @([pscustomobject]@{ file = 'out/nhi_inventory.json'; status = 'absent'; source = 'companion' })
        ($none -split "`n" | Where-Object { $_ -like '*06-NHI-Inventory.ps1*' }) | Should -Match 'Absent: not captured in this pack'
    }

    It 'Get-CompanionFact takes the newest TENANT record of each kind (a fixture is ignored) and keeps ISO dates' {
        $ev = Join-Path $TestDrive 'facts'
        foreach ($d in 'nhi/20261101T000000Z', 'nhi/20261105T101425Z', 'nhi/20261106T000000Z', 'kpis') { New-Item -ItemType Directory -Path (Join-Path $ev $d) -Force | Out-Null }
        '{"source":"tenant","generatedAtUtc":"2026-11-01T00:00:00Z","summary":{"nhiCount":10,"kpi":{"orphanedNhi":2,"tierZeroNhi":1,"nhiWithExpiredCredential":0}}}' | Set-Content (Join-Path $ev 'nhi/20261101T000000Z/nhi-summary.json')
        '{"source":"tenant","complete":true,"generatedAtUtc":"2026-11-05T10:14:25Z","summary":{"nhiCount":19,"kpi":{"orphanedNhi":8,"tierZeroNhi":2,"nhiWithExpiredCredential":0}}}' | Set-Content (Join-Path $ev 'nhi/20261105T101425Z/nhi-summary.json')
        '{"source":"offline-mock","generatedAtUtc":"2026-11-06T00:00:00Z","summary":{"nhiCount":1,"kpi":{"orphanedNhi":0,"tierZeroNhi":0,"nhiWithExpiredCredential":0}}}' | Set-Content (Join-Path $ev 'nhi/20261106T000000Z/nhi-summary.json')
        '{"schema":"contoso-identity-kpis/v1","label":"baseline","generatedAtUtc":"2026-10-27T03:34:28Z","kpis":{"admin_standing_users":{"status":"measured","value":1}}}' | Set-Content (Join-Path $ev 'kpis/a.json')
        '{"schema":"contoso-identity-kpis/v1","label":"after","generatedAtUtc":"2026-11-05T10:19:12Z","kpis":{"admin_standing_users":{"status":"measured","value":1}}}' | Set-Content (Join-Path $ev 'kpis/b.json')
        $comp = @('nhi/20261101T000000Z/nhi-summary.json', 'nhi/20261105T101425Z/nhi-summary.json', 'nhi/20261106T000000Z/nhi-summary.json', 'kpis/a.json', 'kpis/b.json') |
            ForEach-Object { [pscustomobject]@{ file = $_; status = 'ok'; source = 'companion' } }
        $f = Get-CompanionFact -Companion $comp -EvidenceRoot $ev
        $f['Nhi']['orphanedNhi'] | Should -Be 8
        $f['Nhi']['complete'] | Should -BeTrue
        # A record that does not say whether it was complete is never taken as complete.
        '{"source":"tenant","generatedAtUtc":"2026-11-07T00:00:00Z","summary":{"nhiCount":3,"kpi":{"orphanedNhi":0,"tierZeroNhi":0,"nhiWithExpiredCredential":0}}}' | Set-Content (Join-Path $ev 'nhi/20261106T000000Z/nhi-summary.json')
        $f2 = Get-CompanionFact -Companion $comp -EvidenceRoot $ev
        $f2['Nhi']['generatedAtUtc'] | Should -Be '2026-11-07T00:00:00Z'
        $f2['Nhi']['complete'] | Should -BeFalse
        $f['Nhi']['generatedAtUtc'] | Should -Be '2026-11-05T10:14:25Z'
        $f['Kpi']['label'] | Should -Be 'after'
        $f['Kpi']['standing'] | Should -Be '1'
    }
}

Describe 'Export-EvidencePack.ps1 - SUMMARY.md end to end (mocked Graph), against the live 2026-11-05 shape' {
    It 'reports the standing build account and 8 of 19 ownerless robot identities; no fixed claim, no name' {
        $ev = Join-Path $TestDrive 'e2e'; $out = Join-Path $ev 'out'
        New-Item -ItemType Directory -Path @($out, [System.IO.Path]::Combine($ev, 'nhi', '20261105T101425Z')) -Force | Out-Null
        '{"source":"tenant","complete":true,"generatedAtUtc":"2026-11-05T10:14:25Z","summary":{"nhiCount":19,"kpi":{"orphanedNhi":8,"tierZeroNhi":2,"nhiWithExpiredCredential":0}}}' |
            Set-Content -LiteralPath ([System.IO.Path]::Combine($ev, 'nhi', '20261105T101425Z', 'nhi-summary.json'))
        Set-PackMocks
        Mock Write-Warning {}
        Mock Get-MgRoleManagementDirectoryRoleAssignmentScheduleInstance {
            [pscustomobject]@{ RoleDefinitionId = '62e90394-69f5-4237-9190-012177145e10'; RoleDefinition = [pscustomobject]@{ DisplayName = 'Global Administrator' }
                PrincipalId = 'u-build'; Principal = [pscustomobject]@{ AdditionalProperties = @{ displayName = 'Build Person'; '@odata.type' = '#microsoft.graph.user'; userPrincipalName = 'build.person@contoso.test' } }
                AssignmentType = 'Assigned'; MemberType = 'Direct'; StartDateTime = $null; EndDateTime = $null }
            [pscustomobject]@{ RoleDefinitionId = '62e90394-69f5-4237-9190-012177145e10'; RoleDefinition = [pscustomobject]@{ DisplayName = 'Global Administrator' }
                PrincipalId = 'u-bg1'; Principal = [pscustomobject]@{ AdditionalProperties = @{ displayName = 'BG ADMIN 01'; '@odata.type' = '#microsoft.graph.user'; userPrincipalName = 'bg-admin-01@contoso.test' } }
                AssignmentType = 'Assigned'; MemberType = 'Direct'; StartDateTime = $null; EndDateTime = $null }
        }
        $null = & $script:Pack -OutputDirectory $out -EvidenceRoot $ev -SkipPimTierGroups
        $md = Get-Content -LiteralPath (Join-Path $out 'SUMMARY.md') -Raw
        $md | Should -Match '1 user account\(s\) outside break-glass assigned directly \(1 with no end date\), 1 break-glass principal\(s\)'
        $md | Should -Match 'Not zero standing admin'
        $md | Should -Match '19 non-human identities; \*\*8 without an accountable owner\*\*'
        $md | Should -Not -Match 'break-glass only'
        $md | Should -Not -Match 'Incomplete run'
        $md | Should -Not -Match 'has an owner'
        $md | Should -Not -Match 'Build Person|build\.person|bg-admin-01'
        # The rows themselves still carry the type and flag the summary counts.
        $rows = @(Get-Content (Join-Path $out 'pim_active_assignments.json') -Raw | ConvertFrom-Json)
        ($rows | Where-Object principalId -eq 'u-bg1').isBreakGlass | Should -BeTrue
        ($rows | Where-Object principalId -eq 'u-build').principalType | Should -Be '#microsoft.graph.user'
    }
}
