#Requires -Version 7.0
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
    Offline tests for the NHI governance scripts. No tenant: the report scripts
    run in their -Offline mock mode, and the write scripts run against a mocked
    Invoke-MgGraphRequest that keeps state, so read-back verification is
    exercised too. Intended home: lab/scripts/powershell/tests/.

    Run:  Invoke-Pester ./NhiGovernance.Tests.ps1 -Output Detailed
    Set $env:NHI_SCRIPT_ROOT to lab/scripts/powershell when the file lives elsewhere.
#>

BeforeAll {
    $root = if ($env:NHI_SCRIPT_ROOT) { $env:NHI_SCRIPT_ROOT } else { Join-Path $PSScriptRoot '..' }
    $script:Inventory = Join-Path $root '06-NHI-Inventory.ps1'
    $script:Shadow = Join-Path $root 'Find-ShadowAdmins.ps1'
    $script:Leaver = Join-Path $root '04-Leaver.ps1'
    $script:AppPolicy = Join-Path $root 'post-apply/Set-AppGovernancePolicy.ps1'
    $script:Consent = Join-Path $root 'post-apply/Set-ConsentPolicy.ps1'
    $script:Agent = Join-Path $root 'post-apply/New-AgentIdentity.ps1'
}

Describe '06-NHI-Inventory.ps1 -Offline (mock tenant)' {
    BeforeAll {
        $script:out = Join-Path $TestDrive 'nhi'
        $script:r = & $Inventory -Offline -OutputDirectory $out 6>$null
    }

    It 'marks every row as offline-mock, never as tenant evidence' {
        $r.Source | Should -Be 'offline-mock'
        @($r.Inventory | Where-Object Source -ne 'offline-mock').Count | Should -Be 0
        @($r.Findings | Where-Object Source -ne 'offline-mock').Count | Should -Be 0
    }

    It 'flags <Name> with <Id> (<Owasp>, <Severity>)' -TestCases @(
        @{ Name = 'gh-oidc-entra-apply (write)'; Id = 'PERM-TIER0'; Owasp = 'NHI5:2025'; Severity = 'Critical' }
        @{ Name = 'gh-oidc-entra-apply (write)'; Id = 'OWNER-NONE'; Owasp = 'NHI1:2025'; Severity = 'High' }
        @{ Name = 'gh-oidc-entra-plan (read-only)'; Id = 'OWNER-NONE'; Owasp = 'NHI1:2025'; Severity = 'Medium' }
        @{ Name = 'midpoint-reader'; Id = 'SECRET-PRESENT'; Owasp = 'NHI2:2025'; Severity = 'Medium' }
        @{ Name = 'midpoint-reader'; Id = 'CRED-LONG-LIVED'; Owasp = 'NHI7:2025'; Severity = 'Medium' }
        @{ Name = 'midpoint-reader'; Id = 'OWNER-SINGLE'; Owasp = 'NHI1:2025'; Severity = 'Low' }
        @{ Name = 'legacy-report-exporter'; Id = 'OWNER-ALL-DISABLED'; Owasp = 'NHI1:2025'; Severity = 'Critical' }
        @{ Name = 'legacy-report-exporter'; Id = 'IMPLICIT-GRANT'; Owasp = 'NHI4:2025'; Severity = 'High' }
        @{ Name = 'legacy-report-exporter'; Id = 'CRED-EXPIRED'; Owasp = 'NHI1:2025'; Severity = 'Medium' }
        @{ Name = 'legacy-report-exporter'; Id = 'STALE'; Owasp = 'NHI1:2025'; Severity = 'High' }
        @{ Name = 'ci-multi-env-deployer'; Id = 'FIC-PR-WRITE'; Owasp = 'NHI6:2025'; Severity = 'High' }
        @{ Name = 'ci-multi-env-deployer'; Id = 'FIC-MULTI-ENV'; Owasp = 'NHI8:2025'; Severity = 'Medium' }
        @{ Name = 'ci-multi-env-deployer'; Id = 'FIC-REUSE'; Owasp = 'NHI9:2025'; Severity = 'Medium' }
        @{ Name = 'PDF Wizard Online'; Id = 'THIRDPARTY-CONSENT'; Owasp = 'NHI3:2025'; Severity = 'High' }
        @{ Name = 'pilot-scheduling-agent'; Id = 'AGENT-NO-SPONSOR'; Owasp = 'NHI1:2025'; Severity = 'High' }
        @{ Name = 'old-hr-connector'; Id = 'SP-WITHOUT-APP'; Owasp = 'NHI1:2025'; Severity = 'Critical' }
        @{ Name = 'old-hr-connector'; Id = 'ROLE-PRIVILEGED'; Owasp = 'NHI5:2025'; Severity = 'Critical' }
    ) {
        $f = @($r.Findings | Where-Object { $_.DisplayName -eq $Name -and $_.FindingId -eq $Id })
        $f.Count | Should -BeGreaterThan 0
        $f[0].OwaspNhi | Should -Be $Owasp
        $f[0].Severity | Should -Be $Severity
        $f[0].StandardRule | Should -Not -BeNullOrEmpty
        $f[0].Remediation | Should -Not -BeNullOrEmpty
    }

    It 'raises nothing on the well-built NHIs' {
        foreach ($clean in 'uami-idlab-kv-reader', 'uami-agent-runtime', 'DC01', 'contoso-access-review-assistant', 'Contoso Access Review Assistant (blueprint)') {
            @($r.Findings | Where-Object DisplayName -eq $clean).Count | Should -Be 0 -Because "$clean is the good example"
        }
        # The read-only plan identity: only the missing owner (nhi-standard section 2 says the same).
        @($r.Findings | Where-Object DisplayName -eq 'gh-oidc-entra-plan (read-only)' | ForEach-Object FindingId) | Should -Be @('OWNER-NONE')
    }

    It 'covers OWASP NHI1-NHI9 and says NHI10 needs sign-in logs' {
        @($r.OwaspCoverage | Where-Object { $_.CoveredHere -and $_.Findings -gt 0 }).Count | Should -Be 9
        $n10 = $r.OwaspCoverage | Where-Object Owasp -eq 'NHI10:2025'
        $n10.CoveredHere | Should -BeFalse
        $n10.Note | Should -Match 'sign-in log'
    }

    It 'classifies kinds, keeps Microsoft first-party out, and computes the KPI' {
        $r.Summary.excludedMicrosoftFirstParty | Should -Be 1
        ($r.Inventory | Where-Object DisplayName -eq 'uami-idlab-kv-reader').ManagedIdentityType | Should -Be 'UserAssigned'
        ($r.Inventory | Where-Object DisplayName -eq 'DC01').ManagedIdentityType | Should -Be 'SystemAssigned'
        ($r.Inventory | Where-Object DisplayName -eq 'Contoso Access Review Assistant (blueprint)').Kind | Should -Be 'AgentBlueprint'
        $r.Summary.kpi.expiredOrOrphanedNhi | Should -Be 5
        $r.Summary.kpi.tierZeroNhi | Should -Be 3
    }

    It 'writes CSV and JSON that parse' {
        (Import-Csv (Join-Path $out 'nhi_inventory.csv')).Count | Should -Be $r.Inventory.Count
        (Import-Csv (Join-Path $out 'nhi_findings.csv')).Count | Should -Be $r.Findings.Count
        $j = Get-Content (Join-Path $out 'nhi_inventory.json') -Raw | ConvertFrom-Json
        $j.Source | Should -Be 'offline-mock'
        $j.Findings.Count | Should -Be $r.Findings.Count
    }

    It 'writes the per-credential worklist with OwnerCount semantics' {
        $c = @(Import-Csv (Join-Path $out 'nhi_credentials.csv'))
        @($c | Select-Object -ExpandProperty ObjectId -Unique).Count | Should -Be $r.Inventory.Count
        ($c | Where-Object { $_.DisplayName -eq 'legacy-report-exporter' -and $_.CredentialType -eq 'secret' }).CredentialStatus | Should -Be 'expired'
        ($c | Where-Object DisplayName -eq 'legacy-report-exporter' | Select-Object -First 1).OwnerCount | Should -Be '0'
        ($c | Where-Object DisplayName -eq 'uami-idlab-kv-reader').OwnerCount | Should -Be ''
        @($c | Where-Object { $_.DisplayName -eq 'ci-multi-env-deployer' -and $_.CredentialType -eq 'federated' }).Count | Should -Be 3
    }

    It 'keeps the JSON fields 08-Measure-KPIs.ps1 reads' {
        $j = Get-Content (Join-Path $out 'nhi_inventory.json') -Raw | ConvertFrom-Json
        foreach ($k in 'expiredOrOrphanedNhi', 'nhiWithExpiredCredential', 'orphanedNhi') { $j.Summary.kpi.PSObject.Properties.Name | Should -Contain $k }
        $j.Summary.nhiCount | Should -Be $r.Inventory.Count
        $j.GeneratedAtUtc | Should -Not -BeNullOrEmpty
        @($j.DataSources).Count | Should -BeGreaterThan 0
    }

    It '-WhatIf writes nothing' {
        $w = Join-Path $TestDrive 'whatif'
        & $Inventory -Offline -OutputDirectory $w -WhatIf 6>$null | Out-Null
        Test-Path $w | Should -BeFalse
    }

    It '-FailOnSeverity Critical exits 2' {
        & $Inventory -Offline -OutputDirectory (Join-Path $TestDrive 'gate') -FailOnSeverity Critical 6>$null | Out-Null
        $LASTEXITCODE | Should -Be 2
    }
}

Describe '06-NHI-Inventory.ps1 online path (mocked Graph): never silent' {
    BeforeAll {
        Mock Get-MgContext { [pscustomobject]@{ TenantId = 'tid'; Scopes = @('Application.Read.All', 'Directory.Read.All', 'RoleManagement.Read.Directory', 'AuditLog.Read.All') } }
        Mock Connect-MgGraph { }
        Mock Invoke-MgGraphRequest {
            switch -Regex ($Uri) {
                'v1\.0/applications\?' {
                    # No 'owners' key: the script must read owners directly, not assume none.
                    return @{ value = @(@{ id = 'a1'; appId = 'app1'; displayName = 'svc-app'; createdDateTime = '2020-01-01T00:00:00Z'
                                passwordCredentials = @(); keyCredentials = @(); web = @{ implicitGrantSettings = @{ enableAccessTokenIssuance = $false } } }) }
                }
                'applications/a1/owners' { return @{ value = @(@{ '@odata.type' = '#microsoft.graph.user'; id = 'u1'; userPrincipalName = 'o1@x.io' }, @{ '@odata.type' = '#microsoft.graph.user'; id = 'u2'; userPrincipalName = 'o2@x.io' }) } }
                'v1\.0/servicePrincipals\?' { return @{ value = @(@{ id = 's1'; appId = 'app1'; displayName = 'svc-app'; servicePrincipalType = 'Application'; appOwnerOrganizationId = 'tid'; passwordCredentials = @(); keyCredentials = @(); owners = @() }) } }
                'users/u[12]\?' { return @{ id = 'u'; accountEnabled = $true } }
                'federatedIdentityCredentials' { return @{ value = @() } }
                "servicePrincipals\(appId=" { return @{ id = 'graph'; appRoles = @() } }
                'servicePrincipals/graph/appRoleAssignedTo' { return @{ value = @() } }
                'beta/roleManagement' { return @{ value = @() } }
                'v1\.0/roleManagement/directory/roleDefinitions' { return @{ value = @() } }
                'oauth2PermissionGrants' { return @{ value = @() } }
                'servicePrincipalSignInActivities' { throw 'Forbidden: licence' }
                default { throw "unexpected $Uri" }
            }
        }
        $script:o = & $Inventory -OutputDirectory (Join-Path $TestDrive 'online') 6>$null 3>$null
        $script:code = $LASTEXITCODE
    }
    It 'exits 1 and records the failed source' {
        $code | Should -Be 1
        ($o.DataSources | Where-Object Name -like 'servicePrincipalSignInActivities*').Status | Should -BeLike 'FAILED*'
    }
    It 'reports last sign-in as unknown and makes no stale verdict' {
        ($o.Inventory | Where-Object DisplayName -eq 'svc-app').LastSignInUtc | Should -Be 'unknown'
        @($o.Findings | Where-Object FindingId -like 'STALE*').Count | Should -Be 0
    }
    It 'read owners directly when the expand was missing (no false orphan)' {
        ($o.Inventory | Where-Object DisplayName -eq 'svc-app').EnabledHumanOwners | Should -Be 2
        @($o.Findings | Where-Object FindingId -like 'OWNER-*').Count | Should -Be 0
    }
}

Describe 'Find-ShadowAdmins.ps1 -Offline (mock tenant)' {
    BeforeAll { $script:s = & $Shadow -Offline -OutputDirectory (Join-Path $TestDrive 'shadow') 6>$null }

    It '-PrivilegedIdsPath writes the privileged USER object ids (role holders + PIM group members), nothing else' {
        $f = Join-Path $TestDrive 'priv-ids.json'
        $null = & $script:Shadow -Offline -OutputDirectory $TestDrive -PrivilegedIdsPath $f -WarningAction SilentlyContinue 6>$null
        $f | Should -Exist
        $ids = @(Get-Content -Raw -LiteralPath $f | ConvertFrom-Json)
        $ids | Should -Contain 'mock-user-grace'      # eligible member of Privileged-IAM-Admins
        $ids | Should -Contain 'mock-user-daniel'     # direct Cloud Application Administrator
        $ids | Should -Not -Contain 'mock-grp-bg'     # groups are not users
        $ids | Should -Not -Contain 'mock-sp-apply'   # service principals are judged elsewhere
    }

    It 'finds <Principal> via <Technique> (<Severity>, <Status>)' -TestCases @(
        @{ Principal = 'gh-oidc-entra-apply (write)'; Technique = 'OwnerOfRoleAssignableGroup'; Severity = 'Critical'; Status = 'accepted:E1' }
        @{ Principal = 'gh-oidc-entra-apply (write)'; Technique = 'TierZeroWorkload'; Severity = 'Critical'; Status = 'accepted:E1' }
        @{ Principal = 'legacy-report-exporter'; Technique = 'TierZeroWorkload'; Severity = 'Critical'; Status = 'open' }
        @{ Principal = 'omar.haddad@contosohealth.io'; Technique = 'OwnerOfTierZeroApp'; Severity = 'Critical'; Status = 'open' }
        @{ Principal = 'marcus.bello@contosohealth.io'; Technique = 'OwnerOfRoleAssignableGroup'; Severity = 'High'; Status = 'open' }
        @{ Principal = 'lab-operator@contosohealth.io'; Technique = 'OwnerOfRoleAssignableGroup'; Severity = 'High'; Status = 'open' }
        @{ Principal = 'daniel.osei@contosohealth.io'; Technique = 'AppAdminOverTierZeroApp'; Severity = 'High'; Status = 'open' }
        @{ Principal = 'daniel.osei@contosohealth.io'; Technique = 'EligibleAndPermanent'; Severity = 'High'; Status = 'open' }
        @{ Principal = 'grace.mwangi@contosohealth.io'; Technique = 'EligibleAndPermanent'; Severity = 'High'; Status = 'open' }
        @{ Principal = 'omar.haddad@contosohealth.io'; Technique = 'EligibleOwnerOfRoleAssignableGroup'; Severity = 'Medium'; Status = 'open' }
    ) {
        $p = @($s.Paths | Where-Object { $_.Principal -eq $Principal -and $_.Technique -eq $Technique })
        $p.Count | Should -Be 1
        $p[0].Severity | Should -Be $Severity
        $p[0].Status | Should -Be $Status
        $p[0].Mitre | Should -Match '^T1(098\.00[13]|078\.004) '
    }
    It 'does not treat an eligible-only PIM member as a shadow admin' {
        @($s.Paths | Where-Object { $_.Principal -eq 'grace.mwangi@contosohealth.io' -and $_.Target -eq 'Privileged-IAM-Admins' }).Count | Should -Be 0
    }
    It 'keeps accepted paths visible but out of the gate' {
        $s.Summary.acceptedPaths | Should -Be 2
        $global:LASTEXITCODE = 0
        & $Shadow -Offline -OutputDirectory (Join-Path $TestDrive 'shadow2') -FailOnFinding 6>$null | Out-Null
        $LASTEXITCODE | Should -Be 2
        $global:LASTEXITCODE = 0
        & $Shadow -Offline -OutputDirectory (Join-Path $TestDrive 'shadow3') -FailOnFinding -AcceptedRisk @{
            'gh-oidc-entra-apply (write)' = 'E1'; 'legacy-report-exporter' = 'X'; 'omar.haddad@contosohealth.io' = 'X'
            'marcus.bello@contosohealth.io' = 'X'; 'lab-operator@contosohealth.io' = 'X'; 'daniel.osei@contosohealth.io' = 'X'; 'grace.mwangi@contosohealth.io' = 'X'
        } 6>$null | Out-Null
        $LASTEXITCODE | Should -Be 0
    }
}

Describe 'Find-ShadowAdmins.ps1 online path (mocked Graph)' {
    BeforeAll {
        Mock Get-MgContext { [pscustomobject]@{ TenantId = 'tid'; Scopes = @() } }
        Mock Connect-MgGraph { }
        $ga = '62e90394-69f5-4237-9190-012177145e10'; $appAdmin = '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3'
        Mock Invoke-MgGraphRequest {
            $ga = '62e90394-69f5-4237-9190-012177145e10'; $appAdmin = '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3'
            switch -Regex ($Uri) {
                'beta/roleManagement/directory/roleDefinitions' { return @{ value = @(@{ id = $ga; displayName = 'Global Administrator' }, @{ id = $appAdmin; displayName = 'Application Administrator' }) } }
                'roleAssignmentScheduleInstances' {
                    return @{ value = @(
                            @{ principalId = 'g-bg'; roleDefinitionId = $ga; endDateTime = $null; principal = @{ '@odata.type' = '#microsoft.graph.group'; id = 'g-bg'; displayName = 'Break-Glass-Admins' } },
                            @{ principalId = 'u-d'; roleDefinitionId = $appAdmin; endDateTime = $null; principal = @{ '@odata.type' = '#microsoft.graph.user'; id = 'u-d'; userPrincipalName = 'd@x.io' } }) }
                }
                'roleEligibilityScheduleInstances' { return @{ value = @(@{ principalId = 'u-d'; roleDefinitionId = $appAdmin; principal = @{ '@odata.type' = '#microsoft.graph.user'; id = 'u-d'; userPrincipalName = 'd@x.io' } }) } }
                'groups\?\$filter=isAssignableToRole' { return @{ value = @(@{ id = 'g-bg'; displayName = 'Break-Glass-Admins' }) } }
                'groups/g-bg/owners' { return @{ value = @(@{ '@odata.type' = '#microsoft.graph.user'; id = 'u-o'; userPrincipalName = 'owner@x.io' }) } }
                'privilegedAccess/group/eligibilityScheduleInstances' { return @{ value = @() } }
                'privilegedAccess/group/assignmentScheduleInstances' { return @{ value = @() } }
                "servicePrincipals\(appId=" { return @{ id = 'graphsp'; appRoles = @(@{ id = 'r1'; value = 'RoleManagement.ReadWrite.Directory' }, @{ id = 'r2'; value = 'User.Read.All' }) } }
                'servicePrincipals/graphsp/appRoleAssignedTo' {
                    return @{ value = @(@{ principalId = 'sp-t0'; principalType = 'ServicePrincipal'; principalDisplayName = 'tier0-app'; appRoleId = 'r1' },
                            @{ principalId = 'sp-ro'; principalType = 'ServicePrincipal'; principalDisplayName = 'reader'; appRoleId = 'r2' }) }
                }
                'servicePrincipals/sp-t0\?' { return @{ id = 'sp-t0'; appId = 'app-t0'; displayName = 'tier0-app' } }
                'servicePrincipals/sp-t0/owners' { return @{ value = @() } }
                "applications\?\`$filter=appId eq 'app-t0'" { return @{ value = @(@{ id = 'a-t0' }) } }
                'applications/a-t0/owners' { return @{ value = @(@{ '@odata.type' = '#microsoft.graph.user'; id = 'u-ao'; userPrincipalName = 'appowner@x.io' }) } }
                default { throw "unexpected $Uri" }
            }
        }
        $global:LASTEXITCODE = 0
        $script:so = & $Shadow -OutputDirectory (Join-Path $TestDrive 'shadow-online') 6>$null 3>$null
        $script:soCode = $LASTEXITCODE
    }
    It 'runs the online collection without a failed source' {
        $soCode | Should -Be 0
        @($so.DataSources | Where-Object Status -like 'FAILED*').Count | Should -Be 0
    }
    It 'finds the group owner, the app owner, the Tier-0 workload, the App Admin and the eligible+permanent duplicate' {
        $got = @($so.Paths | ForEach-Object { "$($_.Principal)|$($_.Technique)" })
        $got | Should -Contain 'owner@x.io|OwnerOfRoleAssignableGroup'
        $got | Should -Contain 'appowner@x.io|OwnerOfTierZeroApp'
        $got | Should -Contain 'tier0-app|TierZeroWorkload'
        $got | Should -Contain 'd@x.io|AppAdminOverTierZeroApp'
        $got | Should -Contain 'd@x.io|EligibleAndPermanent'
        $got | Should -Not -Contain 'reader|TierZeroWorkload'
        ($so.Paths | Where-Object Principal -eq 'owner@x.io').Severity | Should -Be 'Critical'
    }
}

Describe 'Set-AppGovernancePolicy.ps1 (mocked Graph, stateful)' {
    BeforeEach {
        $global:T = @{}
        # A tenant that already has restrictions this script does NOT manage:
        # they must survive the PATCH.
        $global:T.policy = @{
            id = 'p1'; isEnabled = $false
            applicationRestrictions = @{
                passwordCredentials = @()
                keyCredentials = @(@{ restrictionType = 'trustedCertificateAuthority'; state = 'enabled'; certificateBasedApplicationConfigurationIds = @('ca1') })
                identifierUris = @{ nonDefaultUriAddition = @{ state = 'enabled'; restrictForAppsCreatedAfterDateTime = '2024-01-01T00:00:00Z' } }
            }
            servicePrincipalRestrictions = @{ passwordCredentials = @(); keyCredentials = @() }
        }
        $global:T.patches = [System.Collections.Generic.List[string]]::new()
        Mock Get-MgContext { [pscustomobject]@{ TenantId = 't'; Scopes = @('Policy.Read.All', 'Policy.ReadWrite.ApplicationConfiguration') } }
        Mock Connect-MgGraph { }
        Mock Start-Sleep { }
        Mock Invoke-MgGraphRequest -ParameterFilter { $Method -eq 'GET' } { return $global:T.policy }
        Mock Invoke-MgGraphRequest -ParameterFilter { $Method -eq 'PATCH' } {
            $global:T.patches.Add($Body)
            $b = $Body | ConvertFrom-Json -AsHashtable
            foreach ($k in $b.Keys) { $global:T.policy[$k] = $b[$k] }
        }
    }
    It 'merges: adds the managed restrictions to both collections and keeps the unmanaged ones' {
        & $AppPolicy -Confirm:$false -BackupDirectory $TestDrive 6>$null | Out-Null
        $global:T.patches.Count | Should -Be 1
        $b = $global:T.patches[0] | ConvertFrom-Json -AsHashtable
        $b.isEnabled | Should -BeTrue
        foreach ($col in 'applicationRestrictions', 'servicePrincipalRestrictions') {
            ($b[$col].passwordCredentials | ForEach-Object restrictionType) | Should -Contain 'passwordAddition'
            ($b[$col].passwordCredentials | ForEach-Object restrictionType) | Should -Contain 'symmetricKeyAddition'
            ($b[$col].keyCredentials | Where-Object restrictionType -eq 'asymmetricKeyLifetime').maxLifetime | Should -Be 'P180D'
        }
        ($b.applicationRestrictions.keyCredentials | ForEach-Object restrictionType) | Should -Contain 'trustedCertificateAuthority'
        $b.applicationRestrictions.identifierUris.nonDefaultUriAddition.state | Should -Be 'enabled'
        @(Get-ChildItem $TestDrive -Filter 'app_management_policy_backup_*.json').Count | Should -BeGreaterThan 0
    }
    It 'is idempotent: a second run sends no PATCH and keeps the cut-off date' {
        & $AppPolicy -Confirm:$false -BackupDirectory $TestDrive 6>$null | Out-Null
        $first = ($global:T.patches[0] | ConvertFrom-Json -AsHashtable).applicationRestrictions.passwordCredentials | Where-Object restrictionType -eq 'passwordAddition'
        & $AppPolicy -Confirm:$false -BackupDirectory $TestDrive 6>$null | Out-Null
        $global:T.patches.Count | Should -Be 1
        $first.restrictForAppsCreatedAfterDateTime | Should -Not -BeNullOrEmpty
    }
    It 'keeps a cut-off date already in force instead of moving it to now' {
        $global:T.policy.applicationRestrictions.passwordCredentials = @(@{ restrictionType = 'passwordAddition'; state = 'enabled'; maxLifetime = $null; restrictForAppsCreatedAfterDateTime = '2026-01-01T00:00:00Z' })
        & $AppPolicy -Confirm:$false -BackupDirectory $TestDrive 6>$null | Out-Null
        $b = $global:T.patches[0] | ConvertFrom-Json -AsHashtable -DateKind String
        foreach ($t in 'passwordAddition', 'symmetricKeyAddition') {
            ($b.applicationRestrictions.passwordCredentials | Where-Object restrictionType -eq $t).restrictForAppsCreatedAfterDateTime | Should -Be '2026-01-01T00:00:00Z'
        }
        ($b.applicationRestrictions.keyCredentials | Where-Object restrictionType -eq 'asymmetricKeyLifetime').restrictForAppsCreatedAfterDateTime | Should -Be '2026-01-01T00:00:00Z'
        ($b.applicationRestrictions.passwordCredentials | Where-Object restrictionType -eq 'passwordLifetime').maxLifetime | Should -Be 'P90D'
    }
    It '-WhatIf sends nothing' {
        & $AppPolicy -WhatIf -BackupDirectory $TestDrive 6>$null | Out-Null
        $global:T.patches.Count | Should -Be 0
    }
}

Describe 'Set-ConsentPolicy.ps1 (mocked Graph, stateful)' {
    BeforeEach {
        $global:T = @{}
        $global:T.authz = @{ id = 'authorizationPolicy'; defaultUserRolePermissions = @{
                allowedToCreateApps = $false
                permissionGrantPoliciesAssigned = @('ManagePermissionGrantsForSelf.microsoft-user-default-legacy', 'ManagePermissionGrantsForOwnedResource.microsoft-dynamically-managed-permissions-for-team') } }
        $global:T.acrState = @{ isEnabled = $false; notifyReviewers = $false; remindersEnabled = $false; requestDurationInDays = 30; reviewers = @() }
        $global:T.calls = [System.Collections.Generic.List[object]]::new()
        $global:T.groupExists = $true
        $scopes = foreach ($n in 'openid', 'profile', 'email', 'offline_access', 'User.Read', 'Mail.Read') { @{ id = "id-$n"; value = $n; type = 'User' } }
        $global:T.graphSp = @{ id = 'graphsp'; oauth2PermissionScopes = @($scopes) }
        Mock Get-MgContext { [pscustomobject]@{ TenantId = 't'; Scopes = @() } }
        Mock Connect-MgGraph { }
        Mock Invoke-MgGraphRequest {
            $global:T.calls.Add([pscustomobject]@{ Method = $Method; Uri = $Uri; Body = $Body })
            switch -Regex ("$Method $Uri") {
                '^GET .*/groups\?' { if ($global:T.groupExists) { return @{ value = @(@{ id = 'g1'; displayName = 'App-Consent-Reviewers' }) } } else { return @{ value = @() } } }
                '^GET .*/authorizationPolicy' { return $global:T.authz }
                '^PATCH .*/authorizationPolicy' { $global:T.authz.defaultUserRolePermissions = ($Body | ConvertFrom-Json -AsHashtable).defaultUserRolePermissions; return }
                '^GET .*servicePrincipals\(appId=' { return $global:T.graphSp }
                '^GET .*delegatedPermissionClassifications' { return @{ value = @(@{ id = 'c1'; permissionId = 'id-openid'; permissionName = 'openid'; classification = 'low' }) } }
                '^POST .*delegatedPermissionClassifications' { return @{ id = 'new' } }
                '^GET .*/adminConsentRequestPolicy' { return $global:T.acrState }
                '^PUT .*/adminConsentRequestPolicy' { $global:T.acrState = $Body | ConvertFrom-Json -AsHashtable; return }
                default { throw "unexpected $Method $Uri" }
            }
        }
    }
    It 'fails closed before any write when the reviewer group is missing' {
        $global:T.groupExists = $false
        { & $Consent -Confirm:$false 6>$null } | Should -Throw '*Nothing was changed*'
        @($global:T.calls | Where-Object Method -ne 'GET').Count | Should -Be 0
    }
    It 'swaps legacy consent for verified-publisher low-risk and keeps owned-resource policies' {
        & $Consent -Confirm:$false 6>$null | Out-Null
        $assigned = $global:T.authz.defaultUserRolePermissions.permissionGrantPoliciesAssigned
        $assigned | Should -Contain 'ManagePermissionGrantsForSelf.microsoft-user-default-low'
        $assigned | Should -Contain 'ManagePermissionGrantsForOwnedResource.microsoft-dynamically-managed-permissions-for-team'
        $assigned | Should -Not -Contain 'ManagePermissionGrantsForSelf.microsoft-user-default-legacy'
        $global:T.authz.defaultUserRolePermissions.allowedToCreateApps | Should -BeFalse
    }
    It 'classifies only the missing low-impact permissions' {
        & $Consent -Confirm:$false 6>$null | Out-Null
        $posts = @($global:T.calls | Where-Object { $_.Method -eq 'POST' -and $_.Uri -like '*delegatedPermissionClassifications' })
        $posts.Count | Should -Be 4
        ($posts | ForEach-Object { ($_.Body | ConvertFrom-Json).permissionName }) | Should -Not -Contain 'openid'
    }
    It 'enables the admin consent workflow with the group as transitive reviewers' {
        & $Consent -Confirm:$false 6>$null | Out-Null
        $global:T.acrState.isEnabled | Should -BeTrue
        $global:T.acrState.reviewers[0].query | Should -Be '/groups/g1/transitiveMembers/microsoft.graph.user'
        $global:T.acrState.requestDurationInDays | Should -Be 14
    }
    It 'Disabled mode removes all self-consent and skips classification' {
        & $Consent -UserConsent Disabled -Confirm:$false 6>$null | Out-Null
        @($global:T.authz.defaultUserRolePermissions.permissionGrantPoliciesAssigned | Where-Object { $_ -like 'ManagePermissionGrantsForSelf.*' }).Count | Should -Be 0
        @($global:T.calls | Where-Object { $_.Method -eq 'POST' }).Count | Should -Be 0
    }
}

Describe 'New-AgentIdentity.ps1 (mocked Graph)' {
    BeforeEach {
        $global:T = @{}
        $global:T.calls = [System.Collections.Generic.List[object]]::new()
        $global:T.agentApi = $true
        $global:T.miType = 'ManagedIdentity'
        Mock Get-MgContext { [pscustomobject]@{ TenantId = 'tid-123'; Scopes = @() } }
        Mock Connect-MgGraph { }
        Mock Invoke-MgGraphRequest {
            $global:T.calls.Add([pscustomobject]@{ Method = $Method; Uri = $Uri; Body = $Body })
            switch -Regex ("$Method $Uri") {
                '^GET .*applications/microsoft\.graph\.agentIdentityBlueprint\?' { if ($global:T.agentApi) { return @{ value = @() } } else { throw 'BadRequest: resource not found for segment agentIdentityBlueprint' } }
                '^GET .*/users\?' { return @{ value = @(@{ id = 'sponsor1'; displayName = 'Grace Mwangi'; accountEnabled = $true }) } }
                '^GET .*/servicePrincipals/11111111-2222-3333-4444-555555555555\?' { return @{ id = '11111111-2222-3333-4444-555555555555'; displayName = 'uami-agent-runtime'; servicePrincipalType = $global:T.miType } }
                '^POST .*applications/microsoft\.graph\.agentIdentityBlueprint$' { return @{ id = 'bp-obj'; appId = 'bp-app' } }
                '^GET .*servicePrincipals\?\$filter=appId' { return @{ value = @() } }
                '^POST .*agentIdentityBlueprintPrincipal$' { return @{ id = 'bp-sp' } }
                '^GET .*applications/bp-obj/federatedIdentityCredentials' { return @{ value = @() } }
                '^POST .*applications/bp-obj/federatedIdentityCredentials' { return @{ id = 'fic' } }
                '^GET .*servicePrincipals/microsoft\.graph\.agentIdentity\?' { return @{ value = @() } }
                '^POST .*servicePrincipals/microsoft\.graph\.agentIdentity$' { return @{ id = 'agent-1' } }
                default { throw "unexpected $Method $Uri" }
            }
        }
        $script:mi = '11111111-2222-3333-4444-555555555555'
    }
    It 'refuses a live run without -AcceptPreview, before any Graph call' {
        { & $Agent -ManagedIdentityPrincipalId $mi 6>$null } | Should -Throw '*AcceptPreview*'
        $global:T.calls.Count | Should -Be 0
    }
    It 'refuses to run without a credential path, before any Graph call' {
        { & $Agent -AcceptPreview 6>$null } | Should -Throw '*never adds a client secret*'
        $global:T.calls.Count | Should -Be 0
    }
    It 'fails closed when the Agent ID API is unavailable (no plain app registration fallback)' {
        $global:T.agentApi = $false
        { & $Agent -ManagedIdentityPrincipalId $mi -AcceptPreview -Confirm:$false 6>$null } | Should -Throw '*NOT creating an ordinary app registration*'
        @($global:T.calls | Where-Object Method -eq 'POST').Count | Should -Be 0
    }
    It 'refuses a credential subject that is not a managed identity' {
        $global:T.miType = 'Application'
        { & $Agent -ManagedIdentityPrincipalId $mi -AcceptPreview -Confirm:$false 6>$null } | Should -Throw '*not a managed identity*'
        @($global:T.calls | Where-Object Method -eq 'POST').Count | Should -Be 0
    }
    It 'creates blueprint -> principal -> federated credential -> agent identity, with sponsors and no secret' {
        $res = & $Agent -ManagedIdentityPrincipalId $mi -AcceptPreview -Confirm:$false -OutputDirectory $TestDrive 6>$null
        $posts = @($global:T.calls | Where-Object Method -eq 'POST')
        ($posts | ForEach-Object { ($_.Uri -split '/')[-1] }) | Should -Be @('microsoft.graph.agentIdentityBlueprint', 'microsoft.graph.agentIdentityBlueprintPrincipal', 'federatedIdentityCredentials', 'microsoft.graph.agentIdentity')
        ($posts[0].Body | ConvertFrom-Json).'sponsors@odata.bind' | Should -Be @('https://graph.microsoft.com/v1.0/users/sponsor1')
        $fic = $posts[2].Body | ConvertFrom-Json
        $fic.subject | Should -Be $mi
        $fic.issuer | Should -Be 'https://login.microsoftonline.com/tid-123/v2.0'
        $fic.audiences | Should -Be @('api://AzureADTokenExchange')
        ($posts[3].Body | ConvertFrom-Json).agentIdentityBlueprintId | Should -Be 'bp-app'
        @($global:T.calls | Where-Object { $_.Uri -match 'addPassword|addKey' }).Count | Should -Be 0
        $res.PermissionsGranted | Should -Be 'none'
        Test-Path (Join-Path $TestDrive 'agent_identity.json') | Should -BeTrue
    }
}

Describe '04-Leaver.ps1 step 7: NHI ownership hand-off (mocked Graph)' {
    BeforeAll {
        # The Users/Governance/Groups SDK modules aren't installed here, so stub
        # their cmdlets as functions, then mock them.
        function Get-MgUser { [CmdletBinding()] param([string]$Filter, [string[]]$Property, [string]$UserId) }
        function Revoke-MgUserSignInSession { [CmdletBinding()] param([string]$UserId) }
        function Get-MgEntitlementManagementAssignment { [CmdletBinding()] param([string]$Filter, [string[]]$ExpandProperty, [switch]$All) }
        function New-MgEntitlementManagementAssignmentRequest { [CmdletBinding()] param($BodyParameter) }
        function Get-MgUserMemberOf { [CmdletBinding()] param([string]$UserId, [switch]$All) }
        function Remove-MgGroupMemberDirectoryObjectByRef { [CmdletBinding()] param([string]$GroupId, [string]$DirectoryObjectId) }
        function Get-MgUserAppRoleAssignment { [CmdletBinding()] param([string]$UserId, [switch]$All) }
        function Remove-MgUserAppRoleAssignment { [CmdletBinding()] param([string]$UserId, [string]$AppRoleAssignmentId) }
        function Update-MgUser { [CmdletBinding()] param([string]$UserId, [switch]$AccountEnabled) }
        function Get-MgServicePrincipal { [CmdletBinding()] param([string]$Filter) }
    }
    BeforeEach {
        $global:T = @{}
        $global:T.calls = [System.Collections.Generic.List[object]]::new()
        $global:T.hasManager = $true
        $global:T.failAdd = $false
        Mock Get-MgContext { [pscustomobject]@{ TenantId = 't'; Scopes = @() } }
        Mock Connect-MgGraph { }
        Mock Get-MgUser -ParameterFilter { $Filter } { [pscustomobject]@{ Id = 'u-dana'; DisplayName = 'Dana Okafor'; AccountEnabled = $false; OnPremisesSyncEnabled = $true } }
        Mock Get-MgUser -ParameterFilter { $UserId -eq 'u-grace' } { [pscustomobject]@{ Id = 'u-grace'; UserPrincipalName = 'grace.mwangi@contosohealth.io'; AccountEnabled = $true } }
        Mock Revoke-MgUserSignInSession { }
        Mock Get-MgEntitlementManagementAssignment { @() }
        Mock Get-MgUserMemberOf { @() }
        Mock Get-MgUserAppRoleAssignment { @() }
        Mock Invoke-MgGraphRequest {
            $global:T.calls.Add([pscustomobject]@{ Method = $Method; Uri = $Uri })
            switch -Regex ("$Method $Uri") {
                '^GET .*/users/u-dana/ownedObjects' {
                    return @{ value = @(
                            @{ '@odata.type' = '#microsoft.graph.application'; id = 'app1'; displayName = 'nursing-roster-sync'; passwordCredentials = @(@{ keyId = 'k' }); keyCredentials = @() },
                            @{ '@odata.type' = '#microsoft.graph.servicePrincipal'; id = 'sp1'; displayName = 'nursing-roster-sync'; passwordCredentials = @(); keyCredentials = @() },
                            @{ '@odata.type' = '#microsoft.graph.group'; id = 'g1'; displayName = 'PIM-Tier1-Helpdesk'; isAssignableToRole = $true }) }
                }
                '^GET .*/users/u-dana/manager' { if ($global:T.hasManager) { return @{ id = 'u-grace' } } else { throw 'Request_ResourceNotFound' } }
                '^GET .*/owners\?' { return @{ value = @(@{ id = 'u-dana' }) } }
                '^POST .*/owners/\$ref' { if ($global:T.failAdd) { throw 'Forbidden' }; return }
                '^DELETE .*/owners/u-dana/\$ref' { return }
                # Privilege check of the opt-in hand-off: a low-privilege SP.
                "^GET .*/servicePrincipals\?.*appId eq '00000003" { return @{ value = @(@{ id = 'sp-graph'; appRoles = @(@{ id = 'ar-1'; value = 'User.Read.All' }) }) } }
                '^GET .*/servicePrincipals/sp1/appRoleAssignments' { return @{ value = @(@{ appRoleId = 'ar-1' }) } }
                '^GET .*/servicePrincipals/sp1/transitiveMemberOf' { return @{ value = @() } }
                default { throw "unexpected $Method $Uri" }
            }
        }
    }
    It 'adds the manager before removing the leaver, for the app and the SP (opt-in ReassignToManager)' {
        $all = & $Leaver -NhiHandoff ReassignToManager -Confirm:$false 6>&1 3>$null
        $report = @($all | Where-Object { $_ -isnot [System.Management.Automation.InformationRecord] })
        $info = (@($all | Where-Object { $_ -is [System.Management.Automation.InformationRecord] }) | ForEach-Object { "$_" }) -join "`n"
        foreach ($path in 'applications/app1', 'servicePrincipals/sp1') {
            $seq = @($global:T.calls | Where-Object { $_.Uri -like "*$path/owners*" -and $_.Method -ne 'GET' } | ForEach-Object Method)
            $seq | Should -Be @('POST', 'DELETE')
        }
        @($report | Where-Object { $_.System -eq 'NHI:nursing-roster-sync' -and $_.Status -eq 'reassigned:grace.mwangi@contosohealth.io' }).Count | Should -Be 2
        ($report | Where-Object { $_.Action -eq 'Rotate credentials' }).Status | Should -Be 'FLAGGED-rotate:1'
        ($report | Where-Object System -eq 'OwnedGroup:PIM-Tier1-Helpdesk').Status | Should -Be 'FLAGGED-role-assignable'
        $info | Should -Match '\[6/8\] Deprovision in SCIM apps'
        $info | Should -Match '\[7/8\] Hand off owned apps'
        $info | Should -Match '\[8/8\] Offboarding report'
    }
    It 'never removes the leaver when adding the new owner fails' {
        $global:T.failAdd = $true
        $all = & $Leaver -NhiHandoff ReassignToManager -Confirm:$false 6>$null 3>$null
        @($global:T.calls | Where-Object Method -eq 'DELETE').Count | Should -Be 0
        @($all | Where-Object { $_.Action -eq 'Hand off ownership' -and $_.Status -eq 'FAILED' }).Count | Should -Be 2
    }
    It 'flags instead of guessing when there is no manager' {
        $global:T.hasManager = $false
        $all = & $Leaver -NhiHandoff ReassignToManager -Confirm:$false 6>$null 3>$null
        @($global:T.calls | Where-Object { $_.Method -in 'POST', 'DELETE' }).Count | Should -Be 0
        @($all | Where-Object Status -eq 'FLAGGED-no-new-owner').Count | Should -Be 2
    }
    It 'FlagOnly (the DEFAULT) changes nothing and does not need the write scope' {
        $all = & $Leaver -Confirm:$false 6>$null 3>$null
        @($global:T.calls | Where-Object { $_.Method -in 'POST', 'DELETE' }).Count | Should -Be 0
        @($all | Where-Object { $_.System -like 'NHI:*' -and $_.Status -eq 'FLAGGED-review' }).Count | Should -Be 2
        ($all | Where-Object System -eq 'OwnedGroup:PIM-Tier1-Helpdesk').Status | Should -Be 'FLAGGED-role-assignable'
    }
    It '-WhatIf reads but writes nothing' {
        & $Leaver -WhatIf 6>$null 3>$null | Out-Null
        @($global:T.calls | Where-Object { $_.Method -in 'POST', 'DELETE' }).Count | Should -Be 0
    }
}

AfterAll { Remove-Variable -Name T -Scope Global -ErrorAction SilentlyContinue }
