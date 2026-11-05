# Pester 5 tests for 06-NHI-Inventory.ps1: the built-in -Offline mock tenant
# (contract checks) and the ONLINE path against a tiny tenant served by a
# mocked Invoke-MgGraphRequest. No tenant is contacted.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    $script:Nhi = Get-LabScriptPath '06-NHI-Inventory.ps1'
    $script:TenantId = '11111111-1111-1111-1111-111111111111'

    function Set-NhiTenantMocks {
        param([switch]$GrantsReadFails, [switch]$OwnerStateFails)
        $now = (Get-Date).ToUniversalTime()
        # orphan-app: no owners, a client secret that expired 10 days ago.
        # owned-app: two enabled human owners, a valid 90-day certificate.
        $global:NhiTest = @{
            GrantsReadFails = [bool]$GrantsReadFails; OwnerStateFails = [bool]$OwnerStateFails
            Apps            = @(
                @{ id = 'app-1'; appId = 'aid-1'; displayName = 'orphan-app'; createdDateTime = $now.AddDays(-400).ToString('o'); signInAudience = 'AzureADMyOrg'
                    owners = @(); keyCredentials = @(); web = @{ implicitGrantSettings = @{ enableAccessTokenIssuance = $false } }
                    passwordCredentials = @(@{ keyId = 'k1'; displayName = 'old secret'; startDateTime = $now.AddDays(-100).ToString('o'); endDateTime = $now.AddDays(-10).ToString('o') })
                },
                @{ id = 'app-2'; appId = 'aid-2'; displayName = 'owned-app'; createdDateTime = $now.AddDays(-30).ToString('o'); signInAudience = 'AzureADMyOrg'
                    owners = @(
                        @{ '@odata.type' = '#microsoft.graph.user'; id = 'u-1'; userPrincipalName = 'owner1@contoso.test' },
                        @{ '@odata.type' = '#microsoft.graph.user'; id = 'u-2'; userPrincipalName = 'owner2@contoso.test' })
                    passwordCredentials = @(); web = @{ implicitGrantSettings = @{ enableAccessTokenIssuance = $false } }
                    keyCredentials = @(@{ keyId = 'c1'; displayName = 'cert'; type = 'AsymmetricX509Cert'; usage = 'Verify'; startDateTime = $now.AddDays(-1).ToString('o'); endDateTime = $now.AddDays(89).ToString('o') })
                }
            )
            Sps             = @(
                @{ id = 'sp-1'; appId = 'aid-1'; displayName = 'orphan-app'; servicePrincipalType = 'Application'; accountEnabled = $true; appOwnerOrganizationId = $script:TenantId; owners = @(); passwordCredentials = @(); keyCredentials = @() },
                @{ id = 'sp-2'; appId = 'aid-2'; displayName = 'owned-app'; servicePrincipalType = 'Application'; accountEnabled = $true; appOwnerOrganizationId = $script:TenantId; owners = @(); passwordCredentials = @(); keyCredentials = @() }
            )
        }
        Mock Write-Host {}
        Mock Out-Host {}
        Mock Get-MgContext { [pscustomobject]@{ TenantId = '11111111-1111-1111-1111-111111111111'; Scopes = @('Application.Read.All', 'Directory.Read.All', 'RoleManagement.Read.Directory', 'AuditLog.Read.All') } }
        Mock Connect-MgGraph { throw 'tests must never connect' }
        Mock Invoke-MgGraphRequest {
            $t = $global:NhiTest
            switch -Regex ($Uri) {
                '/v1\.0/applications\?' { return @{ value = @($t.Apps) } }
                '/v1\.0/servicePrincipals\?' { return @{ value = @($t.Sps) } }
                '/v1\.0/users/u-\d' { if ($t.OwnerStateFails) { throw 'Forbidden' }; return @{ id = 'u-x'; accountEnabled = $true } }
                '/federatedIdentityCredentials' { return @{ value = @() } }
                "servicePrincipals\(appId=" { return @{ id = 'graph-sp'; appRoles = @() } }
                '/appRoleAssignedTo' { return @{ value = @() } }
                '/beta/roleManagement/directory/roleDefinitions' { return @{ value = @(@{ id = '62e90394-69f5-4237-9190-012177145e10'; templateId = '62e90394-69f5-4237-9190-012177145e10' }) } }
                '/v1\.0/roleManagement/directory/roleDefinitions' { return @{ value = @(@{ id = '62e90394-69f5-4237-9190-012177145e10'; displayName = 'Global Administrator'; templateId = '62e90394-69f5-4237-9190-012177145e10' }) } }
                '/roleAssignments\?' { return @{ value = @() } }
                '/oauth2PermissionGrants' { if ($t.GrantsReadFails) { throw 'Forbidden' }; return @{ value = @() } }
                default { throw "unexpected Graph call in test: $Uri" }
            }
        }
    }
}

AfterAll { Remove-Variable -Name NhiTest -Scope Global -ErrorAction SilentlyContinue }

Describe '06-NHI-Inventory.ps1 -Offline (built-in mock tenant)' {
    BeforeAll {
        Mock Write-Host {}
        Mock Out-Host {}
        $global:LASTEXITCODE = 0
        $script:Out = Join-Path $TestDrive 'nhi-offline'
        $script:Result = & $script:Nhi -Offline -OutputDirectory $script:Out -WarningAction SilentlyContinue
        $script:Json = Get-Content -LiteralPath (Join-Path $script:Out 'nhi_inventory.json') -Raw | ConvertFrom-Json
    }

    It 'labels every row as mock data, so it can never pass for tenant evidence' {
        $script:Json.Source | Should -Be 'offline-mock'
        @($script:Json.Inventory | Where-Object Source -ne 'offline-mock').Count | Should -Be 0
    }

    It 'maps every finding to an OWASP NHI 2025 id and a standard rule' {
        @($script:Json.Findings).Count | Should -BeGreaterThan 0
        foreach ($f in $script:Json.Findings) {
            $f.OwaspNhi | Should -Match '^NHI\d{1,2}:2025$'
            $f.StandardRule | Should -Not -BeNullOrEmpty
        }
    }

    It 'says NHI10 is not covered by inventory instead of implying full coverage' {
        $nhi10 = @($script:Json.OwaspCoverage | Where-Object Owasp -eq 'NHI10:2025')
        $nhi10.Count | Should -Be 1
        $nhi10[0].CoveredHere | Should -BeFalse
    }

    It 'writes the KPI 08-Measure-KPIs.ps1 reads (expired or orphaned NHIs)' {
        $script:Json.Summary.kpi.expiredOrOrphanedNhi | Should -BeGreaterThan 0
        $script:Json.Summary.kpi.PSObject.Properties.Name | Should -Contain 'orphanedNhi'
        $script:Json.Summary.kpi.PSObject.Properties.Name | Should -Contain 'nhiWithExpiredCredential'
    }
}

Describe '06-NHI-Inventory.ps1 online path (mocked Graph)' {
    BeforeEach { $global:LASTEXITCODE = 0 }

    It 'flags the ownerless app with an expired secret and leaves the well-owned app clean' {
        Set-NhiTenantMocks
        $out = Join-Path $TestDrive 'nhi-online'
        $r = & $script:Nhi -OutputDirectory $out -SkipSignInActivity -WarningAction SilentlyContinue
        $LASTEXITCODE | Should -Be 0
        $orphan = @($r.Findings | Where-Object DisplayName -eq 'orphan-app' | ForEach-Object FindingId)
        $orphan | Should -Contain 'OWNER-NONE'
        $orphan | Should -Contain 'CRED-EXPIRED'
        $orphan | Should -Contain 'SECRET-PRESENT'
        @($r.Findings | Where-Object { $_.DisplayName -eq 'owned-app' -and $_.FindingId -like 'OWNER-*' }).Count | Should -Be 0
        $r.Summary.kpi.expiredOrOrphanedNhi | Should -Be 1
        $r.Source | Should -Be 'tenant'
        Test-Path (Join-Path $out 'nhi_inventory.json') | Should -BeTrue
    }

    It 'records a failed source as FAILED and exits 1 (incomplete, not clean)' {
        Set-NhiTenantMocks -GrantsReadFails
        $r = & $script:Nhi -OutputDirectory (Join-Path $TestDrive 'nhi-failed') -SkipSignInActivity -WarningAction SilentlyContinue
        $LASTEXITCODE | Should -Be 1
        @($r.DataSources | Where-Object { $_.Name -eq 'oauth2PermissionGrants' -and $_.Status -like 'FAILED*' }).Count | Should -Be 1
    }

    It '-PublicSummaryDirectory writes a counts-only record with SHA256SUMS: no name, id, owner or tenant id' {
        Set-NhiTenantMocks
        $out = Join-Path $TestDrive 'nhi-pub-private'; $pub = Join-Path $TestDrive 'nhi-pub'
        $r = & $script:Nhi -OutputDirectory $out -PublicSummaryDirectory $pub -SkipSignInActivity -WarningAction SilentlyContinue
        $LASTEXITCODE | Should -Be 0
        $dir = @(Get-ChildItem -LiteralPath $pub -Directory)
        $dir.Count | Should -Be 1
        $dir[0].Name | Should -Match '^\d{8}T\d{6}Z$'
        $text = Get-Content -LiteralPath (Join-Path $dir[0].FullName 'nhi-summary.json') -Raw
        foreach ($bad in 'orphan-app', 'owned-app', 'owner1', 'contoso.test', 'app-1', 'sp-2', 'aid-1', $script:TenantId) { $text | Should -Not -Match ([regex]::Escape($bad)) }
        $j = $text | ConvertFrom-Json
        $j.source | Should -Be 'tenant'
        $j.complete | Should -BeTrue
        $j.summary.kpi.expiredOrOrphanedNhi | Should -Be $r.Summary.kpi.expiredOrOrphanedNhi
        @($j.findingsById.PSObject.Properties.Name | Where-Object { $_ -like 'OWNER-NONE / *' }).Count | Should -Be 1
        ($j.findingsById.PSObject.Properties | Measure-Object -Property Value -Sum).Sum | Should -Be @($r.Findings).Count
        $j.privateFiles.'nhi_inventory.json' | Should -Be (Get-FileHash (Join-Path $out 'nhi_inventory.json') -Algorithm SHA256).Hash.ToLowerInvariant()
        $sums = Get-Content -LiteralPath (Join-Path $dir[0].FullName 'SHA256SUMS')
        $sums | Should -Be "$((Get-FileHash (Join-Path $dir[0].FullName 'nhi-summary.json') -Algorithm SHA256).Hash.ToLowerInvariant())  nhi-summary.json"
    }

    It '-PublicSummaryDirectory hashes only the files this run wrote (no stale nhi_secrets.csv)' {
        Set-NhiTenantMocks
        $out = Join-Path $TestDrive 'nhi-pub-stale'; $pub = Join-Path $TestDrive 'nhi-pub-stale-public'
        New-Item -ItemType Directory -Path $out -Force | Out-Null
        'old,rows' | Set-Content -LiteralPath (Join-Path $out 'nhi_secrets.csv')   # left by an earlier run with the register
        $null = & $script:Nhi -OutputDirectory $out -PublicSummaryDirectory $pub -SkipSignInActivity -WarningAction SilentlyContinue
        $j = Get-Content -LiteralPath (Get-ChildItem -LiteralPath $pub -Recurse -Filter 'nhi-summary.json').FullName -Raw | ConvertFrom-Json
        @($j.privateFiles.PSObject.Properties.Name) | Should -Not -Contain 'nhi_secrets.csv'
        @($j.privateFiles.PSObject.Properties.Name) | Should -Contain 'nhi_inventory.json'
    }

    It '-PublicSummaryDirectory is refused with -Offline (mock data never sits next to tenant evidence)' {
        { & $script:Nhi -Offline -PublicSummaryDirectory (Join-Path $TestDrive 'nhi-pub-offline') } | Should -Throw '*tenant runs only*'
        Test-Path (Join-Path $TestDrive 'nhi-pub-offline') | Should -BeFalse
    }

    It 'makes no "all owners disabled" verdict when owner state cannot be read' {
        Set-NhiTenantMocks -OwnerStateFails
        $r = & $script:Nhi -OutputDirectory (Join-Path $TestDrive 'nhi-ownerstate') -SkipSignInActivity -WarningAction SilentlyContinue
        @($r.Findings | Where-Object { $_.DisplayName -eq 'owned-app' -and $_.FindingId -eq 'OWNER-ALL-DISABLED' }).Count | Should -Be 0
        $LASTEXITCODE | Should -Be 1   # the unreadable owner state is itself a FAILED source
    }
}

Describe '06-NHI-Inventory.ps1 -SecretsRegisterPath (non-Entra long-lived secrets)' {
    BeforeAll {
        . (Get-ScriptFunctionBlock -Path $script:Nhi -Name 'Test-SecretsRegister')
        $script:Register = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..' '..' '..' 'iga' 'nhi-secrets-register.json'))
    }

    It 'the committed register is valid, names locations only, and covers the secrets the standard calls out' {
        $r = Get-Content -LiteralPath $script:Register -Raw | ConvertFrom-Json -AsHashtable
        $out = Test-SecretsRegister -Register $r -Now ([datetime]'2026-10-20')
        $names = @($out.Rows.Name)
        foreach ($n in 'aws-scim-token', 'servicenow-provisioning-password', 'okta-clinic-idp-client-secret', 'midpoint-reader-client-secret', 'servicenow-integration-password', 'svc-soc-automation-signin', 'splunk-hec-token', 'vault-unseal-keys-and-root-token') { $names | Should -Contain $n }
        # The Teams Workflows webhook URL (a bearer credential) was never created: the notify
        # playbook posts through the Teams connector since 2026-11-05, so the register drops it.
        $names | Should -Not -Contain 'teams-webhook-url'
        @($out.Rows | Where-Object Name -EQ 'servicenow-integration-password')[0].Status | Should -Be 'present'
        foreach ($row in $out.Rows) { $row.Owner | Should -Not -BeNullOrEmpty -Because "$($row.Name) needs an owner role" }
        # No value can hide in the register: no field looks like a token, key or password.
        (Get-Content -LiteralPath $script:Register -Raw) | Should -Not -Match '(hvs\.|-----BEGIN|AKIA[0-9A-Z]{16}|xox[bp]-|https://[^ "]*webhook[^ "]*/[A-Za-z0-9]{20,})'
    }

    It 'flags a missing owner, an expired entry and a missing rotation; undated is Medium' {
        $reg = @{ secrets = @(
                @{ name = 'a'; system = 's'; store = 'kv:a'; owner = ''; expiresOn = '2027-01-01'; rotation = 'P90D'; status = 'planned' },
                @{ name = 'b'; system = 's'; store = 'kv:b'; owner = 'secops'; expiresOn = '2026-01-01'; rotation = 'P90D'; status = 'present' },
                @{ name = 'c'; system = 's'; store = 'file'; owner = 'secops'; expiresOn = $null; rotation = ''; status = 'present' }) }
        $out = Test-SecretsRegister -Register $reg -Now ([datetime]'2026-10-20')
        $f = @($out.Findings | ForEach-Object { "$($_.DisplayName):$($_.FindingId):$($_.Severity)" })
        $f | Should -Contain 'a:SECRET-NO-OWNER:High'
        $f | Should -Contain 'b:SECRET-EXPIRED:High'
        $f | Should -Contain 'c:SECRET-NO-EXPIRY:Medium'
        $f | Should -Contain 'c:SECRET-NO-ROTATION:Medium'
        @($out.Findings | Where-Object DisplayName -eq 'a' | Where-Object FindingId -eq 'SECRET-NO-EXPIRY').Count | Should -Be 0
    }

    It 'refuses an invalid register (never "no secrets")' {
        { Test-SecretsRegister -Register @{ secrets = @(@{ name = 'x'; status = 'planned' }) } -Now (Get-Date) } | Should -Throw '*has no store*'
        { Test-SecretsRegister -Register @{ secrets = @() } -Now (Get-Date) } | Should -Throw '*no secrets*'
        { Test-SecretsRegister -Register @{ secrets = @(@{ name = 'x'; store = 'kv'; status = 'planned'; expiresOn = '20/10/2026' }) } -Now (Get-Date) } | Should -Throw '*yyyy-MM-dd*'
        { Test-SecretsRegister -Register @{ secrets = @(@{ name = 'x'; store = 'kv'; status = 'planned'; createdOn = 'last week' }) } -Now (Get-Date) } | Should -Throw '*createdOn*yyyy-MM-dd*'
        { Test-SecretsRegister -Register @{ secrets = @(@{ name = 'x'; store = 'kv'; status = 'planned'; expiresOn = 'unknown' }) } -Now (Get-Date) } | Should -Throw '*yyyy-MM-dd*'
        { Test-SecretsRegister -Register @{ secrets = @(@{ name = 'x'; store = 'kv'; status = 'present'; createdOn = '2026-10-20'; expiresOn = '2026-10-19' }) } -Now (Get-Date) } | Should -Throw '*before createdOn*'
    }

    It 'an "unknown (reason)" date is a no-date marker: still SECRET-NO-EXPIRY, with the reason, never a pass' {
        $reg = @{ secrets = @(
                @{ name = 'tenant-thing'; system = 's'; store = 'kv:t'; owner = 'secops'; createdOn = 'unknown (tenant-time)'; expiresOn = 'unknown (tenant-time)'; rotation = 'P90D'; status = 'planned' },
                @{ name = 'local-thing'; system = 's'; store = 'file'; owner = 'secops'; createdOn = '2026-10-19'; expiresOn = '2027-04-17'; rotation = 'P180D'; status = 'present' }) }
        $out = Test-SecretsRegister -Register $reg -Now ([datetime]'2026-10-20')
        $nx = @($out.Findings | Where-Object { $_.DisplayName -eq 'tenant-thing' -and $_.FindingId -eq 'SECRET-NO-EXPIRY' })
        $nx.Count | Should -Be 1
        $nx[0].Detail | Should -Match 'unknown \(tenant-time\)'
        ($out.Rows | Where-Object Name -eq 'tenant-thing').ExpiresOn | Should -Be 'unknown (tenant-time)'
        @($out.Findings | Where-Object DisplayName -eq 'local-thing').Count | Should -Be 0
        ($out.Rows | Where-Object Name -eq 'local-thing').ExpiresOn | Should -Be '2027-04-17'
    }

    It 'the committed register dates every present local secret from a recorded source and marks the rest unknown' {
        $r = Get-Content -LiteralPath $script:Register -Raw | ConvertFrom-Json -AsHashtable
        foreach ($e in $r['secrets']) {
            if ($e['status'] -eq 'present') {
                $e['createdOn'] | Should -Match '^\d{4}-\d{2}-\d{2}$' -Because "$($e['name']) is present: its date can be read"
                $e['expiresOn'] | Should -Match '^\d{4}-\d{2}-\d{2}$' -Because $e['name']
                $e['dateSource'] | Should -Match 'createdOn: .*expiresOn = createdOn \+ P\d+D' -Because "$($e['name']) must say where its date came from"
            }
            else {
                $e['createdOn'] | Should -Match '^unknown \(.+\)$' -Because $e['name']
                $e['expiresOn'] | Should -Match '^unknown \(.+\)$' -Because $e['name']
            }
        }
        # Present entries are dated, so on the review day only the planned ones are undated.
        $out = Test-SecretsRegister -Register $r -Now ([datetime]'2026-10-20')
        $undated = @($out.Findings | Where-Object FindingId -eq 'SECRET-NO-EXPIRY' | ForEach-Object DisplayName | Sort-Object)
        $planned = @($r['secrets'] | Where-Object { $_['status'] -eq 'planned' } | ForEach-Object { $_['name'] } | Sort-Object)
        $undated | Should -Be $planned
    }

    It '-Offline with the register writes nhi_secrets.csv and adds the findings to the KPIs' {
        Mock Write-Host {}
        Mock Out-Host {}
        $out = Join-Path $TestDrive 'nhi-reg'
        $r = & $script:Nhi -Offline -OutputDirectory $out -SecretsRegisterPath $script:Register
        Join-Path $out 'nhi_secrets.csv' | Should -Exist
        $r.Summary.kpi.registeredSecrets | Should -BeGreaterThan 5
        @($r.Findings | Where-Object FindingId -like 'SECRET-*').Count | Should -BeGreaterThan 0
        @($r.DataSources | Where-Object Name -eq 'secretsRegister')[0].Status | Should -Be 'ok'
    }

    It 'a missing register is a FAILED source (exit 1), not an empty one' {
        Mock Write-Host {}
        Mock Out-Host {}
        $global:LASTEXITCODE = 0
        & $script:Nhi -Offline -OutputDirectory (Join-Path $TestDrive 'nhi-missing') -SecretsRegisterPath (Join-Path $TestDrive 'nope.json') | Out-Null
        $LASTEXITCODE | Should -Be 1
    }
}

Describe '06-NHI-Inventory.ps1 -OwnersRegisterPath (Tier-0 identities owned by a role, never by an Entra owner)' {
    BeforeAll {
        . (Get-ScriptFunctionBlock -Path $script:Nhi -Name 'Read-OwnersRegister', 'Get-Value')
        $script:Owners = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..' '..' '..' 'iga' 'nhi-owners.json'))
        function New-OwnersRegisterFile([string]$Name, [object[]]$Identities) {
            $p = Join-Path $TestDrive "$Name.json"
            @{ roles = @{ 'Identity Platform Owner' = @{ holder = 'test' } }; identities = $Identities } | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $p
            return $p
        }
        function Invoke-OfflineWithRegister([string]$Register, [string]$Name) {
            Mock Write-Host {}
            Mock Out-Host {}
            $global:LASTEXITCODE = 0
            return (& $script:Nhi -Offline -OutputDirectory (Join-Path $TestDrive $Name) -OwnersRegisterPath $Register -WarningAction SilentlyContinue)
        }
        $script:ApplyRole = @{ displayName = 'gh-oidc-entra-apply (write)'; ownerModel = 'role'; accountableOwnerRole = 'Identity Platform Owner'; tier = 'Tier 0' }
        $script:PlanRole = @{ displayName = 'gh-oidc-entra-plan (read-only)'; ownerModel = 'role'; accountableOwnerRole = 'Identity Platform Owner'; tier = 'Tier 0 (by state access)' }
    }

    It 'the committed register is valid: the five CI and operator identities are owned by a defined role' {
        $map = Read-OwnersRegister -Register (Get-Content -LiteralPath $script:Owners -Raw | ConvertFrom-Json -AsHashtable)
        @($map.Keys | Sort-Object) | Should -Be @('Contoso Lab Operator (local Mac, certificate)', 'EVIDENCE (gh-oidc evidence pack)', 'gh-oidc-entra-apply (write)', 'gh-oidc-entra-plan (read-only)', 'HR-SYNC (gh-oidc hr-feed upload)')
        foreach ($k in $map.Keys) { $map[$k].Role | Should -Be 'Identity Platform Owner'; $map[$k].Tier | Should -BeLike 'Tier 0*' }
    }

    It 'the committed register never makes the access governance lead an owner of an identity that creates or disables accounts (SOD-08)' {
        $r = Get-Content -LiteralPath $script:Owners -Raw | ConvertFrom-Json -AsHashtable
        foreach ($n in 'Contoso HR Inbound Provisioning', 'corp.contosohealthlab.com', 'HR-SYNC (gh-oidc hr-feed upload)') {
            $e = @($r['identities'] | Where-Object { $_['displayName'] -eq $n })[0]
            @($e['owners']) | Should -Not -Contain 'adm-mei.tanaka'
        }
    }

    It 'counts a role-owned Tier-0 identity with no Entra owner as owned (no OWNER-NONE), and says so on its row' {
        $base = Invoke-OfflineWithRegister -Register (New-OwnersRegisterFile 'none' @(@{ displayName = 'unrelated'; ownerModel = 'entra' })) -Name 'base'
        $r = Invoke-OfflineWithRegister -Register (New-OwnersRegisterFile 'role' @($script:ApplyRole, $script:PlanRole)) -Name 'role'
        $LASTEXITCODE | Should -Be 0
        foreach ($n in 'gh-oidc-entra-apply (write)', 'gh-oidc-entra-plan (read-only)') {
            @($r.Findings | Where-Object { $_.DisplayName -eq $n -and $_.FindingId -like 'OWNER-*' }).Count | Should -Be 0
            $row = $r.Inventory | Where-Object DisplayName -eq $n
            $row.OwnerModel | Should -Be 'Register role (Identity Platform Owner)'
            $row.AccountableOwner | Should -Be 'Identity Platform Owner'
            $row.OwnerCount | Should -Be ''
        }
        $r.Summary.kpi.orphanedNhi | Should -Be ($base.Summary.kpi.orphanedNhi - 2)
        $r.Summary.kpi.roleOwnedNhi | Should -Be 2
        ($r.DataSources | Where-Object Name -eq 'ownersRegister').Status | Should -Be 'ok'
    }

    It 'flags a Tier-0 identity (by permission) that HAS an Entra owner: OWNER-TIER0, raised to Critical' {
        $r = Invoke-OfflineWithRegister -Register (New-OwnersRegisterFile 'none2' @(@{ displayName = 'unrelated'; ownerModel = 'entra' })) -Name 'perm'
        $f = @($r.Findings | Where-Object { $_.DisplayName -eq 'legacy-report-exporter' -and $_.FindingId -eq 'OWNER-TIER0' })
        $f.Count | Should -Be 1
        $f[0].Severity | Should -Be 'Critical'
        $f[0].OwaspNhi | Should -Be 'NHI5:2025'
    }

    It 'flags a register Tier-0 identity that HAS an Entra owner (OWNER-TIER0, never "add a second owner")' {
        $mp = @{ displayName = 'midpoint-reader'; ownerModel = 'role'; accountableOwnerRole = 'Identity Platform Owner'; tier = 'Tier 0' }
        $r = Invoke-OfflineWithRegister -Register (New-OwnersRegisterFile 'mp' @($mp)) -Name 'mp'
        $ids = @($r.Findings | Where-Object DisplayName -eq 'midpoint-reader' | ForEach-Object FindingId)
        $ids | Should -Contain 'OWNER-TIER0'
        $ids | Should -Not -Contain 'OWNER-SINGLE'
        ($r.Inventory | Where-Object DisplayName -eq 'midpoint-reader').OwnerModel | Should -Be 'Entra owners'
        $r.Summary.kpi.tierZeroWithEntraOwner | Should -BeGreaterOrEqual 1
    }

    It 'an invalid register is a FAILED source (exit 1) and covers nothing: the Tier-0 orphan stays OWNER-NONE' {
        $bad = New-OwnersRegisterFile 'bad' @(@{ displayName = 'gh-oidc-entra-apply (write)'; ownerModel = 'role'; accountableOwnerRole = 'Nobody'; tier = 'Tier 0' })
        $r = Invoke-OfflineWithRegister -Register $bad -Name 'bad'
        $LASTEXITCODE | Should -Be 1
        ($r.DataSources | Where-Object Name -eq 'ownersRegister').Status | Should -BeLike 'FAILED*'
        @($r.Findings | Where-Object { $_.DisplayName -eq 'gh-oidc-entra-apply (write)' -and $_.FindingId -eq 'OWNER-NONE' }).Count | Should -Be 1
    }

    It 'refuses a register that lists an identity twice or has an unknown owner model' {
        { Read-OwnersRegister -Register @{ roles = @{ R = @{} }; identities = @(@{ displayName = 'a'; ownerModel = 'entra' }, @{ displayName = 'a'; ownerModel = 'entra' }) } } | Should -Throw '*listed twice*'
        { Read-OwnersRegister -Register @{ roles = @{ R = @{} }; identities = @(@{ displayName = 'a'; ownerModel = 'owner' }) } } | Should -Throw "*must be 'entra' or 'role'*"
        { Read-OwnersRegister -Register @{ identities = @(@{ displayName = 'a'; ownerModel = 'entra' }) } } | Should -Throw "*'roles'*"
    }

    It 'never covers a display name that matches two app registrations, and still flags an Entra owner on either (OWNER-TIER0)' {
        Set-NhiTenantMocks
        # Two look-alikes of a role-owned name: one ownerless, one with a single human owner.
        $twin = $global:NhiTest.Apps[0].Clone(); $twin['id'] = 'app-3'; $twin['appId'] = 'aid-3'
        $twin['owners'] = @(@{ '@odata.type' = '#microsoft.graph.user'; id = 'u-1'; userPrincipalName = 'owner1@contoso.test' })
        $global:NhiTest.Apps = @($global:NhiTest.Apps) + @($twin)
        $reg = New-OwnersRegisterFile 'twin' @(@{ displayName = 'orphan-app'; ownerModel = 'role'; accountableOwnerRole = 'Identity Platform Owner'; tier = 'Tier 0' })
        $global:LASTEXITCODE = 0
        $r = & $script:Nhi -OutputDirectory (Join-Path $TestDrive 'nhi-twin') -SkipSignInActivity -OwnersRegisterPath $reg -WarningAction SilentlyContinue
        @($r.Findings | Where-Object { $_.ObjectId -eq 'sp-1' -and $_.FindingId -eq 'OWNER-NONE' }).Count | Should -Be 1
        $owned = @($r.Findings | Where-Object { $_.ObjectId -eq 'app-3' } | ForEach-Object FindingId)
        $owned | Should -Contain 'OWNER-TIER0'
        $owned | Should -Not -Contain 'OWNER-SINGLE'
        @($r.Inventory | Where-Object { $_.DisplayName -eq 'orphan-app' -and $_.OwnerModel -like 'Register role*' }).Count | Should -Be 0
        ($r.DataSources | Where-Object Name -eq 'ownersRegister').Detail | Should -Match "'orphan-app' matches 2 app registrations"
    }

    It 'refuses a role-owned row without a Tier-0 tier (a typo must not switch off OWNER-TIER0)' {
        { Read-OwnersRegister -Register @{ roles = @{ R = @{} }; identities = @(@{ displayName = 'a'; ownerModel = 'role'; accountableOwnerRole = 'R' }) } } | Should -Throw "*tier must start with 'Tier 0'*"
        { Read-OwnersRegister -Register @{ roles = @{ R = @{} }; identities = @(@{ displayName = 'a'; ownerModel = 'role'; accountableOwnerRole = 'R'; tier = 'Tier O' }) } } | Should -Throw "*tier must start with 'Tier 0'*"
    }
}
