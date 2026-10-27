# Pester 5 tests for Export-IdentityConfig.ps1.
#   * Normalisation: the pure functions, loaded from the script's syntax
#     tree - deterministic bytes, volatile fields dropped, identifiers
#     scrubbed and (with -Public) hashed, order kept only where it matters.
#   * Break-glass facts and the well-known role names (parity with 08).
#   * The -Offline fixture end to end: one snapshot per run, hashed, every
#     section present, public-safe, byte-stable across runs.
#   * The ONLINE path against a mocked Invoke-MgGraphRequest that answers
#     from the same fixture: a failed read is recorded as failed (never as an
#     empty section), the error is scrubbed, paging is followed, and the
#     sections match the offline run (one collector, two sources).
# No tenant is contacted.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    $script:Export = Get-LabScriptPath 'Export-IdentityConfig.ps1'
    . (Get-ScriptFunctionBlock -Path $script:Export)
    $script:FixturePath = Join-Path $PSScriptRoot 'fixtures' 'identity-config.fixture.json'
    $script:BgId = '0b1c2d3e-0000-4000-8000-00000000b6a5'
    function Read-Snapshot([string]$Dir) {
        $f = @(Get-ChildItem -LiteralPath $Dir -Filter '*.json' | Sort-Object Name)[-1]
        return @{ File = $f; Json = (Get-Content -LiteralPath $f.FullName -Raw); Object = (Get-Content -LiteralPath $f.FullName -Raw | ConvertFrom-Json -AsHashtable -Depth 50) }
    }
}

Describe 'ConvertTo-StableConfig (normalisation)' {
    It 'drops volatile fields and sorts keys' {
        $o = ConvertTo-StableConfig -Value @{ state = 'enabled'; modifiedDateTime = '2026-10-20T08:15:00Z'; createdDateTime = 'x'; lastModifiedBy = @{ displayName = 'Grace' }; displayName = 'CA001'; '@odata.context' = 'ctx'; version = 3; policyVersion = '1.5' }
        @($o.Keys) | Should -Be @('displayName', 'state')
    }

    It 'is deterministic: key order and set order do not change the bytes' {
        $a = ConvertTo-StableConfig -Value @{ b = @('KP', 'IR', 'SY'); a = @{ y = 1; x = @('g2', 'g1') } }
        $b = ConvertTo-StableConfig -Value ([ordered]@{ a = [ordered]@{ x = @('g1', 'g2'); y = 1 }; b = @('SY', 'KP', 'IR') })
        (ConvertTo-CanonicalJson $a) | Should -BeExactly (ConvertTo-CanonicalJson $b)
        $a['b'] | Should -Be @('IR', 'KP', 'SY')
    }

    It 'keeps order where order is the setting (approval stages, identity-provider precedence)' {
        $o = ConvertTo-StableConfig -Value @{ approvalStages = @(@{ n = 'second' }, @{ n = 'first' }); primaryIdentityProviderPrecedenceOrder = @('socialIdentityProviders', 'azureActiveDirectory') }
        @($o['approvalStages'] | ForEach-Object { $_['n'] }) | Should -Be @('second', 'first')
        $o['primaryIdentityProviderPrecedenceOrder'] | Should -Be @('socialIdentityProviders', 'azureActiveDirectory')
    }

    It 'orders object lists by displayName, then id, never by position' {
        $o = ConvertTo-StableConfig -Value @(@{ displayName = 'CA004'; id = 'z' }, @{ displayName = 'CA001'; id = 'a' }, @{ displayName = 'CA001'; id = '0' }) -Key 'items'
        @($o | ForEach-Object { "$($_['displayName'])/$($_['id'])" }) | Should -Be @('CA001/0', 'CA001/a', 'CA004/z')
    }

    It 'keeps an empty list a list and a one-item list a list' {
        $o = ConvertTo-StableConfig -Value @{ a = @(); b = @(@{ id = 'only' }) }
        (ConvertTo-CanonicalJson $o) | Should -Match '"a": \[\]'
        @($o['b']).Count | Should -Be 1
    }

    It 'scrubs email / UPN strings in every mode and counts notification recipients' {
        $o = ConvertTo-StableConfig -Value @{ notificationRecipients = @('soc@contoso.test', 'iam@contoso.test'); note = 'ask grace.mwangi@contoso.test' }
        $o.Contains('notificationRecipients') | Should -BeFalse
        $o['notificationRecipientCount'] | Should -Be 2
        $o['note'] | Should -Be 'ask [redacted]'
    }

    It 'keeps object ids without -Public and hashes every GUID with it, inside composite ids and queries too' {
        $raw = @{ id = $script:BgId; policyId = "DirectoryRole_9f9f9f9f-0000-4000-8000-000000007e01_$script:BgId"; query = "/groups/$script:BgId/transitiveMembers"; ipRanges = @(@{ cidrAddress = '203.0.113.0/24' }) }
        $plain = ConvertTo-StableConfig -Value $raw
        $plain['id'] | Should -Be $script:BgId
        $plain['ipRanges'][0]['cidrAddress'] | Should -Be '203.0.113.0/24'
        $pub = ConvertTo-StableConfig -Value $raw -HashIds $true
        $h = Get-ObjectIdHash -Value $script:BgId
        $pub['id'] | Should -Be $h
        $pub['policyId'] | Should -Be "DirectoryRole_$(Get-ObjectIdHash -Value '9f9f9f9f-0000-4000-8000-000000007e01')_$h"
        $pub['query'] | Should -Be "/groups/$h/transitiveMembers"
        $pub['ipRanges'][0]['cidrAddress'] | Should -Match '^h:[0-9a-f]{16}$'
        (ConvertTo-CanonicalJson $pub) | Should -Not -Match '[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}|\d{1,3}(\.\d{1,3}){3}'
    }

    It 'Get-ObjectIdHash is stable, case-insensitive and reveals nothing' {
        $h = Get-ObjectIdHash -Value $script:BgId
        $h | Should -Match '^h:[0-9a-f]{16}$'
        Get-ObjectIdHash -Value $script:BgId.ToUpperInvariant() | Should -Be $h
        $h | Should -Not -BeLike "*$($script:BgId.Substring(0, 8))*"
    }
}

Describe 'Get-BreakGlassFact' {
    It 'names the policies that exclude the group and the ones that do not, and counts members without naming them' {
        $g = @{ id = 'g-bg'; isAssignableToRole = $true; displayName = 'Break-Glass-Admins' }
        $policies = @(
            @{ displayName = 'CA002'; conditions = @{ users = @{ excludeGroups = @('other') } } },
            @{ displayName = 'CA001'; conditions = @{ users = @{ excludeGroups = @('g-bg', 'other') } } },
            @{ displayName = 'CA003'; conditions = @{ users = @{ excludeGroups = @() } } }
        )
        $members = @(@{ id = 'u1'; accountEnabled = $true; userPrincipalName = 'bg-admin-01@lab.onmicrosoft.com' }, @{ id = 'u2'; accountEnabled = $false })
        $f = Get-BreakGlassFact -Group $g -Members $members -GlobalAdminAssignments @(@{ id = 'ra' }) -Policies $policies
        $f['groupFound'] | Should -BeTrue
        $f['memberCount'] | Should -Be 2
        $f['enabledMemberCount'] | Should -Be 1
        $f['holdsGlobalAdministrator'] | Should -BeTrue
        $f['excludedFromPolicies'] | Should -Be @('CA001')
        $f['notExcludedFromPolicies'] | Should -Be @('CA002', 'CA003')
        (ConvertTo-Json -InputObject $f -Depth 5) | Should -Not -Match 'onmicrosoft|u1|u2'
    }

    It 'a missing group is a fact, not an empty list: every policy is then "not excluded"' {
        $f = Get-BreakGlassFact -Group $null -Policies @(@{ displayName = 'CA001'; conditions = @{ users = @{ excludeGroups = @('x') } } })
        $f['groupFound'] | Should -BeFalse
        $f['holdsGlobalAdministrator'] | Should -BeFalse
        $f['notExcludedFromPolicies'] | Should -Be @('CA001')
    }
}

Describe 'Get-WellKnownRoleName (parity with 08-Measure-KPIs.ps1 Get-RoleTierMap)' {
    It 'names every role of the tier map identically' {
        . (Get-ScriptFunctionBlock -Path (Get-LabScriptPath '08-Measure-KPIs.ps1') -Name 'Get-RoleTierMap')
        $map = Get-RoleTierMap
        foreach ($id in $map.Keys) { Get-WellKnownRoleName -TemplateId $id | Should -Be $map[$id]['Name'] }
        Get-WellKnownRoleName -TemplateId '62E90394-69F5-4237-9190-012177145E10' | Should -Be 'Global Administrator'
    }

    It 'an unknown role gets a hashed label, never the raw id' {
        $n = Get-WellKnownRoleName -TemplateId '12345678-1234-1234-1234-123456789abc'
        $n | Should -Match '^role h:[0-9a-f]{16}$'
    }
}

Describe 'Get-FixtureResponse / Test-PublicEvidencePath' {
    It 'the longest matching URI fragment answers; an unknown URI throws like a 404' {
        $r = @{ 'policies/authenticationStrengthPolicies' = @{ value = @('list') }; 'policies/authenticationStrengthPolicies/abc/combinationConfigurations' = @{ value = @('child') } }
        (Get-FixtureResponse -Responses $r -Uri 'https://graph.microsoft.com/v1.0/policies/authenticationStrengthPolicies')['value'] | Should -Be @('list')
        (Get-FixtureResponse -Responses $r -Uri 'https://graph.microsoft.com/v1.0/policies/authenticationStrengthPolicies/abc/combinationConfigurations')['value'] | Should -Be @('child')
        { Get-FixtureResponse -Responses $r -Uri 'https://graph.microsoft.com/v1.0/nothing' } | Should -Throw '*no response*'
    }

    It 'knows the public evidence tree from the gitignored out/ tree' {
        $root = Join-Path $TestDrive 'evidence'
        Test-PublicEvidencePath -Path (Join-Path $root 'config-snapshots') -EvidenceRoot $root | Should -BeTrue
        Test-PublicEvidencePath -Path (Join-Path $root 'out' 'config-snapshots') -EvidenceRoot $root | Should -BeFalse
        Test-PublicEvidencePath -Path (Join-Path $TestDrive 'elsewhere') -EvidenceRoot $root | Should -BeFalse
    }
}

Describe 'Export-IdentityConfig.ps1 -Offline (fixture replay)' {
    BeforeAll {
        Mock Write-Host {}
        $script:PubDir = Join-Path $TestDrive 'public'
        $global:LASTEXITCODE = 0
        $script:Result = & $script:Export -Offline -Public -FixturePath $script:FixturePath -OutputDirectory $script:PubDir -Label 'test'
        $script:PubExit = $LASTEXITCODE
        $script:Pub = Read-Snapshot $script:PubDir
    }

    It 'writes one snapshot with every section ok, source offline-fixture, and exits 0' {
        $script:PubExit | Should -Be 0
        $j = $script:Pub.Object
        $j['schema'] | Should -Be 'contoso-identity-config/v1'
        $j['source'] | Should -Be 'offline-fixture'
        $j['public'] | Should -BeTrue
        $j['failedSections'] | Should -BeNullOrEmpty
        foreach ($s in 'conditionalAccessPolicies', 'namedLocations', 'authenticationStrengths', 'authenticationMethodsPolicy', 'pimDirectoryRolePolicies',
            'pimGroupPolicies', 'consentPolicy', 'appManagementPolicy', 'crossTenantAccessDefaults', 'breakGlass') {
            $j['sections'].Contains($s) | Should -BeTrue -Because "section '$s' must always be present (ok or failed)"
            $j['sections'][$s]['status'] | Should -Be 'ok' -Because $s
        }
        $j['sections']['conditionalAccessPolicies']['count'] | Should -Be 4
        @($j['sections']['conditionalAccessPolicies']['items'] | ForEach-Object { $_['displayName'] }) | Should -Be @('CA001 - Require MFA for all users', 'CA002 - Require phishing-resistant MFA for admins', 'CA003 - Block legacy authentication', 'CA004 - Block sign-in from blocked countries')
        $j['sections']['pimGroupPolicies']['groups'] | Should -Be @('pim-tier0-security-admins', 'privileged-iam-admins')
        $j['sections']['pimDirectoryRolePolicies']['items'][0]['roleDisplayName'] | Should -Be 'Global Administrator'
        $j['sections']['breakGlass']['facts']['notExcludedFromPolicies'] | Should -BeNullOrEmpty
        $j['sections']['breakGlass']['facts']['enabledMemberCount'] | Should -Be 2
        $j['sections']['breakGlass']['facts']['holdsGlobalAdministrator'] | Should -BeTrue
        $j['fixture']['sha256'] | Should -Be (Get-FileHash -LiteralPath $script:FixturePath -Algorithm SHA256).Hash.ToLowerInvariant()
    }

    It 'writes a SHA256SUMS line that matches the file (sha256sum format)' {
        $sums = Get-Content -LiteralPath (Join-Path $script:PubDir 'SHA256SUMS')
        @($sums).Count | Should -Be 1
        $sums | Should -Match "^[0-9a-f]{64}  $([regex]::Escape($script:Pub.File.Name))$"
        ($sums -split '\s+')[0] | Should -Be (Get-FileHash -LiteralPath $script:Pub.File.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    }

    It 'drops every volatile field from the whole tree' {
        $script:Pub.Json | Should -Not -Match 'modifiedDateTime|createdDateTime|lastModifiedBy|policyVersion|"version"'
    }

    It 'public snapshot holds no UPN, mailbox, object id, IP range or tenant domain' {
        $script:Pub.Json | Should -Not -Match '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+'   # @odata.type keys are fine; a mailbox is not
        $script:Pub.Json | Should -Not -Match '[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}'
        $script:Pub.Json | Should -Not -Match '\b\d{1,3}(\.\d{1,3}){3}\b|onmicrosoft|bg-admin|Grace|203\.0\.113'
        @(Test-PublicRecordSafe -Json $script:Pub.Json).Count | Should -Be 0
        $script:Pub.Json | Should -Match '"notificationRecipientCount": 2'
        $script:Pub.Json | Should -Not -Match 'notificationRecipients"'
    }

    It 'is deterministic: a second export differs only in its timestamp and label' {
        Start-Sleep -Seconds 1   # the file name is the UTC second
        $dir2 = Join-Path $TestDrive 'public2'
        $null = & $script:Export -Offline -Public -FixturePath $script:FixturePath -OutputDirectory $dir2 -Label 'again'
        $a = $script:Pub.Object; $b = (Read-Snapshot $dir2).Object
        (ConvertTo-Json -InputObject $a['sections'] -Depth 30) | Should -BeExactly (ConvertTo-Json -InputObject $b['sections'] -Depth 30)
        (ConvertTo-Json -InputObject $a['parameters'] -Depth 10) | Should -BeExactly (ConvertTo-Json -InputObject $b['parameters'] -Depth 10)
    }

    It 'without -Public keeps object ids (for the gitignored tree) but still no UPN or mailbox' {
        $dir = Join-Path $TestDrive 'ids'
        $null = & $script:Export -Offline -FixturePath $script:FixturePath -OutputDirectory $dir
        $s = Read-Snapshot $dir
        $s.Object['public'] | Should -BeFalse
        $s.Json | Should -Match $script:BgId
        $s.Json | Should -Not -Match '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+|onmicrosoft|bg-admin'
        $s.Object['sections']['breakGlass']['facts']['groupId'] | Should -Be $script:BgId
    }

    It 'refuses -Offline output into the public evidence tree' {
        $public = Join-Path $script:LabPowerShellRoot '..' '..' 'evidence' 'config-snapshots'
        { & $script:Export -Offline -FixturePath $script:FixturePath -OutputDirectory $public } | Should -Throw '*not tenant evidence*'
    }

    It 'honours -WhatIf: nothing written' {
        $dir = Join-Path $TestDrive 'whatif'
        $null = & $script:Export -Offline -Public -FixturePath $script:FixturePath -OutputDirectory $dir -WhatIf
        Test-Path -LiteralPath $dir | Should -BeFalse
    }
}

Describe 'Export-IdentityConfig.ps1 online path (mocked Graph, answered from the fixture)' {
    BeforeAll {
        Mock Write-Host {}
        Mock Get-MgContext { New-MgContextStub -Scopes @('Policy.Read.All', 'RoleManagementPolicy.Read.Directory', 'RoleManagementPolicy.Read.AzureADGroup', 'Group.Read.All', 'GroupMember.Read.All', 'RoleManagement.Read.Directory') }
        Mock Connect-MgGraph { throw 'tests must never connect' }
        $global:ExportFixture = Get-Content -LiteralPath $script:FixturePath -Raw | ConvertFrom-Json -AsHashtable -Depth 50
        $global:ExportFail = @{}      # URI fragment -> error message to throw
        $global:ExportPageCa = $false # answer the CA list in two pages
        Mock Invoke-MgGraphRequest {
            $decoded = [uri]::UnescapeDataString($Uri)
            foreach ($k in $global:ExportFail.Keys) { if ($decoded.Contains($k)) { throw $global:ExportFail[$k] } }
            if ($global:ExportPageCa -and $decoded -like '*identity/conditionalAccess/policies*') {
                $all = @($global:ExportFixture['responses']['identity/conditionalAccess/policies']['value'])
                if ($decoded -like '*skiptoken=page2*') { return @{ value = @($all[2..3]) } }
                return @{ value = @($all[0..1]); '@odata.nextLink' = 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies?$skiptoken=page2' }
            }
            $best = $null
            foreach ($k in $global:ExportFixture['responses'].Keys) {
                if ($decoded.Contains([string]$k, [System.StringComparison]::OrdinalIgnoreCase) -and ($null -eq $best -or ([string]$k).Length -gt $best.Length)) { $best = [string]$k }
            }
            if ($null -eq $best) { throw "unexpected Graph call in test: $Uri" }
            return $global:ExportFixture['responses'][$best]
        }
        # TestDrive is cleaned between top-level blocks: make the offline reference here.
        $refDir = Join-Path $TestDrive 'offline-ref'
        $null = & $script:Export -Offline -Public -FixturePath $script:FixturePath -OutputDirectory $refDir
        $script:OfflineRef = (Read-Snapshot $refDir).Object
    }
    AfterAll { Remove-Variable -Name ExportFixture, ExportFail, ExportPageCa -Scope Global -ErrorAction SilentlyContinue }
    BeforeEach { $global:ExportFail = @{}; $global:ExportPageCa = $false }

    It 'produces the same sections as the offline run (one collector, two sources) and follows @odata.nextLink' {
        $global:ExportPageCa = $true
        $dir = Join-Path $TestDrive 'online'
        $global:LASTEXITCODE = 0
        $null = & $script:Export -Public -OutputDirectory $dir -Label 'online' -WarningAction SilentlyContinue
        $LASTEXITCODE | Should -Be 0
        Should -Invoke Invoke-MgGraphRequest -ParameterFilter { $Uri -like '*skiptoken=page2*' } -Times 1 -Exactly
        $s = Read-Snapshot $dir
        $s.Object['source'] | Should -Be 'tenant'
        $s.Object['sections']['conditionalAccessPolicies']['count'] | Should -Be 4
        (ConvertTo-Json -InputObject $s.Object['sections'] -Depth 30) | Should -BeExactly (ConvertTo-Json -InputObject $script:OfflineRef['sections'] -Depth 30)
    }

    It 'records a failed read as failed with a scrubbed error (never as an empty section) and exits 1; the other sections still export' {
        $global:ExportFail['identity/conditionalAccess/namedLocations'] = 'Forbidden: Policy.Read.All missing for admin@contoso.test'
        $dir = Join-Path $TestDrive 'failed'
        $global:LASTEXITCODE = 0
        $null = & $script:Export -Public -OutputDirectory $dir -WarningAction SilentlyContinue
        $LASTEXITCODE | Should -Be 1
        $j = (Read-Snapshot $dir).Object
        $j['failedSections'] | Should -Be @('namedLocations')
        $j['sections']['namedLocations']['status'] | Should -Be 'failed'
        $j['sections']['namedLocations']['error'] | Should -Match 'Forbidden'
        $j['sections']['namedLocations']['error'] | Should -Not -Match '@'
        $j['sections']['namedLocations'].Contains('items') | Should -BeFalse -Because 'a failed section must not look like an empty one'
        $j['sections']['conditionalAccessPolicies']['status'] | Should -Be 'ok'
        $j['sections']['breakGlass']['status'] | Should -Be 'ok'
    }

    It 'a missing PIM-governed group fails the PIM section instead of shrinking the list' {
        $global:ExportFail["mailNickname eq 'privileged-iam-admins'"] = 'simulated: group lookup failed'
        $dir = Join-Path $TestDrive 'nogroup'
        $global:LASTEXITCODE = 0
        $null = & $script:Export -Public -OutputDirectory $dir -WarningAction SilentlyContinue
        $LASTEXITCODE | Should -Be 1
        $j = (Read-Snapshot $dir).Object
        $j['sections']['pimGroupPolicies']['status'] | Should -Be 'failed'
    }

    It 'break-glass facts depend on the policies: when those cannot be read, the facts are failed too' {
        $global:ExportFail['identity/conditionalAccess/policies'] = 'Forbidden'
        $dir = Join-Path $TestDrive 'noca'
        $global:LASTEXITCODE = 0
        $null = & $script:Export -Public -OutputDirectory $dir -WarningAction SilentlyContinue
        $LASTEXITCODE | Should -Be 1
        $j = (Read-Snapshot $dir).Object
        $j['sections']['breakGlass']['status'] | Should -Be 'failed'
        $j['failedSections'] | Should -Be @('conditionalAccessPolicies', 'breakGlass')
    }

    It 'refuses a tenant export with object ids into the public evidence tree, before any Graph call' {
        $public = Join-Path $script:LabPowerShellRoot '..' '..' 'evidence' 'config-snapshots'
        { & $script:Export -OutputDirectory $public } | Should -Throw '*add -Public*'
        Should -Invoke Invoke-MgGraphRequest -Times 0 -Exactly
    }
}
