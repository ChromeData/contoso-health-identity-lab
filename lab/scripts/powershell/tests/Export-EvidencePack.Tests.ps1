# Pester 5 tests for Export-EvidencePack.ps1 - the parts added for the
# senior-scope build: PIM tier groups join the PIM artifacts when they exist,
# and the companion evidence other scripts wrote under lab/evidence is hashed
# into the SAME manifest (absent = listed as absent, offline-mock = never).
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

AfterAll { Remove-Variable -Name PackTest -Scope Global -ErrorAction SilentlyContinue }

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
