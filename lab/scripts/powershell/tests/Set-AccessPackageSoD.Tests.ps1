# Pester 5 tests for post-apply/Set-AccessPackageSoD.ps1, now a DEPRECATION
# SHIM that forwards to Set-IncompatibleAccessPackages.ps1 (lab/iga/sod-rules.json).
#   * The old behaviour cannot come back: no Graph call in the shim itself,
#     the old -PackageA/-PackageB pair is refused before anything is read,
#     and no link is ever written ON a birthright package (Nurse, ICU).
#   * Forwarding: -RenderOnly / -WhatIf / -RuleId / -Prune reach the target,
#     and the target's exit code is the shim's (Invoke-PostApply.ps1 step 3).
# Every Graph call is a Pester mock; no tenant is contacted.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
    $script:Shim = Get-LabScriptPath 'post-apply/Set-AccessPackageSoD.ps1'
    $script:Target = Get-LabScriptPath 'post-apply/Set-IncompatibleAccessPackages.ps1'

    function Set-TenantMock {
        # Same in-memory tenant shape as tests/Set-IncompatibleAccessPackages.Tests.ps1.
        param([hashtable]$PkgLinks = @{}, [hashtable]$GrpLinks = @{})
        $global:ShimTest = @{
            Packages = @{ 'Nurse - Clinical Apps' = 'ap-nurse'; 'ICU - Critical Care Apps' = 'ap-icu'; 'ICU - Float Access' = 'ap-icu-float'; 'Pharmacy - Controlled Substances Apps' = 'ap-pharm' }
            Groups   = @{ 'All-Nurses' = 'g-nurses'; 'All-ICU' = 'g-icu'; 'App-Pharmacy-Dispensing-Users' = 'g-pharm' }
            PkgLinks = $PkgLinks; GrpLinks = $GrpLinks; Writes = [System.Collections.Generic.List[object]]::new()
        }
        Mock Write-Host {}
        Mock Get-MgContext { New-MgContextStub -Scopes @('EntitlementManagement.ReadWrite.All', 'Group.Read.All') }
        Mock Connect-MgGraph { throw 'tests must never connect' }
        Mock Invoke-MgGraphRequest {
            $t = $global:ShimTest; $u = [uri]::UnescapeDataString("$Uri")
            if ($Method -in 'POST', 'DELETE') { $t.Writes.Add(@{ Method = $Method; Uri = $u }); return $null }
            $names = @{}; foreach ($k in $t.Packages.Keys) { $names[$t.Packages[$k]] = $k }; foreach ($k in $t.Groups.Keys) { $names[$t.Groups[$k]] = $k }
            if ($u -match "/accessPackages\?\`$filter=displayName eq '(?<n>.+)'&") { $n = $Matches.n.Replace("''", "'"); return @{ value = @($(if ($t.Packages.ContainsKey($n)) { @{ id = $t.Packages[$n]; displayName = $n } }) | Where-Object { $_ }) } }
            if ($u -match "/groups\?\`$filter=displayName eq '(?<n>.+)'&") { $n = $Matches.n.Replace("''", "'"); return @{ value = @($(if ($t.Groups.ContainsKey($n)) { @{ id = $t.Groups[$n]; displayName = $n } }) | Where-Object { $_ }) } }
            if ($u -match '/accessPackages/(?<id>[^/]+)/incompatibleAccessPackages\?') { return @{ value = @(@($t.PkgLinks[$Matches.id]) | Where-Object { $_ } | ForEach-Object { @{ id = $_; displayName = $names[$_] } }) } }
            if ($u -match '/accessPackages/(?<id>[^/]+)/incompatibleGroups\?') { return @{ value = @(@($t.GrpLinks[$Matches.id]) | Where-Object { $_ } | ForEach-Object { @{ id = $_; displayName = $names[$_] } }) } }
            throw "unexpected Graph call in test: $Method $u"
        }
    }
    # SOD-01 fully in place, plus the legacy Nurse -> Pharmacy link the old script wrote.
    $script:Sod01PlusLegacy = @{
        PkgLinks = @{ 'ap-pharm' = @('ap-nurse', 'ap-icu', 'ap-icu-float'); 'ap-icu-float' = @('ap-pharm'); 'ap-nurse' = @('ap-pharm') }
        GrpLinks = @{ 'ap-pharm' = @('g-nurses', 'g-icu'); 'ap-icu-float' = @('g-pharm') }
    }
}

AfterAll { Remove-Variable -Name ShimTest -Scope Global -ErrorAction SilentlyContinue }

Describe 'Set-AccessPackageSoD.ps1 - the old behaviour cannot come back' {
    It 'contains no Graph call of its own (only the forward)' {
        $tokens = $null; $errs = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($script:Shim, [ref]$tokens, [ref]$errs)
        $errs | Should -BeNullOrEmpty
        $cmds = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true) | ForEach-Object { $_.GetCommandName() } | Where-Object { $_ })
        $cmds | Should -Not -Contain 'Invoke-MgGraphRequest'
        $cmds | Should -Not -Contain 'Connect-MgGraph'
    }

    It 'refuses the legacy -PackageA / -PackageB pair before anything is read' {
        Set-TenantMock
        { & $script:Shim -PackageA 'Nurse - Clinical Apps' -PackageB 'Pharmacy - Controlled Substances Apps' -WarningAction SilentlyContinue } | Should -Throw '*deprecated*sod-rules.json*'
        Should -Invoke Invoke-MgGraphRequest -Times 0
    }

    It 'keeps a -WhatIf parameter, so Invoke-PostApply.ps1 step 3 still dry-runs it' {
        (Get-Command $script:Shim).Parameters.Keys | Should -Contain 'WhatIf'
    }
}

Describe 'Set-AccessPackageSoD.ps1 - forwards to Set-IncompatibleAccessPackages.ps1' {
    BeforeEach { $global:LASTEXITCODE = 0 }

    It '-RenderOnly returns the same plan as the target, with no Graph call and no link on a birthright package' {
        Mock Write-Host {}
        Mock Invoke-MgGraphRequest { throw 'no Graph in -RenderOnly' }
        $viaShim = & $script:Shim -RenderOnly -WarningAction SilentlyContinue
        $direct = & $script:Target -RenderOnly
        @($viaShim.Links | ForEach-Object { "$($_.From) X $($_.To)" }) | Should -Be @($direct.Links | ForEach-Object { "$($_.From) X $($_.To)" })
        @($viaShim.Links | Where-Object { $_.From -in 'Nurse - Clinical Apps', 'ICU - Critical Care Apps' }).Count | Should -Be 0
        @($viaShim.Links | Where-Object { $_.From -eq 'ICU - Float Access' -and $_.To -eq 'Pharmacy - Controlled Substances Apps' }).Count | Should -Be 1
        Should -Invoke Invoke-MgGraphRequest -Times 0
    }

    It 'says it is deprecated' {
        Mock Write-Host {}
        Mock Invoke-MgGraphRequest { throw 'no Graph in -RenderOnly' }
        & $script:Shim -RenderOnly -WarningVariable wv -WarningAction SilentlyContinue | Out-Null
        ($wv -join "`n") | Should -Match 'DEPRECATED'
    }

    It 'a live run writes SOD-01 links only on the requestable packages (Pharmacy, ICU - Float Access)' {
        Set-TenantMock
        & $script:Shim -RuleId SOD-01 -Confirm:$false -WarningAction SilentlyContinue | Out-Null
        $LASTEXITCODE | Should -Be 0
        $posts = @($global:ShimTest.Writes | Where-Object Method -eq 'POST')
        $posts.Count | Should -Be 7
        @($posts | Where-Object { $_.Uri -like '*/accessPackages/ap-nurse/*' -or $_.Uri -like '*/accessPackages/ap-icu/*' }).Count | Should -Be 0
    }

    It '-WhatIf is forwarded: nothing is written' {
        Set-TenantMock
        & $script:Shim -RuleId SOD-01 -WhatIf -WarningAction SilentlyContinue | Out-Null
        $LASTEXITCODE | Should -Be 0
        $global:ShimTest.Writes.Count | Should -Be 0
    }

    It 'the legacy Nurse -> Pharmacy link fails the run (target exit code 1) and is not removed without -Prune' {
        Set-TenantMock @script:Sod01PlusLegacy
        & $script:Shim -RuleId SOD-01 -Confirm:$false -WarningAction SilentlyContinue | Out-Null
        $LASTEXITCODE | Should -Be 1
        $global:ShimTest.Writes.Count | Should -Be 0
    }

    It '-Prune is forwarded: the legacy link is removed with DELETE .../$ref, nothing else changes' {
        Set-TenantMock @script:Sod01PlusLegacy
        & $script:Shim -RuleId SOD-01 -Prune -Confirm:$false -WarningAction SilentlyContinue | Out-Null
        $LASTEXITCODE | Should -Be 0
        $w = @($global:ShimTest.Writes)
        $w.Count | Should -Be 1
        $w[0].Method | Should -Be 'DELETE'
        $w[0].Uri | Should -BeLike '*/accessPackages/ap-nurse/incompatibleAccessPackages/ap-pharm/$ref'
    }
}
