# Pester 5. The quiet-period gate in 19-Remove-Adfs.ps1. The script runs only
# on DC01, so the test lifts Test-AdfsAuditProof out of the file (AST) and
# runs it with fixed times.
# Why: the gate accepted ANY old AD FS audit as proof that auditing still
# works (Greptile, PR #237 follow-up). Auditing can stop after that audit,
# and then "no sign-ins" proves nothing. Now the newest audit must be inside
# a bounded window (-AuditFreshHours, 1-24 h) and not in the future.
BeforeAll {
    $path = Join-Path $PSScriptRoot '../scripts/19-Remove-Adfs.ps1'
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$null, [ref]$null)
    $f = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Test-AdfsAuditProof' }, $true))
    $f.Count | Should -Be 1
    . ([scriptblock]::Create($f[0].Extent.Text))
    $script:Param = $ast.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'AuditFreshHours' }

    $script:Now = [datetime]::new(2026, 11, 8, 12, 0, 0, [DateTimeKind]::Utc)
    $script:WindowStart = $script:Now.AddHours(-24)
    $script:LogFrom = $script:Now.AddDays(-7)
    function Invoke-Gate($Newest, $LogFrom = $script:LogFrom, [int]$Fresh = 2) {
        Test-AdfsAuditProof -NewestAuditUtc $Newest -SecurityLogFromUtc $LogFrom -WindowStartUtc $script:WindowStart -NowUtc $script:Now -FreshHours $Fresh
    }
}

Describe 'Test-AdfsAuditProof (19-Remove-Adfs.ps1 quiet-period gate)' {
    It 'passes with a fresh audit and a log that reaches back' {
        $r = Invoke-Gate $script:Now.AddMinutes(-30)
        $r.Proven | Should -BeTrue
        $r.Reasons.Count | Should -Be 0
    }

    It 'refuses an OLD audit as proof that auditing still works' {
        $r = Invoke-Gate $script:Now.AddDays(-3)
        $r.Proven | Should -BeFalse
        $r.Reasons -join ';' | Should -Match 'older than 2 h'
    }

    It 'refuses an audit just outside the window' {
        (Invoke-Gate $script:Now.AddHours(-2).AddSeconds(-1)).Proven | Should -BeFalse
        (Invoke-Gate $script:Now.AddHours(-2)).Proven | Should -BeTrue
    }

    It 'refuses when no audit exists at all' {
        $r = Invoke-Gate $null
        $r.Proven | Should -BeFalse
        $r.Reasons -join ';' | Should -Match 'no AD FS audit'
    }

    It 'refuses an audit dated in the future (clock problem)' {
        $r = Invoke-Gate $script:Now.AddHours(1)
        $r.Proven | Should -BeFalse
        $r.Reasons -join ';' | Should -Match 'future'
    }

    It 'refuses when the Security log does not reach back to the quiet window start' {
        $r = Invoke-Gate $script:Now.AddMinutes(-5) -LogFrom $script:Now.AddHours(-1)
        $r.Proven | Should -BeFalse
        $r.Reasons -join ';' | Should -Match 'Security log starts'
    }

    It 'refuses a freshness window outside 1-24 h, even if called directly' {
        (Invoke-Gate $script:Now.AddMinutes(-5) -Fresh 0).Proven | Should -BeFalse
        (Invoke-Gate $script:Now.AddMinutes(-5) -Fresh 25).Proven | Should -BeFalse
    }

    It 'bounds -AuditFreshHours to 1-24 h in the script parameters' {
        $v = $script:Param.Attributes | Where-Object { $_.TypeName.Name -eq 'ValidateRange' }
        $v | Should -Not -BeNullOrEmpty
        $v.PositionalArguments.Value | Should -Be @(1, 24)
    }

    It 'the -Apply path throws when the proof fails (no unconditional bypass)' {
        $src = Get-Content -Raw (Join-Path $PSScriptRoot '../scripts/19-Remove-Adfs.ps1')
        $src | Should -Match '\$auditsProven = \$proof\.Proven'
        $src | Should -Match "if \(-not \`$auditsProven -and \`$Force -ne 'yes'\)"
        $src | Should -Not -Match '\$anyAudit'
    }
}
