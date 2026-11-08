# Pester 5 tests for ../../dc/Reset-TierAdminPassword.ps1 (PR #251). No DC:
# the script is read as an AST. What is held:
#   * the old-password check (Test-LogonDenied, Get-OldPasswordVerdict) is the
#     same code as Reset-BuildAdminPassword.ps1, whose behaviour
#     BuildAdminRotation.Tests.ps1 tests;
#   * only t0/t1/t2-adm-01 are allowed: contosoadmin is never in the list;
#   * OldPassword is a mandatory parameter (the old-password check always runs).

BeforeAll {
    $dc = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..' '..' 'dc'))
    function Get-Ast([string]$name) {
        [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $dc $name), [ref]$null, [ref]$null)
    }
    function Get-Fn($ast, [string]$n) {
        ($ast.FindAll({ param($a) $a -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $a.Name -eq $n }, $true) | Select-Object -First 1).Extent.Text
    }
    $script:Tier = Get-Ast 'Reset-TierAdminPassword.ps1'
    $script:Build = Get-Ast 'Reset-BuildAdminPassword.ps1'
    $script:Text = $script:Tier.Extent.Text
}

Describe 'Reset-TierAdminPassword.ps1' {
    It 'parses without errors' {
        $errs = $null
        $null = [System.Management.Automation.Language.Parser]::ParseInput($script:Text, [ref]$null, [ref]$errs)
        $errs | Should -BeNullOrEmpty
    }
    It 'uses the same <n> as the build-admin script' -ForEach @(@{ n = 'Test-LogonDenied' }, @{ n = 'Get-OldPasswordVerdict' }) {
        Get-Fn $script:Tier $n | Should -Not -BeNullOrEmpty
        Get-Fn $script:Tier $n | Should -BeExactly (Get-Fn $script:Build $n)
    }
    It 'allows only the three tier admins' {
        $script:Text | Should -Match "\`$allowed = @\('t0-adm-01', 't1-adm-01', 't2-adm-01'\)"
        $script:Text | Should -Not -Match "'contosoadmin'"
    }
    It 'takes OldPassword as a mandatory parameter' {
        $p = $script:Tier.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'OldPassword' }
        $p | Should -Not -BeNullOrEmpty
        ($p.Attributes.Extent.Text -join ' ') | Should -Match 'Mandatory'
    }
}
