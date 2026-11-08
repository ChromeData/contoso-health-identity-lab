# Pester 5 tests for ../../dc/Reset-BuildAdminPassword.ps1 (PR #262). No DC:
# only the pure functions are loaded from the script's AST. What is held:
#   * the old-password check says REFUSED only for SEC_E_LOGON_DENIED
#     (0x8009030C), found anywhere in the exception chain;
#   * a timeout or any other error is ERROR (never REFUSED);
#   * a probe that returns a ticket is ACCEPTED.

BeforeAll {
    $path = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..' '..' 'dc' 'Reset-BuildAdminPassword.ps1'))
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$null, [ref]$null)
    foreach ($n in 'Test-LogonDenied', 'Get-OldPasswordVerdict') {
        $f = $ast.FindAll({ param($a) $a -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $a.Name -eq $n }, $true) | Select-Object -First 1
        if (-not $f) { throw "Reset-BuildAdminPassword.ps1 has no function $n" }
        . ([scriptblock]::Create($f.Extent.Text))
    }
    $script:Denied = -2146893044   # 0x8009030C SEC_E_LOGON_DENIED
}

Describe 'Test-LogonDenied' {
    It 'is true for a Win32Exception with SEC_E_LOGON_DENIED' {
        Test-LogonDenied -Exception ([System.ComponentModel.Win32Exception]::new($script:Denied)) | Should -BeTrue
    }
    It 'is true when the bad-password error is an inner exception' {
        $inner = [System.ComponentModel.Win32Exception]::new($script:Denied)
        Test-LogonDenied -Exception ([System.InvalidOperationException]::new('token provider failed', $inner)) | Should -BeTrue
    }
    It 'is false for a timeout' {
        Test-LogonDenied -Exception ([System.TimeoutException]::new('KDC did not answer')) | Should -BeFalse
    }
    It 'is false for another SSPI error (SEC_E_NO_AUTHENTICATING_AUTHORITY)' {
        Test-LogonDenied -Exception ([System.ComponentModel.Win32Exception]::new(-2146893039)) | Should -BeFalse
    }
}

Describe 'Get-OldPasswordVerdict' {
    It 'is REFUSED when the probe fails with a bad password' {
        $denied = $script:Denied
        Get-OldPasswordVerdict -Probe { throw [System.ComponentModel.Win32Exception]::new($denied) } | Should -Be 'REFUSED'
    }
    It 'is ERROR, not REFUSED, when the probe times out' {
        $v = Get-OldPasswordVerdict -Probe { throw [System.TimeoutException]::new('KDC did not answer') }
        $v | Should -BeLike 'ERROR: *'
        $v | Should -Not -Be 'REFUSED'
    }
    It 'is ACCEPTED when the probe returns a ticket' {
        Get-OldPasswordVerdict -Probe { [pscustomobject]@{ ValidTo = [datetime]::UtcNow } } | Should -Be 'ACCEPTED'
    }
}
