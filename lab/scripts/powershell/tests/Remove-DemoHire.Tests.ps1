# Pester 5 tests for ../../dc/Remove-DemoHire.ps1 - the DC01 half of
# lab/scripts/demo/reset-demo-hire.sh (demo retakes). No domain controller:
# the ActiveDirectory cmdlets are stubs defined here and answered by mocks.
# What is held:
#   * it deletes at most ONE account, found by employeeID, and only with
#     Apply=yes (anything else is a report);
#   * never outside OU=Workforce / OU=Disabled at the domain root, never a
#     protected (adminCount=1) account, never when two accounts match;
#   * "already gone" is success, so a re-run is safe.

BeforeAll {
    $script:Remove = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..' '..' 'dc' 'Remove-DemoHire.ps1'))
    # Stand-ins for the ActiveDirectory module (absent off a DC); the mocks
    # below give them their answers. Global so the script under test sees them.
    # (Set-Item, not `function global:`: PSScriptAnalyzer 1.25 crashes on those.)
    Set-Item -Path function:global:Get-ADDomain -Value { param() }
    Set-Item -Path function:global:Get-ADUser -Value { param([string]$Filter, [string[]]$Properties) $null = $Filter, $Properties }
    Set-Item -Path function:global:Remove-ADUser -Value { param([string]$Identity, [switch]$Confirm) $null = $Identity, $Confirm }
    Set-Item -Path function:global:Set-ADObject -Value { param([string]$Identity, [bool]$ProtectedFromAccidentalDeletion) $null = $Identity, $ProtectedFromAccidentalDeletion }
    $script:Domain = 'DC=corp,DC=contosohealthlab,DC=com'
    function New-AdUser {
        # Called from inside mocks: literal domain, no $script: state.
        param([string]$Ou = 'OU=Information Technology,OU=Workforce,DC=corp,DC=contosohealthlab,DC=com', [int]$AdminCount = 0, [bool]$Protected = $false)
        [pscustomobject]@{ Name = 'Sam Rivera'; SamAccountName = 'sam.rivera'; DistinguishedName = "CN=Sam Rivera,$Ou"; Enabled = $true
            employeeID = '400104'; adminCount = $AdminCount; ProtectedFromAccidentalDeletion = $Protected }
    }
}

Describe 'Remove-DemoHire.ps1 (runs on DC01 via run-on-dc.py)' {
    BeforeEach {
        Mock Get-ADDomain { [pscustomobject]@{ DistinguishedName = 'DC=corp,DC=contosohealthlab,DC=com' } }
        Mock Remove-ADUser {}
        Mock Set-ADObject {}
    }

    It 'deletes the one Workforce account with that employeeID when Apply=yes' {
        Mock Get-ADUser { New-AdUser }
        $out = & $script:Remove -EmployeeId 400104 -Apply yes
        $LASTEXITCODE | Should -Be 0
        Should -Invoke Get-ADUser -Times 1 -ParameterFilter { $Filter -eq "employeeID -eq '400104'" }
        Should -Invoke Remove-ADUser -Times 1 -ParameterFilter { $Identity -eq "CN=Sam Rivera,OU=Information Technology,OU=Workforce,$($script:Domain)" }
        ($out -join "`n") | Should -Match 'Deleted sam\.rivera'
    }

    It 'without Apply=yes only reports (dry run)' {
        Mock Get-ADUser { New-AdUser }
        $out = & $script:Remove -EmployeeId 400104
        $LASTEXITCODE | Should -Be 0
        Should -Invoke Remove-ADUser -Times 0
        ($out -join "`n") | Should -Match 'Dry run: would delete'
    }

    It 'a leaver in OU=Disabled is in scope; a protected-from-deletion flag is lifted first' {
        Mock Get-ADUser { New-AdUser -Ou 'OU=Disabled,DC=corp,DC=contosohealthlab,DC=com' -Protected $true }
        & $script:Remove -EmployeeId 400104 -Apply yes | Out-Null
        Should -Invoke Set-ADObject -Times 1
        Should -Invoke Remove-ADUser -Times 1
    }

    It 'refuses an account outside OU=Workforce / OU=Disabled (Tier 0, PAM, service accounts)' {
        Mock Get-ADUser { New-AdUser -Ou 'OU=Tier0,DC=corp,DC=contosohealthlab,DC=com' }
        $out = & $script:Remove -EmployeeId 400104 -Apply yes
        $LASTEXITCODE | Should -Be 1
        Should -Invoke Remove-ADUser -Times 0
        ($out -join "`n") | Should -Match 'REFUSED: the account is outside'
    }

    It 'refuses a look-alike OU name that only ENDS in Workforce' {
        Mock Get-ADUser { New-AdUser -Ou 'OU=NotWorkforce,DC=corp,DC=contosohealthlab,DC=com' }
        & $script:Remove -EmployeeId 400104 -Apply yes | Out-Null
        $LASTEXITCODE | Should -Be 1
        Should -Invoke Remove-ADUser -Times 0
    }

    It 'refuses a protected account (adminCount=1)' {
        Mock Get-ADUser { New-AdUser -AdminCount 1 }
        & $script:Remove -EmployeeId 400104 -Apply yes | Out-Null
        $LASTEXITCODE | Should -Be 1
        Should -Invoke Remove-ADUser -Times 0
    }

    It 'refuses when two accounts share the employeeID' {
        Mock Get-ADUser { New-AdUser; New-AdUser }
        $out = & $script:Remove -EmployeeId 400104 -Apply yes
        $LASTEXITCODE | Should -Be 1
        Should -Invoke Remove-ADUser -Times 0
        ($out -join "`n") | Should -Match 'REFUSED: 2 AD accounts'
    }

    It 'already gone is success (safe to re-run)' {
        Mock Get-ADUser {}
        $out = & $script:Remove -EmployeeId 400104 -Apply yes
        $LASTEXITCODE | Should -Be 0
        ($out -join "`n") | Should -Match 'nothing to delete'
    }

    It 'refuses a non-numeric employee id before touching AD (no LDAP filter injection)' {
        Mock Get-ADUser { throw 'must not be called' }
        { & $script:Remove -EmployeeId "1' -or employeeID -like '*" -Apply yes } | Should -Throw '*numeric worker id*'
        Should -Invoke Get-ADUser -Times 0
    }
}

AfterAll {
    foreach ($f in 'Get-ADDomain', 'Get-ADUser', 'Remove-ADUser', 'Set-ADObject') { Remove-Item -LiteralPath "function:global:$f" -ErrorAction SilentlyContinue }
}
