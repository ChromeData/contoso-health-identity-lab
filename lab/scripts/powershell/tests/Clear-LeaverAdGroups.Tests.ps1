# Pester 5 tests for ../../dc/Clear-LeaverAdGroups.ps1 (review finding C7:
# a rehire must come back with no prior on-premises groups). No domain
# controller: the ActiveDirectory cmdlets are stubs answered by mocks.

BeforeAll {
    $script:Clear = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..' '..' 'dc' 'Clear-LeaverAdGroups.ps1'))
    Set-Item -Path function:global:Get-ADDomain -Value { param() }
    Set-Item -Path function:global:Get-ADUser -Value { param([string]$Filter, [string]$SearchBase, [string]$SearchScope, [string[]]$Properties, $Identity) $null = $Filter, $SearchBase, $SearchScope, $Properties, $Identity }
    Set-Item -Path function:global:Remove-ADGroupMember -Value { param([string]$Identity, [string]$Members, [switch]$Confirm) $null = $Identity, $Members, $Confirm }
    function New-Leaver {
        param([string]$Sam = 'rae.lin', [bool]$Enabled = $false, [int]$AdminCount = 0, [string[]]$MemberOf = @('CN=GG-Pharmacy-Share,OU=Groups,DC=corp,DC=contosohealthlab,DC=com', 'CN=GG-ICU-Rota,OU=Groups,DC=corp,DC=contosohealthlab,DC=com'))
        [pscustomobject]@{ SamAccountName = $Sam; ObjectGUID = [guid]'5d0c6f1e-0000-4000-8000-000000000210'; DistinguishedName = "CN=$Sam,OU=Disabled,DC=corp,DC=contosohealthlab,DC=com"; Enabled = $Enabled; employeeID = '100210'; adminCount = $AdminCount; MemberOf = $MemberOf }
    }
}

Describe 'Clear-LeaverAdGroups.ps1 (runs on DC01 via run-on-dc.py)' {
    BeforeEach {
        Mock Get-ADDomain { [pscustomobject]@{ DistinguishedName = 'DC=corp,DC=contosohealthlab,DC=com' } }
        Mock Remove-ADGroupMember {}
    }

    It 'removes every group from a disabled leaver in OU=Disabled with Apply=yes (one level, that OU only)' {
        Mock Get-ADUser { New-Leaver }
        $out = & $script:Clear -Apply yes
        Should -Invoke Get-ADUser -Times 1 -ParameterFilter { $SearchBase -eq 'OU=Disabled,DC=corp,DC=contosohealthlab,DC=com' -and $SearchScope -eq 'OneLevel' }
        Should -Invoke Remove-ADGroupMember -Times 2
        Should -Invoke Remove-ADGroupMember -Times 1 -ParameterFilter { $Identity -like 'CN=GG-ICU-Rota,*' -and $Members -like 'CN=rae.lin,OU=Disabled,*' }
        ($out -join "`n") | Should -Match 'Removed rae\.lin from GG-Pharmacy-Share'
    }

    It 'without Apply=yes only reports' {
        Mock Get-ADUser { New-Leaver }
        $out = & $script:Clear
        Should -Invoke Remove-ADGroupMember -Times 0
        ($out -join "`n") | Should -Match 'Dry run: would remove rae\.lin from GG-ICU-Rota'
    }

    It 'leaves an ENABLED account alone (a rehire already switched back on keeps its new groups)' {
        Mock Get-ADUser { New-Leaver -Enabled $true }
        & $script:Clear -Apply yes | Out-Null
        Should -Invoke Remove-ADGroupMember -Times 0
    }

    It 'never touches a protected (adminCount=1) account' {
        Mock Get-ADUser { New-Leaver -AdminCount 1 }
        $out = & $script:Clear -Apply yes
        Should -Invoke Remove-ADGroupMember -Times 0
        ($out -join "`n") | Should -Match 'protected'
    }

    It '-EmployeeId narrows the search to that worker; a non-numeric id is refused' {
        Mock Get-ADUser { New-Leaver }
        & $script:Clear -EmployeeId 100210 | Out-Null
        Should -Invoke Get-ADUser -Times 1 -ParameterFilter { $Filter -eq "employeeID -eq '100210'" }
        { & $script:Clear -EmployeeId 'x*' } | Should -Throw '*numeric*'
    }

    It 're-reads the account before each removal and stops if a rehire switched it on mid-run (review of PR #229)' {
        # The start-of-run list says disabled; by the second group the rehire
        # has enabled it and moved it to its new department OU.
        $global:ClearReads = 0
        Mock Get-ADUser -ParameterFilter { $SearchBase } { New-Leaver }
        Mock Get-ADUser -ParameterFilter { $Identity } {
            $global:ClearReads++
            if ($global:ClearReads -eq 1) { New-Leaver }
            else { [pscustomobject]@{ SamAccountName = 'rae.lin'; DistinguishedName = 'CN=rae.lin,OU=Pharmacy,DC=corp,DC=contosohealthlab,DC=com'; Enabled = $true; adminCount = 0 } }
        }
        $out = & $script:Clear -Apply yes
        Should -Invoke Remove-ADGroupMember -Times 1
        Should -Invoke Remove-ADGroupMember -Times 0 -ParameterFilter { $Identity -like 'CN=GG-ICU-Rota,*' }
        ($out -join "`n") | Should -Match 'Stopped on rae\.lin'
    }

    It 'stops before any removal when the account was enabled between the list and the first removal' {
        Mock Get-ADUser -ParameterFilter { $SearchBase } { New-Leaver }
        Mock Get-ADUser -ParameterFilter { $Identity } { New-Leaver -Enabled $true }
        & $script:Clear -Apply yes | Out-Null
        Should -Invoke Remove-ADGroupMember -Times 0
    }
}
