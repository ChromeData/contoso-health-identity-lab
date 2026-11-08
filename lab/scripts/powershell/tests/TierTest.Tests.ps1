# Pester 5 tests for ../../dc/tier-test (the Tier GPO proof, PR #239). No
# domain controller, no VM: the ActiveDirectory cmdlets and dsacls are stubs
# answered by mocks; Test-TierLogon.ps1's pure functions are loaded from the
# script's AST (the script itself needs a domain-joined Windows machine).
# Fake passwords only. What is held:
#   * Remove-Tier2DeviceObject: a failed AD query STOPS; it never reads as
#     "already removed" (Get-ADComputer -ErrorAction Stop);
#   * Test-TierLogon: "GPO applied" comes from the GPO's own gpresult /x
#     entry; a GPO that gpresult lists as filtered out / denied is NOT applied;
#     a real admin as the Tier 0 test account is refused;
#   * Join-Tier2Device refuses the build admin;
#   * New/Remove-TierTestAccounts: only the three disposable accounts, with
#     an expiry, the right groups, no Domain Admins; a failed read stops.

BeforeAll {
    $script:Dir = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..' '..' 'dc' 'tier-test'))
    # Stand-ins for the ActiveDirectory module (absent off a DC). [CmdletBinding()]
    # so -ErrorAction reaches them like the real cmdlets. Set-Item, not
    # `function global:` (PSScriptAnalyzer 1.25 crashes on those).
    Set-Item -Path function:global:Get-ADComputer -Value { [CmdletBinding()] param([string]$Filter, [string]$SearchBase) $null = $Filter, $SearchBase }
    Set-Item -Path function:global:Get-ADUser -Value { [CmdletBinding()] param([string]$Filter) $null = $Filter }
    Set-Item -Path function:global:Get-ADDomain -Value { [CmdletBinding()] param() }
    Set-Item -Path function:global:Remove-ADObject -Value { [CmdletBinding()] param([string]$Identity, [switch]$Recursive, [switch]$Confirm) $null = $Identity, $Recursive, $Confirm }
    Set-Item -Path function:global:Remove-ADUser -Value { [CmdletBinding()] param([string]$Identity, [switch]$Confirm) $null = $Identity, $Confirm }
    Set-Item -Path function:global:New-ADUser -Value { [CmdletBinding()] param([string]$Name, [string]$SamAccountName, [string]$UserPrincipalName, [string]$Path, [string]$Description, [datetime]$AccountExpirationDate, [bool]$Enabled, [securestring]$AccountPassword) $null = $Name, $SamAccountName, $UserPrincipalName, $Path, $Description, $AccountExpirationDate, $Enabled, $AccountPassword }
    Set-Item -Path function:global:Set-ADAccountControl -Value { [CmdletBinding()] param([string]$Identity, [bool]$AccountNotDelegated) $null = $Identity, $AccountNotDelegated }
    Set-Item -Path function:global:Add-ADGroupMember -Value { [CmdletBinding()] param([string]$Identity, [string[]]$Members) $null = $Identity, $Members }
    Set-Item -Path function:global:dsacls.exe -Value { $global:DsaclsCalls += , @($args); $global:LASTEXITCODE = 0 }
    $script:Domain = 'DC=corp,DC=contosohealthlab,DC=com'

    # Load ONLY the named functions from Test-TierLogon.ps1 (its body needs Windows).
    $ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $script:Dir 'Test-TierLogon.ps1'), [ref]$null, [ref]$null)
    foreach ($n in 'Get-RsopGpoState', 'Test-GpoApplied', 'Get-PrivilegedMembership') {
        $f = $ast.FindAll({ param($a) $a -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $a.Name -eq $n }, $true) | Select-Object -First 1
        if (-not $f) { throw "Test-TierLogon.ps1 has no function $n" }
        . ([scriptblock]::Create($f.Extent.Text))
    }

    function New-Rsop {
        # A gpresult /x shaped report: the deny GPO in the given state, plus
        # one applied GPO so the parser must pick by name.
        param([string]$FilterAllowed = 'true', [string]$AccessDenied = 'false', [int]$AppliedOrder = 2, [string]$IsValid = 'true')
        [xml]@"
<?xml version="1.0" encoding="utf-16"?>
<Rsop xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns="http://www.microsoft.com/GroupPolicy/Rsop">
  <ComputerResults>
    <GPO>
      <Name>Default Domain Policy</Name>
      <Enabled>true</Enabled><IsValid>true</IsValid><FilterAllowed>true</FilterAllowed><AccessDenied>false</AccessDenied>
      <Link><SOMPath>corp.contosohealthlab.com</SOMPath><AppliedOrder>1</AppliedOrder><Enabled>true</Enabled></Link>
    </GPO>
    <GPO>
      <Name>Tier0 - Deny logon to Tier1 and Tier2</Name>
      <Enabled>true</Enabled><IsValid>$IsValid</IsValid><FilterAllowed>$FilterAllowed</FilterAllowed><AccessDenied>$AccessDenied</AccessDenied>
      <Link><SOMPath>corp.contosohealthlab.com/Tier2/Devices</SOMPath><AppliedOrder>$AppliedOrder</AppliedOrder><Enabled>true</Enabled></Link>
    </GPO>
  </ComputerResults>
</Rsop>
"@
    }
}

Describe 'Remove-Tier2DeviceObject.ps1 (DC01)' {
    BeforeEach { Mock Remove-ADObject {} }

    It 'a failed directory query stops the script; it never says "already removed"' {
        Mock Get-ADComputer { Write-Error 'The server is not operational' }
        { & (Join-Path $script:Dir 'Remove-Tier2DeviceObject.ps1') } | Should -Throw '*not operational*'
        Should -Invoke Remove-ADObject -Times 0
    }

    It 'a real, empty answer is "already removed"' {
        Mock Get-ADComputer { }
        $out = & (Join-Path $script:Dir 'Remove-Tier2DeviceObject.ps1')
        ($out -join "`n") | Should -Match 'already removed'
        Should -Invoke Get-ADComputer -Times 1 -ParameterFilter { $Filter -eq "Name -eq 'T2DEV01'" }
    }

    It 'removes T2DEV01 only from Tier2\Devices' {
        Mock Get-ADComputer { [pscustomobject]@{ DistinguishedName = 'CN=T2DEV01,OU=Devices,OU=Tier2,DC=corp,DC=contosohealthlab,DC=com' } } -ParameterFilter { $Filter -like 'Name*' }
        Mock Get-ADComputer { } -ParameterFilter { $Filter -eq '*' }
        Mock Get-ADDomain { [pscustomobject]@{ DistinguishedName = 'DC=corp,DC=contosohealthlab,DC=com' } }
        & (Join-Path $script:Dir 'Remove-Tier2DeviceObject.ps1') | Out-Null
        Should -Invoke Remove-ADObject -Times 1 -ParameterFilter { $Identity -like 'CN=T2DEV01,OU=Devices,OU=Tier2,*' -and $Recursive }
    }
}

Describe 'Test-TierLogon.ps1: GPO applied is read from gpresult /x' {
    It 'an applied GPO (filter allowed, not denied, applied order > 0) is applied' {
        $s = Get-RsopGpoState -Rsop (New-Rsop) -Name 'Tier0 - Deny logon to Tier1 and Tier2'
        Test-GpoApplied $s | Should -BeTrue
    }
    It 'a GPO in the filtered-out list (FilterAllowed false, applied order 0) is NOT applied' {
        $s = Get-RsopGpoState -Rsop (New-Rsop -FilterAllowed 'false' -AppliedOrder 0) -Name 'Tier0 - Deny logon to Tier1 and Tier2'
        $s | Should -Not -BeNullOrEmpty   # the name IS in the report - a text search would say "applied"
        Test-GpoApplied $s | Should -BeFalse
    }
    It 'a GPO denied by security filtering (AccessDenied true) is NOT applied' {
        Test-GpoApplied (Get-RsopGpoState -Rsop (New-Rsop -AccessDenied 'true' -AppliedOrder 0) -Name 'Tier0 - Deny logon to Tier1 and Tier2') | Should -BeFalse
    }
    It 'an invalid GPO is NOT applied, even with an applied order' {
        Test-GpoApplied (Get-RsopGpoState -Rsop (New-Rsop -IsValid 'false') -Name 'Tier0 - Deny logon to Tier1 and Tier2') | Should -BeFalse
    }
    It 'a GPO missing from the report, or a report missing fields, is NOT applied (fail closed)' {
        Get-RsopGpoState -Rsop (New-Rsop) -Name 'Some other GPO' | Should -BeNullOrEmpty
        Test-GpoApplied $null | Should -BeFalse
        [xml]$bare = '<Rsop xmlns="http://www.microsoft.com/GroupPolicy/Rsop"><ComputerResults><GPO><Name>Tier0 - Deny logon to Tier1 and Tier2</Name></GPO></ComputerResults></Rsop>'
        Test-GpoApplied (Get-RsopGpoState -Rsop $bare -Name 'Tier0 - Deny logon to Tier1 and Tier2') | Should -BeFalse
    }
    It 'the script no longer decides from a text search of gpresult /r' {
        $src = Get-Content -Raw (Join-Path $script:Dir 'Test-TierLogon.ps1')
        $src | Should -Not -Match 'gpresult\.exe[^\r\n]*/r\b'
        $src | Should -Match 'gpresult\.exe /scope computer /x'
    }
}

Describe 'Test-TierLogon.ps1: the Tier 0 test account must be disposable' {
    It 'a direct Domain Admins member is privileged (refused)' {
        Get-PrivilegedMembership -MemberOf @("CN=Tier0-Admins,OU=Groups,OU=Tier0,$($script:Domain)", "CN=Domain Admins,CN=Users,$($script:Domain)") | Should -HaveCount 1
    }
    It 'Tier0-Admins + Protected Users only is not privileged' {
        Get-PrivilegedMembership -MemberOf @("CN=Tier0-Admins,OU=Groups,OU=Tier0,$($script:Domain)", "CN=Protected Users,CN=Users,$($script:Domain)") | Should -HaveCount 0
    }
    It 'defaults to the disposable accounts, not the real admins' {
        $src = Get-Content -Raw (Join-Path $script:Dir 'Test-TierLogon.ps1')
        $src | Should -Match "\`$T0User = 't0-tiertest'"
        $src | Should -Not -Match "'t0-adm-01'"
    }
}

Describe 'Join-Tier2Device.ps1: never the build admin' {
    It 'refuses <_>' -ForEach @('CORP\contosoadmin', 'contosoadmin@corp.contosohealthlab.com', 'CORP\Administrator') {
        { & (Join-Path $script:Dir 'Join-Tier2Device.ps1') -JoinUser $_ -JoinPassword 'Fake-Pass_1' } | Should -Throw '*REFUSED*'
    }
}

Describe 'New-TierTestAccounts.ps1 / Remove-TierTestAccounts.ps1 (DC01)' {
    BeforeEach {
        $global:DsaclsCalls = @()
        Mock Get-ADDomain { [pscustomobject]@{ DistinguishedName = 'DC=corp,DC=contosohealthlab,DC=com'; NetBIOSName = 'CORP'; DNSRoot = 'corp.contosohealthlab.com' } }
        Mock New-ADUser {}
        Mock Set-ADAccountControl {}
        Mock Add-ADGroupMember {}
        Mock Remove-ADUser {}
    }
    AfterAll { Remove-Variable -Name DsaclsCalls -Scope Global -ErrorAction SilentlyContinue }

    It 'makes the three accounts, each with an expiry, and never adds Domain Admins' {
        Mock Get-ADUser { }
        & (Join-Path $script:Dir 'New-TierTestAccounts.ps1') -T0Password 'Fake-T0_1a' -T2Password 'Fake-T2_1a' -JoinPassword 'Fake-J_1aa' | Out-Null
        Should -Invoke New-ADUser -Times 3
        Should -Invoke New-ADUser -Times 3 -ParameterFilter { $AccountExpirationDate -gt (Get-Date) -and $AccountExpirationDate -lt (Get-Date).AddHours(9) }
        Should -Invoke New-ADUser -Times 1 -ParameterFilter { $SamAccountName -eq 't0-tiertest' -and $Path -eq 'OU=Accounts,OU=Tier0,DC=corp,DC=contosohealthlab,DC=com' }
        Should -Invoke Add-ADGroupMember -Times 1 -ParameterFilter { $Identity -eq 'Tier0-Admins' -and $Members -contains 't0-tiertest' }
        Should -Invoke Add-ADGroupMember -Times 0 -ParameterFilter { $Identity -match 'Domain Admins|Enterprise Admins|Schema Admins|Administrators' }
        Should -Invoke Add-ADGroupMember -Times 0 -ParameterFilter { $Members -contains 'tiertest-join' }
    }

    It 'delegates join rights to tiertest-join on Tier2\Devices only' {
        Mock Get-ADUser { }
        & (Join-Path $script:Dir 'New-TierTestAccounts.ps1') -T0Password 'Fake-T0_1a' -T2Password 'Fake-T2_1a' -JoinPassword 'Fake-J_1aa' | Out-Null
        $global:DsaclsCalls | Should -HaveCount 5
        foreach ($c in $global:DsaclsCalls) {
            $c[0] | Should -Be 'OU=Devices,OU=Tier2,DC=corp,DC=contosohealthlab,DC=com'
            $c[3] | Should -Match '^CORP\\tiertest-join:'
        }
    }

    It 'refuses when an account already exists, and makes nothing' {
        Mock Get-ADUser { [pscustomobject]@{ DistinguishedName = 'CN=t0-tiertest,OU=Accounts,OU=Tier0,DC=corp,DC=contosohealthlab,DC=com' } } -ParameterFilter { $Filter -like "*'t0-tiertest'" }
        Mock Get-ADUser { } -ParameterFilter { $Filter -notlike "*'t0-tiertest'" }
        { & (Join-Path $script:Dir 'New-TierTestAccounts.ps1') -T0Password 'Fake-T0_1a' -T2Password 'Fake-T2_1a' -JoinPassword 'Fake-J_1aa' } | Should -Throw '*already exists*'
        Should -Invoke New-ADUser -Times 0
    }

    It 'a failed read stops New-TierTestAccounts (not "not there")' {
        Mock Get-ADUser { Write-Error 'The server is not operational' }
        { & (Join-Path $script:Dir 'New-TierTestAccounts.ps1') -T0Password 'Fake-T0_1a' -T2Password 'Fake-T2_1a' -JoinPassword 'Fake-J_1aa' } | Should -Throw '*not operational*'
        Should -Invoke New-ADUser -Times 0
    }

    It 'Remove: delegation first, then only the three accounts in their OUs' {
        Mock Get-ADUser { [pscustomobject]@{ DistinguishedName = "CN=$(($Filter -split "'")[1]),OU=Accounts,OU=$(if ($Filter -like '*t0-*') { 'Tier0' } else { 'Tier2' }),DC=corp,DC=contosohealthlab,DC=com" } }
        & (Join-Path $script:Dir 'Remove-TierTestAccounts.ps1') | Out-Null
        $global:DsaclsCalls | Should -HaveCount 1
        $global:DsaclsCalls[0][1] | Should -Be '/R'
        Should -Invoke Remove-ADUser -Times 3
    }

    It 'Remove refuses an account outside its expected OU' {
        Mock Get-ADUser { [pscustomobject]@{ DistinguishedName = "CN=t0-tiertest,OU=Accounts,OU=Tier2,DC=corp,DC=contosohealthlab,DC=com" } } -ParameterFilter { $Filter -like '*t0-tiertest*' }
        Mock Get-ADUser { } -ParameterFilter { $Filter -notlike '*t0-tiertest*' }
        { & (Join-Path $script:Dir 'Remove-TierTestAccounts.ps1') } | Should -Throw '*REFUSED*'
        Should -Invoke Remove-ADUser -Times 0
    }

    It 'a failed read stops Remove-TierTestAccounts' {
        Mock Get-ADUser { Write-Error 'The server is not operational' }
        { & (Join-Path $script:Dir 'Remove-TierTestAccounts.ps1') } | Should -Throw '*not operational*'
        Should -Invoke Remove-ADUser -Times 0
    }
}
