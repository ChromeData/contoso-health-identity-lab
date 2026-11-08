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
}

# Runs the WHOLE script with every DC cmdlet mocked (Greptile, PR #260): a
# failed proof must make -Apply yes throw BEFORE the first removal command,
# and -Force yes must still go through.
Describe '19-Remove-Adfs.ps1 -Apply yes stops on a failed proof (script run, cmdlets mocked)' {
    BeforeAll {
        $script:Script = Join-Path $PSScriptRoot '../scripts/19-Remove-Adfs.ps1'
        # Stubs so Mock has a target on Linux/macOS pwsh (no AD, AD FS, DNS or
        # Windows event log modules there). auditpol.exe: a function wins over
        # the native command.
        # Stubs with the parameters the script passes, so Mock has a target
        # and the mocks see them.
        $stubs = @{
            'Get-ADDomain'                   = 'param()'
            'Get-WinEvent'                   = 'param([hashtable]$FilterHashtable, [string]$LogName, [switch]$Oldest, [int]$MaxEvents)'
            'Get-AdfsRelyingPartyTrust'      = 'param([string]$Identifier)'
            'Disable-AdfsRelyingPartyTrust'  = 'param([string]$TargetIdentifier)'
            'Remove-AdfsRelyingPartyTrust'   = 'param([string]$TargetIdentifier)'
            'Get-ADObject'                   = 'param([string]$Filter)'
            'Get-ADServiceAccount'           = 'param([string]$Filter)'
            'Remove-ADObject'                = 'param($Identity, [switch]$Recursive, [switch]$Confirm)'
            'Remove-ADServiceAccount'        = 'param($Identity, [switch]$Confirm)'
            'Get-WindowsFeature'             = 'param([string]$Name)'
            'Uninstall-WindowsFeature'       = 'param([string]$Name, [switch]$IncludeManagementTools)'
            'Get-DnsServerResourceRecord'    = 'param([string]$ZoneName, [string]$Name, [string]$RRType)'
            'Remove-DnsServerResourceRecord' = 'param([string]$ZoneName, [switch]$Force, [Parameter(ValueFromPipeline)]$InputObject)'
            'Get-Service'                    = 'param([string[]]$Name)'
            'auditpol.exe'                   = 'param([Parameter(ValueFromRemainingArguments)]$Rest)'
        }
        foreach ($n in $stubs.Keys) {
            if (-not (Get-Command $n -CommandType Cmdlet, Function -ErrorAction SilentlyContinue)) {
                $body = if ($n -eq 'auditpol.exe') { $stubs[$n] } else { "[CmdletBinding()] $($stubs[$n])" }
                Set-Item -Path "function:global:$n" -Value ([scriptblock]::Create($body))
            }
        }
    }

    BeforeEach {
        $global:AdfsTestNewestAudit = (Get-Date).AddMinutes(-10)
        Mock Import-Module {}
        Mock Write-Output {}
        Mock Get-ADDomain { [pscustomobject]@{ DistinguishedName = 'DC=corp,DC=example,DC=test' } }
        Mock Get-Service { if ($Name -contains 'adfssrv') { [pscustomobject]@{ Name = 'adfssrv' } } }
        Mock Get-WinEvent {
            if ($Oldest) { return [pscustomobject]@{ TimeCreated = (Get-Date).AddDays(-30) } }
            if ($FilterHashtable -and $FilterHashtable.ContainsKey('StartTime')) { return @() }   # no app sign-ins
            if ($null -eq $global:AdfsTestNewestAudit) {
                $e = [System.Exception]::new('No events were found that match the specified selection criteria.')
                throw [System.Management.Automation.ErrorRecord]::new($e, 'NoMatchingEventsFound,Microsoft.PowerShell.Commands.GetWinEventCommand', 'ObjectNotFound', $null)
            }
            [pscustomobject]@{ TimeCreated = $global:AdfsTestNewestAudit }
        }
        Mock Get-AdfsRelyingPartyTrust { [pscustomobject]@{ Identifier = 'urn:contoso:claims-viewer' } }
        Mock Disable-AdfsRelyingPartyTrust {}
        Mock Remove-AdfsRelyingPartyTrust {}
        Mock Get-ADObject { $null }
        Mock Get-ADServiceAccount { $null }
        Mock Remove-ADObject {}
        Mock Remove-ADServiceAccount {}
        Mock Get-ChildItem { @() }
        Mock Get-WindowsFeature { [pscustomobject]@{ Installed = $false } }
        Mock Uninstall-WindowsFeature {}
        Mock Get-DnsServerResourceRecord { $null }
        Mock Remove-DnsServerResourceRecord {}
        Mock auditpol.exe {}
    }

    It 'an OLD audit: -Apply yes throws and removes nothing' {
        $global:AdfsTestNewestAudit = (Get-Date).AddDays(-3)
        { & $script:Script -DomainName corp.example.test -Apply yes } | Should -Throw '*Cannot prove the quiet period*older than 2 h*'
        Should -Invoke Disable-AdfsRelyingPartyTrust -Times 0 -Exactly
        Should -Invoke Remove-AdfsRelyingPartyTrust -Times 0 -Exactly
        Should -Invoke auditpol.exe -Times 0 -Exactly
    }

    It 'NO audit at all: -Apply yes throws and removes nothing' {
        $global:AdfsTestNewestAudit = $null
        { & $script:Script -DomainName corp.example.test -Apply yes } | Should -Throw '*no AD FS audit*'
        Should -Invoke Disable-AdfsRelyingPartyTrust -Times 0 -Exactly
    }

    It 'a FRESH audit and no app sign-ins: -Apply yes goes ahead' {
        { & $script:Script -DomainName corp.example.test -Apply yes } | Should -Not -Throw
        Should -Invoke Disable-AdfsRelyingPartyTrust -Times 1 -Exactly
    }

    It '-Force yes still overrides an old audit (the documented escape hatch)' {
        $global:AdfsTestNewestAudit = (Get-Date).AddDays(-3)
        { & $script:Script -DomainName corp.example.test -Apply yes -Force yes } | Should -Not -Throw
        Should -Invoke Disable-AdfsRelyingPartyTrust -Times 1 -Exactly
    }

    It 'report only (no -Apply) never throws and never removes, even with an old audit' {
        $global:AdfsTestNewestAudit = (Get-Date).AddDays(-3)
        { & $script:Script -DomainName corp.example.test } | Should -Not -Throw
        Should -Invoke Disable-AdfsRelyingPartyTrust -Times 0 -Exactly
    }
}
