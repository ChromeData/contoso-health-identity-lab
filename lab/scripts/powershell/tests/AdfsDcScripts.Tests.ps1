# Pester 5 tests for two DC01 scripts of the AD FS -> Entra migration
# (lab/adfs/scripts, README steps 3b and 5b). No domain controller, no agent:
# the ActiveDirectory cmdlets, secedit.exe, gpupdate.exe, the service
# cmdlets and the Connect Health agent cmdlets are stubs defined here and
# answered from one fake state ($global:AdfsFake).
# What is held:
#   10b-Set-AdfsAuditRight.ps1
#     * a re-run after a half-done Grant (template written, AD or GPT.INI
#       version not) REPAIRS it: version bumped in both halves, gpupdate run,
#       right read back. The template line alone is not proof;
#     * a finished Grant re-run changes nothing;
#     * Revoke works after the gMSA is deleted only with -GmsaSid, and stops
#       without it; -GmsaSid is refused for Grant.
#   12b-Register-ConnectHealthAgent.ps1
#     * it reports registered only when the agent log has no failed
#       registration, the TenantId marker is saved and the service runs;
#     * the DC01 failure shape (evidence 05d: "Configuration Failed", exit 0)
#       makes it THROW, so register.sh close never follows a false success.

BeforeAll {
    $adfs = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..' '..' '..' 'adfs' 'scripts'))
    $script:AuditRight = Join-Path $adfs '10b-Set-AdfsAuditRight.ps1'
    $script:Register = Join-Path $adfs '12b-Register-ConnectHealthAgent.ps1'

    # Stand-ins for Windows-only commands (absent on the Linux / macOS runner).
    # Global so the script under test sees them. (Set-Item, not
    # `function global:`: PSScriptAnalyzer 1.25 crashes on those.)
    foreach ($n in 'Get-CimInstance', 'Get-Service', 'Restart-Service') {
        if (-not (Get-Command $n -ErrorAction SilentlyContinue)) { Set-Item -Path "function:global:$n" -Value { param() } }
    }
    Set-Item -Path function:global:Get-ADDomain -Value { param() }
    Set-Item -Path function:global:Get-ADServiceAccount -Value { param([string]$Identity) $null = $Identity }
    Set-Item -Path function:global:Get-ADObject -Value { param([string]$Identity, [string[]]$Properties) $null = $Identity, $Properties }
    Set-Item -Path function:global:Set-ADObject -Value { param([string]$Identity, [hashtable]$Replace) $null = $Identity, $Replace }
    # secedit /export /areas USER_RIGHTS /cfg <file>: writes what DC01 enforces now.
    Set-Item -Path function:global:secedit.exe -Value {
        $cfg = $args[[array]::IndexOf($args, '/cfg') + 1]
        Set-Content -LiteralPath $cfg -Value @('[Privilege Rights]', $global:AdfsFake.Effective)
    }
    # gpupdate: DC01 applies the template only when the AD and SYSVOL
    # versions agree and moved since the last apply (how a GPO refresh works).
    $script:DefaultGpupdate = {
        $f = $global:AdfsFake
        $f.GpupdateCalls++
        $ini = [regex]::Match([IO.File]::ReadAllText($f.Ini), 'Version=(\d+)').Groups[1].Value
        if ([long]$ini -eq $f.AdVersion -and $f.AdVersion -ne $f.AppliedVersion) {
            $f.Effective = ([IO.File]::ReadAllText($f.Inf) -split "`r`n" | Where-Object { $_ -like 'SeAuditPrivilege*' }) -replace '\*S-1-5-21-1-2-3-4101', 'gmsa-adfs$'
            $f.AppliedVersion = $f.AdVersion
        }
    }
    Set-Item -Path function:global:gpupdate.exe -Value $script:DefaultGpupdate
    Set-Item -Path function:global:Register-MicrosoftEntraConnectHealthAgent -Value { param([securestring]$AadToken, [string]$LogFilePath) $null = $AadToken, $LogFilePath }
    Set-Item -Path function:global:Test-MicrosoftEntraConnectHealthConnectivity -Value { param([string]$Role) $null = $Role }

    $script:Sid = 'S-1-5-21-1-2-3-4101'
    $script:Cse = '[{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}]'
    $script:BaseLine = 'SeAuditPrivilege = *S-1-5-19,*S-1-5-20'

    function New-FakeDc {
        # A SYSVOL tree in TestDrive with the Default Domain Controllers
        # Policy template (UTF-16, as on DC01) and GPT.INI.
        param([string]$TemplateLine, [long]$AdVersion, [long]$IniVersion, [string]$Effective, [bool]$Cse = $true)
        $sysvol = Join-Path $TestDrive ('sysvol-{0}' -f [guid]::NewGuid())
        $gpt = Join-Path $sysvol 'corp.contosohealthlab.com\Policies\{6AC1786C-016F-11D2-945F-00C04FB984F9}'
        $inf = Join-Path $gpt 'Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf'
        New-Item -ItemType Directory -Path (Split-Path $inf) -Force | Out-Null
        [IO.File]::WriteAllText($inf, (@('[Unicode]', 'Unicode=yes', '[Privilege Rights]', $TemplateLine, 'SeBackupPrivilege = *S-1-5-32-544') -join "`r`n"), [Text.Encoding]::Unicode)
        $ini = Join-Path $gpt 'GPT.INI'
        [IO.File]::WriteAllText($ini, "[General]`r`nVersion=$IniVersion`r`n", [Text.Encoding]::ASCII)
        $global:AdfsFake = @{
            SysVol = $sysvol; Inf = $inf; Ini = $ini
            AdVersion = $AdVersion; AppliedVersion = $IniVersion
            CseNames = if ($Cse) { $script:Cse } else { '' }
            Effective = $Effective; GpupdateCalls = 0; SetAdCalls = 0; Restarts = 0
        }
    }
}

AfterAll {
    Remove-Variable -Name AdfsFake -Scope Global -ErrorAction SilentlyContinue
}

Describe '10b-Set-AdfsAuditRight.ps1 (runs on DC01 via run-on-dc.py)' {
    BeforeEach {
        $env:TEMP = $TestDrive
        Set-Item -Path function:global:gpupdate.exe -Value $script:DefaultGpupdate   # a test may replace it
        Mock Get-CimInstance { [pscustomobject]@{ DomainRole = 5 } }
        Mock Get-ADDomain { [pscustomobject]@{ DistinguishedName = 'DC=corp,DC=contosohealthlab,DC=com'; DNSRoot = 'corp.contosohealthlab.com'; NetBIOSName = 'CORP' } }
        Mock Get-ADServiceAccount { [pscustomobject]@{ SID = [pscustomobject]@{ Value = 'S-1-5-21-1-2-3-4101' } } }
        Mock Get-ItemProperty { [pscustomobject]@{ SysVol = $global:AdfsFake.SysVol } }   # the only registry read: Netlogon\Parameters
        Mock Get-ADObject { [pscustomobject]@{ versionNumber = $global:AdfsFake.AdVersion; gPCMachineExtensionNames = $global:AdfsFake.CseNames } }
        Mock Set-ADObject { $global:AdfsFake.SetAdCalls++; $global:AdfsFake.AdVersion = [long]$Replace.versionNumber; $global:AdfsFake.CseNames = $Replace.gPCMachineExtensionNames }
        Mock Restart-Service { $global:AdfsFake.Restarts++ }
    }

    It 'a first Grant writes the template, bumps both versions, runs gpupdate and reads the right back' {
        New-FakeDc -TemplateLine $script:BaseLine -AdVersion 7 -IniVersion 7 -Effective $script:BaseLine
        $out = (& $script:AuditRight -Mode Grant | Out-String) | ConvertFrom-Json
        $out.changed | Should -BeTrue
        $out.repaired | Should -BeFalse
        $global:AdfsFake.AdVersion | Should -Be 8
        [IO.File]::ReadAllText($global:AdfsFake.Ini) | Should -Match 'Version=8'
        $global:AdfsFake.Effective | Should -Match 'gmsa-adfs\$'
    }

    It 'REPAIRS a half-done Grant: template written, AD and GPT.INI not (the run stopped after the template)' {
        New-FakeDc -TemplateLine "$($script:BaseLine),*$($script:Sid)" -AdVersion 7 -IniVersion 7 -Effective $script:BaseLine
        $text = & $script:AuditRight -Mode Grant | Out-String
        $out = ($text.Substring($text.IndexOf('{'))) | ConvertFrom-Json
        $out.changed | Should -BeTrue
        $out.repaired | Should -BeTrue
        $global:AdfsFake.SetAdCalls | Should -Be 1
        $global:AdfsFake.AdVersion | Should -Be 8
        [IO.File]::ReadAllText($global:AdfsFake.Ini) | Should -Match 'Version=8'
        $global:AdfsFake.GpupdateCalls | Should -Be 1
        $out.effectiveOnDc01 | Should -Match 'gmsa-adfs\$'
        $text | Should -Match 'change is unfinished'
    }

    It 'REPAIRS a Grant whose AD write landed but GPT.INI did not (versions disagree), moving forward only' {
        New-FakeDc -TemplateLine "$($script:BaseLine),*$($script:Sid)" -AdVersion 8 -IniVersion 7 -Effective $script:BaseLine
        $text = & $script:AuditRight -Mode Grant | Out-String
        $out = ($text.Substring($text.IndexOf('{'))) | ConvertFrom-Json
        $out.repaired | Should -BeTrue
        $out.versionNumber | Should -Be 9
        [IO.File]::ReadAllText($global:AdfsFake.Ini) | Should -Match 'Version=9'
    }

    It 'REPAIRS a missing security extension even when DC01 already enforces the right' {
        New-FakeDc -TemplateLine "$($script:BaseLine),*$($script:Sid)" -AdVersion 7 -IniVersion 7 -Effective "$($script:BaseLine),gmsa-adfs`$" -Cse $false
        $text = & $script:AuditRight -Mode Grant | Out-String
        $global:AdfsFake.SetAdCalls | Should -Be 1
        $global:AdfsFake.CseNames | Should -Be $script:Cse
        $text | Should -Match '"repaired":\s+true'
    }

    It 'a finished Grant re-run changes nothing (holds: true)' {
        New-FakeDc -TemplateLine "$($script:BaseLine),*$($script:Sid)" -AdVersion 8 -IniVersion 8 -Effective "$($script:BaseLine),gmsa-adfs`$"
        $out = (& $script:AuditRight -Mode Grant | Out-String) | ConvertFrom-Json
        $out.changed | Should -BeFalse
        $out.holds | Should -BeTrue
        $global:AdfsFake.SetAdCalls | Should -Be 0
        $global:AdfsFake.GpupdateCalls | Should -Be 0
    }

    It 'a failed read-back still throws (the repair does not hide a right that will not apply)' {
        New-FakeDc -TemplateLine "$($script:BaseLine),*$($script:Sid)" -AdVersion 7 -IniVersion 7 -Effective $script:BaseLine
        Set-Item -Path function:global:gpupdate.exe -Value { $global:AdfsFake.GpupdateCalls++ }   # policy never applies
        { & $script:AuditRight -Mode Grant | Out-Null } | Should -Throw '*Read-back mismatch*'
    }

    It 'Revoke after the gMSA is deleted works with -GmsaSid' {
        New-FakeDc -TemplateLine "$($script:BaseLine),*$($script:Sid)" -AdVersion 8 -IniVersion 8 -Effective "$($script:BaseLine),gmsa-adfs`$"
        Mock Get-ADServiceAccount { throw 'Cannot find an object with identity: gmsa-adfs' }
        $out = (& $script:AuditRight -Mode Revoke -GmsaSid $script:Sid | Out-String) | ConvertFrom-Json
        $out.changed | Should -BeTrue
        $out.lineAfter | Should -Be $script:BaseLine
        Should -Invoke Get-ADServiceAccount -Times 0
    }

    It 'Revoke after the gMSA is deleted stops without -GmsaSid (it cannot know which SID to remove)' {
        New-FakeDc -TemplateLine "$($script:BaseLine),*$($script:Sid)" -AdVersion 8 -IniVersion 8 -Effective "$($script:BaseLine),gmsa-adfs`$"
        Mock Get-ADServiceAccount { throw 'Cannot find an object with identity: gmsa-adfs' }
        { & $script:AuditRight -Mode Revoke | Out-Null } | Should -Throw '*Cannot find*'
        $global:AdfsFake.SetAdCalls | Should -Be 0
    }

    It 'refuses -GmsaSid with Grant (Grant must resolve the live account)' {
        New-FakeDc -TemplateLine $script:BaseLine -AdVersion 7 -IniVersion 7 -Effective $script:BaseLine
        { & $script:AuditRight -Mode Grant -GmsaSid $script:Sid | Out-Null } | Should -Throw '*for Revoke*'
    }
}

Describe '12b-Register-ConnectHealthAgent.ps1 (runs on DC01 via run-on-dc.py)' {
    BeforeEach {
        $env:ProgramData = $TestDrive
        $global:AdfsFake = @{ Registered = $false; ServiceAfter = 'Running'; Saves = $true; Log = 'Result=started;type=registration' }
        # Every mock has a default (no filter): Pester 6 does not fall through
        # to the real command when no filter matches.
        Mock Test-Path { $true }   # the agent module folder (the log is read with [IO.File])
        Mock Import-Module {}
        Mock Start-Sleep {}
        Mock Test-MicrosoftEntraConnectHealthConnectivity { 'Test passed' }
        Mock Get-Service { [pscustomobject]@{ Status = if ($global:AdfsFake.Registered) { $global:AdfsFake.ServiceAfter } else { 'Stopped' } } }
        Mock Get-ItemProperty {
            if ($global:AdfsFake.Registered -and $global:AdfsFake.Saves) { [pscustomobject]@{ TenantId = '86a2e327-4951-4348-a3c4-6f4b79ffd8f2' } }
            else { [pscustomobject]@{ Version = '4.5.2487.0' } }
        }
        Mock Register-MicrosoftEntraConnectHealthAgent {
            Set-Content -LiteralPath $LogFilePath -Value $global:AdfsFake.Log
            $global:AdfsFake.Registered = $true
        }
    }

    It 'reports registered when the log is clean, the TenantId marker is saved and the service runs' {
        $text = & $script:Register -AgentToken 'not-a-real-token' -WaitSeconds 0 | Out-String
        $out = ($text.Substring($text.IndexOf('{'))) | ConvertFrom-Json
        $out.registered | Should -BeTrue
        $out.service | Should -Be 'Running'
        $out.tenantId | Should -Be '86a2e327-4951-4348-a3c4-6f4b79ffd8f2'
        $text | Should -Not -Match 'not-a-real-token'
    }

    It 'THROWS on the DC01 failure shape (evidence 05d): failed log line, no marker, service Stopped, cmdlet returned normally' {
        $global:AdfsFake.Log = "UploadLogFileFromDisk: ...;Result=failed;type=registration;activityId=x"
        $global:AdfsFake.Saves = $false
        $global:AdfsFake.ServiceAfter = 'Stopped'
        { & $script:Register -AgentToken 'not-a-real-token' -WaitSeconds 0 | Out-Null } | Should -Throw '*NOT verified*Result=failed*'
    }

    It 'THROWS when the cmdlet prints "Configuration Failed" even if the service runs' {
        Mock Register-MicrosoftEntraConnectHealthAgent {
            Set-Content -LiteralPath $LogFilePath -Value 'Result=started;type=registration'
            $global:AdfsFake.Registered = $true
            'Configuration Failed'
        }
        { & $script:Register -AgentToken 'not-a-real-token' -WaitSeconds 0 | Out-Null } | Should -Throw '*Configuration Failed*'
    }

    It 'THROWS when the agent saved no registration (no TenantId)' {
        $global:AdfsFake.Saves = $false
        { & $script:Register -AgentToken 'not-a-real-token' -WaitSeconds 0 | Out-Null } | Should -Throw '*no TenantId*'
    }

    It 'THROWS when the service does not reach Running' {
        $global:AdfsFake.ServiceAfter = 'Stopped'
        { & $script:Register -AgentToken 'not-a-real-token' -WaitSeconds 0 | Out-Null } | Should -Throw '*is Stopped, not Running*'
    }

    It 'refuses to register again when the agent is already registered and running' {
        $global:AdfsFake.Registered = $true
        { & $script:Register -AgentToken 'not-a-real-token' -WaitSeconds 0 | Out-Null } | Should -Throw '*Refusing to register again*'
        Should -Invoke Register-MicrosoftEntraConnectHealthAgent -Times 0
    }
}
