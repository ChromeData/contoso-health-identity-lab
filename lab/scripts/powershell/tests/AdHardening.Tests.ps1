# Pester 5 tests for ../../dc/hardening/*.ps1 - the DC01 AD hardening
# (admin tiering, Protected Users, deny-logon GPO, Windows LAPS, read-back).
# No domain controller: the scripts' helper functions are lifted out of each
# file with the PowerShell parser and tested on their own; the AD / GPO /
# LAPS cmdlets are never called. What is held:
#   * every .ps1 in lab/scripts/dc/hardening is ASCII only (Windows
#     PowerShell 5.1 reads a BOM-less file as ANSI, so one smart quote can
#     change what a script does);
#   * Protected Users never receives tier0-admin-01/02 or contosoadmin
#     (their remote-session path uses NTLM, which Protected Users blocks);
#   * the deny-logon template denies all five rights to every Tier 0 SID,
#     and the read-back check fails when one right or one SID is missing;
#   * a GPO version bump changes only the computer half;
#   * the LAPS GPOs write AD backup + encryption, and only the DC policy
#     backs up DSRM; the policy key is the Group Policy root, not Intune's;
#   * a dry run needs no secret; the sign-in proof never runs half;
#   * GPO link read-back fails on a missing, extra or disabled link;
#   * PingCastle always runs the exe from a fresh extract of the pinned zip.

BeforeDiscovery {
    $script:HardeningDir = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..' '..' 'dc' 'hardening'))
    $script:Files = @(Get-ChildItem -LiteralPath $script:HardeningDir -File -Filter '*.ps1' | ForEach-Object { @{ Name = $_.Name; Path = $_.FullName } })
    $script:Files += @{ Name = 'AdHardening.Tests.ps1'; Path = $PSCommandPath }
}

BeforeAll {
    $dir = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..' '..' 'dc' 'hardening'))
    function Import-ScriptFunction {
        # Defines the named functions from a script in the caller's scope,
        # without running the script body.
        param([string]$Path, [string[]]$Name)
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$null, [ref]$null)
        $defs = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $Name -contains $n.Name }, $true)
        if (@($defs).Count -ne $Name.Count) { throw "Expected $($Name -join ', ') in $Path" }
        return ($defs | ForEach-Object { $_.Extent.Text }) -join "`n"
    }
    $script:Tiering = Join-Path $dir 'Set-AdTiering.ps1'
    $script:Laps = Join-Path $dir 'Enable-WindowsLaps.ps1'
    $script:Check = Join-Path $dir 'Test-AdHardening.ps1'
    $script:PingCastle = Join-Path $dir 'Invoke-PingCastle.ps1'
    function New-GpoReport {
        # A Get-GPOReport -ReportType Xml shape: <GPO><LinksTo>... per link.
        param([object[]]$Links)
        $x = ($Links | ForEach-Object { "<LinksTo><SOMName>x</SOMName><SOMPath>$($_.Path)</SOMPath><Enabled>$($_.Enabled)</Enabled><NoOverride>false</NoOverride></LinksTo>" }) -join ''
        [xml]"<GPO>$x</GPO>"
    }
    . ([scriptblock]::Create((Import-ScriptFunction $script:Tiering 'Assert-ProtectedUsersScope', 'Assert-AccountPassword', 'New-DenyLogonInf', 'Get-NextGpoVersion')))
    . ([scriptblock]::Create((Import-ScriptFunction $script:Laps 'Get-LapsPolicyValues', 'Get-BlobFingerprint')))
    . ([scriptblock]::Create((Import-ScriptFunction $script:Check 'Test-InfDenyRights', 'Test-GpoLinks', 'Assert-SignInInputs')))
    # Script-scope values the lifted functions read (same literals as the scripts).
    $script:LegacyAdmins = @('tier0-admin-01', 'tier0-admin-02', 'contosoadmin')
    $script:DenyRights = @('SeDenyInteractiveLogonRight', 'SeDenyRemoteInteractiveLogonRight',
        'SeDenyNetworkLogonRight', 'SeDenyBatchLogonRight', 'SeDenyServiceLogonRight')
    $script:Sids = @('S-1-5-21-1-2-3-512', 'S-1-5-21-1-2-3-519', 'S-1-5-21-1-2-3-518', 'S-1-5-21-1-2-3-3602')
}

Describe 'hardening scripts are ASCII only' {
    It '<Name> has no byte above 0x7F' -ForEach $Files {
        $bytes = [System.IO.File]::ReadAllBytes($Path)
        $bad = @(for ($i = 0; $i -lt $bytes.Length; $i++) { if ($bytes[$i] -gt 0x7F) { $i } })
        $bad.Count | Should -Be 0 -Because "first non-ASCII byte at offset $($bad | Select-Object -First 1)"
    }

    It '<Name> parses without errors' -ForEach $Files {
        $errs = $null
        [void][System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$null, [ref]$errs)
        @($errs).Count | Should -Be 0
    }
}

Describe 'Protected Users scope (Set-AdTiering.ps1)' {
    It 'accepts the three new tiered admins' {
        $r = Assert-ProtectedUsersScope -Names @('t0-adm-01', 't1-adm-01', 't2-adm-01')
        ($r -join ',') | Should -Be 't0-adm-01,t1-adm-01,t2-adm-01'
    }

    It 'refuses <_> (NTLM remote-session path)' -ForEach @('tier0-admin-01', 'tier0-admin-02', 'contosoadmin', 'ContosoAdmin', 'TIER0-ADMIN-01') {
        { Assert-ProtectedUsersScope -Names @('t0-adm-01', $_) } | Should -Throw '*REFUSED*NTLM*'
    }

    It 'the script keeps the same refusal list it documents' {
        $text = Get-Content -LiteralPath $script:Tiering -Raw
        $text | Should -Match "\`$script:LegacyAdmins = @\('tier0-admin-01', 'tier0-admin-02', 'contosoadmin'\)"
        # The only call that adds to Protected Users passes the checked list.
        $adds = [regex]::Matches($text, "Add-ADGroupMember -Identity 'Protected Users' -Members (\S+)")
        $adds.Count | Should -Be 1
        $adds[0].Groups[1].Value | Should -Be '$targets'
        $text | Should -Match '\$targets = Assert-ProtectedUsersScope'
    }
}

Describe 'deny-logon template (Set-AdTiering.ps1 + Test-AdHardening.ps1)' {
    It 'denies all five rights to every Tier 0 SID' {
        $inf = New-DenyLogonInf -Sids $script:Sids
        foreach ($r in $script:DenyRights) { $inf | Should -Match "(?m)^$r = \*S-1-5-21-1-2-3-512,\*S-1-5-21-1-2-3-519,\*S-1-5-21-1-2-3-518,\*S-1-5-21-1-2-3-3602\r?$" }
        $inf | Should -Match '(?m)^\[Privilege Rights\]'
        $inf | Should -Match '(?m)^signature="\$CHICAGO\$"'
        Test-InfDenyRights -Inf $inf -Sids $script:Sids | Should -BeTrue
    }

    It 'refuses an empty SID list' {
        { New-DenyLogonInf -Sids @() } | Should -Throw
    }

    It 'the read-back fails when one right is missing' {
        $inf = (New-DenyLogonInf -Sids $script:Sids) -replace '(?m)^SeDenyNetworkLogonRight.*\r?\n', ''
        Test-InfDenyRights -Inf $inf -Sids $script:Sids | Should -BeFalse
    }

    It 'the read-back fails when one SID is missing' {
        $inf = New-DenyLogonInf -Sids $script:Sids[0..2]
        Test-InfDenyRights -Inf $inf -Sids $script:Sids | Should -BeFalse
    }

    It 'the GPO is linked only to the Tier 1 / Tier 2 computer OUs' {
        $text = Get-Content -LiteralPath $script:Tiering -Raw
        $text | Should -Match "foreach \(\`$target in \`$ou\['Tier1-Servers'\], \`$ou\['Tier2-Devices'\]\)"
        @([regex]::Matches($text, 'New-GPLink')).Count | Should -Be 1
    }
}

Describe 'GPO version bump (Set-AdTiering.ps1)' {
    It 'adds 1 to the computer half only: <In> -> <Out>' -ForEach @(
        @{ In = 0; Out = 1 }
        @{ In = 0x00030002; Out = 0x00030003 }
        @{ In = 0x0001FFFF; Out = 0x00010001 }
    ) {
        Get-NextGpoVersion -Current $In | Should -Be $Out
    }
}

Describe 'Windows LAPS policy (Enable-WindowsLaps.ps1)' {
    It 'DC policy: AD backup, encryption on, DSRM backup on' {
        $v = Get-LapsPolicyValues -Kind Dsrm
        $v.BackupDirectory | Should -Be 2
        $v.ADPasswordEncryptionEnabled | Should -Be 1
        $v.ADBackupDSRMPassword | Should -Be 1
        $v.PasswordComplexity | Should -Be 4
        $v.PasswordLength | Should -BeGreaterOrEqual 14
        $v.PasswordAgeDays | Should -BeIn (1..365)
    }

    It 'server policy: AD backup, encryption on, no DSRM switch' {
        $v = Get-LapsPolicyValues -Kind Server
        $v.BackupDirectory | Should -Be 2
        $v.ADPasswordEncryptionEnabled | Should -Be 1
        $v.Contains('ADBackupDSRMPassword') | Should -BeFalse
    }

    It 'writes the Group Policy root, not the Intune CSP root' {
        $text = Get-Content -LiteralPath $script:Laps -Raw
        $text | Should -Match "\`$script:GpRoot = 'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\LAPS'"
        $text | Should -Not -Match "-Key 'HKLM\\Software\\Microsoft\\Policies\\LAPS'"
    }

    It 'never decrypts or prints the password' {
        # Code only (the header comment tells a human how to read it).
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($script:Laps, [ref]$null, [ref]$null)
        $cmds = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true) | ForEach-Object { $_.GetCommandName() })
        $cmds | Should -Not -Contain 'Get-LapsADPassword'
        @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandParameterAst] -and $n.ParameterName -eq 'AsPlainText' }, $true)).Count | Should -Be 0
    }

    It 'the rotation fingerprint changes with the ciphertext and is short' {
        $a = Get-BlobFingerprint -Bytes ([byte[]](1, 2, 3))
        $b = Get-BlobFingerprint -Bytes ([byte[]](1, 2, 4))
        $a | Should -Match '^[0-9a-f]{12}$'
        $a | Should -Not -Be $b
        Get-BlobFingerprint -Bytes ([byte[]]@()) | Should -Be 'none'
    }
}

Describe 'dry run needs no secret (Set-AdTiering.ps1)' {
    It 'a dry run with no password does not throw' {
        { Assert-AccountPassword -DoApply $false -Sam 't0-adm-01' -Password '' } | Should -Not -Throw
    }

    It 'an apply with no password throws before creating the account' {
        { Assert-AccountPassword -DoApply $true -Sam 't0-adm-01' -Password '' } | Should -Throw '*No password parameter for t0-adm-01*'
    }

    It 'an apply with a password does not throw' {
        { Assert-AccountPassword -DoApply $true -Sam 't0-adm-01' -Password 'x' } | Should -Not -Throw
    }
}

Describe 'GPO link read-back (Test-AdHardening.ps1)' {
    BeforeAll { $script:Want = @('corp.example/Tier1/Servers', 'corp.example/Tier2/Devices') }

    It 'passes on exactly the expected enabled links' {
        $r = New-GpoReport @(@{ Path = 'corp.example/Tier1/Servers'; Enabled = 'true' }, @{ Path = 'corp.example/Tier2/Devices'; Enabled = 'true' })
        (Test-GpoLinks -Report $r -Expected $script:Want).Ok | Should -BeTrue
    }

    It 'fails when a link is missing' {
        $r = New-GpoReport @(@{ Path = 'corp.example/Tier1/Servers'; Enabled = 'true' })
        $res = Test-GpoLinks -Report $r -Expected $script:Want
        $res.Ok | Should -BeFalse
        $res.Detail | Should -Match 'missing: corp.example/Tier2/Devices'
    }

    It 'fails when there is no link at all' {
        (Test-GpoLinks -Report ([xml]'<GPO></GPO>') -Expected $script:Want).Ok | Should -BeFalse
    }

    It 'fails on an extra link (for example the domain root)' {
        $r = New-GpoReport @(@{ Path = 'corp.example/Tier1/Servers'; Enabled = 'true' }, @{ Path = 'corp.example/Tier2/Devices'; Enabled = 'true' }, @{ Path = 'corp.example'; Enabled = 'true' })
        $res = Test-GpoLinks -Report $r -Expected $script:Want
        $res.Ok | Should -BeFalse
        $res.Detail | Should -Match 'extra: corp.example$'
    }

    It 'fails when an expected link is disabled' {
        $r = New-GpoReport @(@{ Path = 'corp.example/Tier1/Servers'; Enabled = 'false' }, @{ Path = 'corp.example/Tier2/Devices'; Enabled = 'true' })
        $res = Test-GpoLinks -Report $r -Expected $script:Want
        $res.Ok | Should -BeFalse
        $res.Detail | Should -Match 'disabled: corp.example/Tier1/Servers'
    }

    It 'the check script reads links and the server decryptor for both LAPS GPOs' {
        $text = Get-Content -LiteralPath $script:Check -Raw
        $text | Should -Match 'Link = "\$\(\$domain.DNSRoot\)/Domain Controllers"'
        $text | Should -Match 'Link = "\$\(\$domain.DNSRoot\)/Tier1/Servers"; Reader = "\$\(\$domain.NetBIOSName\)\\Tier1-Admins"'
        $text | Should -Match "-ValueName ADPasswordEncryptionPrincipal"
    }
}

Describe 'sign-in proof never runs half (Test-AdHardening.ps1)' {
    It 'SignIn=yes without T2Password stops' {
        { Assert-SignInInputs -SignIn 'yes' -T2Password '' } | Should -Throw '*needs T2Password*'
    }

    It 'SignIn=yes with T2Password runs' {
        { Assert-SignInInputs -SignIn 'yes' -T2Password 'x' } | Should -Not -Throw
    }

    It 'no sign-in proof needs no password' {
        { Assert-SignInInputs -SignIn 'no' -T2Password '' } | Should -Not -Throw
    }

    It 'the guard runs before any AD module or object work' {
        $text = Get-Content -LiteralPath $script:Check -Raw
        $text.IndexOf('Assert-SignInInputs -SignIn $SignIn') | Should -BeLessThan $text.IndexOf('Import-Module ActiveDirectory')
        $text.IndexOf('Assert-SignInInputs -SignIn $SignIn') | Should -BeGreaterThan 0
    }
}

Describe 'PingCastle runs only what the pinned zip holds (Invoke-PingCastle.ps1)' {
    It 'never reuses an extracted folder: it deletes it and extracts again' {
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($script:PingCastle, [ref]$null, [ref]$null)
        $expand = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq 'Expand-Archive' }, $true))
        $expand.Count | Should -Be 1
        # Expand-Archive is a top-level statement, not inside an if (not behind a "folder exists" guard).
        $p = $expand[0].Parent; while ($p -and $p -isnot [System.Management.Automation.Language.IfStatementAst] -and $p -isnot [System.Management.Automation.Language.ScriptBlockAst]) { $p = $p.Parent }
        $p | Should -BeOfType ([System.Management.Automation.Language.ScriptBlockAst])
        $text = Get-Content -LiteralPath $script:PingCastle -Raw
        $text | Should -Match 'if \(Test-Path -LiteralPath \$Bin\) \{ Remove-Item -LiteralPath \$Bin -Recurse -Force \}'
        $text.IndexOf('Remove-Item -LiteralPath $Bin') | Should -BeLessThan $text.IndexOf('Expand-Archive')
        $text.IndexOf('Get-FileHash') | Should -BeLessThan $text.IndexOf('Expand-Archive')
    }
}
