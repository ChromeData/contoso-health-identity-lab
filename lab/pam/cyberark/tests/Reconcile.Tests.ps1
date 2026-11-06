<#
  Contract tests for Invoke-SafeReconcile.ps1 and New-LabSafe.ps1 against the
  stub vault (tests/stubs/psPAS). The scripts run UNMODIFIED in a child pwsh
  (they call exit) with the stub first on PSModulePath.

  These prove the drift logic, the fail-closed reads and what -Apply writes,
  against psPAS 8.2.0's parameter names. They are NOT evidence the scripts
  work against a CyberArk vault; the lab has none.

  Ported from the earlier psPAS-PAM-Automation lab. Tests marked NEW were
  added while porting; each fails against that lab's scripts (see the PR).
#>

BeforeAll {
    $script:Root = Split-Path -Parent $PSScriptRoot
    $script:Reconcile = Join-Path $Root 'Invoke-SafeReconcile.ps1'
    $script:NewSafe = Join-Path $Root 'New-LabSafe.ps1'
    $script:Stubs = Join-Path $PSScriptRoot 'stubs'
    Import-Module (Join-Path $Root 'RoleMap.psm1') -Force

    # Live permission objects are built from RoleMap itself, so the tests can
    # never describe a permission set the module no longer has.
    function Get-RolePerm([string]$Role) { [pscustomobject](Get-LabRolePermission -Role $Role) }

    function New-TempFile([string]$Ext, [string]$Text) {
        $p = Join-Path ([IO.Path]::GetTempPath()) "safe-reconcile-$([guid]::NewGuid())$Ext"
        Set-Content -LiteralPath $p -Value $Text -Encoding utf8
        $p
    }
    function New-State($Object) { New-TempFile '.json' ($Object | ConvertTo-Json -Depth 8) }
    function New-Tenant([hashtable]$Tenant) { New-TempFile '.json' ($Tenant | ConvertTo-Json -Depth 8) }

    function Invoke-Script {
        param([string]$Path, [string]$StatePath, [string]$TenantPath, [string[]]$ExtraArgs = @())
        $json = Join-Path ([IO.Path]::GetTempPath()) "drift-$([guid]::NewGuid()).json"
        $writes = New-TempFile '.jsonl' ''
        $argText = ($ExtraArgs -join ' ')
        $jsonArg = if ($Path -eq $Reconcile) { "-JsonPath '$json'" } else { '' }
        $cmd = @"
`$env:PSModulePath = '$Stubs' + [IO.Path]::PathSeparator + `$env:PSModulePath
`$env:STUB_TENANT = '$TenantPath'
`$env:STUB_WRITES = '$writes'
& '$Path' -IntendedStatePath '$StatePath' $jsonArg $argText
exit `$LASTEXITCODE
"@
        $out = pwsh -NoProfile -NonInteractive -Command $cmd 2>&1
        $code = $LASTEXITCODE
        [pscustomobject]@{
            ExitCode = $code
            Output   = ($out -join "`n")
            Report   = if (Test-Path -LiteralPath $json) { Get-Content -Raw -LiteralPath $json | ConvertFrom-Json } else { $null }
            Writes   = @(Get-Content -LiteralPath $writes | Where-Object { $_ } | ForEach-Object { $_ | ConvertFrom-Json -AsHashtable })
        }
    }

    $script:BaseState = @{
        safes    = @(@{
                name = 'CH-Tier0-Admins'; description = 'Tier-0'; managingCPM = 'PasswordManager'
                members = @(@{ name = 'CH-PAM-Admins'; role = 'full' }, @{ name = 'CH-PAM-Auditors'; role = 'audit' })
            })
        accounts = @(@{ safe = 'CH-Tier0-Admins'; platformId = 'WinDomain'; address = 'corp.test.local'; userName = 'tier0-admin-01' })
    }
    function Get-InSyncTenant {
        @{
            safes    = @(@{ safeName = 'CH-Tier0-Admins' })
            members  = @{ 'CH-Tier0-Admins' = @(
                    @{ MemberName = 'CH-PAM-Admins'; Permissions = (Get-RolePerm full) },
                    @{ MemberName = 'CH-PAM-Auditors'; Permissions = (Get-RolePerm audit) }) }
            accounts = @(@{ safeName = 'CH-Tier0-Admins'; userName = 'tier0-admin-01'; address = 'corp.test.local'; platformId = 'WinDomain' })
        }
    }
    $script:EmptyTenant = @{ safes = @(); members = @{}; accounts = @() }
}

Describe 'Drift classification' {
    It 'reports no drift when the vault matches the state file' {
        $r = Invoke-Script $Reconcile (New-State $BaseState) (New-Tenant (Get-InSyncTenant))
        $r.Report.driftCount | Should -Be 0
        $r.ExitCode | Should -Be 0
    }
    It 'flags a member nobody declared as UNEXPECTED' {
        $t = Get-InSyncTenant
        $t.members['CH-Tier0-Admins'] += @{ MemberName = 'mystery-contractor'; Permissions = (Get-RolePerm full) }
        $r = Invoke-Script $Reconcile (New-State $BaseState) (New-Tenant $t)
        $u = @($r.Report.drift | Where-Object Issue -EQ 'UNEXPECTED')
        $u.Count | Should -Be 1
        $u[0].Name | Should -BeLike '*mystery-contractor'
        $r.ExitCode | Should -Be 1
    }
    It 'flags a declared member holding more than their role as EXTRA_PERM' {
        $t = Get-InSyncTenant
        $over = Get-RolePerm audit
        $over | Add-Member -NotePropertyName RetrieveAccounts -NotePropertyValue $true
        $t.members['CH-Tier0-Admins'][1].Permissions = $over
        $r = Invoke-Script $Reconcile (New-State $BaseState) (New-Tenant $t)
        @($r.Report.drift | Where-Object { $_.Issue -eq 'EXTRA_PERM' -and $_.Detail -eq 'RetrieveAccounts' }).Count | Should -Be 1
    }
    It 'NEW: a safe the vault reports 404 is MISSING, and its members are not evaluated' {
        # psPAS THROWS for a missing safe; the old stub returned $null instead.
        $r = Invoke-Script $Reconcile (New-State $BaseState) (New-Tenant $EmptyTenant)
        $r.ExitCode | Should -Be 1
        @($r.Report.drift | Where-Object { $_.Type -eq 'Safe' -and $_.Issue -eq 'MISSING' }).Count | Should -Be 1
        @($r.Report.drift | Where-Object Type -EQ 'Permission').Count | Should -Be 0
    }
    It 'flags an account on the wrong platform' {
        $t = Get-InSyncTenant
        $t.accounts[0].platformId = 'UnixSSH'
        $r = Invoke-Script $Reconcile (New-State $BaseState) (New-Tenant $t)
        @($r.Report.drift | Where-Object Issue -EQ 'WRONG_PLATFORM').Count | Should -Be 1
    }
    It 'NEW: flags the same account twice in a safe as DUPLICATE' {
        $t = Get-InSyncTenant
        $t.accounts += $t.accounts[0].Clone()
        $r = Invoke-Script $Reconcile (New-State $BaseState) (New-Tenant $t)
        @($r.Report.drift | Where-Object Issue -EQ 'DUPLICATE').Count | Should -Be 1
    }
}

Describe 'Fails closed: a failed read stops the run (NEW)' {
    It 'stops with exit 2 when a safe lookup fails with anything but 404' {
        $t = Get-InSyncTenant; $t.fail = @{ 'Get-PASSafe' = 500 }
        $r = Invoke-Script $Reconcile (New-State $BaseState) (New-Tenant $t) -ExtraArgs '-Apply'
        $r.ExitCode | Should -Be 2
        $r.Output | Should -Match 'could not read safe'
        $r.Writes.Count | Should -Be 0
    }
    It 'stops with exit 2, and writes nothing, when the member list cannot be read' {
        # The old script also stopped here, but with exit 1, the "drift" code.
        $t = Get-InSyncTenant; $t.fail = @{ 'Get-PASSafeMember' = 403 }
        $r = Invoke-Script $Reconcile (New-State $BaseState) (New-Tenant $t) -ExtraArgs '-Apply'
        $r.ExitCode | Should -Be 2
        $r.Writes.Count | Should -Be 0
    }
    It 'stops with exit 2 when the account search fails' {
        $t = Get-InSyncTenant; $t.fail = @{ 'Get-PASAccount' = 500 }
        $r = Invoke-Script $Reconcile (New-State $BaseState) (New-Tenant $t) -ExtraArgs '-Apply'
        $r.ExitCode | Should -Be 2
        @($r.Writes | Where-Object { $_.cmdlet -eq 'Add-PASAccount' }).Count | Should -Be 0
    }
}

Describe 'Review fixes (PR #213)' {
    It 'writes nothing when a later read fails, even with drift found earlier' {
        # Membership drift (an auditor with RetrieveAccounts) is found first;
        # the account search then fails. No reset may have been sent.
        $t = Get-InSyncTenant
        $over = Get-RolePerm audit
        $over | Add-Member -NotePropertyName RetrieveAccounts -NotePropertyValue $true
        $t.members['CH-Tier0-Admins'][1].Permissions = $over
        $t.fail = @{ 'Get-PASAccount' = 500 }
        $r = Invoke-Script $Reconcile (New-State $BaseState) (New-Tenant $t) -ExtraArgs '-Apply'
        $r.ExitCode | Should -Be 2
        $r.Writes.Count | Should -Be 0
    }
    It 'a write the vault rejects is exit 2, not the drift code' {
        $t = @{ safes = @(); members = @{}; accounts = @(); fail = @{ 'Add-PASSafeMember' = 400 } }
        $r = Invoke-Script $Reconcile (New-State $BaseState) (New-Tenant $t) -ExtraArgs '-Apply'
        $r.ExitCode | Should -Be 2
        $r.Output | Should -Match 'unexpected error'
    }
    It 'a state file whose root is not an object is exit 2' {
        foreach ($bad in 'null', '[]', '42') {
            $r = Invoke-Script $Reconcile (New-TempFile '.json' $bad) (New-Tenant $EmptyTenant) -ExtraArgs '-Apply'
            $r.ExitCode | Should -Be 2 -Because "root $bad"
            $r.Writes.Count | Should -Be 0
        }
    }
    It 'refuses a safe declared twice and an account declared twice' {
        $s = $BaseState.Clone()
        $s.safes = @($BaseState.safes[0], $BaseState.safes[0])
        $s.accounts = @($BaseState.accounts[0], $BaseState.accounts[0])
        $r = Invoke-Script $Reconcile (New-State $s) (New-Tenant $EmptyTenant) -ExtraArgs '-Apply'
        $r.ExitCode | Should -Be 2
        $r.Output | Should -Match "safe 'CH-Tier0-Admins' is declared twice"
        $r.Output | Should -Match 'account CH-Tier0-Admins/tier0-admin-01@corp.test.local is declared twice'
        $r.Writes.Count | Should -Be 0
    }
    It 'reports the most worrying drift first, across safes' {
        # Safe A (first in the file) has only MISSING_PERM drift; safe B, later,
        # has an UNEXPECTED member. UNEXPECTED must still come first.
        $s = @{ accounts = @(); safes = @(
                @{ name = 'A'; members = @(@{ name = 'm1'; role = 'audit' }) },
                @{ name = 'B'; members = @(@{ name = 'm2'; role = 'audit' }) }) }
        $t = @{ accounts = @(); safes = @(@{ safeName = 'A' }, @{ safeName = 'B' }); members = @{
                A = @(@{ MemberName = 'm1'; Permissions = @{ ListAccounts = $true } })
                B = @(@{ MemberName = 'm2'; Permissions = (Get-RolePerm audit) }, @{ MemberName = 'intruder'; Permissions = (Get-RolePerm full) }) } }
        $r = Invoke-Script $Reconcile (New-State $s) (New-Tenant $t)
        $issues = @($r.Report.drift | ForEach-Object Issue)
        $issues[0] | Should -Be 'UNEXPECTED'
        $issues[-1] | Should -Be 'MISSING_PERM'
    }
}

Describe 'State file validation happens before the vault is touched' {
    It 'refuses an unknown role rather than granting an empty permission set' {
        $s = $BaseState.Clone(); $s.safes = @(@{ name = 'X'; members = @(@{ name = 'someone'; role = 'superuser' }) }); $s.accounts = @()
        $r = Invoke-Script $Reconcile (New-State $s) (New-Tenant $EmptyTenant) -ExtraArgs '-Apply'
        $r.ExitCode | Should -Be 2
        $r.Output | Should -Match 'unknown role'
        $r.Writes.Count | Should -Be 0
    }
    It 'NEW: refuses an account in a safe the file does not declare, a missing field, and a duplicate member' {
        $s = $BaseState.Clone()
        $s.safes = @(@{ name = 'CH-Tier0-Admins'; members = @(@{ name = 'a'; role = 'use' }, @{ name = 'a'; role = 'audit' }) })
        $s.accounts = @(@{ safe = 'Nowhere'; platformId = 'WinDomain'; address = 'corp.test.local'; userName = 'x' }, @{ safe = 'CH-Tier0-Admins'; address = 'h' })
        $r = Invoke-Script $Reconcile (New-State $s) (New-Tenant $EmptyTenant) -ExtraArgs '-Apply'
        $r.ExitCode | Should -Be 2
        $r.Output | Should -Match "names safe 'Nowhere'"
        $r.Output | Should -Match 'has no platformId'
        $r.Output | Should -Match "declared twice"
        $r.Writes.Count | Should -Be 0
    }
}

Describe '-Apply writes what it should, and nothing else' {
    It 'creates a missing safe, adds its members with their FULL RoleMap permission set, and onboards the account' {
        $r = Invoke-Script $Reconcile (New-State $BaseState) (New-Tenant $EmptyTenant) -ExtraArgs '-Apply'
        @($r.Writes | Where-Object cmdlet -EQ 'Add-PASSafe').Count | Should -Be 1
        $adds = @($r.Writes | Where-Object cmdlet -EQ 'Add-PASSafeMember')
        $adds.Count | Should -Be 2
        foreach ($a in $adds) {
            $role = if ($a.params.MemberName -eq 'CH-PAM-Admins') { 'full' } else { 'audit' }
            $want = Get-LabRolePermissionSet -Role $role
            $a.params.Permissions.Keys.Count | Should -Be 22   # NEW: every permission, true or false
            foreach ($k in $want.Keys) { $a.params.Permissions[$k] | Should -Be $want[$k] -Because "$role/$k" }
        }
        @($r.Writes | Where-Object cmdlet -EQ 'Add-PASAccount').Count | Should -Be 1
    }
    It 'NEW: resets privilege creep by sending the extra permission as false' {
        $t = Get-InSyncTenant
        $over = Get-RolePerm audit
        $over | Add-Member -NotePropertyName RetrieveAccounts -NotePropertyValue $true
        $t.members['CH-Tier0-Admins'][1].Permissions = $over
        $r = Invoke-Script $Reconcile (New-State $BaseState) (New-Tenant $t) -ExtraArgs '-Apply'
        $set = @($r.Writes | Where-Object cmdlet -EQ 'Set-PASSafeMember')
        $set.Count | Should -Be 1
        $set[0].params.MemberName | Should -Be 'CH-PAM-Auditors'
        $set[0].params.Permissions['RetrieveAccounts'] | Should -BeFalse
        $set[0].params.Permissions['ListAccounts'] | Should -BeTrue
    }
    It 'never deletes anything, even with undeclared members' {
        $t = Get-InSyncTenant
        $t.members['CH-Tier0-Admins'] += @{ MemberName = 'mystery-contractor'; Permissions = (Get-RolePerm full) }
        $r = Invoke-Script $Reconcile (New-State $BaseState) (New-Tenant $t) -ExtraArgs '-Apply'
        @($r.Writes | Where-Object { $_.cmdlet -like 'Remove-*' }).Count | Should -Be 0
        $r.Writes.Count | Should -Be 0
        $r.Output | Should -Not -Match 'not recognized'
    }
    It 'writes nothing without -Apply' {
        $r = Invoke-Script $Reconcile (New-State $BaseState) (New-Tenant $EmptyTenant)
        $r.Writes.Count | Should -Be 0
    }
    It 'NEW: writes nothing with -Apply -WhatIf' {
        $r = Invoke-Script $Reconcile (New-State $BaseState) (New-Tenant $EmptyTenant) -ExtraArgs '-Apply', '-WhatIf'
        $r.Writes.Count | Should -Be 0
    }
}

Describe 'New-LabSafe.ps1 (NEW: its role map used to disagree with RoleMap.psm1)' {
    It 'adds each member with exactly the RoleMap permission set for its role' {
        $s = $BaseState.Clone()
        $s.safes = @(@{ name = 'CH-Tier0-Admins'; description = 'd'; managingCPM = 'PasswordManager'
                members = @(@{ name = 'A'; role = 'full' }, @{ name = 'U'; role = 'use' }, @{ name = 'R'; role = 'audit' }) })
        $r = Invoke-Script $NewSafe (New-State $s) (New-Tenant $EmptyTenant)
        $r.ExitCode | Should -Be 0 -Because $r.Output
        @($r.Writes | Where-Object cmdlet -EQ 'Add-PASSafe').Count | Should -Be 1
        $adds = @($r.Writes | Where-Object cmdlet -EQ 'Add-PASSafeMember')
        $adds.Count | Should -Be 3
        $roleOf = @{ A = 'full'; U = 'use'; R = 'audit' }
        foreach ($a in $adds) {
            $want = Get-LabRolePermissionSet -Role $roleOf[$a.params.MemberName]
            foreach ($k in $want.Keys) { $a.params.Permissions[$k] | Should -Be $want[$k] -Because "$($a.params.MemberName)/$k" }
        }
    }
    It 'a safe it creates is in sync on the reconciler''s first run' {
        # Build the vault New-LabSafe would leave, from what it wrote.
        $s = $BaseState.Clone(); $s.accounts = @()
        $r = Invoke-Script $NewSafe (New-State $s) (New-Tenant $EmptyTenant)
        $members = @($r.Writes | Where-Object cmdlet -EQ 'Add-PASSafeMember' | ForEach-Object {
                @{ MemberName = $_.params.MemberName; Permissions = $_.params.Permissions } })
        $after = @{ safes = @(@{ safeName = 'CH-Tier0-Admins' }); members = @{ 'CH-Tier0-Admins' = $members }; accounts = @() }
        $r2 = Invoke-Script $Reconcile (New-State $s) (New-Tenant $after)
        $r2.Report.driftCount | Should -Be 0
        $r2.ExitCode | Should -Be 0
    }
    It 'refuses an unknown role before writing anything' {
        $s = $BaseState.Clone(); $s.safes = @(@{ name = 'X'; members = @(@{ name = 'someone'; role = 'superuser' }) })
        $r = Invoke-Script $NewSafe (New-State $s) (New-Tenant $EmptyTenant)
        $r.ExitCode | Should -Not -Be 0
        $r.Writes.Count | Should -Be 0
    }
    It 'adds only missing members to an existing safe' {
        $t = Get-InSyncTenant
        $t.members['CH-Tier0-Admins'] = @($t.members['CH-Tier0-Admins'][0])
        $r = Invoke-Script $NewSafe (New-State $BaseState) (New-Tenant $t)
        @($r.Writes | Where-Object cmdlet -EQ 'Add-PASSafe').Count | Should -Be 0
        $adds = @($r.Writes | Where-Object cmdlet -EQ 'Add-PASSafeMember')
        $adds.Count | Should -Be 1
        $adds[0].params.MemberName | Should -Be 'CH-PAM-Auditors'
    }
    It 'stops, writing nothing, when the safe lookup fails with anything but 404' {
        $t = Get-InSyncTenant; $t.fail = @{ 'Get-PASSafe' = 500 }
        $r = Invoke-Script $NewSafe (New-State $BaseState) (New-Tenant $t)
        $r.ExitCode | Should -Not -Be 0
        $r.Writes.Count | Should -Be 0
    }
}

Describe 'Static analysis' {
    It 'PSScriptAnalyzer reports no errors in lab/pam/cyberark' {
        if (-not (Get-Module -ListAvailable PSScriptAnalyzer)) { Set-ItResult -Skipped -Because 'PSScriptAnalyzer is not installed'; return }
        $errors = @(Invoke-ScriptAnalyzer -Path $Root -Recurse -Severity Error)
        $errors | Format-Table -AutoSize | Out-String | Write-Information
        $errors.Count | Should -Be 0
    }
    It 'every file is ASCII (lab PowerShell rule)' {
        Get-ChildItem -LiteralPath $Root -Recurse -File -Include *.ps1, *.psm1, *.psd1, *.json | ForEach-Object {
            [IO.File]::ReadAllBytes($_.FullName) | Where-Object { $_ -gt 127 } | Should -BeNullOrEmpty -Because $_.Name
        }
    }
}
