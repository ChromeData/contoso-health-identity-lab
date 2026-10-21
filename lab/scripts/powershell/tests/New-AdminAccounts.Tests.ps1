# Pester 5 tests for post-apply/New-AdminAccounts.ps1. Every Graph call is
# answered by a mocked in-memory tenant; nothing signs in.
#   * The shipped register (lab/iga/admin-accounts.json) is valid and its
#     owners are real HR-feed personas in Information Technology.
#   * Register guard: bad names, duplicates, break-glass look-alikes,
#     eligibility that is not a PIM group.
#   * Live path: create cloud-only with an unknown password (never printed),
#     manager = owner, member of the standing Admin-Accounts group; refuse a
#     synced account, a missing / disabled owner and a non-role-assignable group.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    $script:Naa = Get-LabScriptPath 'post-apply/New-AdminAccounts.ps1'
    . (Get-ScriptFunctionBlock -Path $script:Naa -Name 'Test-AdminAccountRegister', 'Get-AdminAccountUpn', 'Get-UnknownPassword', 'ConvertTo-AdminUserBody')
    $script:LabRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..' '..' '..'))
    $script:RegisterPath = Join-Path $script:LabRoot 'iga' 'admin-accounts.json'
    $script:Domain = 'contosohealthlab.onmicrosoft.com'

    function Set-NaaMocks {
        param([hashtable]$Owners = @{ '400101' = @{ id = 'u-ava'; displayName = 'Ava Lin'; userPrincipalName = 'ava.lin@contoso.test'; accountEnabled = $true }
                '400102' = @{ id = 'u-raj'; displayName = 'Raj Patel'; userPrincipalName = 'raj.patel@contoso.test'; accountEnabled = $true }
                '400103' = @{ id = 'u-mei'; displayName = 'Mei Tanaka'; userPrincipalName = 'mei.tanaka@contoso.test'; accountEnabled = $true } },
            [hashtable]$Existing = @{}, [bool]$RoleAssignable = $true, [string[]]$Members = @())
        $global:NaaTest = @{ Owners = $Owners; Existing = $Existing; RoleAssignable = $RoleAssignable; Members = $Members
            Writes = [System.Collections.Generic.List[object]]::new(); Lines = [System.Collections.Generic.List[string]]::new() }
        Mock Write-Host { $global:NaaTest.Lines.Add([string]$Object) }
        Mock Get-MgContext { New-MgContextStub -Scopes @('User.ReadWrite.All', 'GroupMember.ReadWrite.All', 'RoleManagement.ReadWrite.Directory') }
        Mock Connect-MgGraph { throw 'tests must never connect' }
        Mock Invoke-MgGraphRequest {
            $t = $global:NaaTest; $u = [uri]::UnescapeDataString("$Uri")
            if ($Method -in 'POST', 'PUT', 'PATCH', 'DELETE') {
                $b = if ($Body) { $Body | ConvertFrom-Json -AsHashtable } else { $null }
                $t.Writes.Add(@{ Method = $Method; Uri = $u; Body = $b })
                if ($Method -eq 'POST' -and $u -like '*/v1.0/users') { return @{ id = "u-new-$($b['mailNickname'])"; userPrincipalName = $b['userPrincipalName'] } }
                return $null
            }
            if ($u -match "groups\?\`$filter=mailNickname eq 'admin-accounts'") { return @{ value = @(@{ id = 'g-admins'; displayName = 'Admin-Accounts'; isAssignableToRole = $t.RoleAssignable; groupTypes = @() }) } }
            if ($u -like '*/groups/g-admins/members*') { return @{ value = @($t.Members | ForEach-Object { @{ id = $_ } }) } }
            if ($u -match "users\?\`$filter=employeeId eq '(?<e>\d+)'") { return @{ value = @(if ($t.Owners.ContainsKey($Matches.e)) { $t.Owners[$Matches.e] }) } }
            if ($u -match "users\?\`$filter=userPrincipalName eq '(?<upn>[^']+)'") { return @{ value = @(if ($t.Existing.ContainsKey($Matches.upn)) { $t.Existing[$Matches.upn] }) } }
            throw "unexpected Graph call in test: $Method $u"
        }
    }
    function Invoke-Naa {
        param([hashtable]$Extra = @{})
        $global:LASTEXITCODE = 0
        $out = @(& $script:Naa -OnMicrosoftDomain $script:Domain -Confirm:$false -WarningAction SilentlyContinue @Extra)
        return [pscustomobject]@{ Exit = $LASTEXITCODE; Rows = $out; Writes = @($global:NaaTest.Writes); Lines = @($global:NaaTest.Lines) }
    }
}

AfterAll { Remove-Variable -Name NaaTest -Scope Global -ErrorAction SilentlyContinue }

Describe 'lab/iga/admin-accounts.json - contract' {
    It 'is a valid register' {
        $r = Get-Content -LiteralPath $script:RegisterPath -Raw | ConvertFrom-Json -AsHashtable
        @(Test-AdminAccountRegister -Register $r).Count | Should -Be 0
    }
    It 'every owner is an active Information Technology persona in the mock HR feed (never a clinician)' {
        $feed = @(Get-Content -LiteralPath (Join-Path $script:LabRoot 'scripts' 'mock-hr' 'hr_feed.csv') | Where-Object { $_ -notmatch '^\s*#' -and $_ } | ConvertFrom-Csv)
        $r = Get-Content -LiteralPath $script:RegisterPath -Raw | ConvertFrom-Json -AsHashtable
        foreach ($row in $r['accounts']) {
            $p = @($feed | Where-Object employeeId -eq $row['ownerEmployeeId'])
            $p.Count | Should -Be 1 -Because "$($row['adminAccount']) must have exactly one HR owner"
            $p[0].dept | Should -Be 'Information Technology'
            $p[0].status | Should -Be 'active'
        }
    }
    It 'gives the reviewer of record (access governance lead) no eligibility (SOD-08)' {
        $r = Get-Content -LiteralPath $script:RegisterPath -Raw | ConvertFrom-Json -AsHashtable
        $lead = @($r['accounts'] | Where-Object { $_['function'] -match 'governance' })[0]
        @($lead['eligibleFor']).Count | Should -Be 0
        $lead['globalAdminEligible'] | Should -BeFalse
    }
}

Describe 'Test-AdminAccountRegister' {
    It 'refuses <Case>' -ForEach @(
        @{ Case = 'a name that is not adm-first.last'; Rows = @(@{ adminAccount = 'ava.lin'; ownerEmployeeId = '1' }); Expect = 'adm-first.last' }
        @{ Case = 'a break-glass look-alike'; Rows = @(@{ adminAccount = 'adm-breakglass.one'; ownerEmployeeId = '1' }); Expect = 'break-glass' }
        @{ Case = 'the same account twice'; Rows = @(@{ adminAccount = 'adm-a.b'; ownerEmployeeId = '1' }, @{ adminAccount = 'adm-a.b'; ownerEmployeeId = '2' }); Expect = 'twice' }
        @{ Case = 'two admin accounts for one person'; Rows = @(@{ adminAccount = 'adm-a.b'; ownerEmployeeId = '1' }, @{ adminAccount = 'adm-a.c'; ownerEmployeeId = '1' }); Expect = 'more than one' }
        @{ Case = 'eligibility that is not a PIM group'; Rows = @(@{ adminAccount = 'adm-a.b'; ownerEmployeeId = '1'; eligibleFor = @('app-servicenow-users') }); Expect = 'not a PIM-for-Groups group' }
        @{ Case = 'an empty register'; Rows = @(); Expect = 'empty' }
    ) {
        (@(Test-AdminAccountRegister -Register @{ accounts = $Rows }) -join "`n") | Should -Match $Expect
    }
}

Describe 'Get-UnknownPassword / ConvertTo-AdminUserBody' {
    It 'makes a 64-character password with every character class, different each time' {
        $a = Get-UnknownPassword; $b = Get-UnknownPassword
        $a.Length | Should -Be 64
        $a | Should -Match '[A-Z]'; $a | Should -Match '[a-z]'; $a | Should -Match '\d'; $a | Should -Match '[!#%*+\-=?@^_]'
        $a | Should -Not -Be $b
    }
    It 'builds a cloud-only, licence-free body' {
        $body = ConvertTo-AdminUserBody -Upn 'adm-ava.lin@contosohealthlab.onmicrosoft.com' -OwnerDisplayName 'Ava Lin' -InitialSecret 'x'
        $body['mailNickname'] | Should -Be 'adm-ava.lin'
        $body['displayName'] | Should -Be 'ADM Ava Lin'
        $body.Contains('usageLocation') | Should -BeFalse
        $body['passwordProfile']['forceChangePasswordNextSignIn'] | Should -BeTrue
    }
}

Describe 'New-AdminAccounts.ps1 (mocked Graph)' {
    It '-RenderOnly validates and prints the plan with no Graph call' {
        Mock Write-Host {}
        Mock Invoke-MgGraphRequest { throw 'no Graph in -RenderOnly' }
        & $script:Naa -OnMicrosoftDomain $script:Domain -RenderOnly
        Should -Invoke Invoke-MgGraphRequest -Times 0
        Should -Invoke Write-Host -ParameterFilter { "$Object" -match 'adm-ava\.lin@contosohealthlab\.onmicrosoft\.com' }
    }

    It 'creates each account cloud-only, sets the manager, adds it (and the build account) to Admin-Accounts' {
        Set-NaaMocks -Existing @{ 'admin@contosohealthlab.onmicrosoft.com' = @{ id = 'u-build'; userPrincipalName = 'admin@contosohealthlab.onmicrosoft.com'; onPremisesSyncEnabled = $null; assignedLicenses = @() } }
        $r = Invoke-Naa -Extra @{ BuildAccountUpn = 'admin@contosohealthlab.onmicrosoft.com' }
        $r.Exit | Should -Be 0
        $creates = @($r.Writes | Where-Object { $_.Method -eq 'POST' -and $_.Uri -like '*/v1.0/users' })
        $creates.Count | Should -Be 3
        foreach ($c in $creates) {
            $c.Body['userPrincipalName'] | Should -Match '^adm-[a-z.]+@contosohealthlab\.onmicrosoft\.com$'
            $c.Body.Contains('usageLocation') | Should -BeFalse
            $c.Body['passwordProfile']['password'].Length | Should -Be 64
        }
        @($r.Writes | Where-Object { $_.Method -eq 'PUT' -and $_.Uri -like '*/manager/$ref' }).Count | Should -Be 3
        $adds = @($r.Writes | Where-Object { $_.Uri -like '*/groups/g-admins/members/$ref' } | ForEach-Object { $_.Body['@odata.id'] })
        $adds | Should -Contain 'https://graph.microsoft.com/v1.0/directoryObjects/u-build'
        $adds.Count | Should -Be 4
        # The password is a credential nobody keeps: never on the console or in the output.
        foreach ($c in $creates) {
            $pw = $c.Body['passwordProfile']['password']
            ($r.Lines -join "`n").Contains($pw) | Should -BeFalse
            (($r.Rows | ConvertTo-Json -Depth 5)).Contains($pw) | Should -BeFalse
        }
    }

    It 'refuses an existing SYNCED account and a missing owner, still processes the others, exits 1' {
        Set-NaaMocks -Owners @{ '400101' = @{ id = 'u-ava'; displayName = 'Ava Lin'; userPrincipalName = 'ava.lin@contoso.test'; accountEnabled = $true }
            '400103' = @{ id = 'u-mei'; displayName = 'Mei Tanaka'; userPrincipalName = 'mei.tanaka@contoso.test'; accountEnabled = $true } } `
            -Existing @{ 'adm-ava.lin@contosohealthlab.onmicrosoft.com' = @{ id = 'u-adm-ava'; userPrincipalName = 'adm-ava.lin@contosohealthlab.onmicrosoft.com'; onPremisesSyncEnabled = $true; assignedLicenses = @() } }
        $r = Invoke-Naa
        $r.Exit | Should -Be 1
        ($r.Lines -join "`n") | Should -Match '\[FAIL\] adm-ava\.lin@\S+ - exists but is SYNCED'
        ($r.Lines -join "`n") | Should -Match '\[FAIL\] adm-raj\.patel@\S+ - owner employeeId 400102 matches 0'
        @($r.Writes | Where-Object { $_.Body -and $_.Body['userPrincipalName'] -like 'adm-ava*' }).Count | Should -Be 0
        @($r.Writes | Where-Object { $_.Body -and $_.Body['userPrincipalName'] -like 'adm-mei*' }).Count | Should -Be 1
    }

    It 'refuses to create an admin account for a disabled owner (leaver)' {
        Set-NaaMocks -Owners @{ '400101' = @{ id = 'u-ava'; displayName = 'Ava Lin'; userPrincipalName = 'ava.lin@contoso.test'; accountEnabled = $false }
            '400102' = @{ id = 'u-raj'; displayName = 'Raj Patel'; userPrincipalName = 'raj.patel@contoso.test'; accountEnabled = $true }
            '400103' = @{ id = 'u-mei'; displayName = 'Mei Tanaka'; userPrincipalName = 'mei.tanaka@contoso.test'; accountEnabled = $true } }
        $r = Invoke-Naa
        $r.Exit | Should -Be 1
        ($r.Lines -join "`n") | Should -Match 'adm-ava\.lin\S* - owner ava\.lin@contoso\.test is disabled'
    }

    It 'refuses (nothing sent) when Admin-Accounts is not role-assignable' {
        Set-NaaMocks -RoleAssignable $false
        { & $script:Naa -OnMicrosoftDomain $script:Domain -Confirm:$false -WarningAction SilentlyContinue } | Should -Throw '*role-assignable ASSIGNED group*'
        $global:NaaTest.Writes.Count | Should -Be 0
    }

    It 'is idempotent and -WhatIf writes nothing' {
        Set-NaaMocks -Existing @{
            'adm-ava.lin@contosohealthlab.onmicrosoft.com'   = @{ id = 'a1'; userPrincipalName = 'adm-ava.lin@contosohealthlab.onmicrosoft.com'; onPremisesSyncEnabled = $null; assignedLicenses = @() }
            'adm-raj.patel@contosohealthlab.onmicrosoft.com' = @{ id = 'a2'; userPrincipalName = 'adm-raj.patel@contosohealthlab.onmicrosoft.com'; onPremisesSyncEnabled = $null; assignedLicenses = @() }
            'adm-mei.tanaka@contosohealthlab.onmicrosoft.com' = @{ id = 'a3'; userPrincipalName = 'adm-mei.tanaka@contosohealthlab.onmicrosoft.com'; onPremisesSyncEnabled = $null; assignedLicenses = @(@{ skuId = 's' }) }
        } -Members @('a1', 'a2', 'a3')
        $r = Invoke-Naa
        $r.Exit | Should -Be 0
        @($r.Writes | Where-Object { $_.Method -eq 'POST' }).Count | Should -Be 0
        ($r.Lines -join "`n") | Should -Match '\[WARN\] adm-mei\.tanaka\S* - holds a licence'
        Set-NaaMocks
        & $script:Naa -OnMicrosoftDomain $script:Domain -WhatIf -WarningAction SilentlyContinue | Out-Null
        $global:NaaTest.Writes.Count | Should -Be 0
    }
}
