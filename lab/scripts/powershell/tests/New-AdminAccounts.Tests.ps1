# Pester 5 tests for post-apply/New-AdminAccounts.ps1. Every Graph call is
# answered by a mocked in-memory tenant; nothing signs in.
#   * The shipped register (lab/iga/admin-accounts.json) is valid and its
#     owners are real HR-feed personas in Information Technology.
#   * Register guard: bad names, duplicates, break-glass look-alikes,
#     eligibility that is not a PIM group.
#   * Live path: create cloud-only with an unknown password (never printed),
#     manager = owner, member of the standing Admin-Accounts group; refuse a
#     synced account, a missing / disabled owner and a non-role-assignable group.
#   * Sponsor rows (no HR owner, adm-presenter): register rules, the
#     register's displayName, no manager, the sponsor set through
#     POST /users/{id}/sponsors/$ref once (idempotent with an account that
#     already exists), and a missing / disabled / guest sponsor or an
#     unreadable sponsors list refused.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    $script:Naa = Get-LabScriptPath 'post-apply/New-AdminAccounts.ps1'
    . (Get-ScriptFunctionBlock -Path $script:Naa -Name 'Test-AdminAccountRegister', 'Get-AdminAccountUpn', 'Get-UnknownPassword', 'ConvertTo-AdminUserBody')
    $script:LabRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..' '..' '..'))
    $script:RegisterPath = Join-Path $script:LabRoot 'iga' 'admin-accounts.json'
    $script:Domain = 'contosohealthlab.onmicrosoft.com'

    # The shipped register's one sponsor row (adm-presenter) and its sponsor.
    $script:SponsorUpn = [string](@((Get-Content -LiteralPath $script:RegisterPath -Raw | ConvertFrom-Json -AsHashtable)['accounts'] | Where-Object { $_['sponsorUpn'] })[0]['sponsorUpn'])
    $script:Sponsor = @{ id = 'u-sponsor'; displayName = 'Lab Owner'; userPrincipalName = $script:SponsorUpn; userType = 'Member'; accountEnabled = $true }

    function Set-NaaMocks {
        param([hashtable]$Owners = @{ '400101' = @{ id = 'u-ava'; displayName = 'Ava Lin'; userPrincipalName = 'ava.lin@contoso.test'; accountEnabled = $true }
                '400102' = @{ id = 'u-raj'; displayName = 'Raj Patel'; userPrincipalName = 'raj.patel@contoso.test'; accountEnabled = $true }
                '400103' = @{ id = 'u-mei'; displayName = 'Mei Tanaka'; userPrincipalName = 'mei.tanaka@contoso.test'; accountEnabled = $true } },
            [hashtable]$Existing = @{}, [bool]$RoleAssignable = $true, [string[]]$Members = @(),
            # Users found by UPN besides the admin accounts (the sponsor); $null entry = absent.
            [hashtable]$People = @{ $script:SponsorUpn = $script:Sponsor },
            # Admin account id => its current sponsor ids.
            [hashtable]$SponsorsOf = @{}, [switch]$FailSponsorRead)
        $global:NaaTest = @{ Owners = $Owners; Existing = $Existing; RoleAssignable = $RoleAssignable; Members = $Members; People = $People; SponsorsOf = $SponsorsOf; FailSponsorRead = [bool]$FailSponsorRead
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
            if ($u -match "users\?\`$filter=userPrincipalName eq '(?<upn>[^']+)'") {
                $n = $Matches.upn
                return @{ value = @(if ($t.Existing.ContainsKey($n)) { $t.Existing[$n] } elseif ($t.People.ContainsKey($n) -and $null -ne $t.People[$n]) { $t.People[$n] }) }
            }
            if ($u -match '/users/(?<id>[^/?]+)/sponsors\?') {
                if ($t.FailSponsorRead) { throw 'HTTP 503 Service Unavailable' }
                return @{ value = @($t.SponsorsOf[$Matches.id] | Where-Object { $_ } | ForEach-Object { @{ id = $_ } }) }
            }
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
        # Sponsor rows have no HR owner by design (next test).
        foreach ($row in @($r['accounts'] | Where-Object { -not $_['sponsorUpn'] })) {
            $p = @($feed | Where-Object employeeId -eq $row['ownerEmployeeId'])
            $p.Count | Should -Be 1 -Because "$($row['adminAccount']) must have exactly one HR owner"
            $p[0].dept | Should -Be 'Information Technology'
            $p[0].status | Should -Be 'active'
        }
    }
    It 'has exactly one sponsored row: adm-presenter, read-only, sponsored by a person, never Global Administrator' {
        $r = Get-Content -LiteralPath $script:RegisterPath -Raw | ConvertFrom-Json -AsHashtable
        $s = @($r['accounts'] | Where-Object { $_['sponsorUpn'] })
        $s.Count | Should -Be 1
        $s[0]['adminAccount'] | Should -Be 'adm-presenter'
        $s[0]['displayName'] | Should -Be 'Demo presenter (read-only)'
        $s[0].Contains('ownerEmployeeId') | Should -BeFalse
        @($s[0]['eligibleFor']) | Should -Be @('pim-demo-readers')
        $s[0]['globalAdminEligible'] | Should -BeFalse
        $s[0]['sponsorUpn'] | Should -Not -Match '^(adm-|bg-admin)'
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
        @{ Case = 'a row with neither an owner nor a sponsor'; Rows = @(@{ adminAccount = 'adm-a.b' }); Expect = 'must be the HR employeeId' }
        @{ Case = 'a row with both an owner and a sponsor'; Rows = @(@{ adminAccount = 'adm-presenter'; ownerEmployeeId = '1'; sponsorUpn = 'owner@contoso.test'; displayName = 'P' }); Expect = 'both an HR owner' }
        @{ Case = 'a sponsored account shaped like a person'; Rows = @(@{ adminAccount = 'adm-jo.doe'; sponsorUpn = 'owner@contoso.test'; displayName = 'P' }); Expect = 'adm-<function>' }
        @{ Case = 'a sponsored account in upper case'; Rows = @(@{ adminAccount = 'adm-Presenter'; sponsorUpn = 'owner@contoso.test'; displayName = 'P' }); Expect = 'adm-<function>' }
        @{ Case = 'a sponsor that is an admin account'; Rows = @(@{ adminAccount = 'adm-presenter'; sponsorUpn = 'adm-ava.lin@contoso.test'; displayName = 'P' }); Expect = 'admin or break-glass' }
        @{ Case = 'a sponsor that is not a UPN'; Rows = @(@{ adminAccount = 'adm-presenter'; sponsorUpn = 'Lab Owner'; displayName = 'P' }); Expect = 'user principal name' }
        @{ Case = 'a sponsored account without a displayName'; Rows = @(@{ adminAccount = 'adm-presenter'; sponsorUpn = 'owner@contoso.test' }); Expect = 'needs a displayName' }
        @{ Case = 'a sponsored account eligible for write power'; Rows = @(@{ adminAccount = 'adm-presenter'; sponsorUpn = 'owner@contoso.test'; displayName = 'P'; eligibleFor = @('pim-tier1-helpdesk') }); Expect = 'only be eligible for read-only' }
        @{ Case = 'a sponsored account eligible for Global Administrator'; Rows = @(@{ adminAccount = 'adm-presenter'; sponsorUpn = 'owner@contoso.test'; displayName = 'P'; globalAdminEligible = $true }); Expect = 'never Global Administrator' }
        @{ Case = 'a displayName on an owned row'; Rows = @(@{ adminAccount = 'adm-a.b'; ownerEmployeeId = '1'; displayName = 'Someone' }); Expect = 'only for sponsored rows' }
    ) {
        (@(Test-AdminAccountRegister -Register @{ accounts = $Rows }) -join "`n") | Should -Match $Expect
    }

    It 'accepts a sponsored, read-only function account next to the owned ones' {
        $rows = @(@{ adminAccount = 'adm-a.b'; ownerEmployeeId = '1'; eligibleFor = @('pim-tier1-helpdesk') },
            @{ adminAccount = 'adm-presenter'; sponsorUpn = 'owner@contoso.test'; displayName = 'Demo presenter (read-only)'; eligibleFor = @('pim-demo-readers'); globalAdminEligible = $false })
        @(Test-AdminAccountRegister -Register @{ accounts = $rows }).Count | Should -Be 0
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
    It 'names a sponsored account by its own displayName, and refuses a body with no name at all' {
        $body = ConvertTo-AdminUserBody -Upn 'adm-presenter@contosohealthlab.onmicrosoft.com' -DisplayName 'Demo presenter (read-only)' -InitialSecret 'x'
        $body['displayName'] | Should -Be 'Demo presenter (read-only)'
        $body['mailNickname'] | Should -Be 'adm-presenter'
        $body['employeeType'] | Should -Be 'Admin account'
        { ConvertTo-AdminUserBody -Upn 'adm-x@contosohealthlab.onmicrosoft.com' -InitialSecret 'x' } | Should -Throw '*needs an owner display name*'
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
        $creates.Count | Should -Be 4
        foreach ($c in $creates) {
            $c.Body['userPrincipalName'] | Should -Match '^adm-[a-z.]+@contosohealthlab\.onmicrosoft\.com$'
            $c.Body.Contains('usageLocation') | Should -BeFalse
            $c.Body['passwordProfile']['password'].Length | Should -Be 64
        }
        # Owned rows get a manager; the sponsored row gets none.
        @($r.Writes | Where-Object { $_.Method -eq 'PUT' -and $_.Uri -like '*/manager/$ref' }).Count | Should -Be 3
        @($r.Writes | Where-Object { $_.Uri -like '*/users/u-new-adm-presenter/manager*' }).Count | Should -Be 0
        $adds = @($r.Writes | Where-Object { $_.Uri -like '*/groups/g-admins/members/$ref' } | ForEach-Object { $_.Body['@odata.id'] })
        $adds | Should -Contain 'https://graph.microsoft.com/v1.0/directoryObjects/u-build'
        $adds | Should -Contain 'https://graph.microsoft.com/v1.0/directoryObjects/u-new-adm-presenter'
        $adds.Count | Should -Be 5
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
            'adm-presenter@contosohealthlab.onmicrosoft.com'  = @{ id = 'a4'; displayName = 'Demo presenter (read-only)'; userPrincipalName = 'adm-presenter@contosohealthlab.onmicrosoft.com'; onPremisesSyncEnabled = $null; assignedLicenses = @() }
        } -Members @('a1', 'a2', 'a3', 'a4') -SponsorsOf @{ 'a4' = @('u-sponsor') }
        $r = Invoke-Naa
        $r.Exit | Should -Be 0
        @($r.Writes | Where-Object { $_.Method -eq 'POST' }).Count | Should -Be 0
        ($r.Lines -join "`n") | Should -Match '\[WARN\] adm-mei\.tanaka\S* - holds a licence'
        Set-NaaMocks
        & $script:Naa -OnMicrosoftDomain $script:Domain -WhatIf -WarningAction SilentlyContinue | Out-Null
        $global:NaaTest.Writes.Count | Should -Be 0
    }

    It 'sponsored row: register displayName, NO manager, sponsor added once through POST /users/{id}/sponsors/$ref' {
        Set-NaaMocks
        $r = Invoke-Naa
        $r.Exit | Should -Be 0
        $create = @($r.Writes | Where-Object { $_.Method -eq 'POST' -and $_.Uri -like '*/v1.0/users' -and $_.Body['userPrincipalName'] -like 'adm-presenter@*' })
        $create.Count | Should -Be 1
        $create[0].Body['displayName'] | Should -Be 'Demo presenter (read-only)'
        $sp = @($r.Writes | Where-Object { $_.Uri -like '*/users/u-new-adm-presenter/sponsors/$ref' })
        $sp.Count | Should -Be 1
        $sp[0].Method | Should -Be 'POST'
        $sp[0].Uri | Should -Be 'https://graph.microsoft.com/v1.0/users/u-new-adm-presenter/sponsors/$ref'
        $sp[0].Body['@odata.id'] | Should -Be 'https://graph.microsoft.com/v1.0/users/u-sponsor'
        @($r.Writes | Where-Object { $_.Uri -like '*/sponsors/*' }).Count | Should -Be 1 -Because 'owned rows never get a sponsor written'
        ($r.Lines -join "`n") | Should -Match '\[PASS\] adm-presenter@\S+ - sponsor \S+ added'
    }

    It 'sponsored row that ALREADY exists (made elsewhere, e.g. by the operator): not recreated or renamed, sponsor not re-added; a different name only warns' {
        Set-NaaMocks -Existing @{ 'adm-presenter@contosohealthlab.onmicrosoft.com' = @{ id = 'a4'; displayName = 'Demo Presenter'; userPrincipalName = 'adm-presenter@contosohealthlab.onmicrosoft.com'; onPremisesSyncEnabled = $null; assignedLicenses = @() } } `
            -SponsorsOf @{ 'a4' = @('u-sponsor') } -Members @('a4')
        $r = Invoke-Naa
        $r.Exit | Should -Be 0
        @($r.Writes | Where-Object { $_.Uri -like '*/users/a4*' -or ($_.Body -and $_.Body['userPrincipalName'] -like 'adm-presenter@*') }).Count | Should -Be 0
        ($r.Lines -join "`n") | Should -Match "\[WARN\] adm-presenter@\S+ - display name is 'Demo Presenter', the register says 'Demo presenter \(read-only\)'"
        ($r.Lines -join "`n") | Should -Match '\[PASS\] adm-presenter@\S+ - sponsor \S+ already set'
        # Existing account WITHOUT the sponsor: only the sponsor is added.
        Set-NaaMocks -Existing @{ 'adm-presenter@contosohealthlab.onmicrosoft.com' = @{ id = 'a4'; displayName = 'Demo presenter (read-only)'; userPrincipalName = 'adm-presenter@contosohealthlab.onmicrosoft.com'; onPremisesSyncEnabled = $null; assignedLicenses = @() } } -Members @('a4')
        $r = Invoke-Naa
        @($r.Writes | Where-Object { $_.Uri -like '*/users/a4*' } | ForEach-Object { "$($_.Method) $($_.Uri)" }) | Should -Be @('POST https://graph.microsoft.com/v1.0/users/a4/sponsors/$ref')
    }

    It 'refuses a sponsored row whose sponsor is <Case> (not created, others still processed, exit 1)' -ForEach @(
        @{ Case = 'missing'; Sponsor = $null; Expect = 'not found' }
        @{ Case = 'disabled'; Sponsor = @{ id = 'u-sponsor'; userPrincipalName = 'x'; userType = 'Member'; accountEnabled = $false }; Expect = 'is disabled' }
        @{ Case = 'a guest'; Sponsor = @{ id = 'u-sponsor'; userPrincipalName = 'x'; userType = 'Guest'; accountEnabled = $true }; Expect = 'is not a Member user' }
    ) {
        Set-NaaMocks -People @{ $script:SponsorUpn = $Sponsor }
        $r = Invoke-Naa
        $r.Exit | Should -Be 1
        ($r.Lines -join "`n") | Should -Match "\[FAIL\] adm-presenter@\S+ - sponsor \S+ $Expect"
        @($r.Writes | Where-Object { ($_.Body -and $_.Body['userPrincipalName'] -like 'adm-presenter@*') -or $_.Uri -like '*/sponsors/*' }).Count | Should -Be 0
        @($r.Writes | Where-Object { $_.Method -eq 'POST' -and $_.Uri -like '*/v1.0/users' }).Count | Should -Be 3
    }

    It 'a failed sponsors READ is a FAIL (exit 1), never "not set yet": no sponsor POST' {
        Set-NaaMocks -Existing @{ 'adm-presenter@contosohealthlab.onmicrosoft.com' = @{ id = 'a4'; displayName = 'Demo presenter (read-only)'; userPrincipalName = 'adm-presenter@contosohealthlab.onmicrosoft.com'; onPremisesSyncEnabled = $null; assignedLicenses = @() } } -Members @('a4') -FailSponsorRead
        $r = Invoke-Naa
        $r.Exit | Should -Be 1
        ($r.Lines -join "`n") | Should -Match '\[FAIL\] adm-presenter@\S+ - .*503'
        @($r.Writes | Where-Object { $_.Uri -like '*/sponsors/*' }).Count | Should -Be 0
    }

    It '-WhatIf on a sponsored row writes nothing (no user, no sponsor)' {
        Set-NaaMocks
        & $script:Naa -OnMicrosoftDomain $script:Domain -WhatIf -WarningAction SilentlyContinue | Out-Null
        @($global:NaaTest.Writes | Where-Object { $_.Uri -like '*/sponsors/*' -or ($_.Body -and $_.Body['userPrincipalName'] -like 'adm-presenter@*') }).Count | Should -Be 0
    }
}
