# Pester 5 tests for post-apply/Set-PimGroupEligibility.ps1.
#   * Pure helpers (from the syntax tree): tier from the nickname, duration
#     caps, break-glass / admin-account guards, the request body.
#   * Whole-script runs against a mocked tenant: every Graph call is answered
#     by a Pester Mock of the real Invoke-MgGraphRequest (its signature is
#     copied, so a parameter the SDK lacks fails the test).
# No tenant is contacted.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    $script:Pge = Get-LabScriptPath 'post-apply/Set-PimGroupEligibility.ps1'
    . (Get-ScriptFunctionBlock -Path $script:Pge -Name 'Get-PimGroupTier', 'ConvertTo-DurationDay', 'Get-EligibilityDuration', 'Test-BreakGlassUpn', 'Test-AdminAccountUpn', 'Get-EligibilityRequestBody')

    function Set-PgeMock {
        # In-memory tenant: groups by mailNickname, users by UPN, approver
        # group members, existing eligibility schedules.
        param(
            [hashtable]$Groups = @{ 'privileged-iam-admins' = 'g-iam'; 'pim-tier0-ca-admins' = 'g-t0ca'; 'pim-tier1-helpdesk' = 'g-t1hd'; 'pim-approvers-tier0' = 'g-appr0'; 'pim-approvers-tier1' = 'g-appr1' },
            [hashtable]$Users = @{ 'adm-ava.lin@contosohealthlab.onmicrosoft.com' = 'u-ava'; 'adm-raj.patel@contosohealthlab.onmicrosoft.com' = 'u-raj'; 'grace.mwangi@contosohealth.io' = 'u-grace' },
            [hashtable]$Approvers = @{ 'g-appr0' = @('u-appr-1', 'u-appr-2'); 'g-appr1' = @('u-appr-3') },
            [hashtable[]]$Existing = @(),
            [switch]$FailEligibilityRead
        )
        $global:PgeTest = @{ Posts = [System.Collections.Generic.List[object]]::new(); Groups = $Groups; Users = $Users; Approvers = $Approvers; Existing = $Existing; FailRead = [bool]$FailEligibilityRead }
        Mock Write-Host {}
        Mock Get-MgContext { New-MgContextStub -Scopes @('PrivilegedEligibilitySchedule.ReadWrite.AzureADGroup', 'Group.Read.All', 'User.Read.All') }
        Mock Connect-MgGraph { throw 'tests must never connect' }
        Mock Invoke-MgGraphRequest {
            $t = $global:PgeTest; $u = [uri]::UnescapeDataString("$Uri")
            if ($Method -eq 'POST') {
                $t.Posts.Add(@{ Uri = $u; Body = ($Body | ConvertFrom-Json -AsHashtable) })
                return @{ id = 'req-1'; status = 'Provisioned' }
            }
            if ($u -match "/groups\?\`$filter=mailNickname eq '(?<n>[^']+)'") {
                $n = $Matches.n
                return @{ value = @(if ($t.Groups.ContainsKey($n)) { @{ id = $t.Groups[$n]; displayName = $n } }) }
            }
            if ($u -match '/groups/(?<g>[^/]+)/transitiveMembers') { return @{ value = @($t.Approvers[$Matches.g] | ForEach-Object { @{ id = $_ } }) } }
            if ($u -match "/users\?\`$filter=userPrincipalName eq '(?<n>[^']+)'") {
                $n = $Matches.n
                return @{ value = @(if ($t.Users.ContainsKey($n)) { @{ id = $t.Users[$n]; displayName = $n } }) }
            }
            if ($u -match "eligibilitySchedules\?\`$filter=groupId eq '(?<g>[^']+)' and principalId eq '(?<p>[^']+)'") {
                if ($t.FailRead) { throw 'HTTP 503 Service Unavailable' }
                $g = $Matches.g; $p = $Matches.p
                return @{ value = @($t.Existing | Where-Object { $_.groupId -eq $g -and $_.principalId -eq $p } | ForEach-Object {
                            @{ groupId = $_.groupId; principalId = $_.principalId; accessId = 'member'; scheduleInfo = @{ expiration = @{ type = $_.expirationType } } } }) }
            }
            throw "unexpected Graph call in test: $Method $u"
        }
    }
}

AfterAll { Remove-Variable -Name PgeTest -Scope Global -ErrorAction SilentlyContinue }

Describe 'Set-PimGroupEligibility.ps1 - helpers' {
    It 'reads the tier from the modules/pim nickname contract' {
        Get-PimGroupTier -MailNickname 'pim-tier0-ca-admins' | Should -Be 0
        Get-PimGroupTier -MailNickname 'pim-tier0-privileged-auth-admins' | Should -Be 0
        Get-PimGroupTier -MailNickname 'pim-tier1-helpdesk' | Should -Be 1
        Get-PimGroupTier -MailNickname 'privileged-iam-admins' | Should -Be 1
    }

    It 'defaults to the tier maximum and refuses anything longer' {
        Get-EligibilityDuration -Tier 0 | Should -Be 'P180D'
        Get-EligibilityDuration -Tier 1 | Should -Be 'P365D'
        Get-EligibilityDuration -Tier 1 -Requested 'P90D' | Should -Be 'P90D'
        Get-EligibilityDuration -Tier 0 -Requested 'P30D' | Should -Be 'P30D'
        { Get-EligibilityDuration -Tier 0 -Requested 'P365D' } | Should -Throw '*exceeds the Tier-0 maximum*'
    }

    It 'recognises break-glass and admin accounts by the naming standard' {
        Test-BreakGlassUpn -UserPrincipalName 'bg-admin-01@contosohealthlab.onmicrosoft.com' | Should -BeTrue
        Test-BreakGlassUpn -UserPrincipalName 'adm-ava.lin@contosohealthlab.onmicrosoft.com' | Should -BeFalse
        Test-AdminAccountUpn -UserPrincipalName 'adm-ava.lin@contosohealthlab.onmicrosoft.com' | Should -BeTrue
        Test-AdminAccountUpn -UserPrincipalName 'grace.mwangi@contosohealth.io' | Should -BeFalse
    }

    It 'builds an EXPIRING request - never noExpiration' {
        $b = Get-EligibilityRequestBody -GroupId 'g' -PrincipalId 'p' -Justification 'j' -Duration 'P180D' -Start ([datetime]'2026-11-02T10:00:00Z')
        $b.scheduleInfo.expiration.type | Should -Be 'afterDuration'
        $b.scheduleInfo.expiration.duration | Should -Be 'P180D'
        $b.accessId | Should -Be 'member'
        $b.action | Should -Be 'adminAssign'
        ($b | ConvertTo-Json -Depth 5) | Should -Not -Match 'noExpiration'
    }

    It 'has no default person (Invoke-PostApply contract: GroupMailNickname, UserPrincipalNames, WhatIf)' {
        $cmd = Get-Command $Pge
        $p = $cmd.Parameters['UserPrincipalNames']
        @($p.Attributes | Where-Object { $_ -is [System.Management.Automation.ParameterAttribute] -and $_.Mandatory }).Count | Should -Be 1
        $cmd.Parameters.Keys | Should -Contain 'GroupMailNickname'
        $cmd.Parameters.Keys | Should -Contain 'WhatIf'
        (Get-Content -LiteralPath $Pge -Raw) | Should -Not -Match 'grace\.mwangi'
    }

    It 'has comment-based help that Get-Help can parse (no non-standard keywords)' {
        (Get-Help $Pge).Synopsis | Should -Match 'ELIGIBLE'
        (Get-Help $Pge -Full | Out-String) | Should -Match 'afterDuration'
    }
}

Describe 'Set-PimGroupEligibility.ps1 - against a mocked tenant' {
    BeforeEach { $global:LASTEXITCODE = 0 }

    It 'Tier 0: requests a 180-day eligibility for the group' {
        Set-PgeMock
        & $Pge -GroupMailNickname 'pim-tier0-ca-admins' -UserPrincipalNames 'adm-ava.lin@contosohealthlab.onmicrosoft.com'
        $LASTEXITCODE | Should -Be 0
        $global:PgeTest.Posts.Count | Should -Be 1
        $p = $global:PgeTest.Posts[0]
        $p.Uri | Should -Be 'https://graph.microsoft.com/v1.0/identityGovernance/privilegedAccess/group/eligibilityScheduleRequests'
        $p.Body.groupId | Should -Be 'g-t0ca'
        $p.Body.principalId | Should -Be 'u-ava'
        $p.Body.scheduleInfo.expiration.type | Should -Be 'afterDuration'
        $p.Body.scheduleInfo.expiration.duration | Should -Be 'P180D'
    }

    It 'Tier 1 / Privileged-IAM-Admins: 365 days by default' {
        Set-PgeMock
        & $Pge -UserPrincipalNames 'adm-ava.lin@contosohealthlab.onmicrosoft.com'
        $global:PgeTest.Posts[0].Body.groupId | Should -Be 'g-iam'
        $global:PgeTest.Posts[0].Body.scheduleInfo.expiration.duration | Should -Be 'P365D'
    }

    It 'refuses a Tier-0 duration longer than 180 days before touching Graph' {
        Set-PgeMock
        { & $Pge -GroupMailNickname 'pim-tier0-ca-admins' -UserPrincipalNames 'adm-ava.lin@contosohealthlab.onmicrosoft.com' -EligibilityDuration 'P365D' } | Should -Throw '*exceeds the Tier-0 maximum*'
        Should -Invoke Invoke-MgGraphRequest -Times 0 -Exactly
    }

    It 'never makes break-glass eligible (exit 1) but still processes the others' {
        Set-PgeMock
        Mock Write-Warning {}
        & $Pge -GroupMailNickname 'pim-tier1-helpdesk' -UserPrincipalNames 'bg-admin-01@contosohealthlab.onmicrosoft.com', 'adm-raj.patel@contosohealthlab.onmicrosoft.com'
        $LASTEXITCODE | Should -Be 1
        @($global:PgeTest.Posts | ForEach-Object { $_.Body.principalId }) | Should -Be @('u-raj')
        Should -Invoke Write-Warning -ParameterFilter { $Message -match 'break-glass' }
    }

    It 'warns (does not refuse) on a workforce account without the adm- prefix' {
        Set-PgeMock
        Mock Write-Warning {}
        & $Pge -UserPrincipalNames 'grace.mwangi@contosohealth.io'
        $global:PgeTest.Posts.Count | Should -Be 1
        Should -Invoke Write-Warning -ParameterFilter { $Message -match 'not an adm- account' }
    }

    It 'warns when the person is also an approver of the same tier' {
        Set-PgeMock -Approvers @{ 'g-appr0' = @('u-ava'); 'g-appr1' = @() }
        Mock Write-Warning {}
        & $Pge -GroupMailNickname 'pim-tier0-ca-admins' -UserPrincipalNames 'adm-ava.lin@contosohealthlab.onmicrosoft.com'
        Should -Invoke Write-Warning -ParameterFilter { $Message -match 'pim-approvers-tier0' }
    }

    It 'keeps an existing expiring eligibility and reports a PERMANENT one - no new request either way' {
        Set-PgeMock -Existing @(
            @{ groupId = 'g-iam'; principalId = 'u-ava'; expirationType = 'afterDateTime' },
            @{ groupId = 'g-iam'; principalId = 'u-raj'; expirationType = 'noExpiration' })
        Mock Write-Warning {}
        & $Pge -UserPrincipalNames 'adm-ava.lin@contosohealthlab.onmicrosoft.com', 'adm-raj.patel@contosohealthlab.onmicrosoft.com'
        $LASTEXITCODE | Should -Be 0
        $global:PgeTest.Posts.Count | Should -Be 0
        Should -Invoke Write-Warning -Times 1 -Exactly -ParameterFilter { $Message -match 'PERMANENT' -and $Message -match 'adm-raj' }
    }

    It 'a failed eligibility READ is a failure (exit 1), never "not eligible yet"' {
        Set-PgeMock -FailEligibilityRead
        Mock Write-Warning {}
        & $Pge -UserPrincipalNames 'adm-ava.lin@contosohealthlab.onmicrosoft.com'
        $LASTEXITCODE | Should -Be 1
        $global:PgeTest.Posts.Count | Should -Be 0
    }

    It 'an unknown user is a failure (exit 1)' {
        Set-PgeMock
        Mock Write-Warning {}
        & $Pge -UserPrincipalNames 'adm-nobody@contosohealthlab.onmicrosoft.com'
        $LASTEXITCODE | Should -Be 1
    }

    It '-WhatIf requests nothing' {
        Set-PgeMock
        & $Pge -GroupMailNickname 'pim-tier0-ca-admins' -UserPrincipalNames 'adm-ava.lin@contosohealthlab.onmicrosoft.com' -WhatIf
        $global:PgeTest.Posts.Count | Should -Be 0
    }

    It 'stops when the group does not exist' {
        Set-PgeMock
        { & $Pge -GroupMailNickname 'pim-tier0-nope' -UserPrincipalNames 'adm-ava.lin@contosohealthlab.onmicrosoft.com' } | Should -Throw "*not found*"
        $global:PgeTest.Posts.Count | Should -Be 0
    }
}
