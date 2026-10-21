# Pester 5 tests for post-apply/Set-AuthContextPolicies.ps1 (CA021 + the PIM
# activation authentication context). Graph is a Pester mock holding the
# tenant's CA policies, authentication contexts, the break-glass group and the
# admin strength in memory; no tenant is contacted.
#
# The request fixture is the EXACT string modules/conditional-access renders
# (pinned by run "ca021_render_contract_with_the_post_apply_script_tests" in
# tests/ca002_ca020_ca021_admins.tftest.hcl, same placeholder ids), so a change
# to the Terraform rendering fails one side or the other.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    $script:Sac = Get-LabScriptPath 'post-apply/Set-AuthContextPolicies.ps1'
    . (Get-ScriptFunctionBlock -Path $script:Sac -Name 'Read-AuthContextRequest', 'Get-MapValue', 'Test-AuthContextRequest', 'Add-FlatValue', 'Get-CaPolicyDrift', 'Get-AuthContextDrift', 'Test-PhishingResistantStrength')

    $script:BgId = '22222222-2222-2222-2222-222222222222'
    $script:StrengthId = '44444444-4444-4444-4444-444444444444'
    $script:PolicyName = 'CA021 - Require phishing-resistant strength for privileged role activation (auth context c1)'
    # Verbatim terraform output (jsonencode, keys sorted) - see the header.
    $script:PolicyBodyJson = '{"conditions":{"applications":{"includeAuthenticationContextClassReferences":["c1"]},"clientAppTypes":["all"],"users":{"excludeGroups":["22222222-2222-2222-2222-222222222222"],"includeUsers":["All"]}},"displayName":"CA021 - Require phishing-resistant strength for privileged role activation (auth context c1)","grantControls":{"authenticationStrength":{"id":"44444444-4444-4444-4444-444444444444"},"operator":"OR"},"sessionControls":{"signInFrequency":{"authenticationType":"primaryAndSecondaryAuthentication","frequencyInterval":"everyTime","isEnabled":true}},"state":"enabledForReportingButNotEnforced"}'
    $script:CtxBodyJson = '{"description":"PIM Tier-0 activation step-up: phishing-resistant strength, fresh sign-in (CA021)","displayName":"Privileged role activation","isAvailable":true}'

    function New-RequestObject {
        # Shaped like `terraform output -json pim_auth_context_requests`.
        param([string]$PolicyBodyJson = $script:PolicyBodyJson, [string]$CtxBodyJson = $script:CtxBodyJson, [string]$State = 'enabledForReportingButNotEnforced')
        if ($State -ne 'enabledForReportingButNotEnforced') { $PolicyBodyJson = $PolicyBodyJson.Replace('"state":"enabledForReportingButNotEnforced"', """state"":""$State""") }
        return [ordered]@{
            auth_context_body   = $CtxBodyJson
            auth_context_id     = 'c1'
            policy_body         = $PolicyBodyJson
            policy_display_name = $script:PolicyName
            policy_key          = 'CA021'
            policy_match_prefix = 'CA021 - '
            policy_state        = $State
        }
    }

    function Write-RequestFile {
        param([string]$Path, $Request = (New-RequestObject), [switch]$FullOutput, [switch]$NullOutput)
        $value = if ($NullOutput) { $null } else { $Request }
        $doc = if ($FullOutput) { [ordered]@{ pim_auth_context_requests = [ordered]@{ sensitive = $false; value = $value } } } else { $value }
        if ($null -eq $doc) { 'null' | Set-Content -LiteralPath $Path -Encoding utf8NoBOM }
        else { ($doc | ConvertTo-Json -Depth 20) | Set-Content -LiteralPath $Path -Encoding utf8NoBOM }
        return $Path
    }

    function New-ModifiedBody {
        # The fixture body with one change applied by a scriptblock.
        param([scriptblock]$Change)
        $b = $script:PolicyBodyJson | ConvertFrom-Json -AsHashtable
        & $Change $b
        return ($b | ConvertTo-Json -Depth 20 -Compress)
    }

    function New-GraphShapedPolicy {
        # CA021 as Graph GET returns it: nulls for unset conditions, the
        # strength object expanded, annotations - the drift compare must see
        # this as EQUAL to the rendered body.
        param([string]$Id = 'p-021', [string]$State = 'enabledForReportingButNotEnforced', [string[]]$ExcludeGroups = @($script:BgId), [string]$Name = $script:PolicyName)
        return @{
            '@odata.context' = 'https://graph.microsoft.com/v1.0/$metadata#identity/conditionalAccess/policies/$entity'
            id = $Id; templateId = $null; displayName = $Name; createdDateTime = '2026-10-20T00:00:00Z'; modifiedDateTime = $null; state = $State
            conditions = @{
                userRiskLevels = @(); signInRiskLevels = @(); clientAppTypes = @('all'); servicePrincipalRiskLevels = @(); insiderRiskLevels = $null
                platforms = $null; locations = $null; devices = $null; clientApplications = $null; authenticationFlows = $null
                applications = @{ includeApplications = @(); excludeApplications = @(); includeUserActions = @(); includeAuthenticationContextClassReferences = @('c1'); applicationFilter = $null }
                users = @{ includeUsers = @('All'); excludeUsers = @(); includeGroups = @(); excludeGroups = $ExcludeGroups; includeRoles = @(); excludeRoles = @(); includeGuestsOrExternalUsers = $null; excludeGuestsOrExternalUsers = $null }
            }
            grantControls = @{
                operator = 'OR'; builtInControls = @(); customAuthenticationFactors = @(); termsOfUse = @()
                'authenticationStrength@odata.context' = 'https://graph.microsoft.com/v1.0/$metadata#...'
                authenticationStrength = @{ id = $script:StrengthId; displayName = 'Phishing-Resistant MFA (lab)'; policyType = 'custom'; requirementsSatisfied = 'mfa'; allowedCombinations = @('windowsHelloForBusiness', 'fido2', 'x509CertificateMultiFactor') }
            }
            sessionControls = @{
                disableResilienceDefaults = $null; applicationEnforcedRestrictions = $null; cloudAppSecurity = $null; persistentBrowser = $null; continuousAccessEvaluation = $null; secureSignInSession = $null
                signInFrequency = @{ value = $null; type = $null; authenticationType = 'primaryAndSecondaryAuthentication'; frequencyInterval = 'everyTime'; isEnabled = $true }
            }
        }
    }

    function Set-AcMocks {
        # In-memory tenant. Every request is logged; anything unexpected throws.
        param([object[]]$Policies = @(), [object[]]$Contexts = @(),
            [string[]]$StrengthCombinations = @('windowsHelloForBusiness', 'fido2', 'x509CertificateMultiFactor'),
            [string]$TenantBreakGlassId = $script:BgId, [int]$BreakGlassMatches = 1, [switch]$NoSession)
        $global:AcTest = @{
            Policies = [System.Collections.Generic.List[object]]::new(); Contexts = [System.Collections.Generic.List[object]]::new()
            Writes = [System.Collections.Generic.List[string]]::new(); Requests = [System.Collections.Generic.List[string]]::new()
            Combos = $StrengthCombinations; BgId = $TenantBreakGlassId; BgMatches = $BreakGlassMatches; NoSession = [bool]$NoSession
            ConnectScopes = $null; LastPolicyBody = $null; LastContextBody = $null
        }
        foreach ($p in $Policies) { $global:AcTest.Policies.Add($p) }
        foreach ($c in $Contexts) { $global:AcTest.Contexts.Add($c) }
        Mock Write-Host {}
        Mock Write-Warning {}
        Mock Get-MgContext { if ($global:AcTest.NoSession) { return $null }; New-MgContextStub -Scopes @('Policy.Read.All', 'Policy.ReadWrite.ConditionalAccess', 'GroupMember.Read.All') }
        Mock Connect-MgGraph { throw 'tests must never connect' }
        Mock Invoke-MgGraphRequest {
            $t = $global:AcTest
            $t.Requests.Add("$Method $Uri")
            if ($Method -eq 'GET' -and $Uri -match "/v1\.0/groups\?.*mailNickname eq '(?<n>[^']+)'") {
                return @{ value = @(for ($i = 0; $i -lt $t.BgMatches; $i++) { @{ id = $t.BgId; displayName = 'Break-Glass-Admins' } }) }
            }
            if ($Method -eq 'GET' -and $Uri -match '/v1\.0/policies/authenticationStrengthPolicies/(?<id>[0-9a-fA-F-]+)$') {
                return @{ id = $Matches.id; displayName = 'Phishing-Resistant MFA (lab)'; allowedCombinations = @($t.Combos) }
            }
            if ($Method -eq 'GET' -and $Uri -match '/identity/conditionalAccess/authenticationContextClassReferences$') { return @{ value = @($t.Contexts) } }
            if ($Method -eq 'PATCH' -and $Uri -match '/identity/conditionalAccess/authenticationContextClassReferences/(?<id>c\d+)$') {
                $b = $Body | ConvertFrom-Json -AsHashtable; $id = $Matches.id; $t.LastContextBody = $b
                $existing = @($t.Contexts | Where-Object { $_['id'] -eq $id })
                if ($existing.Count) { foreach ($k in $b.Keys) { $existing[0][$k] = $b[$k] } } else { $b['id'] = $id; $t.Contexts.Add($b) }
                $t.Writes.Add("PATCH context $id"); return $null
            }
            if ($Method -eq 'GET' -and $Uri -match '/identity/conditionalAccess/policies$') { return @{ value = @($t.Policies) } }
            if ($Method -eq 'POST' -and $Uri -match '/identity/conditionalAccess/policies$') {
                $b = $Body | ConvertFrom-Json -AsHashtable; $t.LastPolicyBody = $b
                $b['id'] = "p-$($t.Policies.Count + 1)"; $t.Policies.Add($b); $t.Writes.Add("POST $($b['displayName'])"); return $b
            }
            if ($Method -eq 'PATCH' -and $Uri -match '/identity/conditionalAccess/policies/(?<id>[^/]+)$') {
                $b = $Body | ConvertFrom-Json -AsHashtable; $id = $Matches.id; $t.LastPolicyBody = $b
                $p = @($t.Policies | Where-Object { $_['id'] -eq $id })[0]
                foreach ($k in $b.Keys) { $p[$k] = $b[$k] }
                $t.Writes.Add("PATCH policy $id"); return $null
            }
            throw "unexpected Graph call in test: $Method $Uri"
        }
    }
}

AfterAll { Remove-Variable -Name AcTest -Scope Global -ErrorAction SilentlyContinue }

Describe 'Set-AuthContextPolicies.ps1 - pure helpers' {
    It 'reads the single output and a full terraform output -json; null output = $null (flag off)' {
        $r = Read-AuthContextRequest -Path (Write-RequestFile -Path (Join-Path $TestDrive 'one.json'))
        $r.AuthContextId | Should -Be 'c1'
        $r.PolicyMatchPrefix | Should -Be 'CA021 - '
        $r.PolicyBody['conditions']['applications']['includeAuthenticationContextClassReferences'] | Should -Be @('c1')
        $r.AuthContextBody['isAvailable'] | Should -BeTrue

        $full = Read-AuthContextRequest -Path (Write-RequestFile -Path (Join-Path $TestDrive 'full.json') -FullOutput)
        $full.PolicyDisplayName | Should -Be $script:PolicyName

        Read-AuthContextRequest -Path (Write-RequestFile -Path (Join-Path $TestDrive 'null.json') -NullOutput) | Should -BeNullOrEmpty
        Read-AuthContextRequest -Path (Write-RequestFile -Path (Join-Path $TestDrive 'fullnull.json') -FullOutput -NullOutput) | Should -BeNullOrEmpty
    }

    It 'accepts the Terraform rendering as-is' {
        $r = Read-AuthContextRequest -Path (Write-RequestFile -Path (Join-Path $TestDrive 'ok.json'))
        @(Test-AuthContextRequest -Request $r).Count | Should -Be 0
    }

    It 'refuses a tampered request: <Case>' -TestCases @(
        @{ Case = 'break-glass exclusion removed'; Expect = '*exclude the break-glass*'; Change = { param($b) $b['conditions']['users']['excludeGroups'] = @() } }
        @{ Case = 'mfa OR-ed beside the strength'; Expect = '*built-in controls*'; Change = { param($b) $b['grantControls']['builtInControls'] = @('mfa') } }
        @{ Case = 'apps targeted as well'; Expect = '*applications*'; Change = { param($b) $b['conditions']['applications']['includeApplications'] = @('All') } }
        @{ Case = 'the PIM group targeted'; Expect = '*users.includeGroups*'; Change = { param($b) $b['conditions']['users']['includeGroups'] = @('33333333-3333-3333-3333-333333333333') } }
        @{ Case = 'path-form strength id'; Expect = '*bare object id*'; Change = { param($b) $b['grantControls']['authenticationStrength']['id'] = '/policies/authenticationStrengthPolicies/44444444-4444-4444-4444-444444444444' } }
        @{ Case = 'time-based frequency'; Expect = '*everyTime*'; Change = { param($b) $b['sessionControls']['signInFrequency']['frequencyInterval'] = 'timeBased' } }
        @{ Case = 'a different context'; Expect = '*exactly the auth context*'; Change = { param($b) $b['conditions']['applications']['includeAuthenticationContextClassReferences'] = @('c2') } }
        @{ Case = 'state edited away from policy_state'; Expect = '*differs from policy_state*'; Change = { param($b) $b['state'] = 'enabled' } }
        @{ Case = 'renamed outside the prefix'; Expect = '*does not start with*'; Change = { param($b) $b['displayName'] = 'CA099 - something else' } }
    ) {
        param($Case, $Expect, $Change)
        $req = New-RequestObject -PolicyBodyJson (New-ModifiedBody -Change $Change)
        $r = Read-AuthContextRequest -Path (Write-RequestFile -Path (Join-Path $TestDrive 'bad.json') -Request $req)
        $problems = @(Test-AuthContextRequest -Request $r)
        $problems.Count | Should -BeGreaterThan 0 -Because $Case
        ($problems -join ' | ') | Should -BeLike $Expect
    }

    It 'refuses an unpublished or out-of-range auth context' {
        $req = New-RequestObject -CtxBodyJson $script:CtxBodyJson.Replace('"isAvailable":true', '"isAvailable":false')
        $r = Read-AuthContextRequest -Path (Write-RequestFile -Path (Join-Path $TestDrive 'ctx.json') -Request $req)
        (@(Test-AuthContextRequest -Request $r) -join ' | ') | Should -BeLike '*isAvailable*'
        $r.AuthContextId = 'c26'
        (@(Test-AuthContextRequest -Request $r) -join ' | ') | Should -BeLike '*c1..c25*'
    }

    It 'drift: a Graph-shaped copy of the body is EQUAL (nulls, expanded strength, annotations ignored)' {
        $desired = $script:PolicyBodyJson | ConvertFrom-Json -AsHashtable
        @(Get-CaPolicyDrift -Desired $desired -Current (New-GraphShapedPolicy)).Count | Should -Be 0
    }

    It 'drift: an added exclusion, a state change and an added location are all reported' {
        $desired = $script:PolicyBodyJson | ConvertFrom-Json -AsHashtable
        $current = New-GraphShapedPolicy -State 'disabled' -ExcludeGroups @($script:BgId, '99999999-9999-9999-9999-999999999999')
        $current['conditions']['locations'] = @{ includeLocations = @('All'); excludeLocations = @('AllTrusted') }
        $drift = @(Get-CaPolicyDrift -Desired $desired -Current $current)
        $drift | Should -Contain 'state'
        $drift | Should -Contain 'conditions.users.excludeGroups'
        $drift | Should -Contain 'conditions.locations.includeLocations'
        $drift | Should -Contain 'conditions.locations.excludeLocations'
    }

    It 'auth-context drift and the phishing-resistant strength check' {
        $d = $script:CtxBodyJson | ConvertFrom-Json -AsHashtable
        @(Get-AuthContextDrift -Desired $d -Current @{ id = 'c1'; displayName = 'Privileged role activation'; description = $d['description']; isAvailable = $true }).Count | Should -Be 0
        @(Get-AuthContextDrift -Desired $d -Current @{ id = 'c1'; displayName = 'Privileged role activation'; description = 'old'; isAvailable = $false }) | Should -Be @('description', 'isAvailable')
        Test-PhishingResistantStrength -AllowedCombinations @('fido2', 'windowsHelloForBusiness') | Should -BeTrue
        Test-PhishingResistantStrength -AllowedCombinations @('fido2', 'password,sms') | Should -BeFalse
        Test-PhishingResistantStrength -AllowedCombinations @() | Should -BeFalse
    }
}

Describe 'Set-AuthContextPolicies.ps1 - against a mocked tenant' {
    BeforeEach { $script:Req = Write-RequestFile -Path (Join-Path $TestDrive 'ca021.json') }

    It 'never runs while enable_pim_auth_context is off (null output) - no Graph call' {
        Set-AcMocks
        $null = Write-RequestFile -Path $script:Req -NullOutput
        { & $script:Sac -RequestsPath $script:Req -Confirm:$false } | Should -Throw '*enable_pim_auth_context = false*'
        $global:AcTest.Requests.Count | Should -Be 0
    }

    It 'refuses a tampered request before touching the tenant' {
        Set-AcMocks
        $req = New-RequestObject -PolicyBodyJson (New-ModifiedBody -Change { param($b) $b['conditions']['users']['excludeGroups'] = @() })
        $null = Write-RequestFile -Path $script:Req -Request $req
        { & $script:Sac -RequestsPath $script:Req -Confirm:$false } | Should -Throw '*Refusing to send*'
        $global:AcTest.Requests.Count | Should -Be 0
    }

    It '-WhatIf without a Graph session is an offline preview: nothing read, nothing written, no connect' {
        Set-AcMocks -NoSession
        $r = @(& $script:Sac -RequestsPath $script:Req -WhatIf)
        @($r.Action) | Should -Be @('Preview', 'Preview')
        $global:AcTest.Requests.Count | Should -Be 0
        Should -Invoke Connect-MgGraph -Times 0 -Exactly
    }

    It '-WhatIf with a session reads the tenant and writes nothing' {
        Set-AcMocks
        $r = @(& $script:Sac -RequestsPath $script:Req -WhatIf)
        @($r.Action) | Should -Be @('WouldCreate', 'WouldCreate')
        $global:AcTest.Writes.Count | Should -Be 0
        @($global:AcTest.Requests | Where-Object { $_ -notlike 'GET *' }).Count | Should -Be 0
    }

    It 'connects with least-privilege scopes only (read + CA write + group read)' {
        Set-AcMocks -NoSession
        Mock Connect-MgGraph { $global:AcTest.ConnectScopes = @($Scopes); $global:AcTest.NoSession = $false }
        $null = & $script:Sac -RequestsPath $script:Req -Confirm:$false
        @($global:AcTest.ConnectScopes | Sort-Object) | Should -Be @('GroupMember.Read.All', 'Policy.Read.All', 'Policy.ReadWrite.ConditionalAccess')
    }

    It 'fresh tenant: publishes c1, THEN creates CA021 report-only with the exact rendered body; a re-run writes nothing' {
        Set-AcMocks
        $r = @(& $script:Sac -RequestsPath $script:Req -Confirm:$false)
        @($r.Action) | Should -Be @('Created', 'Created')
        @($global:AcTest.Writes) | Should -Be @('PATCH context c1', "POST $script:PolicyName")
        $global:AcTest.LastContextBody['isAvailable'] | Should -BeTrue
        $p = $global:AcTest.LastPolicyBody
        $p['state'] | Should -Be 'enabledForReportingButNotEnforced'
        @($p['conditions']['applications']['includeAuthenticationContextClassReferences']) | Should -Be @('c1')
        @($p['conditions']['users']['includeUsers']) | Should -Be @('All')
        @($p['conditions']['users']['excludeGroups']) | Should -Be @($script:BgId)
        $p['grantControls']['authenticationStrength']['id'] | Should -Be $script:StrengthId
        $p['sessionControls']['signInFrequency']['frequencyInterval'] | Should -Be 'everyTime'

        $before = $global:AcTest.Writes.Count
        $again = @(& $script:Sac -RequestsPath $script:Req -Confirm:$false)
        @($again.Action) | Should -Be @('Unchanged', 'Unchanged')
        $global:AcTest.Writes.Count | Should -Be $before
    }

    It 'a Graph-shaped CA021 already in sync is left alone' {
        Set-AcMocks -Policies @(New-GraphShapedPolicy) -Contexts @(@{ id = 'c1'; displayName = 'Privileged role activation'; description = 'PIM Tier-0 activation step-up: phishing-resistant strength, fresh sign-in (CA021)'; isAvailable = $true })
        $r = @(& $script:Sac -RequestsPath $script:Req -Confirm:$false)
        @($r.Action) | Should -Be @('Unchanged', 'Unchanged')
        $global:AcTest.Writes.Count | Should -Be 0
    }

    It 'portal drift (extra exclusion, disabled) is reverted to the rendered body by PATCH' {
        Set-AcMocks -Policies @(New-GraphShapedPolicy -State 'disabled' -ExcludeGroups @($script:BgId, '99999999-9999-9999-9999-999999999999')) -Contexts @(@{ id = 'c1'; displayName = 'Privileged role activation'; description = 'PIM Tier-0 activation step-up: phishing-resistant strength, fresh sign-in (CA021)'; isAvailable = $true })
        $r = @(& $script:Sac -RequestsPath $script:Req -Confirm:$false)
        $r[1].Action | Should -Be 'Updated'
        $r[1].Drift | Should -Contain 'state'
        $r[1].Drift | Should -Contain 'conditions.users.excludeGroups'
        @($global:AcTest.Writes) | Should -Be @('PATCH policy p-021')
        $global:AcTest.LastPolicyBody['state'] | Should -Be 'enabledForReportingButNotEnforced'
        @($global:AcTest.LastPolicyBody['conditions']['users']['excludeGroups']) | Should -Be @($script:BgId)
    }

    It 'an unpublished c1 with the right name is republished' {
        Set-AcMocks -Contexts @(@{ id = 'c1'; displayName = 'Privileged role activation'; description = 'PIM Tier-0 activation step-up: phishing-resistant strength, fresh sign-in (CA021)'; isAvailable = $false })
        $r = @(& $script:Sac -RequestsPath $script:Req -Confirm:$false)
        $r[0].Action | Should -Be 'Updated'
        $r[0].Drift | Should -Be @('isAvailable')
    }

    It 'refuses to take over a context id that belongs to something else' {
        Set-AcMocks -Contexts @(@{ id = 'c1'; displayName = 'Sensitive SharePoint sites'; description = ''; isAvailable = $true })
        { & $script:Sac -RequestsPath $script:Req -Confirm:$false } | Should -Throw '*belongs to something else*'
        $global:AcTest.Writes.Count | Should -Be 0
    }

    It 'refuses when two policies carry the CA021 prefix' {
        Set-AcMocks -Policies @((New-GraphShapedPolicy -Id 'a'), (New-GraphShapedPolicy -Id 'b' -Name 'CA021 - duplicate'))
        { & $script:Sac -RequestsPath $script:Req -Confirm:$false } | Should -Throw '*2 policies start with*'
        @($global:AcTest.Writes | Where-Object { $_ -like '*policy*' -or $_ -like 'POST*' }).Count | Should -Be 0
    }

    It 'refuses to overwrite a CA021-named policy that is not an auth-context policy' {
        $other = New-GraphShapedPolicy -Id 'x' -Name 'CA021 - Some app policy'
        $other['conditions']['applications']['includeAuthenticationContextClassReferences'] = @()
        $other['conditions']['applications']['includeApplications'] = @('All')
        Set-AcMocks -Policies @($other)
        { & $script:Sac -RequestsPath $script:Req -Confirm:$false } | Should -Throw '*does not target an authentication context*'
        @($global:AcTest.Writes | Where-Object { $_ -like '*policy*' -or $_ -like 'POST*' }).Count | Should -Be 0
    }

    It 'refuses when the tenant break-glass group is not the one the body excludes' {
        Set-AcMocks -TenantBreakGlassId '77777777-7777-7777-7777-777777777777'
        { & $script:Sac -RequestsPath $script:Req -Confirm:$false } | Should -Throw '*does not exclude the tenant''s break-glass group*'
        $global:AcTest.Writes.Count | Should -Be 0
    }

    It 'refuses when break-glass cannot be resolved to exactly one group' {
        Set-AcMocks -BreakGlassMatches 0
        { & $script:Sac -RequestsPath $script:Req -Confirm:$false } | Should -Throw '*resolved to 0 groups*'
        $global:AcTest.Writes.Count | Should -Be 0
    }

    It 'refuses to gate activation with a strength that allows phishable methods' {
        Set-AcMocks -StrengthCombinations @('fido2', 'password,microsoftAuthenticatorPush')
        { & $script:Sac -RequestsPath $script:Req -Confirm:$false } | Should -Throw '*non-phishing-resistant*'
        $global:AcTest.Writes.Count | Should -Be 0
    }

    It '-GraphVersion beta sends only the Conditional Access calls to /beta' {
        Set-AcMocks
        $null = & $script:Sac -RequestsPath $script:Req -GraphVersion beta -Confirm:$false
        @($global:AcTest.Requests | Where-Object { $_ -like '*/identity/conditionalAccess/*' -and $_ -notlike '*/beta/*' }).Count | Should -Be 0
        @($global:AcTest.Requests | Where-Object { $_ -like '*/groups?*' -or $_ -like '*/authenticationStrengthPolicies/*' } | Where-Object { $_ -notlike '*/v1.0/*' }).Count | Should -Be 0
    }

    It 'an enforced CA021 body is written as enabled (state comes from Terraform, not the script)' {
        Set-AcMocks
        $null = Write-RequestFile -Path $script:Req -Request (New-RequestObject -State 'enabled')
        $null = & $script:Sac -RequestsPath $script:Req -Confirm:$false
        $global:AcTest.LastPolicyBody['state'] | Should -Be 'enabled'
        # Only a real write tells the operator to attest the tenant state.
        Should -Invoke Write-Host -ParameterFilter { "$Object" -match 'ENFORCED in the tenant' -and "$Object" -match 'ca021_enforced_in_tenant = true' }
    }

    It 'a dry run of an enforced CA021 says NOT to attest (nothing was written)' {
        Set-AcMocks
        $null = Write-RequestFile -Path $script:Req -Request (New-RequestObject -State 'enabled')
        $null = & $script:Sac -RequestsPath $script:Req -WhatIf
        Should -Invoke Write-Host -ParameterFilter { "$Object" -match 'dry run' -and "$Object" -match 'do NOT set ca021_enforced_in_tenant' }
        $global:AcTest.Writes.Count | Should -Be 0
    }

    It 'CA023 (protected actions, context c2) goes through the same checks and never talks about the PIM attestation' {
        Set-AcMocks
        $body = $script:PolicyBodyJson.Replace('"c1"', '"c2"').Replace('CA021 - Require phishing-resistant strength for privileged role activation (auth context c1)', 'CA023 - Require phishing-resistant strength for protected actions (auth context c2)')
        $req = New-RequestObject -PolicyBodyJson $body
        $req['auth_context_id'] = 'c2'; $req['policy_key'] = 'CA023'; $req['policy_match_prefix'] = 'CA023 - '
        $req['policy_display_name'] = 'CA023 - Require phishing-resistant strength for protected actions (auth context c2)'
        $null = Write-RequestFile -Path $script:Req -Request $req
        $r = @(& $script:Sac -RequestsPath $script:Req -Confirm:$false)
        @($r.Action) | Should -Be @('Created', 'Created')
        @($global:AcTest.Writes) | Should -Be @('PATCH context c2', 'POST CA023 - Require phishing-resistant strength for protected actions (auth context c2)')
        Should -Invoke Write-Host -ParameterFilter { "$Object" -match 'Do NOT bind .c2. to the protected actions' }
        Should -Invoke Write-Host -Times 0 -ParameterFilter { "$Object" -match 'ca021_enforced_in_tenant' }
    }
}
