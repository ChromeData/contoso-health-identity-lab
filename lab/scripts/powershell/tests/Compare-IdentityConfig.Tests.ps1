# Pester 5 tests for Compare-IdentityConfig.ps1.
#   * The diff and the classification table: pure functions from the
#     script's syntax tree.
#   * The tfvars reader against the REAL lab.tfvars (so a renamed block
#     fails a test, not a nightly run).
#   * Exceptions: validity, expiry, wildcards, the standard's term limits.
#   * End to end on snapshots produced by Export-IdentityConfig.ps1 -Offline:
#     the placeholder baseline ("no baseline yet"), a clean compare, drift of
#     every class and its exit code, exceptions, an unread section, public-
#     safe Markdown and JSON, unusable inputs.
# No tenant is contacted.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    $script:Compare = Get-LabScriptPath 'Compare-IdentityConfig.ps1'
    $script:Export = Get-LabScriptPath 'Export-IdentityConfig.ps1'
    . (Get-ScriptFunctionBlock -Path $script:Compare)
    $script:FixturePath = Join-Path $PSScriptRoot 'fixtures' 'identity-config.fixture.json'
    $script:Placeholder = Join-Path $script:LabPowerShellRoot '..' '..' 'config-baseline' 'identity-config.json'
    $script:ExceptionsFile = Join-Path $script:LabPowerShellRoot '..' '..' 'config-baseline' 'drift-exceptions.json'
    $script:TfVars = Join-Path $script:LabPowerShellRoot '..' '..' 'terraform' 'envs' 'dev' 'lab.tfvars'
    $script:Today = [datetime]::new(2026, 10, 26, 0, 0, 0, [DateTimeKind]::Utc)

    function New-Finding([string]$Key, [string]$Severity = 'High') {
        [ordered]@{ key = $Key; severity = $Severity; section = 'x'; object = ''; attribute = ''; kind = 'changed'; before = 1; after = 2; message = $Key; twin = '' }
    }
    function New-Exception([string]$Id = 'E60', [string]$Finding, [string]$Owner = 'IAM Eng', [string]$Approved = '2026-10-01', [string]$Expires = '2026-12-01') {
        $x = [ordered]@{ id = $Id; finding = $Finding; approver = 'CISO'; reason = 'test'; compensatingControls = 'test' }
        if ($Owner) { $x['owner'] = $Owner }
        if ($Approved) { $x['approved'] = $Approved }
        if ($Expires) { $x['expires'] = $Expires }
        return $x
    }
    function Write-JsonFile([string]$Path, $Object) { ConvertTo-Json -InputObject $Object -Depth 50 | Set-Content -LiteralPath $Path -Encoding utf8NoBOM; return $Path }
    function Read-JsonObject([string]$Path) { return (Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json -AsHashtable -Depth 50) }
}

Describe 'Compare-ConfigNode (deep diff)' {
    It 'reports changed, added and removed keys with their path' {
        $rows = @(Compare-ConfigNode -Before @{ a = 1; b = @{ c = 'x'; gone = 1 } } -After @{ a = 2; b = @{ c = 'x'; new = 1 } })
        @($rows | ForEach-Object { "$($_.Kind):$($_.Path)" } | Sort-Object) | Should -Be @('added:b/new', 'changed:a', 'removed:b/gone')
    }

    It 'matches named objects by identity, not position: reorder is nothing, rename is removed + added' {
        $b = @(@{ displayName = 'CA001'; state = 'enabled' }, @{ displayName = 'CA002'; state = 'enabled' })
        $a = @(@{ displayName = 'CA002'; state = 'enabled' }, @{ displayName = 'CA001'; state = 'enabled' })
        @(Compare-ConfigNode -Before $b -After $a -Path 'items').Count | Should -Be 0
        $rows = @(Compare-ConfigNode -Before $b -After @(@{ displayName = 'CA001'; state = 'enabled' }, @{ displayName = 'CA002 renamed'; state = 'enabled' }) -Path 'items')
        @($rows | ForEach-Object { "$($_.Kind):$($_.Path)" } | Sort-Object) | Should -Be @('added:items/CA002 renamed', 'removed:items/CA002')
    }

    It 'treats a scalar list as one value and ignores a null-vs-null' {
        $rows = @(Compare-ConfigNode -Before @{ ex = @('g1'); n = $null } -After @{ ex = @(); n = $null })
        $rows.Count | Should -Be 1
        $rows[0].Path | Should -Be 'ex'
        $rows[0].Before | Should -Be @('g1')
    }

    It 'keys PIM group items by group and role, directory roles by role name' {
        Get-ItemIdentity @{ groupMailNickname = 'pim-tier0-x'; roleDefinitionId = 'member'; id = 'Group_1_2' } | Should -Be 'pim-tier0-x:member'
        Get-ItemIdentity @{ roleDisplayName = 'Global Administrator'; id = 'DirectoryRole_1_2' } | Should -Be 'Global Administrator'
        Get-ItemIdentity @{ id = 'Expiration_EndUser_Assignment' } | Should -Be 'Expiration_EndUser_Assignment'
        Get-ItemIdentity 'scalar' | Should -BeNullOrEmpty
    }
}

Describe 'Get-DriftSeverity (the classification table)' {
    It '<Section> <Object>/<Attribute> <Kind> -> <Expected>' -ForEach @(
        @{ Section = 'conditionalAccessPolicies'; Object = 'CA003'; Attribute = 'state'; Kind = 'changed'; Expected = 'High' }
        @{ Section = 'conditionalAccessPolicies'; Object = 'CA001'; Attribute = 'conditions/users/excludeGroups'; Kind = 'changed'; Expected = 'High' }
        @{ Section = 'conditionalAccessPolicies'; Object = 'CA001'; Attribute = 'conditions/users/includeRoles'; Kind = 'changed'; Expected = 'High' }
        @{ Section = 'conditionalAccessPolicies'; Object = 'CA001'; Attribute = ''; Kind = 'removed'; Expected = 'High' }
        @{ Section = 'conditionalAccessPolicies'; Object = 'Microsoft-managed'; Attribute = ''; Kind = 'added'; Expected = 'Low' }
        @{ Section = 'conditionalAccessPolicies'; Object = 'CA002'; Attribute = 'grantControls/authenticationStrength/id'; Kind = 'changed'; Expected = 'Medium' }
        @{ Section = 'conditionalAccessPolicies'; Object = 'CA002'; Attribute = 'conditions/applications/includeApplications'; Kind = 'changed'; Expected = 'Medium' }
        @{ Section = 'conditionalAccessPolicies'; Object = 'CA002'; Attribute = 'description'; Kind = 'changed'; Expected = 'Low' }
        @{ Section = 'breakGlass'; Object = ''; Attribute = 'facts/holdsGlobalAdministrator'; Kind = 'changed'; Expected = 'High' }
        @{ Section = 'authenticationMethodsPolicy'; Object = ''; Attribute = 'policy/authenticationMethodConfigurations/Sms/state'; Kind = 'changed'; Expected = 'High' }
        @{ Section = 'authenticationMethodsPolicy'; Object = ''; Attribute = 'policy/registrationEnforcement/authenticationMethodsRegistrationCampaign/state'; Kind = 'changed'; Expected = 'High' }
        @{ Section = 'authenticationStrengths'; Object = 'Phishing-Resistant MFA (lab)'; Attribute = 'allowedCombinations'; Kind = 'changed'; Expected = 'High' }
        @{ Section = 'authenticationStrengths'; Object = 'Phishing-Resistant MFA (lab)'; Attribute = 'combinationConfigurations/x/allowedAAGUIDs'; Kind = 'changed'; Expected = 'High' }
        @{ Section = 'authenticationStrengths'; Object = 'Phishing-Resistant MFA (lab)'; Attribute = ''; Kind = 'removed'; Expected = 'High' }
        @{ Section = 'authenticationStrengths'; Object = 'New strength'; Attribute = ''; Kind = 'added'; Expected = 'Low' }
        @{ Section = 'namedLocations'; Object = 'Blocked Countries'; Attribute = 'countriesAndRegions'; Kind = 'changed'; Expected = 'Medium' }
        @{ Section = 'namedLocations'; Object = 'Operator egress (lab)'; Attribute = 'isTrusted'; Kind = 'changed'; Expected = 'Medium' }
        @{ Section = 'namedLocations'; Object = 'Blocked Countries'; Attribute = ''; Kind = 'removed'; Expected = 'Medium' }
        @{ Section = 'pimGroupPolicies'; Object = 'pim-tier0-security-admins:member'; Attribute = 'policy/rules/Expiration_EndUser_Assignment/maximumDuration'; Kind = 'changed'; Expected = 'High' }
        @{ Section = 'pimGroupPolicies'; Object = 'pim-tier0-security-admins:member'; Attribute = 'policy/rules/Enablement_EndUser_Assignment/enabledRules'; Kind = 'changed'; Expected = 'High' }
        @{ Section = 'pimGroupPolicies'; Object = 'pim-tier0-security-admins:member'; Attribute = 'policy/rules/Approval_EndUser_Assignment/setting/isApprovalRequired'; Kind = 'changed'; Expected = 'High' }
        @{ Section = 'pimDirectoryRolePolicies'; Object = 'Global Administrator'; Attribute = 'policy/rules/AuthenticationContext_EndUser_Assignment/isEnabled'; Kind = 'changed'; Expected = 'High' }
        @{ Section = 'pimDirectoryRolePolicies'; Object = 'Global Administrator'; Attribute = 'policy/rules/Expiration_Admin_Eligibility/maximumDuration'; Kind = 'changed'; Expected = 'Medium' }
        @{ Section = 'pimDirectoryRolePolicies'; Object = 'Global Administrator'; Attribute = 'policy/rules/Notification_Admin_EndUser_Assignment/notificationRecipientCount'; Kind = 'changed'; Expected = 'Low' }
        @{ Section = 'pimGroupPolicies'; Object = 'pim-tier1-x:member'; Attribute = ''; Kind = 'removed'; Expected = 'High' }
        @{ Section = 'consentPolicy'; Object = ''; Attribute = 'authorizationPolicy/defaultUserRolePermissions/permissionGrantPoliciesAssigned'; Kind = 'changed'; Expected = 'Medium' }
        @{ Section = 'appManagementPolicy'; Object = ''; Attribute = 'policy/isEnabled'; Kind = 'changed'; Expected = 'Medium' }
        @{ Section = 'appManagementPolicy'; Object = ''; Attribute = 'policy/displayName'; Kind = 'changed'; Expected = 'Low' }
        @{ Section = 'crossTenantAccessDefaults'; Object = ''; Attribute = 'policy/inboundTrust/isMfaAccepted'; Kind = 'changed'; Expected = 'Medium' }
    ) {
        Get-DriftSeverity -Section $Section -Object $Object -Attribute $Attribute -Kind $Kind | Should -Be $Expected
    }
}

Describe 'ConvertFrom-LabTfVarFile' {
    It 'reads the real lab.tfvars: every CA state and the blocked countries' {
        $t = ConvertFrom-LabTfVarFile -Text (Get-Content -LiteralPath $script:TfVars -Raw)
        $t.HasCaPolicyStates | Should -BeTrue
        $t.HasBlockedCountries | Should -BeTrue
        @($t.CaPolicyStates.Keys).Count | Should -BeGreaterOrEqual 15
        foreach ($k in 'CA001', 'CA004', 'CA021', 'CA060') { $t.CaPolicyStates.Contains($k) | Should -BeTrue -Because $k }
        foreach ($k in $t.CaPolicyStates.Keys) { $t.CaPolicyStates[$k] | Should -BeIn @('enabled', 'enabledForReportingButNotEnforced', 'disabled') }
        $t.BlockedCountries | Should -Be @('KP', 'IR', 'SY', 'CU')
    }

    It 'ignores comments and tolerates spacing' {
        $t = ConvertFrom-LabTfVarFile -Text "x = 1`nca_policy_states = {`n  CA001 = `"enabled`" # graduated`n  CA002   =  `"disabled`"`n}`nblocked_countries = [`"KP`"]`n"
        @($t.CaPolicyStates.Keys) | Should -Be @('CA001', 'CA002')
        $t.CaPolicyStates['CA001'] | Should -Be 'enabled'
        $t.BlockedCountries | Should -Be @('KP')
        (ConvertFrom-LabTfVarFile -Text 'nothing = 1').HasCaPolicyStates | Should -BeFalse
    }
}

Describe 'Get-IntentFinding (declared intent and break-glass invariants)' {
    BeforeAll {
        function New-Snapshot([object[]]$Policies, $Facts = $null, $Countries = $null) {
            $s = [ordered]@{ sections = [ordered]@{ conditionalAccessPolicies = [ordered]@{ status = 'ok'; items = @($Policies) } } }
            if ($null -ne $Countries) { $s['sections']['namedLocations'] = [ordered]@{ status = 'ok'; items = @(@{ displayName = 'Blocked Countries'; countriesAndRegions = @($Countries) }) } }
            if ($Facts) { $s['sections']['breakGlass'] = [ordered]@{ status = 'ok'; groupMailNickname = 'break-glass-admins'; facts = $Facts } }
            return $s
        }
        $script:Tf = @{ CaPolicyStates = [ordered]@{ CA001 = 'enabledForReportingButNotEnforced'; CA003 = 'enabledForReportingButNotEnforced'; CA060 = 'enabledForReportingButNotEnforced' }; BlockedCountries = @('KP', 'IR'); HasCaPolicyStates = $true; HasBlockedCountries = $true }
    }

    It 'a policy enabled in the tenant but declared report-only is High; the reverse too; an absent declared policy is not drift' {
        $snap = New-Snapshot @(@{ displayName = 'CA001 - Require MFA for all users'; state = 'enabled' }, @{ displayName = 'CA003 - Block legacy authentication'; state = 'enabledForReportingButNotEnforced' })
        $f = @(Get-IntentFinding -Snapshot $snap -TfVars $script:Tf)
        @($f | ForEach-Object { $_['key'] }) | Should -Be @('intent/ca/CA001/state')
        $f[0]['severity'] | Should -Be 'High'
        $f[0]['before'] | Should -Be 'enabledForReportingButNotEnforced'
        $f[0]['after'] | Should -Be 'enabled'
        $tf2 = @{ CaPolicyStates = [ordered]@{ CA003 = 'enabled' }; BlockedCountries = @(); HasCaPolicyStates = $true; HasBlockedCountries = $false }
        @(Get-IntentFinding -Snapshot $snap -TfVars $tf2 | ForEach-Object { $_['key'] }) | Should -Be @('intent/ca/CA003/state')
    }

    It 'a declared blocked country missing from the tenant is Medium, an extra one Low' {
        $snap = New-Snapshot @() -Countries @('IR', 'CU')
        $f = @(Get-IntentFinding -Snapshot $snap -TfVars $script:Tf)
        @($f | ForEach-Object { "$($_['severity']):$($_['key'])" }) | Should -Be @('Medium:intent/namedLocation/Blocked Countries/countries-missing', 'Low:intent/namedLocation/Blocked Countries/countries-extra')
        $f[0]['message'] | Should -Match 'KP'
    }

    It 'break-glass invariants: missing group, too few members, no Global Administrator, a policy without the exclusion - each High' {
        $facts = @{ groupFound = $true; enabledMemberCount = 1; holdsGlobalAdministrator = $false; notExcludedFromPolicies = @('CA004 - Block sign-in from blocked countries') }
        $f = @(Get-IntentFinding -Snapshot (New-Snapshot @() -Facts $facts) -TfVars $null)
        @($f | ForEach-Object { $_['key'] } | Sort-Object) | Should -Be @('breakGlass/CA004 - Block sign-in from blocked countries/not-excluded', 'breakGlass/global-administrator/missing', 'breakGlass/members/too-few')
        foreach ($x in $f) { $x['severity'] | Should -Be 'High' }
        $g = @(Get-IntentFinding -Snapshot (New-Snapshot @() -Facts @{ groupFound = $false; notExcludedFromPolicies = @('CA001') }) -TfVars $null)
        @($g | ForEach-Object { $_['key'] }) | Should -Be @('breakGlass/group/missing')
        @(Get-IntentFinding -Snapshot (New-Snapshot @() -Facts @{ groupFound = $true; enabledMemberCount = 2; holdsGlobalAdministrator = $true; notExcludedFromPolicies = @() }) -TfVars $null).Count | Should -Be 0
    }

    It 'a failed section yields no intent finding (Get-UnreadFinding reports it instead)' {
        $snap = [ordered]@{ sections = [ordered]@{ conditionalAccessPolicies = [ordered]@{ status = 'failed'; error = 'Forbidden' }; breakGlass = [ordered]@{ status = 'failed'; error = 'x' } } }
        @(Get-IntentFinding -Snapshot $snap -TfVars $script:Tf).Count | Should -Be 0
        $u = @(Get-UnreadFinding -Snapshot $snap)
        @($u | ForEach-Object { $_['key'] }) | Should -Be @('section/conditionalAccessPolicies/unread', 'section/breakGlass/unread')
        $u[0]['severity'] | Should -Be 'Medium'
        $u[0]['message'] | Should -Match 'Forbidden'
    }
}

Describe 'Exceptions (drift-exceptions.json)' {
    It 'Test-DriftException: owner, dates, id format and the 90 / 180-day term' {
        @(Test-DriftException -Exception (New-Exception -Finding 'x') -Severity 'High').Count | Should -Be 0                      # 61 days
        @(Test-DriftException -Exception (New-Exception -Finding 'x' -Owner '') -Severity 'High') | Should -Contain 'owner missing'
        @(Test-DriftException -Exception (New-Exception -Finding 'x' -Expires '') -Severity 'High') | Should -Contain 'expires missing'
        @(Test-DriftException -Exception (New-Exception -Id 'EX' -Finding 'x') -Severity 'Low') | Should -Contain 'id must look like E12 (exception-process.md register)'
        @(Test-DriftException -Exception (New-Exception -Finding 'x' -Expires '2026-09-01') -Severity 'Low') | Should -Contain 'expires before approved'
        @(Test-DriftException -Exception (New-Exception -Finding 'x' -Expires '2027-01-01') -Severity 'High') | Should -Contain "term exceeds the standard's 90 days for a High finding"   # 92 days
        @(Test-DriftException -Exception (New-Exception -Finding 'x' -Expires '2027-01-01') -Severity 'Medium').Count | Should -Be 0
        @(Test-DriftException -Exception (New-Exception -Finding 'x' -Expires '2027-04-01') -Severity 'Low') | Should -Contain "term exceeds the standard's 180 days for a Low finding"
        @(Test-DriftException -Exception (New-Exception -Finding 'x' -Approved 'soon') -Severity 'Low') | Should -Contain 'approved is not a date'
    }

    It 'Resolve-DriftException: a valid entry excepts the finding (through its expiry date), an expired one reactivates it, a bad one is ignored and listed, wildcards match' {
        $findings = @((New-Finding 'conditionalAccessPolicies/CA010 - x/conditions/users/excludeGroups'), (New-Finding 'conditionalAccessPolicies/MS-managed/added' 'Low'), (New-Finding 'namedLocations/x/isTrusted' 'Medium'), (New-Finding 'other/thing' 'Medium'))
        $exceptions = @(
            (New-Exception -Id 'E60' -Finding 'conditionalAccessPolicies/CA010 - x/conditions/users/excludeGroups' -Expires '2026-10-26'),   # valid through today
            (New-Exception -Id 'E61' -Finding 'conditionalAccessPolicies/*/added' -Expires '2027-03-01'),                                     # wildcard, Low: 151 days ok
            (New-Exception -Id 'E62' -Finding 'namedLocations/x/isTrusted' -Expires '2026-10-25'),                                            # expired yesterday
            (New-Exception -Id 'E63' -Finding 'other/thing' -Owner '')                                                                        # invalid
        )
        $r = Resolve-DriftException -Findings $findings -Exceptions $exceptions -AsOf $script:Today
        $by = @{}; foreach ($f in $r.Findings) { $by[$f['key']] = $f }
        $by['conditionalAccessPolicies/CA010 - x/conditions/users/excludeGroups']['status'] | Should -Be 'excepted'
        $by['conditionalAccessPolicies/CA010 - x/conditions/users/excludeGroups']['exception'] | Should -Match '^E60 \(owner IAM Eng, expires 2026-10-26\)$'
        $by['conditionalAccessPolicies/MS-managed/added']['status'] | Should -Be 'excepted'
        $by['namedLocations/x/isTrusted']['status'] | Should -Be 'open'
        $by['namedLocations/x/isTrusted']['exception'] | Should -Match 'E62 expired 2026-10-25'
        $by['other/thing']['status'] | Should -Be 'open'
        $by['other/thing']['exception'] | Should -Match 'E63 ignored: owner missing'
        @($r.Ignored).Count | Should -Be 1
        $r.Ignored[0]['id'] | Should -Be 'E63'
        # The day after: E60 is expired, the High finding is back.
        $r2 = Resolve-DriftException -Findings @((New-Finding 'conditionalAccessPolicies/CA010 - x/conditions/users/excludeGroups')) -Exceptions $exceptions -AsOf $script:Today.AddDays(1)
        $r2.Findings[0]['status'] | Should -Be 'open'
        Get-DriftExitCode -Findings $r.Findings | Should -Be 1      # the expired Medium is open; the High is excepted
        Get-DriftExitCode -Findings $r2.Findings | Should -Be 2
        Get-DriftExitCode -Findings @((New-Finding 'a' 'Low' | ForEach-Object { $_['status'] = 'open'; $_ })) | Should -Be 0
        Get-DriftExitCode -Findings @() | Should -Be 0
    }

    It 'the committed register is valid JSON with an empty, well-formed list' {
        $x = Read-JsonObject $script:ExceptionsFile
        $x['schema'] | Should -Be 'contoso-identity-drift-exceptions/v1'
        @($x['exceptions']).Count | Should -Be 0
    }
}

Describe 'ConvertTo-DriftMarkdown' {
    It 'escapes pipes, lists every severity, excepted and ignored entries' {
        $f1 = New-Finding 'a/b|c' 'High'; $f1['status'] = 'open'; $f1['exception'] = ''; $f1['message'] = 'pipe | inside'
        $f2 = New-Finding 'low/one' 'Low'; $f2['status'] = 'excepted'; $f2['exception'] = 'E60 (owner IAM Eng, expires 2026-12-01)'
        $report = [ordered]@{ generatedAtUtc = '2026-10-26T01:02:03Z'; snapshot = @{ file = 's.json'; source = 'tenant'; identifiers = 'hashed' }; baseline = @{ status = 'ok'; file = 'identity-config.json'; generatedAtUtc = '2026-10-20T00:00:00Z' }
            intent = @{ checked = $true; tfvars = 'lab/terraform/envs/dev/lab.tfvars' }; summary = @{ open = @{ High = 1; Medium = 0; Low = 0 }; excepted = @{ High = 0; Medium = 0; Low = 1 }; exitCode = 2 }
            findings = @($f1, $f2); exceptionsIgnored = @(@{ id = 'E63'; finding = 'x'; reasons = @('owner missing') }) }
        $md = ConvertTo-DriftMarkdown -Report $report
        $md | Should -Match '## Identity configuration drift - 2026-10-26'
        $md | Should -Match '\| High \| 1 \| 0 \|'
        $md | Should -Match '### High \(1\)'
        $md | Should -Match '`a/b\\\|c`'
        $md | Should -Match 'pipe \\\| inside'
        $md | Should -Match 'none: nightly only'
        $md | Should -Match '### Excepted \(1\)'
        $md | Should -Match '### Exceptions ignored \(1\)'
        $md | Should -Match 'Exit code \*\*2\*\*'
    }
}

Describe 'Compare-IdentityConfig.ps1 end to end (snapshots from the offline export)' {
    BeforeAll {
        Mock Write-Host {}
        $script:CleanDir = Join-Path $TestDrive 'clean'
        $null = & $script:Export -Offline -Public -FixturePath $script:FixturePath -OutputDirectory $script:CleanDir
        $script:CleanPath = @(Get-ChildItem -LiteralPath $script:CleanDir -Filter '*.json')[0].FullName
        $script:Counter = 0
        function New-DriftedSnapshot([scriptblock]$Mutate) {
            $j = Read-JsonObject $script:CleanPath
            & $Mutate $j
            $script:Counter++
            return (Write-JsonFile (Join-Path $TestDrive "drift-$($script:Counter).json") $j)
        }
        function Invoke-Compare([string]$Snapshot, [string]$Baseline = $script:CleanPath, [string]$Exceptions = $script:ExceptionsFile, [switch]$SkipIntent) {
            # Declared intent comes from the fixture tfvars (all report-only), not the live lab.tfvars: a graduation must not fail this suite.
            $fixtureTfVars = Join-Path $PSScriptRoot 'fixtures' 'lab.fixture.tfvars'
            $global:LASTEXITCODE = 0
            $script:Counter++
            $md = Join-Path $TestDrive "out-$($script:Counter).md"; $json = Join-Path $TestDrive "out-$($script:Counter).json"
            $null = & $script:Compare -SnapshotPath $Snapshot -BaselinePath $Baseline -ExceptionsPath $Exceptions -MarkdownPath $md -JsonPath $json -AsOf $script:Today -WarningAction SilentlyContinue -TfVarsPath $fixtureTfVars -SkipIntent:$SkipIntent
            $r = @{ Exit = $LASTEXITCODE; Md = $md; Json = $json; Report = $null; Keys = @() }
            if (Test-Path -LiteralPath $json) { $r.Report = Read-JsonObject $json; $r.Keys = @($r.Report['findings'] | ForEach-Object { "$($_['severity']):$($_['status']):$($_['key'])" }) }
            return $r
        }
        $script:CaName = @{ CA001 = 'CA001 - Require MFA for all users'; CA003 = 'CA003 - Block legacy authentication' }
    }

    It 'against the committed placeholder: exit 0, "no baseline yet", intent and unread checks still run' {
        $r = Invoke-Compare -Snapshot $script:CleanPath -Baseline $script:Placeholder
        $r.Exit | Should -Be 0
        $r.Report['baseline']['status'] | Should -Be 'no-baseline'
        $r.Report['intent']['checked'] | Should -BeTrue
        @($r.Report['findings']).Count | Should -Be 0
        (Get-Content -LiteralPath $r.Md -Raw) | Should -Match 'no baseline yet'
        # intent still runs without a baseline
        $drift = New-DriftedSnapshot { param($j) ($j['sections']['conditionalAccessPolicies']['items'] | Where-Object { $_['displayName'] -like 'CA003*' })['state'] = 'enabled' }
        $r2 = Invoke-Compare -Snapshot $drift -Baseline $script:Placeholder
        $r2.Exit | Should -Be 2
        $r2.Keys | Should -Be @('High:open:intent/ca/CA003/state')
    }

    It 'a snapshot against itself: no findings, exit 0' {
        $r = Invoke-Compare -Snapshot $script:CleanPath
        $r.Exit | Should -Be 0
        @($r.Report['findings']).Count | Should -Be 0
        $r.Report['baseline']['status'] | Should -Be 'ok'
        (Get-Content -LiteralPath $r.Md -Raw) | Should -Match 'No drift found'
    }

    It 'High drift of every Tier-0 kind is found, keyed and classified, with the real-time twin; exit 2' {
        $drift = New-DriftedSnapshot {
            param($j)
            $ca = $j['sections']['conditionalAccessPolicies']['items']
            ($ca | Where-Object { $_['displayName'] -like 'CA003*' })['state'] = 'enabled'
            ($ca | Where-Object { $_['displayName'] -like 'CA001*' })['conditions']['users']['excludeGroups'] = @()
            $j['sections']['breakGlass']['facts']['notExcludedFromPolicies'] = @($script:CaName.CA001)
            $j['sections']['breakGlass']['facts']['excludedFromPolicies'] = @($j['sections']['breakGlass']['facts']['excludedFromPolicies'] | Where-Object { $_ -ne $script:CaName.CA001 })
            $j['sections']['breakGlass']['facts']['holdsGlobalAdministrator'] = $false
            $g = $j['sections']['pimGroupPolicies']['items'] | Where-Object { $_['groupMailNickname'] -eq 'pim-tier0-security-admins' }
            ($g['policy']['rules'] | Where-Object { $_['id'] -eq 'Expiration_EndUser_Assignment' })['maximumDuration'] = 'PT8H'
            ($g['policy']['rules'] | Where-Object { $_['id'] -eq 'Approval_EndUser_Assignment' })['setting']['isApprovalRequired'] = $false
            ($j['sections']['authenticationMethodsPolicy']['policy']['authenticationMethodConfigurations'] | Where-Object { $_['id'] -eq 'Sms' })['state'] = 'enabled'
            ($j['sections']['authenticationStrengths']['items'] | Where-Object { $_['displayName'] -eq 'Phishing-Resistant MFA (lab)' })['allowedCombinations'] += 'password,sms'
            $j['sections']['pimDirectoryRolePolicies']['items'] = @()
        }
        $r = Invoke-Compare -Snapshot $drift
        $r.Exit | Should -Be 2
        $r.Keys | Should -Contain "High:open:conditionalAccessPolicies/$($script:CaName.CA003)/state"
        $r.Keys | Should -Contain "High:open:intent/ca/CA003/state"
        $r.Keys | Should -Contain "High:open:conditionalAccessPolicies/$($script:CaName.CA001)/conditions/users/excludeGroups"
        $r.Keys | Should -Contain "High:open:breakGlass/$($script:CaName.CA001)/not-excluded"
        $r.Keys | Should -Contain 'High:open:breakGlass/global-administrator/missing'
        $r.Keys | Should -Contain 'High:open:breakGlass/facts/holdsGlobalAdministrator'
        $r.Keys | Should -Contain 'High:open:pimGroupPolicies/pim-tier0-security-admins:member/policy/rules/Expiration_EndUser_Assignment/maximumDuration'
        $r.Keys | Should -Contain 'High:open:pimGroupPolicies/pim-tier0-security-admins:member/policy/rules/Approval_EndUser_Assignment/setting/isApprovalRequired'
        $r.Keys | Should -Contain 'High:open:authenticationMethodsPolicy/policy/authenticationMethodConfigurations/Sms/state'
        $r.Keys | Should -Contain 'High:open:authenticationStrengths/Phishing-Resistant MFA (lab)/allowedCombinations'
        $r.Keys | Should -Contain 'High:open:pimDirectoryRolePolicies/Global Administrator/removed'
        # derived exclusion lists are not reported twice
        $r.Keys | Should -Not -Contain 'High:open:breakGlass/facts/notExcludedFromPolicies'
        $ca3 = @($r.Report['findings'] | Where-Object { $_['key'] -eq "conditionalAccessPolicies/$($script:CaName.CA003)/state" })[0]
        $ca3['before'] | Should -Be 'enabledForReportingButNotEnforced'
        $ca3['after'] | Should -Be 'enabled'
        $ca3['twin'] | Should -Be 'lab/kql/ca-policy-changed.kql'
        $r.Report['summary']['open']['High'] | Should -Be 11
        $r.Report['summary']['exitCode'] | Should -Be 2
    }

    It 'Medium-only drift exits 1; Low-only (a policy added) exits 0 but is listed' {
        $medium = New-DriftedSnapshot {
            param($j)
            ($j['sections']['namedLocations']['items'] | Where-Object { $_['displayName'] -eq 'Blocked Countries' })['countriesAndRegions'] = @('CU', 'IR')
            $j['sections']['consentPolicy']['adminConsentRequestPolicy']['isEnabled'] = $false
            ($j['sections']['conditionalAccessPolicies']['items'] | Where-Object { $_['displayName'] -like 'CA001*' })['grantControls']['builtInControls'] = @('mfa', 'compliantDevice')
        }
        $r = Invoke-Compare -Snapshot $medium
        $r.Exit | Should -Be 1
        $r.Keys | Should -Be @(
            'Medium:open:conditionalAccessPolicies/CA001 - Require MFA for all users/grantControls/builtInControls',
            'Medium:open:consentPolicy/adminConsentRequestPolicy/isEnabled',
            'Medium:open:intent/namedLocation/Blocked Countries/countries-missing',
            'Medium:open:namedLocations/Blocked Countries/countriesAndRegions')
        $low = New-DriftedSnapshot { param($j) $j['sections']['conditionalAccessPolicies']['items'] += [ordered]@{ displayName = 'Microsoft-managed: Multifactor authentication for admins'; state = 'enabledForReportingButNotEnforced'; conditions = @{ users = @{ excludeGroups = @('h:cf7c6ea9f36fd885') } } } }
        $r2 = Invoke-Compare -Snapshot $low
        $r2.Exit | Should -Be 0
        $r2.Keys | Should -Be @('Low:open:conditionalAccessPolicies/Microsoft-managed: Multifactor authentication for admins/added')
        (Get-Content -LiteralPath $r2.Md -Raw) | Should -Match '### Low \(1\)'
    }

    It 'a section the export could not read is a Medium finding and exit 1, never silence' {
        $unread = New-DriftedSnapshot { param($j) $j['sections']['crossTenantAccessDefaults'] = [ordered]@{ status = 'failed'; error = 'Forbidden' }; $j['failedSections'] = @('crossTenantAccessDefaults') }
        $r = Invoke-Compare -Snapshot $unread
        $r.Exit | Should -Be 1
        $r.Keys | Should -Be @('Medium:open:section/crossTenantAccessDefaults/unread')
        (Get-Content -LiteralPath $r.Md -Raw) | Should -Match 'could not be read; their drift is unknown, not absent'
    }

    It 'a valid exception takes a High finding out of the exit code; expired or malformed ones do not' {
        $drift = New-DriftedSnapshot { param($j) ($j['sections']['conditionalAccessPolicies']['items'] | Where-Object { $_['displayName'] -like 'CA001*' })['conditions']['users']['excludeGroups'] += 'h:0000000000000001' }
        $key = "conditionalAccessPolicies/$($script:CaName.CA001)/conditions/users/excludeGroups"
        $valid = Write-JsonFile (Join-Path $TestDrive 'exc-valid.json') @{ schema = 'contoso-identity-drift-exceptions/v1'; exceptions = @((New-Exception -Id 'E60' -Finding $key -Approved '2026-10-20' -Expires '2027-01-18')) }
        $r = Invoke-Compare -Snapshot $drift -Exceptions $valid
        $r.Exit | Should -Be 0
        $r.Keys | Should -Be @("High:excepted:$key")
        $r.Report['summary']['excepted']['High'] | Should -Be 1
        (Get-Content -LiteralPath $r.Md -Raw) | Should -Match '### Excepted \(1\)'
        $expired = Write-JsonFile (Join-Path $TestDrive 'exc-expired.json') @{ exceptions = @((New-Exception -Id 'E60' -Finding $key -Approved '2026-07-01' -Expires '2026-09-28')) }
        $r2 = Invoke-Compare -Snapshot $drift -Exceptions $expired
        $r2.Exit | Should -Be 2
        $r2.Report['findings'][0]['exception'] | Should -Match 'E60 expired 2026-09-28'
        $tooLong = Write-JsonFile (Join-Path $TestDrive 'exc-long.json') @{ exceptions = @((New-Exception -Id 'E60' -Finding $key -Approved '2026-10-20' -Expires '2027-04-01')) }
        $r3 = Invoke-Compare -Snapshot $drift -Exceptions $tooLong
        $r3.Exit | Should -Be 2
        $r3.Report['exceptionsIgnored'][0]['id'] | Should -Be 'E60'
        (Get-Content -LiteralPath $r3.Md -Raw) | Should -Match '### Exceptions ignored \(1\)'
    }

    It 'Markdown and JSON from a public snapshot carry no object id, UPN, mailbox or IP' {
        $drift = New-DriftedSnapshot {
            param($j)
            ($j['sections']['conditionalAccessPolicies']['items'] | Where-Object { $_['displayName'] -like 'CA001*' })['conditions']['users']['excludeGroups'] = @()
            ($j['sections']['namedLocations']['items'] | Where-Object { $_['displayName'] -like 'Operator*' })['isTrusted'] = $false
            $j['sections']['consentPolicy']['adminConsentRequestPolicy']['reviewers'] = @()
        }
        $r = Invoke-Compare -Snapshot $drift
        foreach ($p in $r.Md, $r.Json) {
            $text = Get-Content -LiteralPath $p -Raw
            $text | Should -Not -Match '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+'
            $text | Should -Not -Match '[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}'
            $text | Should -Not -Match '\b\d{1,3}(\.\d{1,3}){3}\b|onmicrosoft|bg-admin'
            @(Test-PublicRecordSafe -Json $text).Count | Should -Be 0
        }
        $r.Report['schema'] | Should -Be 'contoso-identity-drift/v1'
        $r.Report['snapshot']['sha256'] | Should -Be (Get-FileHash -LiteralPath $drift -Algorithm SHA256).Hash.ToLowerInvariant()
    }

    It 'unusable inputs exit 3 (never 1 or 2): public mismatch, wrong schema, missing snapshot' {
        $idsDir = Join-Path $TestDrive 'ids'
        $null = & $script:Export -Offline -FixturePath $script:FixturePath -OutputDirectory $idsDir
        $ids = @(Get-ChildItem -LiteralPath $idsDir -Filter '*.json')[0].FullName
        (Invoke-Compare -Snapshot $ids).Exit | Should -Be 3
        $bad = Write-JsonFile (Join-Path $TestDrive 'bad.json') @{ schema = 'something-else' }
        (Invoke-Compare -Snapshot $bad).Exit | Should -Be 3
        (Invoke-Compare -Snapshot (Join-Path $TestDrive 'missing.json')).Exit | Should -Be 3
        (Invoke-Compare -Snapshot $script:CleanPath -Baseline $bad).Exit | Should -Be 3
    }

    It '-SkipIntent compares the baseline only' {
        $drift = New-DriftedSnapshot { param($j) ($j['sections']['conditionalAccessPolicies']['items'] | Where-Object { $_['displayName'] -like 'CA003*' })['state'] = 'enabled' }
        $r = Invoke-Compare -Snapshot $drift -SkipIntent
        $r.Exit | Should -Be 2
        $r.Keys | Should -Be @("High:open:conditionalAccessPolicies/$($script:CaName.CA003)/state")
        $r.Report['intent']['checked'] | Should -BeFalse
    }
}
