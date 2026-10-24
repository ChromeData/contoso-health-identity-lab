# Pester 5 tests for Invoke-LabDay.ps1, the trial-window day runner, and what
# it reads and writes: the plan as data (evidence/LabDayPlan.psd1) and the
# read-only capture helpers (evidence/LabEvidence.psm1).
#
# Offline and deterministic. Every lab script the plan calls is a STUB
# generated from the real script's param block, attributes included: a
# parameter the plan passes that the script does not declare, or a value its
# ValidateSet / ValidatePattern refuses, makes PowerShell refuse the call, so
# "every call binds" is checked, not assumed. Every Microsoft Graph read
# (Invoke-MgGraphRequest) and every az / gh read (Invoke-LabNativeCommand) is
# a Pester mock, and so is every operator prompt. Nothing signs in, nothing is
# sent, nothing is written inside the repository.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    $script:LabDay = Get-LabScriptPath 'Invoke-LabDay.ps1'
    $script:RealPlan = Get-LabScriptPath 'evidence/LabDayPlan.psd1'
    $script:RealLab = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..' '..' '..'))
    # Imported once, from the path the runner imports it from: the runner then
    # keeps this copy, and the -ModuleName mocks below stay in place.
    Import-Module (Get-LabScriptPath 'evidence/LabEvidence.psm1') -Force -DisableNameChecking
    # The runner's own functions (the plan loader, placeholder expansion) for
    # the checks that need no run.
    . (Get-ScriptFunctionBlock -Path $script:LabDay)

    $script:WindowPlan = Import-LabDayPlan -Path $script:RealPlan
    $script:AllSpecs = @($script:WindowPlan.Steps | ForEach-Object { $_.Capture; $_.CaptureBefore } | Where-Object { $_ })

    function New-LabDayStubRoot {
        # A lab/ tree holding every script the plan calls (and 00-Preflight.ps1)
        # as a stub with the REAL param block. Each call appends one JSON line
        # to $env:LABDAY_TEST_LOG and exits with the code $env:LABDAY_TEST_EXIT
        # maps to its path (0 otherwise). Plus the two files the computed
        # placeholders look for.
        param([Parameter(Mandatory)][string]$Root)
        $rels = @(@($script:WindowPlan.Steps | Where-Object { $_.Kind -eq 'script' } | ForEach-Object { $_.Script }) + 'scripts/powershell/00-Preflight.ps1' | Sort-Object -Unique)
        foreach ($rel in $rels) {
            $ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $script:RealLab $rel), [ref]$null, [ref]$null)
            # [CmdletBinding(...)] sits on the param block but outside its extent.
            $attrs = @($ast.ParamBlock.Attributes | ForEach-Object { $_.Extent.Text }) -join [Environment]::NewLine
            $body = @"
$attrs
$($ast.ParamBlock.Extent.Text)
`$rec = [ordered]@{ script = '$rel'; params = @(`$PSBoundParameters.Keys | Sort-Object); whatIf = [bool]`$WhatIfPreference; values = [ordered]@{} }
foreach (`$k in @(`$PSBoundParameters.Keys | Sort-Object)) {
    `$v = `$PSBoundParameters[`$k]
    if (`$v -is [switch]) { `$v = [bool]`$v } elseif (`$v -is [datetime]) { `$v = `$v.ToUniversalTime().ToString('o') }
    `$rec.values[`$k] = `$v
}
Add-Content -LiteralPath `$env:LABDAY_TEST_LOG -Value (`$rec | ConvertTo-Json -Compress -Depth 6) -WhatIf:`$false -Confirm:`$false
Write-Output 'stub: $rel'
`$code = 0
if (`$env:LABDAY_TEST_EXIT) { `$map = `$env:LABDAY_TEST_EXIT | ConvertFrom-Json -AsHashtable; if (`$map.ContainsKey('$rel')) { `$code = [int]`$map['$rel'] } }
exit `$code
"@
            $dest = Join-Path $Root $rel
            New-Item -ItemType Directory -Path (Split-Path -Parent $dest) -Force | Out-Null
            Set-Content -LiteralPath $dest -Value $body -Encoding utf8NoBOM
        }
        $kpi = Join-Path $Root 'evidence' 'kpis'
        $restore = Join-Path $Root 'evidence' 'out' 'ca-restore'
        New-Item -ItemType Directory -Path $kpi, $restore -Force | Out-Null
        $script:KpiBaselineFile = Join-Path $kpi '20261101T100000Z.json'
        Set-Content -LiteralPath $script:KpiBaselineFile -Value '{"label":"baseline"}' -Encoding utf8NoBOM
        $script:SnapshotFile = Join-Path $restore 'ca-policies-20261118T100000Z.json'
        Set-Content -LiteralPath $script:SnapshotFile -Value '[]' -Encoding utf8NoBOM
    }

    function New-LabDayBox {
        # Fresh settings, state, evidence root and capture log under TestDrive.
        # The stub tree is shared: the runner only reads it.
        param([string]$Plan = $script:RealPlan)
        $dir = Join-Path $TestDrive ('box-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        $box = @{
            Dir = $dir; Lab = $script:StubLab; Plan = $Plan; Settings = (Join-Path $dir 'settings.json')
            State = (Join-Path $dir 'state' 'state.json'); Evidence = (Join-Path $dir 'evidence' 'tenant'); Log = (Join-Path $dir 'evidence' 'capture-log.csv')
        }
        # Names and ids only, as in the real settings file; the change ticket
        # stays empty so the runner asks for it.
        [ordered]@{
            OnMicrosoftDomain = 'contosolab.onmicrosoft.com'; Domain = 'contosohealth.test'
            KeyVaultName = 'kv-idlab-test'; EvidenceStorageAccount = 'stidlabevidence'
            ProvisioningServicePrincipalId = '22222222-2222-2222-2222-222222222222'; ProvisioningJobId = 'API2AD.test'
            E5SkuPartNumber = 'SPE_E5'; ServiceNowInstance = 'dev000000'; ServiceNowUser = 'svc-integration'
            TeamsGroupId = '33333333-3333-3333-3333-333333333333'; TeamsChannelId = '19:lab@thread.tacv2'
            PilotUpn = 'adm-ava.lin@contosolab.onmicrosoft.com'; VipUserPrincipalNames = @('cno@contosohealth.test')
            Operator = 'MW'; CaRestorePolicyName = 'CA004 - Block countries'
        } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $box.Settings -Encoding utf8NoBOM
        $env:LABDAY_TEST_LOG = Join-Path $dir 'calls.jsonl'
        $env:LABDAY_TEST_EXIT = ''
        return $box
    }

    function Invoke-LabDayRun {
        # One run of the REAL runner against the stub tree; returns its exit code.
        param([Parameter(Mandatory)][hashtable]$Box, [Parameter(Mandatory)][hashtable]$Arguments)
        $global:LASTEXITCODE = 0
        $null = & $script:LabDay @Arguments -LabRoot $Box.Lab -PlanPath $Box.Plan -SettingsPath $Box.Settings -StatePath $Box.State `
            -EvidenceRoot $Box.Evidence -CaptureLogPath $Box.Log -WarningAction SilentlyContinue
        return $LASTEXITCODE
    }

    function Get-LabDayCall {
        # The stub calls of the current box, in order.
        if (-not (Test-Path -LiteralPath $env:LABDAY_TEST_LOG)) { return @() }
        return @(Get-Content -LiteralPath $env:LABDAY_TEST_LOG | ForEach-Object { $_ | ConvertFrom-Json })
    }

    function Get-LabDayState {
        param([Parameter(Mandatory)][hashtable]$Box)
        return (Get-Content -LiteralPath $Box.State -Raw | ConvertFrom-Json -AsHashtable)
    }

    function Get-LabDayString {
        # Every string inside a plan value (strings, arrays, hashtables).
        param($Value)
        if ($null -eq $Value) { return }
        if ($Value -is [string]) { return $Value }
        if ($Value -is [System.Collections.IDictionary]) { foreach ($k in $Value.Keys) { Get-LabDayString -Value $Value[$k] }; return }
        if ($Value -is [System.Collections.IEnumerable]) { foreach ($v in $Value) { Get-LabDayString -Value $v } }
    }

    function Set-LabDayMocks {
        # Graph, az / gh, the console and the operator, all mocked. Prompts
        # are answered from Answers (a queue) first, then by the usual "go on"
        # answer for the prompt; anything else fails the test.
        $global:LabDayTest = @{
            Graph = [System.Collections.Generic.List[object]]::new()
            Native = [System.Collections.Generic.List[string]]::new()
            Prompts = [System.Collections.Generic.List[string]]::new()
            Inputs = [System.Collections.Generic.List[string]]::new()
            Console = [System.Collections.Generic.List[string]]::new()
            Answers = [System.Collections.Generic.Queue[string]]::new()
            Scopes = @(Get-LabCaptureScope -Specs $script:AllSpecs)
            GraphThrows = ''
            GhList = '[]'
        }
        Mock Write-Host { $global:LabDayTest.Console.Add("$Object") }
        Mock Write-Host -ModuleName LabEvidence { $global:LabDayTest.Console.Add("$Object") }
        Mock Out-Host {}
        Mock Read-Host { throw 'tests must not prompt' }
        Mock Read-Host -ModuleName LabEvidence { throw 'tests must not prompt' }
        Mock Connect-MgGraph { throw 'tests must never connect' }
        Mock Get-MgContext -ModuleName LabEvidence { [pscustomobject]@{ Scopes = $global:LabDayTest.Scopes } }
        Mock Read-LabOperatorChoice {
            $p = $Prompt.Trim()
            $global:LabDayTest.Prompts.Add($p)
            if ($global:LabDayTest.Answers.Count) { return $global:LabDayTest.Answers.Dequeue() }
            switch -Regex ($p) {
                '^Optional step' { return 'run' }
                '^When it is done' { return 'done' }
                '^Run it for real' { return 'yes' }
                '^Preflight' { return 'yes' }
                default { throw "unexpected prompt in test: $p" }
            }
        }
        Mock Read-LabOperatorInput { $global:LabDayTest.Inputs.Add($Prompt.Trim()); if ('CHG0001234' -match $Pattern) { 'CHG0001234' } else { 'CA004 - Block countries' } }
        Mock Invoke-MgGraphRequest -ModuleName LabEvidence {
            $global:LabDayTest.Graph.Add([pscustomobject]@{ Method = [string]$Method; Uri = [string]$Uri })
            if ($global:LabDayTest.GraphThrows) { throw $global:LabDayTest.GraphThrows }
            $u = [uri]::UnescapeDataString([string]$Uri)
            $now = [datetime]::UtcNow.ToString('o')
            switch -Regex ($u) {
                '/groups\?' { return @{ value = @(@{ id = 'grp-tier0'; displayName = 'PIM-Tier0-CA-Admins'; mailNickname = 'pim-tier0-ca-admins' }) } }
                '/identity/conditionalAccess/policies' {
                    return @{ value = @(
                            @{ id = 'pol-1'; displayName = 'CA001 - Require MFA for all users'; state = 'enabledForReportingButNotEnforced' }
                            @{ id = 'pol-2'; displayName = 'CA003 - Block legacy authentication'; state = 'enabled' }) }
                }
                '/authenticationContextClassReferences' { return @{ value = @(@{ id = 'c1'; isAvailable = $true }) } }
                '/privilegedAccess/group/eligibilitySchedules' { return @{ value = @(@{ id = 'sch-1'; groupId = 'grp-tier0'; scheduleInfo = @{ expiration = @{ type = 'afterDateTime' } } }) } }
                '/administrativeUnits\?' { return @{ value = @(@{ id = 'au-1'; displayName = 'AU-Workforce-Standard'; membershipType = 'Dynamic' }) } }
                '/accessPackages\?' { return @{ value = @(@{ id = 'ap-1'; displayName = 'Nurse - Clinical Apps'; assignmentPolicies = @(@{ id = 'apol-1'; automaticRequestSettings = @{ requestAccessForAllowedTargets = $true } }) }) } }
                '/accessReviews/definitions$' { return @{ value = @(@{ id = 'def-1'; displayName = 'T1 - PIM-Tier0-CA-Admins'; status = 'InProgress' }) } }
                '/instances$' { return @{ value = @(@{ id = 'inst-1'; status = 'InProgress' }) } }
                '/decisions$' { return @{ value = @(@{ id = 'dec-1'; decision = 'Deny'; applyResult = 'New'; principal = @{ userPrincipalName = 'dana.okafor@contosohealth.test' } }) } }
                '/auditLogs/signIns' {
                    return @{ value = @(@{ id = 'si-1'; createdDateTime = $now; userPrincipalName = 'tst-a@contosolab.onmicrosoft.com'; ipAddress = '203.0.113.10'; status = @{ errorCode = 0 }
                                appliedConditionalAccessPolicies = @(@{ displayName = 'CA001 - Require MFA for all users'; result = 'reportOnlySuccess' }) }) }
                }
                '/auditLogs/directoryAudits' { return @{ value = @(@{ id = 'ev-1'; activityDateTime = $now; activityDisplayName = 'Add member to group'; initiatedBy = @{ user = @{ userPrincipalName = 'admin@contosolab.onmicrosoft.com'; ipAddress = '203.0.113.10' } } }) } }
                '/policies/authenticationMethodsPolicy' { return @{ id = 'authenticationMethodsPolicy'; authenticationMethodConfigurations = @(@{ id = 'Fido2'; state = 'enabled' }) } }
                '/policies/authorizationPolicy' { return @{ id = 'authorizationPolicy'; allowInvitesFrom = 'adminsAndGuestInviters' } }
                '/adminConsentRequestPolicy|/defaultAppManagementPolicy' { return @{ isEnabled = $true } }
                '/directory/subscriptions' { return @{ value = @(@{ skuPartNumber = 'SPE_E5'; isTrial = $true; status = 'Enabled'; nextLifecycleDateTime = '2026-12-01T00:00:00Z' }) } }
                default { return @{ value = @() } }
            }
        }
        Mock Invoke-LabNativeCommand -ModuleName LabEvidence {
            # The read-only allowlist still decides; only the process is mocked.
            Assert-LabReadOnlyCommand -FilePath $FilePath -ArgumentList $ArgumentList
            $line = "$FilePath $($ArgumentList -join ' ')"
            $global:LabDayTest.Native.Add($line)
            $now = [datetime]::UtcNow.ToString('o')
            $out = switch -Regex ($line) {
                '^az monitor log-analytics workspace show' { '{"customerId":"ws-cust","id":"/subscriptions/sub-0000/resourceGroups/rg-identity-lab/providers/Microsoft.OperationalInsights/workspaces/loga-idlab"}' }
                '^az rest --method post' { '{"tables":[{"name":"PrimaryResult","columns":[{"name":"Count","type":"long"}],"rows":[[3],[4]]}]}' }
                '^az rest --method get' { '{"value":[{"name":"item-1","kind":"Scheduled","properties":{"enabled":true,"status":"Succeeded","assignmentType":"Activated","startTime":"' + $now + '"}}]}' }
                '^az account show' { '{"id":"sub-0000"}' }
                '^az storage account show' { '{"allowSharedKeyAccess":false,"publicNetworkAccess":"Disabled","minimumTlsVersion":"TLS1_2","immutableStorageWithVersioning":{"enabled":true,"immutabilityPolicy":{"state":"Unlocked","immutabilityPeriodSinceCreationInDays":2190}}}' }
                '^az resource list' { '[{"name":"pb-identity-contain"}]' }
                '^gh (pr|run) list' { $global:LabDayTest.GhList }
                '^gh pr view' { '{"number":7,"title":"Graduate CA003"}' }
                '^gh run view' { 'terraform apply: 1 changed' }
                default { throw "unexpected native call in test: $line" }
            }
            [pscustomobject]@{ ExitCode = 0; StdOut = [string]$out; StdErr = '' }
        }
    }

    $script:StubLab = Join-Path $TestDrive 'stub' 'lab'
    New-LabDayStubRoot -Root $script:StubLab
}

AfterAll {
    Remove-Variable -Name LabDayTest -Scope Global -ErrorAction SilentlyContinue
    Remove-Item Env:LABDAY_TEST_LOG, Env:LABDAY_TEST_EXIT -ErrorAction SilentlyContinue
    Remove-Module LabEvidence -ErrorAction SilentlyContinue
}

Describe 'LabDayPlan.psd1: the trial window as data' {
    It 'loads through the runner''s own loader, and every step carries what the runner needs' {
        $WindowPlan.Steps.Count | Should -BeGreaterThan 100
        foreach ($s in $WindowPlan.Steps) {
            $s.Title | Should -Not -BeNullOrEmpty -Because $s.Id
            switch ($s.Kind) {
                'script' {
                    Test-Path -LiteralPath (Join-Path $RealLab $s.Script) -PathType Leaf | Should -BeTrue -Because "$($s.Id) runs lab/$($s.Script)"
                    $modes = @($s.Runs | ForEach-Object { [string]$_['Mode'] })
                    $modes.Count | Should -BeGreaterThan 0
                    if ('real' -in $modes) {
                        [array]::IndexOf($modes, 'dry') | Should -BeGreaterOrEqual 0 -Because "$($s.Id): a change has a dry run"
                        [array]::IndexOf($modes, 'dry') | Should -BeLessThan ([array]::IndexOf($modes, 'real')) -Because "$($s.Id): the dry run comes first"
                    }
                }
                'pr' { ($s.Flags.Count + $s.FlagsOff.Count + $s.Enforce.Count + $s.Do.Count) | Should -BeGreaterThan 0 -Because "$($s.Id) must say what the PR changes" }
                default { $s.Do.Count | Should -BeGreaterThan 0 -Because "$($s.Id) must say what to do" }
            }
        }
        foreach ($d in 0..29) {
            $WindowPlan.Titles.ContainsKey($d) | Should -BeTrue -Because "Day $d needs a title"
            @(Get-LabDayStepFor -Plan $WindowPlan -ForDay $d).Count | Should -BeGreaterThan 0 -Because "Day $d needs a step"
        }
    }

    It 'refuses a malformed step before anything runs' -ForEach @(
        @{ Case = 'no day'; Step = @{ Id = 'x'; Kind = 'console'; Title = 'X'; Do = @('y') }; Message = '*names no Day*' }
        @{ Case = 'a typo in a field'; Step = @{ Id = 'x'; Day = 1; Kind = 'console'; Title = 'X'; Do = @('y'); Capure = @() }; Message = '*unknown field*Capure*' }
        @{ Case = 'an unknown recipe'; Step = @{ Id = 'x'; Day = 1; Kind = 'console'; Title = 'X'; Evidence = @('E12'); Capture = @(@{ Recipe = 'ca-polices' }) }; Message = '*capture recipe*' }
        @{ Case = 'a capture with nowhere to go'; Step = @{ Id = 'x'; Day = 1; Kind = 'console'; Title = 'X'; Capture = @(@{ Recipe = 'ca-policies' }) }; Message = '*names no Evidence*' }
        @{ Case = 'a Log Analytics read with no query'; Step = @{ Id = 'x'; Day = 1; Kind = 'console'; Title = 'X'; Evidence = @('E09'); Capture = @(@{ Recipe = 'la' }) }; Message = '*needs Query*' }
        @{ Case = 'a run mode that is not read, dry or real'; Step = @{ Id = 'x'; Day = 1; Kind = 'script'; Title = 'X'; Script = 's.ps1'; Runs = @(@{ Mode = 'live' }) }; Message = '*run mode*' }
    ) {
        { ConvertTo-LabDayStep -Raw $Step } | Should -Throw $Message -Because $Case
    }

    It 'covers every trial-window evidence id in lab/docs/evidence-capture-plan.md, and only those' {
        $dash = '[-' + [char]0x2013 + ']'
        $window = [System.Collections.Generic.HashSet[string]]::new()
        $pre = [System.Collections.Generic.HashSet[string]]::new()
        foreach ($line in Get-Content -LiteralPath (Join-Path $RealLab 'docs' 'evidence-capture-plan.md') | Where-Object { $_ -match '^\|' }) {
            $cells = $line -split '\|'
            if ($cells.Count -lt 4) { continue }
            # Assigned inside the branches: an if-expression would enumerate the set.
            if ($cells[3].Trim() -match '^P') { $target = $pre } else { $target = $window }
            foreach ($m in [regex]::Matches($cells[2], "\bE(\d{2})([a-z]?)\b(?:\s*$dash\s*E(\d{2})\b)?")) {
                if ($m.Groups[3].Success) { foreach ($n in [int]$m.Groups[1].Value..[int]$m.Groups[3].Value) { [void]$target.Add(('E{0:d2}' -f $n)) } }
                else { [void]$target.Add(('E{0:d2}{1}' -f [int]$m.Groups[1].Value, $m.Groups[2].Value)) }
            }
        }
        $window.Count | Should -BeGreaterThan 50
        $planIds = @($WindowPlan.Steps | ForEach-Object { $_.Evidence } | Sort-Object -Unique)
        @($planIds | Where-Object { -not $window.Contains($_) }) | Should -BeNullOrEmpty -Because 'the plan files under an id the capture plan does not list'
        @($window | Where-Object { $_ -notin $planIds }) | Should -BeNullOrEmpty -Because 'a window capture the plan never takes'
        @($pre | Where-Object { $_ -in $planIds }) | Should -BeNullOrEmpty -Because 'the pre-window captures happen before Day 0'
    }

    It 'flips only staging flags lab.tfvars declares, and graduates only policies ca_policy_states holds' {
        $tf = Read-LabTfvarsState -Path (Join-Path $RealLab 'terraform' 'envs' 'dev' 'lab.tfvars')
        $tf | Should -Not -BeNullOrEmpty
        foreach ($f in @($WindowPlan.PreWindowFlags) + @($WindowPlan.Steps | ForEach-Object { $_.Flags; $_.FlagsOff })) {
            $tf.Flags.Contains($f) | Should -BeTrue -Because "'$f' must be a top-level true/false in lab.tfvars (preflight reads it there)"
        }
        foreach ($c in @($WindowPlan.Steps | ForEach-Object { $_.Enforce })) { $tf.CaStates.Contains($c) | Should -BeTrue -Because "$c must be in ca_policy_states" }
    }

    It 'uses only placeholders the settings file or the runner can fill' {
        $known = @((Get-LabDaySettingDefault).Keys) + @('StartUtc', 'NewestFile', 'KpiBaseline', 'PowerShellOut')
        foreach ($s in $WindowPlan.Steps) {
            $text = @(Get-LabDayString -Value @($s.Do, $s.Before, $s.Success, $s.Args, $s.Runs, $s.Capture, $s.CaptureBefore)) -join "`n"
            foreach ($m in [regex]::Matches($text, '\{([A-Za-z][A-Za-z0-9]*)(?::([^{}]+))?\}')) {
                $m.Groups[1].Value | Should -BeIn $known -Because "step $($s.Id) uses {$($m.Groups[1].Value)}"
                if ($m.Groups[1].Value -eq 'StartUtc') {
                    $ref = @($WindowPlan.Steps | Where-Object { $_.Id -eq $m.Groups[2].Value })
                    $ref.Count | Should -Be 1 -Because "{StartUtc:$($m.Groups[2].Value)} must name a step"
                    ($ref[0].Days | Measure-Object -Maximum).Maximum | Should -BeLessOrEqual ($s.Days | Measure-Object -Minimum).Minimum
                }
            }
        }
    }

    It 'passes each script only parameters it declares, every mandatory one, and dry runs that change nothing' {
        $changes = @('Execute', 'Apply', 'AcceptPreview', 'PromoteReadyToPilot', 'GrantDisableRole', 'Remove', 'Force', 'RevealTap', 'IssueTapFor', 'AllowEnforce', 'AllowEnabledRecreate')
        foreach ($s in @($WindowPlan.Steps | Where-Object { $_.Kind -eq 'script' })) {
            $ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $RealLab $s.Script), [ref]$null, [ref]$null)
            $declared = @($ast.ParamBlock.Parameters | ForEach-Object { $_.Name.VariablePath.UserPath })
            $sps = [bool]@($ast.ParamBlock.Attributes | Where-Object { $_.TypeName.Name -eq 'CmdletBinding' -and @($_.NamedArguments | Where-Object { $_.ArgumentName -eq 'SupportsShouldProcess' }).Count }).Count
            $mandatory = @($ast.ParamBlock.Parameters | Where-Object { @($_.Attributes | Where-Object { $_.TypeName.Name -eq 'Parameter' -and @($_.NamedArguments | Where-Object { $_.ArgumentName -eq 'Mandatory' }).Count }).Count } |
                    ForEach-Object { $_.Name.VariablePath.UserPath })
            foreach ($run in $s.Runs) {
                $p = @{}
                foreach ($k in $s.Args.Keys) { $p[$k] = $s.Args[$k] }
                if ($run['Add']) { foreach ($k in $run['Add'].Keys) { $p[$k] = $run['Add'][$k] } }
                $because = "$($s.Id) ($($run['Mode']) run of lab/$($s.Script))"
                foreach ($k in $p.Keys) {
                    if ($k -in 'WhatIf', 'Confirm') { $sps | Should -BeTrue -Because "$because passes -$k" }
                    else { $k | Should -BeIn $declared -Because $because }
                }
                foreach ($m in $mandatory) { @($p.Keys) | Should -Contain $m -Because $because }
                switch ([string]$run['Mode']) {
                    'dry' { ($p['WhatIf'] -eq $true -or ($s.Script -like '*/Invoke-PostApply.ps1' -and -not $p['Execute'])) | Should -BeTrue -Because "$because must change nothing (-WhatIf, or Invoke-PostApply without -Execute)" }
                    'read' { @($p.Keys | Where-Object { $_ -in $changes }) | Should -BeNullOrEmpty -Because $because }
                    'real' { $p.ContainsKey('WhatIf') | Should -BeFalse -Because $because }
                }
                @($p.Keys) | Should -Not -Contain 'GrantDisableRole' -Because 'ADR 0017 keeps the containment disable role off'
            }
        }
    }

    It 'names only capture recipes the module implements' {
        $ast = [System.Management.Automation.Language.Parser]::ParseFile((Get-LabScriptPath 'evidence/LabEvidence.Recipes.ps1'), [ref]$null, [ref]$null)
        $fn = $ast.Find({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Invoke-LabCaptureRecipe' }, $true)
        $switch = $fn.Find({ param($n) $n -is [System.Management.Automation.Language.SwitchStatementAst] }, $true)
        $handled = @($switch.Clauses | ForEach-Object { $_.Item1.Value } | Sort-Object)
        (@(Get-LabCaptureRecipeName) -join ',') | Should -Be ($handled -join ',')
    }

    It 'cites only lab/ documents and scripts that exist' {
        $text = Get-Content -LiteralPath $RealPlan -Raw
        $paths = @([regex]::Matches($text, 'lab/[A-Za-z0-9_./-]+\.(md|ps1|psm1|sh|json|csv|example)\b') | ForEach-Object { $_.Value } | Sort-Object -Unique |
                Where-Object { $_ -notmatch '^lab/evidence/(?!drills/README\.md)' -and $_ -notmatch '/out/' })
        $paths.Count | Should -BeGreaterThan 10
        foreach ($p in $paths) { Test-Path -LiteralPath (Join-Path (Split-Path -Parent $RealLab) $p) | Should -BeTrue -Because "the plan cites $p" }
    }

    It 'keeps step titles and notes public-safe: the manifests copy them' {
        foreach ($s in $WindowPlan.Steps) { Test-LabPublicSafeText -Text "$($s.Title) $($s.Note)" | Should -BeTrue -Because $s.Id }
    }
}

Describe 'LabEvidence: read-only by construction' {
    It 'reaches Graph only through Get-LabGraphResult with -Method GET; the runner reads nothing itself' {
        $calls = foreach ($rel in 'evidence/LabEvidence.Core.ps1', 'evidence/LabEvidence.Recipes.ps1', 'evidence/LabEvidence.psm1', 'Invoke-LabDay.ps1') {
            $ast = [System.Management.Automation.Language.Parser]::ParseFile((Get-LabScriptPath $rel), [ref]$null, [ref]$null)
            $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true) | ForEach-Object { [pscustomobject]@{ File = $rel; Name = $_.GetCommandName(); Ast = $_ } }
        }
        $graph = @($calls | Where-Object { $_.Name -eq 'Invoke-MgGraphRequest' })
        $graph.Count | Should -Be 1
        $graph[0].File | Should -Be 'evidence/LabEvidence.Core.ps1'
        $graph[0].Ast.Extent.Text | Should -Match '-Method GET\b'
        $p = $graph[0].Ast.Parent
        while ($p -and $p -isnot [System.Management.Automation.Language.FunctionDefinitionAst]) { $p = $p.Parent }
        $p.Name | Should -Be 'Get-LabGraphResult'
        @($calls | Where-Object { $_.Name -match '^(New|Set|Update|Remove|Add|Invoke|Grant|Revoke|Restore)-Mg' -and $_.Name -ne 'Invoke-MgGraphRequest' }) | Should -BeNullOrEmpty
        @($calls | Where-Object { $_.Name -in 'Invoke-RestMethod', 'Invoke-WebRequest', 'az', 'gh', 'terraform', 'Connect-MgGraph' }) | Should -BeNullOrEmpty
        @($calls | Where-Object { $_.File -eq 'Invoke-LabDay.ps1' -and $_.Name -in 'Invoke-MgGraphRequest', 'Invoke-LabNativeCommand', 'Get-LabGraphResult' }) | Should -BeNullOrEmpty -Because 'the runner reads the tenant only through the capture recipes'
    }

    It '<Tool> <Arguments>: allowed = <Ok>' -ForEach @(
        @{ Tool = 'az'; Arguments = @('account', 'show'); Ok = $true }
        @{ Tool = 'az'; Arguments = @('monitor', 'log-analytics', 'workspace', 'show', '-g', 'rg', '-n', 'ws'); Ok = $true }
        @{ Tool = 'az'; Arguments = @('rest', '--method', 'get', '--url', 'https://management.azure.com/subscriptions/x'); Ok = $true }
        @{ Tool = 'az'; Arguments = @('rest', '--method', 'post', '--url', 'https://api.loganalytics.io/v1/workspaces/ws/query'); Ok = $true }
        @{ Tool = 'gh'; Arguments = @('run', 'view', '42', '--log'); Ok = $true }
        @{ Tool = 'gh'; Arguments = @('pr', 'list', '--state', 'merged'); Ok = $true }
        @{ Tool = 'az'; Arguments = @('role', 'assignment', 'create', '--role', 'Owner'); Ok = $false }
        @{ Tool = 'az'; Arguments = @('rest', '--method', 'post', '--url', 'https://management.azure.com/subscriptions/x'); Ok = $false }
        @{ Tool = 'az'; Arguments = @('rest', '--method', 'delete', '--url', 'https://management.azure.com/subscriptions/x'); Ok = $false }
        @{ Tool = 'az'; Arguments = @('rest', '--method', 'get', '--url', 'https://graph.microsoft.com/v1.0/users'); Ok = $false }
        @{ Tool = 'az'; Arguments = @('storage', 'blob', 'upload', '-f', 'x'); Ok = $false }
        @{ Tool = 'az'; Arguments = @('keyvault', 'secret', 'show', '-n', 'x'); Ok = $false }
        @{ Tool = 'gh'; Arguments = @('pr', 'merge', '7'); Ok = $false }
        @{ Tool = 'gh'; Arguments = @('run', 'rerun', '42'); Ok = $false }
        @{ Tool = 'gh'; Arguments = @('pr', 'view', '7', '--web'); Ok = $false }
        @{ Tool = 'gh'; Arguments = @('api', 'repos/x/y', '-X', 'DELETE'); Ok = $false }
        @{ Tool = 'terraform'; Arguments = @('output', '-json'); Ok = $false }
        # az parses with argparse: the LAST --method / --url wins, a value can be
        # attached (--method=post, -mpost) and a prefix (--meth) is the same flag.
        # Each of the two exactly once, in a plain spelling, or refused.
        @{ Tool = 'az'; Arguments = @('rest', '-m', 'get', '-u', 'https://management.azure.com/subscriptions/x'); Ok = $true }
        @{ Tool = 'az'; Arguments = @('rest', '--method', 'get', '--uri', 'https://management.azure.com/subscriptions/x'); Ok = $true }
        @{ Tool = 'az'; Arguments = @('rest', '--method', 'get', '--url', 'https://management.azure.com/x', '--method', 'post'); Ok = $false }
        @{ Tool = 'az'; Arguments = @('rest', '--method', 'get', '--url', 'https://management.azure.com/x', '-m', 'post'); Ok = $false }
        @{ Tool = 'az'; Arguments = @('rest', '--method', 'get', '--url', 'https://management.azure.com/x', '--url', 'https://graph.microsoft.com/v1.0/users'); Ok = $false }
        @{ Tool = 'az'; Arguments = @('rest', '--method', 'get', '--url', 'https://management.azure.com/x', '--uri', 'https://graph.microsoft.com/v1.0/users'); Ok = $false }
        @{ Tool = 'az'; Arguments = @('rest', '--method', 'get', '--url', 'https://management.azure.com/x', '-u', 'https://graph.microsoft.com/v1.0/users'); Ok = $false }
        @{ Tool = 'az'; Arguments = @('rest', '--method=get', '--url', 'https://management.azure.com/x'); Ok = $false }
        @{ Tool = 'az'; Arguments = @('rest', '--method', 'get', '--url=https://management.azure.com/x'); Ok = $false }
        @{ Tool = 'az'; Arguments = @('rest', '--method', 'get', '--uri=https://management.azure.com/x'); Ok = $false }
        @{ Tool = 'az'; Arguments = @('rest', '--method', 'get', '--url', 'https://management.azure.com/x', '-mpost'); Ok = $false }
        @{ Tool = 'az'; Arguments = @('rest', '--method', 'get', '--url', 'https://management.azure.com/x', '-m=post'); Ok = $false }
        @{ Tool = 'az'; Arguments = @('rest', '--method', 'get', '--url', 'https://management.azure.com/x', '-uhttps://graph.microsoft.com/v1.0/users'); Ok = $false }
        @{ Tool = 'az'; Arguments = @('rest', '--meth', 'post', '--method', 'get', '--url', 'https://management.azure.com/x'); Ok = $false }
        @{ Tool = 'az'; Arguments = @('rest', '--method', 'get', '--ur', 'https://graph.microsoft.com/v1.0/users', '--url', 'https://management.azure.com/x'); Ok = $false }
    ) {
        if ($Ok) { { Assert-LabReadOnlyCommand -FilePath $Tool -ArgumentList $Arguments } | Should -Not -Throw }
        else { { Assert-LabReadOnlyCommand -FilePath $Tool -ArgumentList $Arguments } | Should -Throw '*read-only capture allowlist*' }
    }

    It 'runs every recipe against mocked Graph, az and gh: GET reads and allowlisted commands only, nothing failed' {
        Set-LabDayMocks
        $now = [datetime]::UtcNow.ToString('o')
        $global:LabDayTest.GhList = '[{"number":7,"title":"Graduate CA003","mergedAt":"' + $now + '","url":"u","headRefName":"ca003","databaseId":101,"displayTitle":"apply","event":"push","headBranch":"main","status":"completed","conclusion":"success","createdAt":"' + $now + '"}]'
        $special = @{
            la = @{ Recipe = 'la'; Name = 'signin-volume'; Query = 'SigninLogs | take 1' }
            files = @{ Recipe = 'files'; Name = 'kpi'; Path = 'evidence/kpis/*.json'; LookbackHours = 1 }
            'logic-app-runs' = @{ Recipe = 'logic-app-runs'; Workflow = 'pb-identity-contain' }
            'sign-ins' = @{ Recipe = 'sign-ins'; User = 'tst-a@contosolab.onmicrosoft.com' }
            'directory-audits' = @{ Recipe = 'directory-audits'; Service = 'PIM' }
        }
        $settings = @{ ResourceGroup = 'rg-identity-lab'; WorkspaceName = 'loga-idlab'; EvidenceStorageAccount = 'stidlabevidence'; OnMicrosoftDomain = 'contosolab.onmicrosoft.com' }
        foreach ($r in Get-LabCaptureRecipeName) {
            $spec = if ($special.ContainsKey($r)) { $special[$r] } else { @{ Recipe = $r } }
            $ctx = Initialize-LabCapture -EvidenceRoot (Join-Path $TestDrive 'recipes') -Id 'E99' -Part $r -SinceUtc ([datetime]::UtcNow.AddHours(-1)) -Settings $settings -LabRoot $StubLab
            Invoke-LabCaptureRecipe -Context $ctx -Spec $spec
            $res = Complete-LabCapture -Context $ctx -Meta @{ labDay = 1; step = 'recipe-check'; title = $r }
            $failed = @($ctx.Items | Where-Object { $_['status'] -eq 'failed' } | ForEach-Object { "$($_['name']): $($_['reason'])" })
            $res.Failed | Should -Be 0 -Because "recipe '$r' against the mocks ($($failed -join '; '))"
            @($ctx.Items | Where-Object { $_['status'] -eq 'ok' }).Count | Should -BeGreaterThan 0 -Because "recipe '$r' reads something"
        }
        $global:LabDayTest.Graph.Count | Should -BeGreaterThan 20
        @($global:LabDayTest.Graph | Where-Object { $_.Method -ne 'GET' }) | Should -BeNullOrEmpty
        @($global:LabDayTest.Native | Where-Object { $_ -match '^az rest --method post' -and $_ -notmatch 'https://api\.loganalytics\.io/v1/workspaces/[^/ ]+/query ' }) | Should -BeNullOrEmpty
        @($global:LabDayTest.Native | Where-Object { $_ -like 'gh run view *--log*' }).Count | Should -BeGreaterThan 0 -Because 'the pipeline recipe keeps the apply run log'
    }
}

Describe 'Redaction: IPv6 literals in every written form' {
    # A firewall-denied error quotes the client address, and a failed read's
    # reason is copied into the public manifest. RFC 3849 documentation
    # addresses stand in for real ones (the patterns read the shape, not the
    # range); no global IPv6 literal sits in this file.
    It 'replaces <Form>, and refuses it unredacted' -ForEach @(
        @{ Form = 'compressed, groups on both sides'; Ip = '2001:db8:85a3::8a2e:370:7334'; Expect = '<ip>' }
        @{ Form = 'compressed, two groups then one'; Ip = '2001:db8::7d8e'; Expect = '<ip>' }
        @{ Form = 'link-local with a zone'; Ip = 'fe80::1%eth0'; Expect = '<ip>%eth0' }
        @{ Form = 'loopback'; Ip = '::1'; Expect = '<ip>' }
        @{ Form = 'IPv4-mapped, in hex'; Ip = '::ffff:c000:201'; Expect = '<ip>' }
        @{ Form = 'a prefix'; Ip = '2001:db8::/32'; Expect = '<ip>/32' }
        @{ Form = 'upper case'; Ip = '2001:DB8::7D8E'; Expect = '<ip>' }
        @{ Form = 'in brackets with a port'; Ip = '[2001:db8::7d8e]:443'; Expect = '[<ip>]:443' }
        @{ Form = 'after a field name'; Ip = 'ip:2001:db8::7d8e'; Expect = 'ip:<ip>' }
        @{ Form = 'ending a clause'; Ip = '2001:db8::7d8e:'; Expect = '<ip>:' }
        @{ Form = 'the full eight groups'; Ip = '2001:0db8:85a3:0000:0000:8a2e:0370:7334'; Expect = '<ip>' }
        @{ Form = 'two compressions (no valid address, still removed)'; Ip = 'a::b::c'; Expect = '<ip><ip>' }
        @{ Form = 'a colon-separated MAC (a hardware id, kept out on purpose)'; Ip = '00:1a:2b:3c:4d:5e'; Expect = '<ip>' }
    ) {
        $text = "Client address $Ip is not allowed"
        Test-LabPublicSafeText -Text $text | Should -BeFalse
        $safe = ConvertTo-LabSafeText -Text $text
        $safe | Should -BeExactly "Client address $Expect is not allowed"
        Test-LabPublicSafeText -Text $safe | Should -BeTrue -Because 'redacted text always passes the manifest check'
    }

    It 'replaces a global short-form address in a quoted reason (assembled at run time)' {
        $ip = '2a02:c7c' + '::7d8e'
        Test-LabPublicSafeText -Text "Client address '$ip' is not authorized" | Should -BeFalse
        ConvertTo-LabSafeText -Text "Client address '$ip' is not authorized" | Should -BeExactly "Client address '<ip>' is not authorized"
    }

    It 'leaves <Text> alone' -ForEach @(
        @{ Text = 'retried at 10:30, then at 23:30:05' }
        @{ Text = 'capturedAtUtc 2026-11-03T23:30:05Z' }
        @{ Text = '[System.IO.Path]::GetFullPath($p)' }
        @{ Text = '[regex]::Escape($a) and [Math]::Ceiling($n)' }
        @{ Text = '[Foo]::Add(1) and [DateTimeStyles]::AdjustToUniversal' }
        @{ Text = 'std::vector and Time::HiRes' }
        @{ Text = 'MAC 00-1A-2B-3C-4D-5E' }
        @{ Text = 'ratio 1:2 and CA001 :: report-only' }
        @{ Text = 'sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08' }
    ) {
        Test-LabPublicSafeText -Text $Text | Should -BeTrue
        ConvertTo-LabSafeText -Text $Text | Should -BeExactly $Text
    }
}

Describe 'Capture folders, manifests and SHA256SUMS' {
    BeforeEach { Set-LabDayMocks }

    It 'files a capture as root/UTC day/id[-part]/ with raw/ ignored, and never overwrites one' {
        $root = Join-Path $TestDrive 'paths'
        $t = [datetime]::new(2026, 11, 3, 23, 30, 5, [DateTimeKind]::Utc)
        $a = Initialize-LabCapture -EvidenceRoot $root -Id 'E16b' -Part 'policy' -SinceUtc $t.AddHours(-1) -NowUtc $t
        $a.Dir | Should -Be (Join-Path $root '20261103' 'E16b-policy')
        (Get-Content -LiteralPath (Join-Path $a.Dir '.gitignore') -Raw) | Should -Match '(?m)^raw/$'
        Test-Path -LiteralPath $a.Raw -PathType Container | Should -BeTrue
        $b = Initialize-LabCapture -EvidenceRoot $root -Id 'E16b' -Part 'policy' -SinceUtc $t -NowUtc $t.AddDays(1).AddMinutes(1)
        $b.Name | Should -Be 'E16b-policy.rerun-20261104T233105Z'
        $b.RerunOf | Should -Be 'E16b-policy'
        $b.Dir | Should -Be (Join-Path $root '20261104' 'E16b-policy.rerun-20261104T233105Z')
        $c = Initialize-LabCapture -EvidenceRoot $root -Id 'E20' -SinceUtc $t -NowUtc $t -Rerun
        $c.Name | Should -Be 'E20.rerun-20261103T233005Z' -Because 'a planned re-take is a new capture id even with no earlier folder'
        { Initialize-LabCapture -EvidenceRoot $root -Id 'E20' -SinceUtc $t -NowUtc $t -Rerun } | Should -Throw '*never overwritten*'
        { Initialize-LabCapture -EvidenceRoot $root -Id '../E20' -SinceUtc $t } | Should -Throw
    }

    It 'seals a manifest and a SHA256SUMS that verifies, and the capture-log row pins SHA256SUMS' {
        $ctx = Initialize-LabCapture -EvidenceRoot (Join-Path $TestDrive 'seal') -Id 'E12' -SinceUtc ([datetime]::UtcNow.AddHours(-1)) -Settings @{ OnMicrosoftDomain = 'contosolab.onmicrosoft.com'; Domain = 'contosohealth.test' }
        Invoke-LabCaptureRecipe -Context $ctx -Spec @{ Recipe = 'ca-policies' }
        Invoke-LabCaptureRecipe -Context $ctx -Spec @{ Recipe = 'sign-ins'; User = 'tst-a@contosolab.onmicrosoft.com' }
        $tx = Join-Path $TestDrive 'ca-report-only-1-read.log'
        Set-Content -LiteralPath $tx -Value 'transcript line'
        Add-LabCaptureFile -Context $ctx -Path $tx
        $res = Complete-LabCapture -Context $ctx -Meta @{ labDay = 1; step = 'ca-report-only'; title = 'PR #1: every Conditional Access policy, report-only' }
        $m = Get-Content -LiteralPath (Join-Path $res.Dir 'manifest.json') -Raw | ConvertFrom-Json
        $m.schema | Should -Be 'contoso-lab-capture/1'
        $m.status | Should -Be ('RAN ' + [char]0x00B7 + ' tenant')
        $m.complete | Should -BeTrue
        $m.labDay | Should -Be 1
        @($m.files | ForEach-Object { $_.path }) | Should -Be @('raw/ca-policies.json', 'raw/sign-ins.json', 'raw/transcripts/ca-report-only-1-read.log')
        ($m.items | Where-Object { $_.name -eq 'ca-policies' }).summary.labPolicies.CA003 | Should -Be 'enabled'
        $lines = @(Get-Content -LiteralPath (Join-Path $res.Dir 'SHA256SUMS'))
        $lines.Count | Should -Be 4
        $lines[-1] | Should -Match '  manifest\.json$'
        foreach ($l in $lines) {
            $l | Should -Match '^[0-9a-f]{64}  \S'
            $hash, $rel = $l -split '  ', 2
            (Get-FileHash -LiteralPath (Join-Path $res.Dir $rel) -Algorithm SHA256).Hash.ToLowerInvariant() | Should -Be $hash -Because $rel
        }
        $log = Join-Path $TestDrive 'seal-log.csv'
        Add-LabCaptureLogRow -Path $log -Id $res.Name -Utc ([datetime]::UtcNow) -What 'PR #1' -Sha256 $res.Sha256 -StoredAt 'lab/evidence/tenant/20261103/E12/' -Public 'manifest' -Operator 'MW'
        (Get-Content -LiteralPath $log -TotalCount 1) | Should -Be 'id,utc,what,sha256,stored_at,public,operator'
        $row = @(Import-Csv -LiteralPath $log)[0]
        $row.id | Should -Be 'E12'
        $row.sha256 | Should -Be (Get-FileHash -LiteralPath (Join-Path $res.Dir 'SHA256SUMS') -Algorithm SHA256).Hash.ToLowerInvariant()
    }

    It 'keeps tenant identifiers, tokens and home paths out of the manifest, and refuses a manifest that would carry one' {
        $ctx = Initialize-LabCapture -EvidenceRoot (Join-Path $TestDrive 'safe') -Id 'E17b' -SinceUtc ([datetime]::UtcNow.AddHours(-1)) -Settings @{ OnMicrosoftDomain = 'contosolab.onmicrosoft.com'; Domain = 'contosohealth.test' }
        Invoke-LabCaptureRecipe -Context $ctx -Spec @{ Recipe = 'sign-ins'; User = 'tst-a@contosolab.onmicrosoft.com' }
        Invoke-LabCaptureRecipe -Context $ctx -Spec @{ Recipe = 'directory-audits' }
        # Assembled at run time: no token-shaped literal sits in this file.
        $jwt = ('ey' + 'JhbGciOiJSUzI1NiJ9') + '.' + ('ey' + 'JzdWIiOiJsYWIifQ') + '.c2lnbmF0dXJl'
        $global:LabDayTest.GraphThrows = "Forbidden for dana.okafor@contosohealth.test from 203.0.113.10 and 2001:db8:85a3::7d8e in tenant aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa ($('bbbb' * 8)); Authorization: $('Bear' + 'er') $jwt; replay $jwt; $('client' + '_secret')=abc123; see https://graph.microsoft.com/v1.0/x in /Users/someone/lab"
        Invoke-LabCaptureRecipe -Context $ctx -Spec @{ Recipe = 'risky-users' }
        $res = Complete-LabCapture -Context $ctx -Meta @{ labDay = 2; step = 'first-activation'; title = 'First PIM activation' }
        $text = Get-Content -LiteralPath (Join-Path $res.Dir 'manifest.json') -Raw
        Test-LabPublicSafeText -Text $text | Should -BeTrue
        foreach ($leak in 'contosolab', 'contosohealth.test', '203.0.113.10', 'db8:85a3', '::7d8e', 'aaaaaaaa-aaaa', ('bbbb' * 8), $jwt.Substring(0, 12), 'abc123', 'graph.microsoft.com/v1.0/x', '/Users/someone', 'dana.okafor', 'tst-a@') {
            $text.Contains($leak) | Should -BeFalse -Because "the manifest must not carry '$leak'"
        }
        $m = $text | ConvertFrom-Json
        $m.complete | Should -BeFalse
        ($m.items | Where-Object { $_.name -eq 'risky-users' }).status | Should -Be 'failed'
        (Get-Content -LiteralPath (Join-Path $res.Dir 'raw' 'sign-ins.json') -Raw) | Should -Match '203\.0\.113\.10' -Because 'raw/ keeps the detail: it is private and never committed'
        $bad = Initialize-LabCapture -EvidenceRoot (Join-Path $TestDrive 'safe') -Id 'E18' -SinceUtc ([datetime]::UtcNow)
        { Complete-LabCapture -Context $bad -Meta @{ title = 'escalated by grace.mwangi@contosohealth.test' } } | Should -Throw '*Refusing to write*'
        Test-Path -LiteralPath (Join-Path $bad.Dir 'manifest.json') | Should -BeFalse
    }

    It 'records a failed read as failed, never an empty ok, and a read that depends on it as failed too' {
        $global:LabDayTest.GraphThrows = 'Forbidden'
        $ctx = Initialize-LabCapture -EvidenceRoot (Join-Path $TestDrive 'failed') -Id 'E19' -SinceUtc ([datetime]::UtcNow)
        Invoke-LabCaptureRecipe -Context $ctx -Spec @{ Recipe = 'access-packages' }
        Invoke-LabCaptureRecipe -Context $ctx -Spec @{ Recipe = 'access-reviews' }
        @($ctx.Items | ForEach-Object { "$($_['name'])=$($_['status'])" }) | Should -Be @('access-packages=failed', 'access-packages-incompatible=failed', 'access-reviews-definitions=failed', 'access-reviews-decisions=failed')
        $res = Complete-LabCapture -Context $ctx
        $res.Failed | Should -Be 4
        (Get-Content -LiteralPath (Join-Path $res.Dir 'manifest.json') -Raw | ConvertFrom-Json).complete | Should -BeFalse
    }
}

Describe 'Placeholders: typed values for the scripts, previews that never ask' {
    BeforeEach {
        $script:State = @{ steps = @{} }
        $script:StepPrompted = @{}
        $script:Promptable = @{ ChangeTicket = '^[A-Za-z0-9._-]{1,32}$' }
        $script:LabRootFull = $StubLab
    }

    It 'keeps the setting''s type for a whole placeholder, joins inside a string, and fills nested settings' {
        $script:Settings = @{ OnMicrosoftDomain = 'contosolab.onmicrosoft.com'; AdminUpn = 'admin@{OnMicrosoftDomain}'; SkipPam = $false; BreakGlassKeysPerAccount = 2; VipUserPrincipalNames = @('a@contosohealth.test', 'b@contosohealth.test') }
        Expand-LabDayValue -Value '{SkipPam}' | Should -BeOfType [bool]
        Expand-LabDayValue -Value '{SkipPam}' | Should -BeFalse
        Expand-LabDayValue -Value '{BreakGlassKeysPerAccount}' | Should -BeOfType [int]
        @(Expand-LabDayValue -Value '{VipUserPrincipalNames}').Count | Should -Be 2
        Expand-LabDayValue -Value '{AdminUpn}' | Should -Be 'admin@contosolab.onmicrosoft.com'
        Expand-LabDayValue -Value 'as {AdminUpn} on {OnMicrosoftDomain}' | Should -Be 'as admin@contosolab.onmicrosoft.com on contosolab.onmicrosoft.com'
        $h = Expand-LabDayValue -Value @{ Only = @('baseline', 'pim-eligibility'); Who = @('{AdminUpn}') }
        ($h['Only'] -join ',') | Should -Be 'baseline,pim-eligibility'
        $h['Who'] | Should -Be 'admin@contosolab.onmicrosoft.com'
        Expand-LabDayValue -Value '{KpiBaseline}' | Should -Be $KpiBaselineFile
        Expand-LabDayValue -Value '{NewestFile:evidence/out/ca-restore/ca-policies-*.json}' | Should -Be $SnapshotFile
    }

    It 'a preview shows the placeholder name for what it cannot fill and never asks; a real run asks once per step, and refuses a missing setting' {
        $script:Settings = @{ ChangeTicket = ''; KeyVaultName = '' }
        Mock Read-LabOperatorInput { 'CHG0000001' }
        Expand-LabDayValue -Value '{KeyVaultName}' -Preview | Should -Be '<KeyVaultName>'
        Expand-LabDayValue -Value '{ChangeTicket}' -Preview | Should -Be '<ChangeTicket>'
        Expand-LabDayValue -Value '{StartUtc:bg-drill-signins}' -Preview | Should -Be '<when step bg-drill-signins started>'
        Should -Invoke Read-LabOperatorInput -Times 0 -Exactly
        Expand-LabDayValue -Value '{ChangeTicket}' | Should -Be 'CHG0000001'
        Expand-LabDayValue -Value '{ChangeTicket}' | Should -Be 'CHG0000001'
        Should -Invoke Read-LabOperatorInput -Times 1 -Exactly
        { Expand-LabDayValue -Value '{KeyVaultName}' } | Should -Throw '*settings file*'
        { Expand-LabDayValue -Value '{StartUtc:bg-drill-signins}' } | Should -Throw '*no recorded start*'
    }
}

Describe 'Invoke-LabDay.ps1 -WhatIf: the day, printed' {
    BeforeEach { Set-LabDayMocks }

    It 'Day <Day>: prints the day and calls nothing (no script, no Graph, no az / gh, no prompt) and writes nothing' -ForEach @(0..29 | ForEach-Object { @{ Day = $_ } }) {
        $box = New-LabDayBox
        Invoke-LabDayRun -Box $box -Arguments @{ Day = $Day; WhatIf = $true } | Should -Be 0
        Test-Path -LiteralPath $env:LABDAY_TEST_LOG | Should -BeFalse -Because 'no script runs under -WhatIf, not even preflight'
        Should -Invoke Invoke-MgGraphRequest -ModuleName LabEvidence -Times 0 -Exactly
        Should -Invoke Invoke-LabNativeCommand -ModuleName LabEvidence -Times 0 -Exactly
        Should -Invoke Read-LabOperatorChoice -Times 0 -Exactly
        Should -Invoke Read-LabOperatorInput -Times 0 -Exactly
        foreach ($p in $box.State, $box.Evidence, $box.Log) { Test-Path -LiteralPath $p | Should -BeFalse -Because "$p must not be written" }
        @($global:LabDayTest.Console | Where-Object { $_ -like '*preflight: lab/scripts/powershell/00-Preflight.ps1*' }).Count | Should -Be 1
        $ids = @(Get-LabDayStepFor -Plan $WindowPlan -ForDay $Day | ForEach-Object { $_.Id })
        @($global:LabDayTest.Console | Where-Object { $_ -match '^\s+step id: ' } | ForEach-Object { ($_ -split 'step id: ')[1].Trim() }) | Should -Be $ids
    }
}

Describe 'Invoke-LabDay.ps1: one day, step by step' {
    BeforeAll {
        $script:MiniPlan = Join-Path $TestDrive 'mini-plan.psd1'
        Set-Content -LiteralPath $script:MiniPlan -Encoding utf8NoBOM -Value @'
@{
    Schema         = 'contoso-lab-day/1'
    PreWindowFlags = @('enable_dc')
    Days           = @(@{ Day = 3; Title = 'Test day' }, @{ Day = 4; Title = 'Next day' })
    Steps          = @(
        @{ Id = 'inventory'; Day = 3; Kind = 'script'; Evidence = @('E19'); Title = 'A read-only script'
           Script = 'scripts/powershell/06-NHI-Inventory.ps1'; Capture = @(@{ Recipe = 'ca-policies' }) }
        @{ Id = 'joiner'; Day = 3; Kind = 'script'; Evidence = @('E20'); Title = 'A change'
           Script = 'scripts/powershell/02-Joiner.ps1'; Args = @{ UserPrincipalName = '{JoinerUpn}'; LicenseSkuPartNumber = '{E5SkuPartNumber}' }
           Runs = @(@{ Mode = 'dry'; Add = @{ WhatIf = $true } }, @{ Mode = 'real' })
           CaptureBefore = @(@{ Recipe = 'auth-methods-policy'; Part = 'before' }); Capture = @(@{ Recipe = 'sign-ins'; User = '{JoinerUpn}' }) }
        @{ Id = 'portal'; Day = 3; Kind = 'console'; Evidence = @('E20b'); Title = 'A portal step'
           Do = @('Entra admin center > Users'); Capture = @(@{ Recipe = 'directory-audits' }) }
        @{ Id = 'flag'; Day = 3; Kind = 'pr'; Title = 'A flag flip'; Flags = @('enable_governance') }
        @{ Id = 'tomorrow'; Day = 4; Kind = 'console'; Title = 'The next day'; Do = @('Look again') }
    )
}
'@
        $script:Preflight = 'scripts/powershell/00-Preflight.ps1'
        $script:Inventory = 'scripts/powershell/06-NHI-Inventory.ps1'
        $script:Joiner = 'scripts/powershell/02-Joiner.ps1'
    }
    BeforeEach { Set-LabDayMocks }

    It 'runs preflight first, then the steps in plan order: a read straight through, a change dry run first, then a yes, then the real run' {
        $box = New-LabDayBox -Plan $MiniPlan
        Invoke-LabDayRun -Box $box -Arguments @{ Day = 3 } | Should -Be 0
        $calls = @(Get-LabDayCall)
        @($calls | ForEach-Object { "$($_.script)|$($_.whatIf)" }) | Should -Be @("$Preflight|False", "$Inventory|False", "$Joiner|True", "$Joiner|False")
        @($calls[0].values.ExpectedOnFlags) | Should -Be @('enable_dc')
        $calls[0].values.OnMicrosoftDomain | Should -Be 'contosolab.onmicrosoft.com'
        $calls[3].values.UserPrincipalName | Should -Be 'dana.okafor@contosohealth.test'
        $calls[3].values.LicenseSkuPartNumber | Should -Be 'SPE_E5'
        @($global:LabDayTest.Prompts) | Should -Be @('Run it for real? (its own confirmations still apply)', 'When it is done:', 'When it is done:')
        $state = Get-LabDayState -Box $box
        foreach ($id in 'inventory', 'joiner', 'portal', 'flag') { $state.steps[$id].status | Should -Be 'done' -Because $id }
        $state.steps.ContainsKey('tomorrow') | Should -BeFalse -Because 'Day 4 is not today'
    }

    It 'files each capture as evidence root/UTC day/evidence id[-part]/ with its transcripts and one capture-log row' {
        $box = New-LabDayBox -Plan $MiniPlan
        $before = [datetime]::UtcNow.ToString('yyyyMMdd')
        Invoke-LabDayRun -Box $box -Arguments @{ Day = 3 } | Should -Be 0
        $after = [datetime]::UtcNow.ToString('yyyyMMdd')
        $days = @(Get-ChildItem -LiteralPath $box.Evidence -Directory | ForEach-Object { $_.Name })
        $days.Count | Should -Be 1
        $days[0] | Should -BeIn @($before, $after)
        $day = $days[0]
        @(Get-ChildItem -LiteralPath (Join-Path $box.Evidence $day) -Directory | ForEach-Object { $_.Name } | Sort-Object) | Should -Be @('E19', 'E20', 'E20-before', 'E20b')
        $rows = @(Import-Csv -LiteralPath $box.Log)
        @($rows | ForEach-Object { $_.id } | Sort-Object) | Should -Be @('E19', 'E20', 'E20-before', 'E20b')
        foreach ($r in $rows) {
            $r.stored_at | Should -Match "evidence/tenant/$day/$([regex]::Escape($r.id))/$"
            $r.sha256 | Should -Match '^[0-9a-f]{64}$'
            $r.operator | Should -Be 'MW'
        }
        $m = Get-Content -LiteralPath (Join-Path $box.Evidence $day 'E20' 'manifest.json') -Raw | ConvertFrom-Json
        $m.step | Should -Be 'joiner'
        $m.labDay | Should -Be 3
        @($m.files | Where-Object { $_.path -like 'raw/transcripts/joiner-*' } | ForEach-Object { ($_.path -split '-')[-1] }) | Should -Be @('dry.log', 'real.log')
        (Get-Content -LiteralPath (Join-Path $box.Evidence $day 'E20-before' 'manifest.json') -Raw | ConvertFrom-Json).part | Should -Be 'before'
    }

    It 'resumes after a failed step: what is done never runs again, the failed step starts again from its dry run as the same attempt' {
        $box = New-LabDayBox -Plan $MiniPlan
        $env:LABDAY_TEST_EXIT = '{"' + $Joiner + '": 1}'
        Invoke-LabDayRun -Box $box -Arguments @{ Day = 3 } | Should -Be 3
        @(Get-LabDayCall | ForEach-Object { "$($_.script)|$($_.whatIf)" }) | Should -Be @("$Preflight|False", "$Inventory|False", "$Joiner|True")
        $state = Get-LabDayState -Box $box
        $state.steps['inventory'].status | Should -Be 'done'
        $state.steps['joiner'].status | Should -Be 'failed'
        $state.steps['joiner'].error | Should -Match 'exited 1'
        $firstStart = $state.steps['joiner'].startedUtc
        Remove-Item -LiteralPath $env:LABDAY_TEST_LOG
        $env:LABDAY_TEST_EXIT = ''
        Invoke-LabDayRun -Box $box -Arguments @{ Day = 3 } | Should -Be 0
        @(Get-LabDayCall | ForEach-Object { "$($_.script)|$($_.whatIf)" }) | Should -Be @("$Preflight|False", "$Joiner|True", "$Joiner|False")
        $state = Get-LabDayState -Box $box
        foreach ($id in 'inventory', 'joiner', 'portal', 'flag') { $state.steps[$id].status | Should -Be 'done' -Because $id }
        $state.steps['joiner'].startedUtc | Should -Be $firstStart -Because 'a resumed step keeps its first start: its captures read the window from there'
        @(Get-ChildItem -LiteralPath $box.Evidence -Recurse -Directory -Filter 'E20-before*').Count | Should -Be 1 -Because 'the before-state is captured once per attempt'
        @(Get-ChildItem -LiteralPath $box.Evidence -Recurse -Directory -Filter 'E19*').Count | Should -Be 1 -Because 'a done step is not captured again'
    }

    It '[q]uit stops at the step with nothing run for real; the next run starts there again' {
        $box = New-LabDayBox -Plan $MiniPlan
        $global:LabDayTest.Answers.Enqueue('quit')
        Invoke-LabDayRun -Box $box -Arguments @{ Day = 3 } | Should -Be 1
        (Get-LabDayState -Box $box).steps['joiner'].status | Should -Be 'deferred'
        @(Get-LabDayCall | Where-Object { $_.script -eq $Joiner -and -not $_.whatIf }) | Should -BeNullOrEmpty
        Remove-Item -LiteralPath $env:LABDAY_TEST_LOG
        Invoke-LabDayRun -Box $box -Arguments @{ Day = 3 } | Should -Be 0
        @(Get-LabDayCall | ForEach-Object { "$($_.script)|$($_.whatIf)" }) | Should -Be @("$Preflight|False", "$Joiner|True", "$Joiner|False")
    }

    It '[s]kip leaves a step for later (exit 1); [m]issed writes its missed row and is never offered again' {
        $box = New-LabDayBox -Plan $MiniPlan
        foreach ($a in 'yes', 'missed', 'skip') { $global:LabDayTest.Answers.Enqueue($a) }
        Invoke-LabDayRun -Box $box -Arguments @{ Day = 3 } | Should -Be 1
        $state = Get-LabDayState -Box $box
        $state.steps['portal'].status | Should -Be 'missed'
        $state.steps['flag'].status | Should -Be 'deferred'
        $missed = @(Import-Csv -LiteralPath $box.Log | Where-Object { $_.what -like 'missed:*' })
        @($missed | ForEach-Object { $_.id }) | Should -Be @('E20b')
        $missed[0].sha256 | Should -BeNullOrEmpty
        Remove-Item -LiteralPath $env:LABDAY_TEST_LOG
        $global:LabDayTest.Prompts.Clear()
        Invoke-LabDayRun -Box $box -Arguments @{ Day = 3 } | Should -Be 0
        @($global:LabDayTest.Prompts) | Should -Be @('When it is done:') -Because 'only the skipped step comes back'
        @(Get-LabDayCall | ForEach-Object { $_.script }) | Should -Be @($Preflight)
    }

    It '-Step runs only that step (by id or by evidence id), again when done, as re-run captures; a step not on the day exits 4 before preflight' {
        $box = New-LabDayBox -Plan $MiniPlan
        Invoke-LabDayRun -Box $box -Arguments @{ Day = 3 } | Should -Be 0
        Remove-Item -LiteralPath $env:LABDAY_TEST_LOG
        Invoke-LabDayRun -Box $box -Arguments @{ Day = 3; Step = 'inventory' } | Should -Be 0
        @(Get-LabDayCall | ForEach-Object { $_.script }) | Should -Be @($Preflight, $Inventory)
        Remove-Item -LiteralPath $env:LABDAY_TEST_LOG
        Invoke-LabDayRun -Box $box -Arguments @{ Day = 3; Step = 'E20' } | Should -Be 0
        @(Get-LabDayCall | ForEach-Object { "$($_.script)|$($_.whatIf)" }) | Should -Be @("$Preflight|False", "$Joiner|True", "$Joiner|False")
        $names = @(Get-ChildItem -LiteralPath $box.Evidence -Recurse -Directory | Where-Object { $_.Name -like 'E*' } | ForEach-Object { $_.Name })
        @($names | Where-Object { $_ -like 'E19.rerun-*' }).Count | Should -Be 1
        @($names | Where-Object { $_ -like 'E20.rerun-*' }).Count | Should -Be 1
        @(Import-Csv -LiteralPath $box.Log | Where-Object { $_.what -like 're-run of E20:*' }).Count | Should -Be 1
        Remove-Item -LiteralPath $env:LABDAY_TEST_LOG
        Invoke-LabDayRun -Box $box -Arguments @{ Day = 3; Step = 'tomorrow' } | Should -Be 4
        Test-Path -LiteralPath $env:LABDAY_TEST_LOG | Should -BeFalse
        @($global:LabDayTest.Console | Where-Object { $_ -like "No step 'tomorrow' on Day 3. It is on: tomorrow (Day 4)*" }).Count | Should -Be 1
    }

    It '-CaptureOnly takes the after-captures without running a step, asking anything or marking anything done' {
        $box = New-LabDayBox -Plan $MiniPlan
        Invoke-LabDayRun -Box $box -Arguments @{ Day = 3; CaptureOnly = $true } | Should -Be 0
        @(Get-LabDayCall | ForEach-Object { $_.script }) | Should -Be @($Preflight) -Because 'preflight still runs first, and nothing else'
        Should -Invoke Read-LabOperatorChoice -Times 0 -Exactly
        @(Get-ChildItem -LiteralPath $box.Evidence -Recurse -Directory | Where-Object { $_.Name -like 'E*' } | ForEach-Object { $_.Name } | Sort-Object) | Should -Be @('E19', 'E20', 'E20b') -Because 'no before-capture: that state is gone once a step ran'
        $state = Get-LabDayState -Box $box
        foreach ($id in 'inventory', 'joiner', 'portal') {
            [string]$state.steps[$id].status | Should -BeNullOrEmpty -Because "$id did not run"
            $state.steps[$id].capturedUtc | Should -Not -BeNullOrEmpty
        }
        Remove-Item -LiteralPath $env:LABDAY_TEST_LOG
        Invoke-LabDayRun -Box $box -Arguments @{ Day = 3; Step = 'E20b'; CaptureOnly = $true } | Should -Be 0
        @(Get-ChildItem -LiteralPath $box.Evidence -Recurse -Directory -Filter 'E20b.rerun-*').Count | Should -Be 1
        @(Get-ChildItem -LiteralPath $box.Evidence -Recurse -Directory -Filter 'E20.rerun-*').Count | Should -Be 0 -Because 'an evidence id as -Step takes only its own folders'
        @($global:LabDayTest.Graph | Where-Object { $_.Method -ne 'GET' }) | Should -BeNullOrEmpty
    }

    It 'stops before any step when preflight is blocked (exit 2), and asks before going on when it warns (exit 1)' {
        $box = New-LabDayBox -Plan $MiniPlan
        $env:LABDAY_TEST_EXIT = '{"' + $Preflight + '": 2}'
        Invoke-LabDayRun -Box $box -Arguments @{ Day = 3 } | Should -Be 2
        @(Get-LabDayCall).Count | Should -Be 1
        Should -Invoke Read-LabOperatorChoice -Times 0 -Exactly
        Remove-Item -LiteralPath $env:LABDAY_TEST_LOG
        $env:LABDAY_TEST_EXIT = '{"' + $Preflight + '": 1}'
        $global:LabDayTest.Answers.Enqueue('no')
        Invoke-LabDayRun -Box $box -Arguments @{ Day = 3 } | Should -Be 1
        @(Get-LabDayCall).Count | Should -Be 1
        $global:LabDayTest.Prompts[-1] | Should -Match '^Preflight: ready with warnings'
        Remove-Item -LiteralPath $env:LABDAY_TEST_LOG
        Invoke-LabDayRun -Box $box -Arguments @{ Day = 3 } | Should -Be 0 -Because '[y]es goes on'
        @(Get-LabDayCall).Count | Should -Be 4
    }

    It 'a capture that breaks leaves its step done (a resume never runs it again) and names the -CaptureOnly re-take' {
        $box = New-LabDayBox -Plan $MiniPlan
        New-Item -ItemType Directory -Path (Split-Path -Parent $box.Log) -Force | Out-Null
        Set-Content -LiteralPath $box.Log -Value 'when,what' -Encoding utf8NoBOM
        Invoke-LabDayRun -Box $box -Arguments @{ Day = 3 } | Should -Be 3
        $state = Get-LabDayState -Box $box
        $state.steps['inventory'].status | Should -Be 'done'
        $state.steps['inventory'].captureError | Should -Match 'capture log header'
        @($global:LabDayTest.Console | Where-Object { $_ -like '*-Day 3 -Step inventory -CaptureOnly*' }).Count | Should -Be 1
        Remove-Item -LiteralPath $box.Log, $env:LABDAY_TEST_LOG
        Invoke-LabDayRun -Box $box -Arguments @{ Day = 3 } | Should -Be 0
        @(Get-LabDayCall | ForEach-Object { $_.script }) | Should -Not -Contain $Inventory
        Invoke-LabDayRun -Box $box -Arguments @{ Day = 3; Step = 'inventory'; CaptureOnly = $true } | Should -Be 0
        @(Import-Csv -LiteralPath $box.Log | Where-Object { $_.id -like 'E19.rerun-*' }).Count | Should -Be 1
    }

    It 'tells preflight what the plan says is on by now: pre-window flags, earlier days, steps done, flags declared by hand' {
        $box = New-LabDayBox
        $env:LABDAY_TEST_EXIT = '{"' + $Preflight + '": 2}'
        Invoke-LabDayRun -Box $box -Arguments @{ Day = 0; ExpectedOnFlags = @('accept_admin_synced_passkey_risk') } | Should -Be 2
        $pf = @(Get-LabDayCall)[0].values
        $pf.PreTrial | Should -BeTrue
        @($pf.ExpectedOnFlags) | Should -Be @('accept_admin_synced_passkey_risk', 'enable_dc', 'enable_evidence_store')
        @($pf.PSObject.Properties.Name) | Should -Not -Contain 'ExpectedEnforcedPolicies'
        Remove-Item -LiteralPath $env:LABDAY_TEST_LOG
        Invoke-LabDayRun -Box $box -Arguments @{ Day = 13 } | Should -Be 2
        $pf = @(Get-LabDayCall)[0].values
        @($pf.PSObject.Properties.Name) | Should -Not -Contain 'PreTrial'
        @($pf.ExpectedOnFlags) | Should -Contain 'enable_premium'
        @($pf.ExpectedOnFlags) | Should -Contain 'pim_tier0_auth_context_switchover_step1'
        @($pf.ExpectedOnFlags) | Should -Not -Contain 'clinical_portal_preauthorize_azure_cli' -Because 'Day 4 turned it off again'
        @($pf.ExpectedOnFlags) | Should -Not -Contain 'enable_itdr_containment' -Because 'that Day 13 step has not run yet'
        @($pf.ExpectedEnforcedPolicies) | Should -Be @('CA001', 'CA002', 'CA003', 'CA006', 'CA007', 'CA009', 'CA010', 'CA020', 'CA021')
        # A step the runner recorded as deferred does not count: the PR that
        # turns the Clinical Portal flag off again has not happened.
        New-Item -ItemType Directory -Path (Split-Path -Parent $box.State) -Force | Out-Null
        Set-Content -LiteralPath $box.State -Value '{"schema":"contoso-lab-day-state/1","steps":{"oidc-preauth-off":{"status":"deferred"}}}' -Encoding utf8NoBOM
        Remove-Item -LiteralPath $env:LABDAY_TEST_LOG
        Invoke-LabDayRun -Box $box -Arguments @{ Day = 5 } | Should -Be 2
        @(@(Get-LabDayCall)[0].values.ExpectedOnFlags) | Should -Contain 'clinical_portal_preauthorize_azure_cli'
    }
}

Describe 'Invoke-LabDay.ps1 over the whole window, Day 0 to Day 29' {
    BeforeAll {
        # Every day in turn, one state file, every prompt answered "go on":
        # each step's scripts run against the stubs, each capture against the
        # mocks. The per-day expectation is computed from the plan alone.
        Set-LabDayMocks
        $script:Window = New-LabDayBox
        $script:DayRuns = @{}
        $done = @{}
        foreach ($d in 0..29) {
            if (Test-Path -LiteralPath $env:LABDAY_TEST_LOG) { Remove-Item -LiteralPath $env:LABDAY_TEST_LOG }
            $exit = Invoke-LabDayRun -Box $script:Window -Arguments @{ Day = $d }
            $expected = [System.Collections.Generic.List[string]]::new()
            $expected.Add('scripts/powershell/00-Preflight.ps1|False')
            foreach ($s in @(Get-LabDayStepFor -Plan $WindowPlan -ForDay $d)) {
                if ($done.ContainsKey($s.Id)) { continue }
                $done[$s.Id] = $true
                if ($s.Kind -eq 'script') { foreach ($r in $s.Runs) { $expected.Add("$($s.Script)|$([bool]($r['Add'] -and $r['Add']['WhatIf']))") } }
            }
            $calls = @(Get-LabDayCall)
            $script:DayRuns[$d] = @{ Exit = $exit; Expected = $expected.ToArray(); Actual = @($calls | ForEach-Object { "$($_.script)|$($_.whatIf)" }); Calls = $calls }
        }
        $script:Manifests = @(Get-ChildItem -LiteralPath $script:Window.Evidence -Recurse -Filter 'manifest.json')
        $script:WindowCalls = @($script:DayRuns.Keys | Sort-Object | ForEach-Object { $script:DayRuns[$_].Calls })
    }

    It 'Day <Day>: exit 0; preflight, then every script run of the day in plan order, each dry run under -WhatIf before its real run' -ForEach @(0..29 | ForEach-Object { @{ Day = $_ } }) {
        $r = $DayRuns[$Day]
        $r.Exit | Should -Be 0
        ($r.Actual -join "`n") | Should -Be ($r.Expected -join "`n")
    }

    It 'fills each script''s parameters from the settings, the state and the prompts, with the types the scripts declare' {
        $kpi = @($WindowCalls | Where-Object { $_.script -like '*/08-Measure-KPIs.ps1' })
        $kpi[0].values.Label | Should -Be 'baseline'
        $kpi[0].values.SkipPam | Should -BeTrue
        $kpi[1].values.Label | Should -Be 'after'
        $kpi[1].values.CompareTo | Should -Be $KpiBaselineFile
        $build = @($WindowCalls | Where-Object { $_.script -like '*/Convert-BuildAccountToEligible.ps1' })
        $build[0].whatIf | Should -BeTrue
        @($build[0].params) | Should -Not -Contain 'ChangeTicket'
        $build[1].values.ChangeTicket | Should -Be 'CHG0001234'
        $build[1].values.BuildAccountUpn | Should -Be 'admin@contosolab.onmicrosoft.com'
        $verify = @($WindowCalls | Where-Object { $_.script -like '*/Invoke-BreakGlassDrill.ps1' -and $_.values.Phase -eq 'Verify' })[0]
        $state = Get-LabDayState -Box $Window
        ([datetime]$verify.values.DrillStartUtc).ToUniversalTime() | Should -Be ([datetime]$state.steps['bg-drill-signins'].startedUtc).ToUniversalTime()
        @($verify.values.DeclaredSignIns) | Should -Be @('bg-admin-01:key 1', 'bg-admin-01:key 2', 'bg-admin-02:key 1', 'bg-admin-02:key 2')
        $restore = @($WindowCalls | Where-Object { $_.script -like '*/Invoke-CaRestoreDrill.ps1' })
        @($restore | ForEach-Object { "$($_.values.Mode)|$($_.whatIf)" }) | Should -Be @('Snapshot|False', 'Compare|False', 'Restore|True', 'Restore|False')
        $restore[1].values.SnapshotPath | Should -Be $SnapshotFile
        $restore[3].values.Apply | Should -BeTrue
        $restore[3].values.PolicyName | Should -Be 'CA004 - Block countries'
        $leaver = @($WindowCalls | Where-Object { $_.script -like '*/04-Leaver.ps1' })
        $leaver[0].whatIf | Should -BeTrue
        $leaver[1].values.Confirm | Should -BeFalse
        $leaver[1].values.NhiHandoff | Should -Be 'ReassignToManager'
        @($global:LabDayTest.Prompts | Where-Object { $_ -like '*-Confirm:$false: this answer is its only confirmation*' }).Count | Should -Be 1
        @($WindowCalls | Where-Object { @($_.params) -contains 'GrantDisableRole' }) | Should -BeNullOrEmpty
        @($global:LabDayTest.Inputs).Count | Should -Be 2 -Because 'the change ticket is asked once in each step that needs it (build-account, bg-drill-verify)'
    }

    It 'seals every capture: its SHA256SUMS verifies, its manifest is public-safe, and it has exactly one capture-log row' {
        $Manifests.Count | Should -BeGreaterThan 100
        $rows = @(Import-Csv -LiteralPath $Window.Log)
        $rows.Count | Should -Be $Manifests.Count
        foreach ($mf in $Manifests) {
            $dir = $mf.Directory.FullName
            $text = Get-Content -LiteralPath $mf.FullName -Raw
            Test-LabPublicSafeText -Text $text | Should -BeTrue -Because $dir
            $text | Should -Not -Match 'contosolab|contosohealth\.test|203\.0\.113\.10' -Because $dir
            ($text | ConvertFrom-Json).counts.failed | Should -Be 0 -Because "$($mf.Directory.Name): every read is mocked"
            foreach ($l in Get-Content -LiteralPath (Join-Path $dir 'SHA256SUMS')) {
                $hash, $rel = $l -split '  ', 2
                (Get-FileHash -LiteralPath (Join-Path $dir $rel) -Algorithm SHA256).Hash.ToLowerInvariant() | Should -Be $hash -Because "$($mf.Directory.Name)/$rel"
            }
            $row = @($rows | Where-Object { $_.id -eq $mf.Directory.Name })
            $row.Count | Should -Be 1 -Because $mf.Directory.Name
            $row[0].sha256 | Should -Be (Get-FileHash -LiteralPath (Join-Path $dir 'SHA256SUMS') -Algorithm SHA256).Hash.ToLowerInvariant()
        }
    }

    It 'reads the tenant with GET only, through allowlisted az / gh verbs only, with no scope missing' {
        $global:LabDayTest.Graph.Count | Should -BeGreaterThan 100
        @($global:LabDayTest.Graph | Where-Object { $_.Method -ne 'GET' }) | Should -BeNullOrEmpty
        @($global:LabDayTest.Native | Where-Object { $_ -match '^az rest --method post' -and $_ -notmatch 'https://api\.loganalytics\.io/v1/workspaces/[^/ ]+/query ' }) | Should -BeNullOrEmpty
        @($global:LabDayTest.Console | Where-Object { $_ -like '*read(s) failed*' }) | Should -BeNullOrEmpty
    }

    It 'ends with every step done, and the Day 28 close-out names the ids no API can capture' {
        $state = Get-LabDayState -Box $Window
        foreach ($s in $WindowPlan.Steps) { $state.steps[$s.Id].status | Should -Be 'done' -Because $s.Id }
        $coverage = @($global:LabDayTest.Console | Where-Object { $_ -like '*capture log:*' })
        $coverage.Count | Should -Be 1
        $coverage[0] | Should -Match 'no row yet: E24, E53c, E57, E58 '
        @($global:LabDayTest.Console | Where-Object { $_ -like '*Nothing left on Day 2[1-4]:*' }).Count | Should -Be 4 -Because 'the buffer step is done on Day 20'
    }
}
