# Pester 5 structure checks for the two workflows that call the pipeline
# scripts (actionlint checks the syntax; this pins the safety properties):
#   * evidence-pack.yml: manual only, main only, EVIDENCE over OIDC with no
#     subscription and no secret, every action SHA-pinned, the pack never
#     uploaded to GitHub, nothing continue-on-error, the summary always runs.
#   * terraform-apply.yml: the automatic access rule step runs only after a
#     successful apply, after a fresh APPLY sign-in, app-only, and is NOT
#     continue-on-error; the Apply summary reads its lines.
#   * config-drift.yml: a night the check could not run (no comparison)
#     opens or updates an issue instead of only going red.
# The YAML is parsed by python3 + PyYAML (lab-tests.yml installs python3-yaml
# before the Pester step); without them these checks are skipped, not passed.

BeforeDiscovery {
    $script:CanParse = $false
    if (Get-Command python3 -ErrorAction SilentlyContinue) {
        & python3 -c 'import yaml' 2>$null
        $script:CanParse = ($LASTEXITCODE -eq 0)
    }
}

BeforeAll {
    $script:Wf = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..' '..' '..' '..' '.github' 'workflows'))
    function Read-Workflow([string]$Name) {
        $json = & python3 -c 'import json,sys,yaml; d=yaml.safe_load(open(sys.argv[1])); d["on"]=d.pop(True, d.get("on")); print(json.dumps(d))' (Join-Path $script:Wf $Name)
        return ($json | ConvertFrom-Json -AsHashtable -Depth 50)
    }
    # The first step whose name matches (a hashtable; $null when none).
    function Get-Step($Job, [string]$Like) { @($Job['steps'] | Where-Object { [string]$_['name'] -like $Like }) | Select-Object -First 1 }
}

Describe 'evidence-pack.yml' -Skip:(-not $script:CanParse) {
    BeforeAll {
        $script:E = Read-Workflow 'evidence-pack.yml'
        $script:Job = $script:E['jobs']['file']
        $script:Raw = Get-Content -LiteralPath (Join-Path $script:Wf 'evidence-pack.yml') -Raw
    }

    It 'runs on a manual dispatch only' {
        @($script:E['on'].Keys) | Should -Be @('workflow_dispatch')
    }

    It 'holds only id-token: write and contents: read' {
        $script:E['permissions']['contents'] | Should -Be 'read'
        @($script:Job['permissions'].Keys | Sort-Object) | Should -Be @('contents', 'id-token')
        $script:Job['permissions']['id-token'] | Should -Be 'write'
        $script:Job['permissions']['contents'] | Should -Be 'read'
    }

    It 'signs in as EVIDENCE over OIDC with no subscription, twice (fresh token before the upload)' {
        $logins = @($script:Job['steps'] | Where-Object { [string]$_['uses'] -like 'azure/login@*' })
        $logins.Count | Should -Be 2
        foreach ($l in $logins) {
            $l['with']['client-id'] | Should -Be '${{ vars.EVIDENCE_CLIENT_ID }}'
            $l['with']['allow-no-subscriptions'] | Should -BeTrue
            $l['with'].Contains('subscription-id') | Should -BeFalse
        }
    }

    It 'refuses to run off main (the step explains it; the federated credential enforces it)' {
        (Get-Step $script:Job 'Check the one-time setup')['run'] | Should -Match "GITHUB_REF -ne 'refs/heads/main'"
    }

    It 'pins every action to a full commit SHA and never uploads the pack to GitHub' {
        foreach ($s in $script:Job['steps']) { if ($s['uses']) { [string]$s['uses'] | Should -Match '@[0-9a-f]{40}$' } }
        $script:Raw | Should -Not -Match 'upload-artifact|cache@'
        $script:Raw | Should -Not -Match 'secrets\.'
    }

    It 'collects with -UseAzureCliToken and files with new-blob-only publish under the dated prefix' {
        (Get-Step $script:Job 'Collect the evidence*')['run'] | Should -Match 'Export-EvidencePack\.ps1 -UseAzureCliToken'
        (Get-Step $script:Job 'File it in the locked evidence store*')['run'] | Should -Match '(?s)Publish-EvidencePack\.ps1 .*-Prefix \$env:PREFIX.*-Confirm:\$false'
        (Get-Step $script:Job 'Check the one-time setup')['run'] | Should -Match 'prefix=evidence-packs/'
    }

    It 'has no continue-on-error step, and the story is told on every outcome but a cancel' {
        @($script:Job['steps'] | Where-Object { $_.Contains('continue-on-error') }).Count | Should -Be 0
        (Get-Step $script:Job 'Tell the story*')['if'] | Should -Be '${{ !cancelled() }}'
        (Get-Step $script:Job 'Remove the local copy*')['if'] | Should -Be 'always()'
    }
}

Describe 'terraform-apply.yml - automatic access rules after the apply' -Skip:(-not $script:CanParse) {
    BeforeAll {
        $script:A = Read-Workflow 'terraform-apply.yml'
        $script:Steps = @($script:A['jobs']['terraform-apply']['steps'])
        $script:Names = @($script:Steps | ForEach-Object { [string]$_['name'] })
    }

    It 'runs Set-AutoAssignmentPolicies.ps1 app-only, only after a successful apply, NOT continue-on-error' {
        $s = @($script:Steps | Where-Object { $_['id'] -eq 'autoassign' })[0]
        $s['if'] | Should -Be "steps.apply.outcome == 'success'"
        $s.Contains('continue-on-error') | Should -BeFalse
        $s['run'] | Should -Match 'Set-AutoAssignmentPolicies\.ps1 -UseAzureCliToken -Confirm:\$false'
        $s['run'] | Should -Match '-SummaryPath \$plain -SummaryDetailsPath \$tech'
        $s['run'] | Should -Match 'exit \$LASTEXITCODE'
    }

    It 'signs in again as APPLY between the apply and the access-rule step' {
        $apply = [array]::IndexOf($script:Names, 'terraform apply')
        $rules = [array]::IndexOf($script:Names, 'Set who gets each automatic access package (birthright rules)')
        $login = @(0..($script:Steps.Count - 1) | Where-Object { [string]$script:Steps[$_]['uses'] -like 'azure/login@*' -and $_ -gt $apply -and $_ -lt $rules })
        $login.Count | Should -Be 1
        $script:Steps[$login[0]]['with']['client-id'] | Should -Be '${{ vars.AZURE_APPLY_CLIENT_ID }}'
        $script:Steps[$login[0]]['if'] | Should -Be "steps.apply.outcome == 'success'"
    }

    It 'the Apply summary reads the access-rule lines and the step outcome' {
        $s = @($script:Steps | Where-Object { $_['name'] -eq 'Apply summary' })[0]
        $s['if'] | Should -Be 'always()'
        $s['env']['AUTOASSIGN_OUTCOME'] | Should -Be '${{ steps.autoassign.outcome }}'
        $s['run'] | Should -Match 'plain-autoassign\.md'
        $s['run'] | Should -Match 'tech-autoassign\.md'
    }
}

Describe 'config-drift.yml - a night the check could not run is never silent' -Skip:(-not $script:CanParse) {
    # 2026-10-30 to 2026-11-04: the job could not sign in (AADSTS700213) and
    # went red six nights with no issue, because the drift issue needs a
    # comparison (lab/docs/field-notes.md, entry 5).
    BeforeAll {
        $script:D = Read-Workflow 'config-drift.yml'
        $script:DJob = $script:D['jobs']['reconcile']
        $script:Step = Get-Step $script:DJob 'Open or close the "check could not run" issue'
    }

    It 'has the step, runs it on every outcome but a cancel, with a SHA-pinned github-script' {
        $script:Step | Should -Not -BeNullOrEmpty
        $script:Step['if'] | Should -Be '${{ !cancelled() }}'
        [string]$script:Step['uses'] | Should -Match '^actions/github-script@[0-9a-f]{40}$'
        $script:DJob['permissions']['issues'] | Should -Be 'write'
    }

    It 'treats only compare_exit 0, 1 or 2 as "the check ran"; anything else (3, missing) opens or updates the issue' {
        $script:Step['env']['COMPARE_EXIT'] | Should -Be '${{ steps.compare.outputs.compare_exit }}'
        $js = [string]$script:Step['with']['script']
        $js | Should -Match "\['0', '1', '2'\]\.includes\(code\)"
        $js | Should -Match "process\.env\.COMPARE_EXIT \|\| 'missing'"
        $js | Should -Match 'issues\.create\('
        $js | Should -Match "state: 'closed'"
        $js | Should -Match 'AADSTS700213'
    }

    It 'comes before the step that fails the job, and the compare step still runs after a failed sign-in' {
        $names = @($script:DJob['steps'] | ForEach-Object { [string]$_['name'] })
        [array]::IndexOf($names, 'Open or close the "check could not run" issue') | Should -BeLessThan ([array]::IndexOf($names, 'Fail job on drift or a failed export (once a baseline exists)'))
        (Get-Step $script:DJob 'Compare against the baseline*')['if'] | Should -Be '${{ !cancelled() }}'
        (Get-Step $script:DJob 'Compare against the baseline*')['run'] | Should -Match 'compare_exit=3'
    }
}

Describe 'config-drift.yml - the "could not run" step, run under node with a mocked GitHub API' -Skip:(-not ($script:CanParse -and (Get-Command node -ErrorAction SilentlyContinue))) {
    # Runs the step's real github-script body against a mock of the Octokit
    # calls it makes, for each night type. (The string checks above pin the
    # wiring; these pin the behaviour: one issue, never a duplicate, closed on
    # recovery, the drift issue never touched.)
    BeforeAll {
        $step = Get-Step (Read-Workflow 'config-drift.yml')['jobs']['reconcile'] 'Open or close the "check could not run" issue'
        $script:StepJs = Join-Path $TestDrive 'step.js'
        Set-Content -LiteralPath $script:StepJs -Value ([string]$step['with']['script']) -Encoding utf8NoBOM
        $script:Harness = Join-Path $TestDrive 'harness.js'
        Set-Content -LiteralPath $script:Harness -Encoding utf8NoBOM -Value @'
const fs = require('fs');
const body = fs.readFileSync(process.argv[2], 'utf8');
const sc = JSON.parse(process.argv[3]);
if (sc.compareExit === null) delete process.env.COMPARE_EXIT; else process.env.COMPARE_EXIT = sc.compareExit;
const calls = [];
const issues = {
  listForRepo: 'listForRepo',
  getLabel: async () => { calls.push({ op: 'getLabel' }); if (!sc.labelExists) { const e = new Error('Not Found'); e.status = 404; throw e; } return {}; },
  createLabel: async (a) => { calls.push({ op: 'createLabel', name: a.name }); },
  create: async (a) => { calls.push({ op: 'create', title: a.title, labels: a.labels }); return { data: { number: 99 } }; },
  createComment: async (a) => { calls.push({ op: 'comment', issue: a.issue_number }); },
  update: async (a) => { calls.push({ op: 'update', issue: a.issue_number, state: a.state }); },
};
const github = { rest: { issues }, paginate: async (fn, a) => { calls.push({ op: 'list', label: a.labels, state: a.state }); return sc.open; } };
const context = { repo: { owner: 'o', repo: 'r' }, serverUrl: 'https://github.com', runId: 1, sha: 'abcdef0' };
const core = { info: () => {} };
const AsyncFunction = Object.getPrototypeOf(async function () {}).constructor;
new AsyncFunction('github', 'context', 'core', 'require', body)(github, context, core, require)
  .then(() => process.stdout.write(JSON.stringify(calls)))
  .catch((e) => { process.stdout.write(JSON.stringify([{ op: 'threw', message: String(e) }])); process.exitCode = 1; });
'@
        $script:Title = 'Nightly identity drift check could not run'
        $script:DriftIssue = @{ number = 5; title = 'Identity configuration drift (nightly reconcile)' }
        function Invoke-Night([AllowNull()][string]$CompareExit, [object[]]$Open = @(), [switch]$LabelExists) {
            $sc = @{ compareExit = $CompareExit; open = @($Open); labelExists = [bool]$LabelExists } | ConvertTo-Json -Depth 5 -Compress
            $out = & node $script:Harness $script:StepJs $sc
            return @($out | ConvertFrom-Json)
        }
    }

    It 'first night it could not run (no compare_exit): opens ONE issue with the label, creating the label if needed' {
        $calls = Invoke-Night -CompareExit $null -Open @($script:DriftIssue)
        @($calls | Where-Object op -eq 'create').Count | Should -Be 1
        ($calls | Where-Object op -eq 'create').title | Should -Be $script:Title
        ($calls | Where-Object op -eq 'create').labels | Should -Be @('identity-drift')
        @($calls | Where-Object op -eq 'createLabel').Count | Should -Be 1
        @($calls | Where-Object { $_.op -in 'comment', 'update' }).Count | Should -Be 0
    }

    It 'another night it could not run (compare_exit 3): comments on the open issue, never a duplicate, never touches the drift issue' {
        $calls = Invoke-Night -CompareExit '3' -Open @($script:DriftIssue, @{ number = 7; title = $script:Title }) -LabelExists
        @($calls | Where-Object op -eq 'create').Count | Should -Be 0
        @($calls | Where-Object op -eq 'comment').issue | Should -Be @(7)
        @($calls | Where-Object { $_.op -eq 'update' }).Count | Should -Be 0
    }

    It 'the next night that compared (0, 1 or 2) closes it; drift itself is left to the drift issue' -ForEach @('0', '1', '2') {
        $calls = Invoke-Night -CompareExit $_ -Open @($script:DriftIssue, @{ number = 7; title = $script:Title }) -LabelExists
        @($calls | Where-Object op -eq 'comment').issue | Should -Be @(7)
        $u = @($calls | Where-Object op -eq 'update')
        $u.Count | Should -Be 1
        $u[0].issue | Should -Be 7
        $u[0].state | Should -Be 'closed'
        @($calls | Where-Object op -eq 'create').Count | Should -Be 0
    }

    It 'a normal night with nothing open does nothing but look' {
        $calls = Invoke-Night -CompareExit '0' -Open @($script:DriftIssue) -LabelExists
        @($calls | Where-Object { $_.op -ne 'list' }).Count | Should -Be 0
    }
}
