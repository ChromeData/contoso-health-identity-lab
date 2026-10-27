# Pester 5 tests for New-KpiOnePager.ps1.
#   * Pure rendering functions, loaded from the script's syntax tree.
#   * One end-to-end run on synthetic snapshot files in a temp folder.
# No tenant is contacted; no file under lab/evidence is written.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    $script:Script = Get-LabScriptPath 'New-KpiOnePager.ps1'
    . (Get-ScriptFunctionBlock -Path $script:Script)

    function New-Snapshot {
        param([string]$Label = 'baseline', [string]$At = '2026-10-20T12:00:00.0000000Z', [hashtable]$Kpis)
        $k = [ordered]@{}
        foreach ($key in ($Kpis.Keys | Sort-Object)) { $k[$key] = $Kpis[$key] }
        return [ordered]@{
            schema = 'contoso-identity-kpis/v1'; label = $Label; generatedAtUtc = $At
            generator = 'lab/scripts/powershell/08-Measure-KPIs.ps1'
            parameters = [ordered]@{ staleDays = 90 }
            kpis = $k
        }
    }
    $script:Base = New-Snapshot -Label 'baseline' -Kpis @{
        admin_standing_users        = [ordered]@{ status = 'measured'; value = 7; unit = 'users' }
        phishing_resistant_pct      = [ordered]@{ status = 'measured'; value = 12.5; unit = '%'; numerator = 25; denominator = 200 }
        hr_to_disable_minutes       = [ordered]@{ status = 'not-measured'; value = $null; unit = 'minutes (median)'; note = 'no leaver in the window' }
        stale_accounts              = [ordered]@{ status = 'failed'; value = $null; unit = 'accounts'; error = 'AuditLog.Read.All missing' }
        access_review_revocation_pct = [ordered]@{ status = 'measured'; value = 10; unit = '%' }
    }
    $script:After = New-Snapshot -Label 'after' -At '2026-11-20T12:00:00.0000000Z' -Kpis @{
        admin_standing_users        = [ordered]@{ status = 'measured'; value = 2; unit = 'users'; note = 'break-glass counted apart' }
        phishing_resistant_pct      = [ordered]@{ status = 'measured'; value = 40; unit = '%'; numerator = 80; denominator = 200 }
        hr_to_disable_minutes       = [ordered]@{ status = 'measured'; value = 11; unit = 'minutes (median)' }
        stale_accounts              = [ordered]@{ status = 'measured'; value = 30; unit = 'accounts' }
        access_review_revocation_pct = [ordered]@{ status = 'measured'; value = 12; unit = '%' }
        custom_kpi_from_future      = [ordered]@{ status = 'measured'; value = 3; unit = 'things' }
    }
}

Describe 'Format-KpiValue' {
    It 'prints a measured value with its unit and the fraction' {
        Format-KpiValue $script:After['kpis']['phishing_resistant_pct'] | Should -Be '40 % (80 of 200)'
    }
    It 'never prints 0 for a failed read; it prints the error' {
        $s = Format-KpiValue $script:Base['kpis']['stale_accounts']
        $s | Should -Match '^not available \(read failed\): AuditLog'
        $s | Should -Not -Match '\b0\b'
    }
    It 'prints the reason for a not-measured KPI' {
        Format-KpiValue $script:Base['kpis']['hr_to_disable_minutes'] | Should -Be 'not measured: no leaver in the window'
    }
    It 'says when no reason was recorded' {
        Format-KpiValue ([ordered]@{ status = 'failed'; value = $null; unit = '' }) | Should -Be 'not available (read failed): no reason recorded'
    }
}

Describe 'Get-KpiDirection' {
    It 'calls a fall in standing admins better' {
        (Get-KpiDirection -Good down -Delta ([ordered]@{ before = 7; after = 2; delta = -5 })).Word | Should -Be 'better'
    }
    It 'calls a fall in phishing-resistant coverage worse' {
        (Get-KpiDirection -Good up -Delta ([ordered]@{ before = 40; after = 30; delta = -10 })).Word | Should -Be 'worse'
    }
    It 'is unchanged at zero and blank when not comparable' {
        (Get-KpiDirection -Good up -Delta ([ordered]@{ before = 1; after = 1; delta = 0 })).Word | Should -Be 'unchanged'
        (Get-KpiDirection -Good up -Delta ([ordered]@{ comparable = $false; before = 'failed'; after = 'measured' })).Word | Should -Be ''
        (Get-KpiDirection -Good up -Delta $null).Text | Should -Be ''
    }
    It 'does not judge a KPI with no good direction' {
        (Get-KpiDirection -Good 'n/a' -Delta ([ordered]@{ before = 10; after = 12; delta = 2 })).Word | Should -Be 'changed'
    }
}

Describe 'Compare-KpiSnapshot (parity with 08)' {
    It 'diffs only KPIs measured in both, and marks the rest not comparable' {
        $d = Compare-KpiSnapshot -Before $script:Base -After $script:After
        $d['admin_standing_users']['delta'] | Should -Be -5
        $d['hr_to_disable_minutes']['comparable'] | Should -BeFalse
        $d['hr_to_disable_minutes']['before'] | Should -Be 'not-measured'
        $d['custom_kpi_from_future']['before'] | Should -Be 'absent'
    }
}

Describe 'ConvertTo-KpiOnePager' {
    BeforeAll { $script:Md = ConvertTo-KpiOnePager -Snapshot $script:After -Before $script:Base -SnapshotFileName 'after.json' -SnapshotHash 'abc123' }

    It 'leads with the three board numbers, with direction' {
        $script:Md | Should -Match '## The three numbers'
        $script:Md | Should -Match '\*\*Standing privileged humans\*\* \| 2 users \| -5 \(better\)'
        $script:Md | Should -Match '\*\*Workforce on phishing-resistant sign-in\*\* \| 40 % \(80 of 200\) \| \+27\.5 \(better\)'
    }
    It 'lists every KPI, including ones the catalog does not know' {
        $script:Md | Should -Match '\| custom_kpi_from_future \| 3 things \|'
    }
    It 'states what was not measured instead of hiding it' {
        $md = ConvertTo-KpiOnePager -Snapshot $script:Base
        $md | Should -Match '## Not measured this time'
        $md | Should -Match '- \*\*Minutes from HR leaver to account disabled\*\*: not measured: no leaver in the window'
        $md | Should -Match '- \*\*Enabled accounts with no recent sign-in\*\*: not available \(read failed\): AuditLog'
        $md | Should -Not -Match 'Enabled accounts with no recent sign-in \| 0 '
    }
    It 'says when every KPI was measured and when there is no direction' {
        $md = ConvertTo-KpiOnePager -Snapshot $script:After
        $md | Should -Match 'Every KPI was measured\.'
        $md | Should -Match 'Direction of travel:\*\* none'
    }
    It 'prefers the comparison block 08 wrote over -Before' {
        $snap = [ordered]@{} + $script:After
        $snap['comparison'] = [ordered]@{ against = '2026-01-01T00:00:00Z'; againstLabel = 'older'; deltas = [ordered]@{ admin_standing_users = [ordered]@{ before = 9; after = 2; delta = -7 } } }
        $md = ConvertTo-KpiOnePager -Snapshot $snap -Before $script:Base
        $md | Should -Match "against 'older'"
        $md | Should -Match '-7 \(better\)'
    }
    It 'carries the snapshot hash and file name so the page is a record' {
        $script:Md | Should -Match 'file `after\.json`'
        $script:Md | Should -Match 'Snapshot SHA-256: `abc123`'
    }
    It 'escapes pipes in notes so the table survives' {
        $snap = New-Snapshot -Kpis @{ admin_standing_users = [ordered]@{ status = 'measured'; value = 1; unit = 'users'; note = 'a | b' } }
        (ConvertTo-KpiOnePager -Snapshot $snap) | Should -Match 'a \\\| b'
    }
    It 'refuses a snapshot without kpis or with another schema' {
        { ConvertTo-KpiOnePager -Snapshot ([ordered]@{ schema = 'contoso-identity-kpis/v1' }) } | Should -Throw '*no kpis*'
        { ConvertTo-KpiOnePager -Snapshot ([ordered]@{ schema = 'other/v9'; kpis = [ordered]@{} }) } | Should -Throw '*schema*'
    }
    It 'is deterministic' {
        (ConvertTo-KpiOnePager -Snapshot $script:After -Before $script:Base) | Should -Be (ConvertTo-KpiOnePager -Snapshot $script:After -Before $script:Base)
    }
}

Describe 'End to end on files' {
    BeforeAll {
        $script:Tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("kpi-onepager-" + [guid]::NewGuid().ToString('n'))
        New-Item -ItemType Directory -Path $script:Tmp | Out-Null
        $script:Base | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $script:Tmp '20261020T120000Z.json') -Encoding utf8NoBOM
        $script:After | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $script:Tmp '20261120T120000Z.json') -Encoding utf8NoBOM
    }
    AfterAll { if (Test-Path $script:Tmp) { Remove-Item -LiteralPath $script:Tmp -Recurse -Force } }

    It 'picks the newest snapshot, writes the page and its hash, and returns the Markdown' {
        $md = & $script:Script -SnapshotDirectory $script:Tmp -CompareTo (Join-Path $script:Tmp '20261020T120000Z.json') -PassThru 6> $null
        $out = Join-Path $script:Tmp '20261120T120000Z-onepager.md'
        Test-Path $out | Should -BeTrue
        Test-Path "$out.sha256" | Should -BeTrue
        $md | Should -Match '-5 \(better\)'
        (Get-Content -LiteralPath "$out.sha256" -Raw) | Should -Match "^[0-9a-f]{64}  20261120T120000Z-onepager\.md"
    }
    It 'ignores one-pagers when choosing the newest snapshot' {
        $md = & $script:Script -SnapshotDirectory $script:Tmp -PassThru -WhatIf 6> $null
        $md | Should -Match "Snapshot:\*\* after"
    }
    It 'writes nothing under -WhatIf' {
        Remove-Item -LiteralPath (Join-Path $script:Tmp '20261120T120000Z-onepager.md') -ErrorAction SilentlyContinue
        $null = & $script:Script -SnapshotDirectory $script:Tmp -WhatIf 6> $null
        Test-Path (Join-Path $script:Tmp '20261120T120000Z-onepager.md') | Should -BeFalse
    }
}
