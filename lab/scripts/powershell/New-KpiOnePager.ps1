<#
.SYNOPSIS
    Renders a KPI snapshot from 08-Measure-KPIs.ps1 as the one-page view the
    CISO reads monthly and the board sees quarterly (operating model section 4):
    three headline numbers, every KPI with its direction of travel, and what
    could not be measured, stated as such.

.DESCRIPTION
    Reads the newest snapshot in lab/evidence/kpis/ (or -SnapshotPath), and
    an earlier one for direction (-CompareTo, or the snapshot's own
    'comparison' block written by 08 -CompareTo). Writes Markdown next to the
    snapshot (<stamp>-onepager.md) with a .sha256 sidecar, so the page an
    executive reads is the hashed record, not a slide someone retyped.

    Rules the page keeps, the same as the snapshot:
      * a KPI with status 'failed' or 'not-measured' is printed as that, with
        its reason. It is never printed as 0 and never left out;
      * direction is judged against each KPI's good direction (standing
        admins: down; phishing-resistant coverage: up), so an arrow is
        'better' or 'worse', never just 'up';
      * nothing is estimated: no number appears that is not in a snapshot;
      * public-safe: only what the snapshot holds (the kpis folder is public;
        per-object detail stays in the gitignored detail folder).

    Status: BUILT, tested offline against synthetic snapshots. No snapshot has
    been taken from a tenant (RAN tenant: none), so no page has real numbers.

.PARAMETER SnapshotPath
    A snapshot file. Default: the newest *.json in -SnapshotDirectory that is
    not a one-pager.
.PARAMETER CompareTo
    An earlier snapshot for direction of travel. Ignored when the snapshot
    already carries a 'comparison' block.
.PARAMETER SnapshotDirectory
    Where snapshots live. Default: lab/evidence/kpis.
.PARAMETER OutputPath
    Where to write the Markdown. Default: next to the snapshot as
    <stamp>-onepager.md.
.PARAMETER PassThru
    Also return the Markdown as a string.

.EXAMPLE
    pwsh lab/scripts/powershell/New-KpiOnePager.ps1
.EXAMPLE
    pwsh lab/scripts/powershell/New-KpiOnePager.ps1 -SnapshotPath after.json -CompareTo baseline.json -PassThru
#>
#Requires -Version 7.0
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$SnapshotPath,
    [string]$CompareTo,
    [string]$SnapshotDirectory = (Join-Path $PSScriptRoot '..' '..' 'evidence' 'kpis'),
    [string]$OutputPath,
    [switch]$PassThru
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-Console {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'Interactive operator console (colour): status lines for the person running the script, not pipeline data.')]
    param()
    Write-Host @args
}

# =============================================================================
# PURE FUNCTIONS (tested from the syntax tree, no I/O)
# =============================================================================

function Get-KpiCatalog {
    # Every KPI 08 can write, in page order, with its good direction and
    # whether it is one of the three board numbers. A KPI not listed here is
    # still printed (after these), with direction 'n/a'.
    return @(
        [pscustomobject]@{ Key = 'admin_standing_users'; Title = 'Standing privileged humans'; Good = 'down'; Board = $true; Why = 'People who hold admin power when they are not using it' }
        [pscustomobject]@{ Key = 'phishing_resistant_pct'; Title = 'Workforce on phishing-resistant sign-in'; Good = 'up'; Board = $true; Why = 'Share of staff a stolen password cannot get past' }
        [pscustomobject]@{ Key = 'hr_to_disable_minutes'; Title = 'Minutes from HR leaver to account disabled'; Good = 'down'; Board = $true; Why = 'How long a leaver keeps a working badge' }
        [pscustomobject]@{ Key = 'admin_jit_pct'; Title = 'Share of admins on just-in-time access only'; Good = 'up'; Board = $false; Why = 'Eligible-only admins out of all admins: who can only elevate, not who did' }
        [pscustomobject]@{ Key = 'admin_eligible_only_users'; Title = 'Admins eligible only (no standing role)'; Good = 'up'; Board = $false; Why = '' }
        [pscustomobject]@{ Key = 'privileged_service_principals'; Title = 'Workload identities with privileged access'; Good = 'down'; Board = $false; Why = '' }
        [pscustomobject]@{ Key = 'phishing_resistant_device_bound_pct'; Title = 'Workforce with device-bound (attested) passkeys'; Good = 'up'; Board = $false; Why = '' }
        [pscustomobject]@{ Key = 'ca_mfa_coverage_pct'; Title = 'Users covered by an enforced MFA policy'; Good = 'up'; Board = $false; Why = '' }
        [pscustomobject]@{ Key = 'ca_mfa_coverage_incl_report_only_pct'; Title = 'Same, if report-only policies were enforced'; Good = 'up'; Board = $false; Why = '' }
        [pscustomobject]@{ Key = 'access_review_completion_pct'; Title = 'Access review decisions made by a person'; Good = 'up'; Board = $false; Why = '' }
        [pscustomobject]@{ Key = 'access_review_revocation_pct'; Title = 'Reviews that removed access'; Good = 'n/a'; Board = $false; Why = '' }
        [pscustomobject]@{ Key = 'access_review_revocation_applied_pct'; Title = 'Removals that were applied'; Good = 'up'; Board = $false; Why = '' }
        [pscustomobject]@{ Key = 'stale_accounts'; Title = 'Enabled accounts with no recent sign-in'; Good = 'down'; Board = $false; Why = '' }
        [pscustomobject]@{ Key = 'nhi_expired_or_orphaned'; Title = 'Non-human identities expired or without an owner'; Good = 'down'; Board = $false; Why = '' }
        [pscustomobject]@{ Key = 'nhi_with_expired_credential'; Title = 'Non-human identities with an expired credential'; Good = 'down'; Board = $false; Why = '' }
        [pscustomobject]@{ Key = 'nhi_orphaned'; Title = 'Non-human identities without an accountable owner'; Good = 'down'; Board = $false; Why = '' }
        # Microsoft's own score of the tenant's security settings. Its note
        # carries the baseline day vs today from Microsoft's daily history,
        # so the before/after reads even against a snapshot that predates it.
        [pscustomobject]@{ Key = 'secure_score_pct'; Title = 'Microsoft Secure Score'; Good = 'up'; Board = $false; Why = "Microsoft's rating of the tenant's security settings" }
    )
}

function Protect-MarkdownCell {
    param([AllowNull()][string]$Text)
    if ($null -eq $Text) { return '' }
    return ($Text -replace '\|', '\|' -replace "`r?`n", ' ').Trim()
}

function Format-KpiValue {
    # The printed value. Failed and not-measured KPIs say so with the reason;
    # they are never 0.
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Entry)
    $status = [string]$Entry['status']
    if ($status -ne 'measured') {
        $reason = if ($Entry.Contains('note') -and $Entry['note']) { [string]$Entry['note'] } elseif ($Entry.Contains('error') -and $Entry['error']) { [string]$Entry['error'] } else { 'no reason recorded' }
        $word = if ($status -eq 'failed') { 'not available (read failed)' } else { 'not measured' }
        return "${word}: $reason"
    }
    $v = $Entry['value']; $unit = [string]$Entry['unit']
    $num = if ($v -is [ValueType]) { ('{0:0.#}' -f [double]$v) } else { [string]$v }
    $out = if ($unit -eq '%') { "$num %" } elseif ($unit) { "$num $unit" } else { $num }
    if ($Entry.Contains('numerator') -and $Entry.Contains('denominator')) { $out += " ($($Entry['numerator']) of $($Entry['denominator']))" }
    return $out
}

function Get-KpiDirection {
    # 'better' / 'worse' / 'unchanged' / '' (not comparable), with the delta.
    param([Parameter(Mandatory)][string]$Good, [AllowNull()][System.Collections.IDictionary]$Delta)
    if ($null -eq $Delta -or -not $Delta.Contains('delta')) { return [pscustomobject]@{ Word = ''; Text = '' } }
    $d = [double]$Delta['delta']
    $sign = ('{0:+0.#;-0.#;0}' -f $d)
    if ($d -eq 0) { return [pscustomobject]@{ Word = 'unchanged'; Text = 'unchanged' } }
    if ($Good -eq 'n/a') { return [pscustomobject]@{ Word = 'changed'; Text = "$sign (no good direction)" } }
    $better = ($Good -eq 'down' -and $d -lt 0) -or ($Good -eq 'up' -and $d -gt 0)
    $word = if ($better) { 'better' } else { 'worse' }
    return [pscustomobject]@{ Word = $word; Text = "$sign ($word)" }
}

function ConvertTo-KpiOnePager {
    # Markdown for one snapshot, with direction against $Before when given
    # (or the snapshot's own comparison block).
    param(
        [Parameter(Mandatory)][System.Collections.IDictionary]$Snapshot,
        [AllowNull()][System.Collections.IDictionary]$Before = $null,
        [string]$SnapshotFileName = '',
        [string]$SnapshotHash = ''
    )
    if (-not $Snapshot.Contains('kpis') -or $null -eq $Snapshot['kpis']) { throw 'Snapshot has no kpis block.' }
    if ([string]$Snapshot['schema'] -ne 'contoso-identity-kpis/v1') { throw "Unexpected snapshot schema '$($Snapshot['schema'])' (expected contoso-identity-kpis/v1)." }
    $kpis = $Snapshot['kpis']
    $deltas = $null; $againstText = ''
    if ($Snapshot.Contains('comparison') -and $Snapshot['comparison']) {
        $deltas = $Snapshot['comparison']['deltas']
        $againstText = "against '$($Snapshot['comparison']['againstLabel'])' ($($Snapshot['comparison']['against']))"
    }
    elseif ($Before) {
        $deltas = Compare-KpiSnapshot -Before $Before -After $Snapshot
        $againstText = "against '$($Before['label'])' ($($Before['generatedAtUtc']))"
    }
    $catalog = Get-KpiCatalog
    $known = @{}; foreach ($c in $catalog) { $known[$c.Key] = $c }
    $order = @($catalog.Key) + @($kpis.Keys | Where-Object { -not $known.ContainsKey($_) } | Sort-Object)

    $sb = [System.Text.StringBuilder]::new()
    $null = $sb.AppendLine("# Identity KPIs: one page")
    $null = $sb.AppendLine()
    $null = $sb.AppendLine("**Snapshot:** $($Snapshot['label']) / generated $($Snapshot['generatedAtUtc']) by ``$($Snapshot['generator'])``" + $(if ($SnapshotFileName) { " / file ``$SnapshotFileName``" } else { '' }))
    if ($againstText) { $null = $sb.AppendLine("**Direction of travel:** $againstText") }
    else { $null = $sb.AppendLine("**Direction of travel:** none (first snapshot, or no -CompareTo)") }
    $null = $sb.AppendLine()
    $null = $sb.AppendLine('Every number below is read from the tenant or the local PAM stand-ins by a read-only query. A KPI that could not be read says so; it is never shown as 0.')
    $null = $sb.AppendLine()

    # ---- board block ----
    $null = $sb.AppendLine('## The three numbers')
    $null = $sb.AppendLine()
    $null = $sb.AppendLine('| | Now | Direction | What it means |')
    $null = $sb.AppendLine('|---|---|---|---|')
    foreach ($c in ($catalog | Where-Object Board)) {
        $e = if ($kpis.Contains($c.Key)) { $kpis[$c.Key] } else { [ordered]@{ status = 'not-measured'; note = 'not in this snapshot' } }
        $dir = Get-KpiDirection -Good $c.Good -Delta $(if ($deltas -and $deltas.Contains($c.Key)) { $deltas[$c.Key] } else { $null })
        $null = $sb.AppendLine("| **$($c.Title)** | $(Protect-MarkdownCell (Format-KpiValue $e)) | $(Protect-MarkdownCell $dir.Text) | $(Protect-MarkdownCell $c.Why) |")
    }
    $null = $sb.AppendLine()

    # ---- all KPIs ----
    $null = $sb.AppendLine('## All KPIs')
    $null = $sb.AppendLine()
    $null = $sb.AppendLine('| KPI | Now | Direction | Good direction | Note |')
    $null = $sb.AppendLine('|---|---|---|---|---|')
    $unmeasured = @()
    foreach ($key in $order) {
        if (-not $kpis.Contains($key)) { continue }
        $e = $kpis[$key]
        $c = if ($known.ContainsKey($key)) { $known[$key] } else { [pscustomobject]@{ Key = $key; Title = $key; Good = 'n/a'; Board = $false; Why = '' } }
        $dir = Get-KpiDirection -Good $c.Good -Delta $(if ($deltas -and $deltas.Contains($key)) { $deltas[$key] } else { $null })
        $note = if ($e.Contains('note') -and [string]$e['status'] -eq 'measured') { [string]$e['note'] } else { '' }
        $null = $sb.AppendLine("| $(Protect-MarkdownCell $c.Title) | $(Protect-MarkdownCell (Format-KpiValue $e)) | $(Protect-MarkdownCell $dir.Text) | $($c.Good) | $(Protect-MarkdownCell $note) |")
        if ([string]$e['status'] -ne 'measured') { $unmeasured += [pscustomobject]@{ Key = $key; Title = $c.Title; Status = [string]$e['status']; Reason = (Format-KpiValue $e) } }
    }
    $null = $sb.AppendLine()

    # ---- what is missing, said plainly ----
    $null = $sb.AppendLine('## Not measured this time')
    $null = $sb.AppendLine()
    if ($unmeasured.Count -eq 0) { $null = $sb.AppendLine('Every KPI was measured.') }
    else {
        foreach ($u in $unmeasured) { $null = $sb.AppendLine("- **$(Protect-MarkdownCell $u.Title)**: $(Protect-MarkdownCell $u.Reason)") }
    }
    $null = $sb.AppendLine()

    # ---- footer ----
    $null = $sb.AppendLine('---')
    $null = $sb.AppendLine()
    $params = if ($Snapshot.Contains('parameters') -and $Snapshot['parameters']) { (@($Snapshot['parameters'].Keys | ForEach-Object { "$_=$($Snapshot['parameters'][$_])" }) -join ', ') } else { '' }
    if ($params) { $null = $sb.AppendLine("Parameters: $params. ") }
    if ($SnapshotHash) { $null = $sb.AppendLine("Snapshot SHA-256: ``$SnapshotHash``. ") }
    $null = $sb.AppendLine('Definitions: `lab/scripts/powershell/08-Measure-KPIs.ps1` (synopsis). Reporting cadence: `lab/docs/standards/iam-operating-model.md` section 4. Rendered by `New-KpiOnePager.ps1`.')
    return $sb.ToString()
}

function Compare-KpiSnapshot {
    # Same rule as 08-Measure-KPIs.ps1: numeric deltas for KPIs measured in
    # BOTH snapshots; anything else is 'not comparable', never a diff against null.
    param([System.Collections.IDictionary]$Before, [System.Collections.IDictionary]$After)
    $deltas = [ordered]@{}
    foreach ($key in @($After['kpis'].Keys)) {
        $a = $After['kpis'][$key]
        $b = if ($Before -and $Before.Contains('kpis') -and $Before['kpis'].Contains($key)) { $Before['kpis'][$key] } else { $null }
        $ok = $b -and [string]$b['status'] -eq 'measured' -and [string]$a['status'] -eq 'measured' -and ($a['value'] -is [ValueType]) -and ($b['value'] -is [ValueType])
        if ($ok) { $deltas[$key] = [ordered]@{ before = $b['value']; after = $a['value']; delta = [math]::Round([double]$a['value'] - [double]$b['value'], 1) } }
        else { $deltas[$key] = [ordered]@{ comparable = $false; before = $(if ($b) { [string]$b['status'] } else { 'absent' }); after = [string]$a['status'] } }
    }
    return $deltas
}

# =============================================================================
# MAIN
# =============================================================================
if ($MyInvocation.InvocationName -ne '.') {
    $dir = [System.IO.Path]::GetFullPath($SnapshotDirectory)
    if (-not $SnapshotPath) {
        if (-not (Test-Path -LiteralPath $dir)) { throw "No snapshot directory at '$dir'. Run 08-Measure-KPIs.ps1 first, or pass -SnapshotPath." }
        $newest = Get-ChildItem -LiteralPath $dir -Filter '*.json' -File | Where-Object { $_.Name -notlike '*-onepager*' -and $_.Name -notlike '*-detail*' } | Sort-Object Name -Descending | Select-Object -First 1
        if (-not $newest) { throw "No KPI snapshot in '$dir'. Run 08-Measure-KPIs.ps1 first." }
        $SnapshotPath = $newest.FullName
    }
    if (-not (Test-Path -LiteralPath $SnapshotPath)) { throw "-SnapshotPath '$SnapshotPath' not found." }
    $snapshot = Get-Content -LiteralPath $SnapshotPath -Raw | ConvertFrom-Json -AsHashtable
    $hash = (Get-FileHash -LiteralPath $SnapshotPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $before = $null
    if ($CompareTo) {
        if (-not (Test-Path -LiteralPath $CompareTo)) { throw "-CompareTo '$CompareTo' not found." }
        $before = Get-Content -LiteralPath $CompareTo -Raw | ConvertFrom-Json -AsHashtable
    }
    $md = ConvertTo-KpiOnePager -Snapshot $snapshot -Before $before -SnapshotFileName (Split-Path -Leaf $SnapshotPath) -SnapshotHash $hash
    if (-not $OutputPath) { $OutputPath = [System.IO.Path]::ChangeExtension($SnapshotPath, $null).TrimEnd('.') + '-onepager.md' }
    if ($PSCmdlet.ShouldProcess($OutputPath, 'write KPI one-pager (+ .sha256)')) {
        $md | Set-Content -LiteralPath $OutputPath -Encoding utf8NoBOM -NoNewline
        $h = (Get-FileHash -LiteralPath $OutputPath -Algorithm SHA256).Hash.ToLowerInvariant()
        "$h  $(Split-Path -Leaf $OutputPath)" | Set-Content -LiteralPath "$OutputPath.sha256" -Encoding utf8NoBOM
        Write-Console "One-pager: $OutputPath (sha256 $h)" -ForegroundColor Cyan
    }
    if ($PassThru) { $md }
}
