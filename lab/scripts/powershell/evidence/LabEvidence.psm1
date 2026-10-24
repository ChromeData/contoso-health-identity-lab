<#
.SYNOPSIS
    Read-only evidence capture for the trial window, used by
    ../Invoke-LabDay.ps1: Microsoft Graph exports, Log Analytics query
    results, Azure Resource Manager reads, the pipeline's own run logs
    (Terraform plan / apply in GitHub Actions), local files and script
    transcripts. One folder per evidence id, each with a public-safe
    manifest.json and a SHA256SUMS file.

.DESCRIPTION
    One capture (UTC day stamp; ids from lab/docs/evidence-capture-plan.md):

        lab/evidence/tenant/<yyyyMMdd>/<id>[-<part>]/
            raw/          the exports: PRIVATE (tenant and object ids, UPNs,
                          IPs). The .gitignore written beside it keeps raw/
                          out of git and out of the public repository; upload
                          the folder to the WORM store the same day.
            manifest.json PUBLIC-SAFE: what was read (the request template,
                          never a filled-in id), when, the window, each
                          file's SHA-256 and size, counts and a few numeric
                          summaries. No tenant id, object id, UPN or IP.
            SHA256SUMS    sha256sum format over raw/** and manifest.json:
                          `shasum -a 256 -c SHA256SUMS` on the private copy,
                          `shasum -a 256 -c --ignore-missing SHA256SUMS` on
                          the public one (raw/ is absent there by design).
            .gitignore    raw/

    A folder is never overwritten: a second capture of the same id is a
    new folder <id>.rerun-<UTC> whose manifest says which capture it re-runs
    (capture rule 1).

    Read-only by construction:
      * Graph: Get-LabGraphResult is the only caller of Invoke-MgGraphRequest
        and always passes -Method GET.
      * az / gh: Invoke-LabNativeCommand refuses anything outside a short
        allowlist of read verbs (Assert-LabReadOnlyCommand). The one POST is
        the Log Analytics query API, which reads.
      * Never `terraform output`: under -json it prints sensitive outputs in
        clear text. The plan / apply record comes from the pipeline's run
        logs, which GitHub masks.
    Fail-open, never silent: a read that fails is an item with status
    'failed' and a redacted reason; the capture still completes and is
    hashed, so a missing export shows as missing, never as "nothing there".

.NOTES
    Status: BUILT. tests/Invoke-LabDay.Tests.ps1 covers it with every Graph,
    az and gh call mocked. Not run against a tenant: none exists yet.
    verify: each recipe's least-privilege scope and $expand support against
      Microsoft Learn on the day (marked verify: beside the recipe).
#>


Set-StrictMode -Version Latest

# The functions live in two .ps1 files so the lab analyzer gate covers them
# (tests/Invoke-LabTests.ps1 lints *.ps1); they are dot-sourced into this
# module scope, so Pester mocks them with -ModuleName LabEvidence.
. (Join-Path $PSScriptRoot 'LabEvidence.Core.ps1')
. (Join-Path $PSScriptRoot 'LabEvidence.Recipes.ps1')

Export-ModuleMember -Function @(
    'Write-LabCaptureLine', 'Read-LabOperatorChoice', 'Read-LabOperatorInput',
    'ConvertTo-LabSafeText', 'Test-LabPublicSafeText',
    'Assert-LabReadOnlyCommand', 'Invoke-LabNativeCommand',
    'Get-LabGraphResult', 'Get-LabGraphScopeGap',
    'Initialize-LabCapture', 'Invoke-LabCaptureRecipe', 'Add-LabCaptureFile', 'Complete-LabCapture',
    'Add-LabCaptureLogRow', 'Get-LabCaptureLogId',
    'Get-LabCaptureRecipeName', 'Get-LabCaptureScope',
    'Read-LabTfvarsState', 'Find-LabKpiBaseline'
)
