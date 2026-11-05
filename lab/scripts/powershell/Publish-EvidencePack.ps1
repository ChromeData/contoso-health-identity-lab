<#
.SYNOPSIS
    Files an evidence pack (Export-EvidencePack.ps1 output) in the WORM
    evidence store: new blobs only, under one dated prefix, each file's
    SHA-256 checked against the manifest before upload and read back after,
    and the store's retention lock reported per file.

.DESCRIPTION
    The second half of .github/workflows/evidence-pack.yml (the first half is
    Export-EvidencePack.ps1 -UseAzureCliToken). Runs as whatever the Azure
    CLI is signed in as: in the workflow, the EVIDENCE identity, whose only
    storage right is "create new blobs and read them" in the evidence
    container (envs/bootstrap, ABAC condition). Locally, an operator with the
    E05 grant can run it the same way.

    WHAT IS UPLOADED
      manifest.json, SUMMARY.md and every collected artifact the manifest
      lists in the pack folder (status ok or failed: a failed artifact's
      error stub is evidence of the gap). Companion evidence is not copied:
      the manifest carries its hashes, and the run's commit (-Commit)
      anchors them to the repository.

    FAIL CLOSED
      * A pack file whose SHA-256 differs from the manifest stops the run
        before anything is sent (outcome invalid, fingerprint-mismatch).
      * Every upload is --overwrite false; the EVIDENCE grant could not
        overwrite anyway. A name already in the store is a refusal, never a
        replacement.
      * A refusal that would repeat for every file (the store's firewall,
        no permission, no sign-in, store not found) stops at the first file.
      * After upload each blob is downloaded again and re-hashed; a mismatch
        fails the run. So does a read-back that never finished (a time-out,
        a sign-in that expired mid-run, a download that wrote nothing): that
        file is in the store but was never compared with its fingerprint,
        and an unchecked file is not a filed one (outcome failed, kind
        read-back). Only -SkipReadBack, asked for explicitly, files a pack
        without that comparison.

    PRIVACY
      The pack files hold names and UPNs; they go to the private WORM
      container only. This script prints file names, sizes, hashes and the
      store's answers: no file content.

    TRANSPORT
      Entra auth only (`az storage blob ... --auth-mode login`; the account
      has Shared Key disabled). The storage firewall must admit the machine
      this runs on: a GitHub-hosted runner is outside an operator-IP-only
      firewall and gets AuthorizationFailure (outcome refused, kind network).

.PARAMETER PackDirectory
    The folder Export-EvidencePack.ps1 wrote (manifest.json inside).

.PARAMETER StorageAccountName
    The WORM evidence account (envs/dev output evidence_storage_account_name).

.PARAMETER ContainerName
    The evidence container. Default evidence.

.PARAMETER Prefix
    Blob folder for this pack, e.g. evidence-packs/2026-11-02/231500Z-run123-1.
    A new prefix per run: the store never takes the same name twice.

.PARAMETER ResultPath
    Machine-readable result for the run summary (Write-EvidencePackSummary.ps1):
    outcome, refusal kind, and per file the blob name, SHA-256, upload and
    read-back result, version id and retention lock. Written on every outcome.

.PARAMETER RunId
    Stored as blob metadata (runid) next to sha256.

.PARAMETER Commit
    Stored as blob metadata (commit): the commit whose companion evidence the
    manifest hashed.

.PARAMETER SkipReadBack
    Do not download and re-hash each blob after upload: the run can then end
    "filed" with no stored copy compared against its fingerprint. Without
    it, a read-back that does not complete fails the run, as a mismatch does.

.EXAMPLE
    ./Publish-EvidencePack.ps1 -PackDirectory ../../evidence/out -StorageAccountName stidlabevidence7f3a `
        -Prefix "evidence-packs/$(Get-Date -AsUTC -Format yyyy-MM-dd)/manual-$(Get-Date -AsUTC -Format HHmmss)Z" -WhatIf

.OUTPUTS
    Exit 0 when the pack is filed (or -WhatIf); 1 otherwise.

.NOTES
    verify: on the first run, that `az storage blob show` reports the
    inherited account-level policy per blob as immutabilityPolicy.expiryTime
    / policyMode (the same open check as Invoke-BaselineAssessment.ps1).
    Without it the summary says the lock could not be read back.
#>

#Requires -Version 7.0

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$PackDirectory,

    [Parameter(Mandatory)]
    [ValidatePattern('^[a-z0-9]{3,24}$')]
    [string]$StorageAccountName,

    [Parameter()]
    [ValidatePattern('^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$')]
    [string]$ContainerName = 'evidence',

    [Parameter(Mandatory)]
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._/-]{0,199}$')]
    [string]$Prefix,

    [Parameter()]
    [string]$ResultPath = '',

    [Parameter()]
    [ValidatePattern('^[A-Za-z0-9._-]{0,64}$')]
    [string]$RunId = '',

    [Parameter()]
    [ValidatePattern('^[0-9a-fA-F]{0,40}$')]
    [string]$Commit = '',

    [Parameter()]
    [switch]$SkipReadBack
)

# Operator console output. Write-Host on purpose (colour, -NoNewline); every
# script-level status line goes through here, so the analyzer suppression is
# scoped to this one function, never to the file.
function Write-Console {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'Interactive operator console (colour, -NoNewline): status lines for the person running the script, not pipeline data.')]
    param()
    Write-Host @args
}

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# =============================================================================
# PURE HELPERS (tests/EvidencePackPipeline.Tests.ps1)
# =============================================================================
function Get-StoreFailureKind {
    # An az storage error -> what it means. network = the storage firewall
    # (AuthorizationFailure); permission = RBAC / the ABAC condition
    # (AuthorizationPermissionMismatch); exists = the name is taken.
    param([AllowEmptyString()][string]$Message = '')
    if ($Message -match 'AuthorizationPermissionMismatch|using this permission|AuthorizationCondition') { return 'permission' }
    if ($Message -match 'AuthorizationFailure|not authorized to perform this operation') { return 'network' }
    if ($Message -match 'BlobAlreadyExists|already exists') { return 'exists' }
    if ($Message -match 'az login|AADSTS|Please run|credentials? (are|is) not|No subscription found') { return 'sign-in' }
    if ($Message -match 'ContainerNotFound|ResourceNotFound|Name or service not known|getaddrinfo|nodename nor servname|Failed to resolve') { return 'not-found' }
    return 'other'
}

function Get-PackFileList {
    # The files to file: manifest artifacts that live in the pack folder
    # (collected ones, ok or failed; never companion evidence), then
    # manifest.json itself. Each with the SHA-256 the manifest recorded
    # (manifest.json: hashed here, it does not hash itself).
    param([Parameter(Mandatory)]$Manifest, [Parameter(Mandatory)][string]$Directory)
    $list = [System.Collections.Generic.List[object]]::new()
    foreach ($a in @($Manifest['artifacts'] | Where-Object { $_ })) {
        $src = if ($a.Contains('source')) { [string]$a['source'] } else { '' }
        if ($src -eq 'companion') { continue }
        $name = [string]$a['file']
        if (-not $name -or $name -match '[\\/]' -or [string]$a['status'] -notin 'ok', 'failed') { continue }
        $list.Add([pscustomobject]@{ file = $name; path = (Join-Path $Directory $name); sha256 = ([string]$a['sha256']).ToLowerInvariant() })
    }
    return $list.ToArray()
}

# =============================================================================
# SCRIPT BODY
# =============================================================================
if ($Prefix -match '\.\.|//' -or $Prefix.EndsWith('/')) { throw "-Prefix '$Prefix' must be a plain folder path (no '..', no '//', no trailing '/')." }
$PackDirectory = [System.IO.Path]::GetFullPath($PackDirectory)
$started = [datetime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
$files = [System.Collections.Generic.List[object]]::new()
$resultTarget = $ResultPath   # -ResultPath, written on every outcome from here on

function Save-PublishResult {
    # The run summary's input (-ResultPath): names, hashes and the store's
    # answers, never file content. -WhatIf:$false: this is the run's report.
    param([Parameter(Mandatory)][string]$Outcome, [hashtable]$Refusal = $null)
    if (-not $resultTarget) { return }
    $doc = [ordered]@{
        schema     = 'evidence-pack-publish/1'
        outcome    = $Outcome          # invalid | dry-run | refused | failed | partial | filed
        refusal    = $Refusal
        account    = $StorageAccountName
        container  = $ContainerName
        prefix     = "$Prefix/"
        runId      = $RunId
        commit     = $Commit
        startedUtc = $started
        files      = @($files)
    }
    $dir = Split-Path -Parent $resultTarget
    if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force -WhatIf:$false | Out-Null }
    ($doc | ConvertTo-Json -Depth 6) | Set-Content -LiteralPath $resultTarget -Encoding utf8NoBOM -WhatIf:$false
}

# ---- 1. The pack, checked against its own manifest --------------------------
$manifestPath = Join-Path $PackDirectory 'manifest.json'
if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
    Save-PublishResult -Outcome 'invalid' -Refusal @{ kind = 'no-pack' }
    throw "No manifest.json in '$PackDirectory': run Export-EvidencePack.ps1 first. Nothing was uploaded."
}
$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json -AsHashtable
$pack = @(Get-PackFileList -Manifest $manifest -Directory $PackDirectory)
if (-not $pack) {
    Save-PublishResult -Outcome 'invalid' -Refusal @{ kind = 'no-pack' }
    throw 'The manifest lists no collected file in the pack folder. Nothing was uploaded.'
}
foreach ($f in $pack) {
    $have = if (Test-Path -LiteralPath $f.path -PathType Leaf) { (Get-FileHash -LiteralPath $f.path -Algorithm SHA256).Hash.ToLowerInvariant() } else { '' }
    if ($have -ne $f.sha256) {
        Save-PublishResult -Outcome 'invalid' -Refusal @{ kind = 'fingerprint-mismatch'; file = $f.file }
        throw "Fingerprint mismatch: $($f.file) is not the file the manifest hashed. Nothing was uploaded."
    }
}
$pack += [pscustomobject]@{ file = 'manifest.json'; path = $manifestPath; sha256 = (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant() }
Write-Console "Evidence pack: $($pack.Count) file(s), every fingerprint matches the manifest." -ForegroundColor Cyan
Write-Console "Destination: $StorageAccountName / $ContainerName / $Prefix/ (new files only)" -ForegroundColor Cyan

if (-not $PSCmdlet.ShouldProcess("$StorageAccountName/$ContainerName/$Prefix/", "upload $($pack.Count) new blob(s)")) {
    foreach ($f in $pack) {
        Write-Console "  [whatif] $Prefix/$($f.file)  sha256 $($f.sha256)" -ForegroundColor DarkYellow
        $files.Add([ordered]@{ file = $f.file; blob = "$Prefix/$($f.file)"; sha256 = $f.sha256; sizeBytes = (Get-Item -LiteralPath $f.path).Length; uploaded = $false; verified = $false; versionId = $null; immutabilityExpiry = $null; policyMode = $null; error = $null })
    }
    Save-PublishResult -Outcome 'dry-run'
    Write-Console 'Dry run: nothing was uploaded.' -ForegroundColor DarkYellow
    return
}

# ---- 2. Upload: new blobs only ----------------------------------------------
$readDir = Join-Path ([System.IO.Path]::GetTempPath()) ('evidence-readback-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $readDir -Force | Out-Null
$stop = $null
try {
    foreach ($f in $pack) {
        $blob = "$Prefix/$($f.file)"
        $row = [ordered]@{ file = $f.file; blob = $blob; sha256 = $f.sha256; sizeBytes = (Get-Item -LiteralPath $f.path).Length; uploaded = $false; verified = $false; versionId = $null; immutabilityExpiry = $null; policyMode = $null; error = $null }
        $files.Add($row)
        if ($stop) { $row.error = "not attempted ($($stop.kind))"; continue }

        $meta = @("sha256=$($f.sha256)") + @(if ($RunId) { "runid=$RunId" }) + @(if ($Commit) { "commit=$Commit" })
        $global:LASTEXITCODE = 0
        $out = & az storage blob upload --account-name $StorageAccountName --container-name $ContainerName --name $blob --file $f.path `
            --auth-mode login --overwrite false --validate-content --metadata @meta --only-show-errors --output none 2>&1
        if ($LASTEXITCODE -ne 0) {
            $msg = (($out | Out-String).Trim())
            $kind = Get-StoreFailureKind $msg
            $row.error = "$kind`: $(if ($msg.Length -gt 300) { $msg.Substring(0, 300) } else { $msg })"
            Write-Warning "Upload refused for $($f.file) ($kind): $msg"
            if ($kind -in 'network', 'permission', 'sign-in', 'not-found', 'exists') { $stop = @{ kind = $kind } }
            continue
        }
        $row.uploaded = $true

        # The store's own answer: version id and the retention lock on this blob.
        $global:LASTEXITCODE = 0
        $show = & az storage blob show --account-name $StorageAccountName --container-name $ContainerName --name $blob --auth-mode login `
            --query '{versionId:versionId, expiry:immutabilityPolicy.expiryTime, mode:immutabilityPolicy.policyMode}' --output json --only-show-errors 2>&1
        if ($LASTEXITCODE -eq 0) {
            try {
                $sj = ($show | Out-String) | ConvertFrom-Json -AsHashtable
                $row.versionId = [string]$sj['versionId']
                $row.immutabilityExpiry = if ($sj['expiry']) { ([datetime]$sj['expiry']).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') } else { $null }
                $row.policyMode = if ($sj['mode']) { [string]$sj['mode'] } else { $null }
            }
            catch { Write-Warning "Could not read the blob properties of $($f.file): $($_.Exception.Message)" }
        }

        # Read it back and re-hash: what the store holds is what was fingerprinted.
        if (-not $SkipReadBack) {
            $copy = Join-Path $readDir $f.file
            $global:LASTEXITCODE = 0
            $dl = & az storage blob download --account-name $StorageAccountName --container-name $ContainerName --name $blob --file $copy `
                --auth-mode login --no-progress --only-show-errors --output none 2>&1
            if ($LASTEXITCODE -eq 0 -and (Test-Path -LiteralPath $copy)) {
                $row.verified = ((Get-FileHash -LiteralPath $copy -Algorithm SHA256).Hash.ToLowerInvariant() -eq $f.sha256)
                if (-not $row.verified) { $row.error = 'read-back: the stored copy does not match the fingerprint' }
            }
            else {
                $row.error = "read-back failed: $((($dl | Out-String).Trim()))"
                Write-Warning "Could not read $($f.file) back from the store to check it ($(Get-StoreFailureKind $row.error)): $($row.error)"
            }
        }
        Write-Console ("  [+] {0}  sha256 {1}{2}" -f $blob, $f.sha256, $(if ($row.verified) { '  (read back, matches)' } else { '' })) -ForegroundColor Green
    }
}
finally { Remove-Item -LiteralPath $readDir -Recurse -Force -ErrorAction SilentlyContinue }

# ---- 3. Outcome ---------------------------------------------------------------
$uploaded = @($files | Where-Object { $_.uploaded }).Count
$mismatch = @($files | Where-Object { $_.uploaded -and $_.error -like 'read-back: the stored copy*' }).Count
# Unchecked: stored, but the read-back that compares it with its fingerprint
# never finished (time-out, a sign-in that expired mid-run, no file written).
# Counted as "uploaded and not verified, other than a mismatch" rather than
# from the error text, so ANY read-back that did not end in a match fails
# closed. Silence is not a pass: a pack is filed only when every stored copy
# was compared, unless -SkipReadBack waived the comparison explicitly.
$unchecked = if ($SkipReadBack) { 0 } else { @($files | Where-Object { $_.uploaded -and -not $_.verified }).Count - $mismatch }
$outcome = if ($mismatch) { 'failed' }
elseif ($uploaded -eq $files.Count -and $unchecked) { 'failed' }
elseif ($uploaded -eq $files.Count) { 'filed' }
elseif ($uploaded -gt 0) { 'partial' }
elseif ($stop) { 'refused' }
else { 'failed' }
# Every upload succeeding means no $stop, so a read-back failure carries its
# own kind: the summary must say "stored but not checked", not "not stored".
$refusal = if ($stop -and $outcome -ne 'filed') { $stop }
elseif ($outcome -eq 'failed' -and $unchecked -and -not $mismatch) { @{ kind = 'read-back'; unchecked = $unchecked } }
else { $null }
Save-PublishResult -Outcome $outcome -Refusal $refusal
Write-Console ("`n{0}: {1} of {2} file(s) stored as new blobs under {3}/" -f $outcome, $uploaded, $files.Count, $Prefix) -ForegroundColor $(if ($outcome -eq 'filed') { 'Green' } else { 'Red' })
if ($unchecked) {
    Write-Console ("{0} of the stored file(s) could not be read back to check them against their fingerprints (see the warnings above). They are in the store under whatever retention it reported above, but nobody has confirmed they match what was collected, so the pack does not count as filed. Run it again under a new -Prefix to file a checked copy." -f $unchecked) -ForegroundColor Red
}
if ($outcome -ne 'filed') { exit 1 }
exit 0
