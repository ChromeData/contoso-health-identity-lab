# =============================================================================
# LabEvidence.Core.ps1 - dot-sourced by LabEvidence.psm1 (the module that
# ../Invoke-LabDay.ps1 imports). The operator seams, redaction, the read-only
# az / gh / Graph wrappers, the capture folder, manifest, SHA256SUMS and the
# capture log. Read-only toward the tenant by construction: see the module
# header. Kept as .ps1 so the lab analyzer gate (tests/Invoke-LabTests.ps1)
# and the suppression-scope test cover it like every other script.
# =============================================================================

Set-StrictMode -Version Latest


$script:Graph = 'https://graph.microsoft.com/v1.0'
# Entra role template id: the same in every tenant (public, documented).
$script:GlobalAdminRoleId = '62e90394-69f5-4237-9190-012177145e10'
$script:ManifestSchema = 'contoso-lab-capture/1'
$script:CaptureLogHeader = 'id,utc,what,sha256,stored_at,public,operator'
# IPv6 written with '::' (2001:db8::7d8e, 2001:db8:85a3::8a2e:370:7334, fe80::1,
# ::ffff:c000:201, a prefix such as 2001:db8::). Never the tail of a longer hex
# run, never right after a ']' (a .NET static call: [Foo]::Add), never followed
# by a letter or digit ([regex]::Escape, std::vector); a ':' after it is fine
# (an address ending a sentence or a field). Forms without '::' (the full
# eight groups) are the next pattern's.
$script:Ipv6CompressedPattern = '(?i)(?<![0-9a-f\]]|[0-9a-f]:)(?:(?:[0-9a-f]{1,4}:){1,7}:(?:[0-9a-f]{1,4}(?::[0-9a-f]{1,4}){0,6})?|::[0-9a-f]{1,4}(?::[0-9a-f]{1,4}){0,6})(?![0-9a-z])'
$script:Ipv6FullPattern = '(?i)\b(?:[0-9a-f]{1,4}:){3,7}[0-9a-f]{1,4}\b'


# =============================================================================
# Console and operator seams (mocked in tests)
# =============================================================================
function Write-LabCaptureLine {
    # Status lines for the person at the keyboard.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'Interactive operator console (colour): status lines for the person running the day, not pipeline data.')]
    [CmdletBinding()]
    param([AllowEmptyString()][string]$Text = '', [ConsoleColor]$Color = [ConsoleColor]::Gray)
    Write-Host $Text -ForegroundColor $Color
}

function Read-LabOperatorChoice {
    <#
    The one place the day runner waits for the operator. -Choices are
    'key=word' pairs ('d=done', 's=skip'); the word is returned. No default
    unless -Default names a key: an accidental Enter never approves a change.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'Interactive operator prompt: the hint line belongs on the console, not in the pipeline.')]
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][string]$Prompt,
        [Parameter(Mandatory)][string[]]$Choices,
        [string]$Default = ''
    )
    $map = [ordered]@{}
    foreach ($c in $Choices) {
        $pair = $c -split '=', 2
        $map[$pair[0].ToLowerInvariant()] = $pair[1]
    }
    $hint = (@($map.Keys | ForEach-Object { if ($_ -eq $Default) { "[$($_.ToUpperInvariant())]$($map[$_])" } else { "[$_]$($map[$_])" } })) -join ' / '
    while ($true) {
        $answer = [string](Read-Host "$Prompt  $hint")
        $key = $answer.Trim().ToLowerInvariant()
        if (-not $key -and $Default) { return [string]$map[$Default] }
        if ($map.Contains($key)) { return [string]$map[$key] }
        if (@($map.Values) -contains $key) { return $key }
        Write-Host "  Answer one of: $hint" -ForegroundColor Yellow
    }
}

function Read-LabOperatorInput {
    # A value the plan cannot know in advance (a change ticket, a policy
    # name). Re-asks until it matches -Pattern; never echoed to a log.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'Interactive operator prompt: the re-ask line belongs on the console.')]
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][string]$Prompt, [Parameter(Mandatory)][string]$Pattern)
    while ($true) {
        $v = ([string](Read-Host $Prompt)).Trim()
        if ($v -match $Pattern) { return $v }
        Write-Host "  Does not match $Pattern - try again." -ForegroundColor Yellow
    }
}

# =============================================================================
# Redaction
# =============================================================================
function ConvertTo-LabSafeText {
    <#
    What may reach a public file: tenant / object ids (GUIDs, 32-hex ids),
    e-mail-shaped strings (UPNs), onmicrosoft domains, IPv4 / IPv6 literals,
    URLs (they carry ids), bearer tokens / JWTs / secret-bearing query
    parameters and home-folder paths are replaced; -Also adds literal values
    (the settings' own domains). Used on error reasons and summary strings.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowNull()][AllowEmptyString()][string]$Text, [AllowEmptyCollection()][string[]]$Also = @())
    if (-not $Text) { return '' }
    $t = $Text
    $t = $t -replace 'https?://\S+', '<url>'
    $t = $t -replace '(?i)\bbearer\s+[A-Za-z0-9._~+/=-]+', 'Bearer <token>'
    $t = $t -replace '\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}(\.[A-Za-z0-9_-]*)?', '<token>'
    $t = $t -replace '(?i)\b(sig|code|client_secret|password|pwd|access_token|refresh_token|id_token)=[^&\s"'']+', '$1=<redacted>'
    $t = $t -replace '(?i)(/Users/|/home/|[A-Z]:\\Users\\)[^/\\\s]+', '<home>'
    $t = $t -replace '(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b', '<guid>'
    $t = $t -replace '(?i)(?<![0-9a-z])[0-9a-f]{32}(?![0-9a-z])', '<id>'
    $t = $t -replace '[A-Za-z0-9._%+''-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}', '<upn>'
    $t = $t -replace '(?i)\b[a-z0-9-]+\.onmicrosoft\.com\b', '<tenant>'
    # The literal values last: replaced first, a domain would turn
    # name@domain into name@<redacted>, which no longer looks like a UPN and
    # would leave the person's name behind.
    foreach ($a in @($Also | Where-Object { $_ -and $_.Length -ge 4 })) { $t = $t -replace [regex]::Escape($a), '<redacted>' }
    $t = $t -replace '\b(?:\d{1,3}\.){3}\d{1,3}\b', '<ip>'
    # Until nothing IPv6-shaped is left (each pass removes colons, so it ends):
    # one pass can leave a remainder such as '<ip>::c' from 'a::b::c', and the
    # result must always pass Test-LabPublicSafeText.
    do {
        $before = $t
        $t = $t -replace $script:Ipv6CompressedPattern, '<ip>'
        $t = $t -replace $script:Ipv6FullPattern, '<ip>'
    } while ($t -ne $before)
    $t = ($t -replace '\s+', ' ').Trim()
    if ($t.Length -gt 240) { $t = $t.Substring(0, 240) + '...' }
    return $t
}

function Test-LabPublicSafeText {
    # True when the text carries nothing ConvertTo-LabSafeText would replace
    # (the same identifier shapes the public repository's release gates
    # refuse: dashed GUIDs and their 32-hex form, IP literals).
    [CmdletBinding()]
    [OutputType([bool])]
    param([AllowNull()][AllowEmptyString()][string]$Text, [AllowEmptyCollection()][string[]]$Also = @())
    if (-not $Text) { return $true }
    foreach ($a in @($Also | Where-Object { $_ -and $_.Length -ge 4 })) { if ($Text.Contains($a)) { return $false } }
    $patterns = @(
        '(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b'
        '(?i)(?<![0-9a-z])[0-9a-f]{32}(?![0-9a-z])'
        '[A-Za-z0-9._%+''-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}'
        '(?i)\b[a-z0-9-]+\.onmicrosoft\.com\b'
        '\b(?:\d{1,3}\.){3}\d{1,3}\b'
        $script:Ipv6CompressedPattern
        $script:Ipv6FullPattern
        '\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}'
        '(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{8,}'
        '(?i)(/Users/|/home/|[A-Z]:\\Users\\)[^/\\\s]+'
    )
    foreach ($p in $patterns) { if ($Text -match $p) { return $false } }
    return $true
}

function ConvertTo-LabSafeValue {
    # Recursively redacts every string in a summary structure.
    param([AllowNull()]$Value, [AllowEmptyCollection()][string[]]$Also = @())
    if ($null -eq $Value) { return $null }
    if ($Value -is [string]) { return (ConvertTo-LabSafeText -Text $Value -Also $Also) }
    if ($Value -is [System.Collections.IDictionary]) {
        $o = [ordered]@{}
        foreach ($k in $Value.Keys) { $o[(ConvertTo-LabSafeText -Text ([string]$k) -Also $Also)] = ConvertTo-LabSafeValue -Value $Value[$k] -Also $Also }
        return $o
    }
    if ($Value -is [System.Collections.IEnumerable]) { return , @(foreach ($v in $Value) { ConvertTo-LabSafeValue -Value $v -Also $Also }) }
    return $Value
}

# =============================================================================
# Native commands (az, gh): read verbs only
# =============================================================================
function Get-LabArgValue {
    param([string[]]$ArgumentList, [string[]]$Name)
    for ($i = 0; $i -lt $ArgumentList.Count - 1; $i++) {
        if ($ArgumentList[$i].ToLowerInvariant() -in $Name) { return [string]$ArgumentList[$i + 1] }
    }
    return ''
}

function Assert-LabReadOnlyCommand {
    <#
    The capture side may READ through az and gh, never change anything.
    Anything outside this allowlist throws before a process starts:
      gh   run list | run view | pr list | pr view   (never --web)
      az   account show, monitor log-analytics workspace show, storage
           account show, storage blob list, role assignment list,
           resource list; rest --method get on management.azure.com;
           rest --method post ONLY to the Log Analytics query API.
    az reads its arguments with Python's argparse: the LAST --method / --url
    wins, a value may be attached (--method=post, -mpost) and a prefix
    (--meth) is the same flag. So az rest takes each of the two exactly once,
    spelled --method / -m and --url / --uri / -u with the value as the next
    argument: the value checked here is then the value az uses.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$FilePath, [AllowEmptyCollection()][string[]]$ArgumentList = @())
    $a = @($ArgumentList | ForEach-Object { [string]$_ })
    $lower = @($a | ForEach-Object { $_.ToLowerInvariant() })
    $ok = $false
    switch ($FilePath) {
        'gh' {
            $ok = $a.Count -ge 2 -and $lower[0] -in @('run', 'pr') -and $lower[1] -in @('list', 'view') -and ('--web' -notin $lower) -and ('-w' -notin $lower)
        }
        'az' {
            $verb = (@($lower | Select-Object -First 5) -join ' ') + ' '
            $reads = @('account show ', 'monitor log-analytics workspace show ', 'storage account show ', 'storage blob list ', 'role assignment list ', 'resource list ')
            if (@($reads | Where-Object { $verb.StartsWith($_) }).Count) { $ok = $true }
            elseif ($lower.Count -and $lower[0] -eq 'rest') {
                $methodFlags = @($lower | Where-Object { $_ -in @('--method', '-m') })
                $urlFlags = @($lower | Where-Object { $_ -in @('--url', '--uri', '-u') })
                # -mpost, -m=post, -uhttps://..., --method=post, --url=..., and
                # the prefixes argparse accepts for them (--m to --metho, --u, --ur).
                $otherSpellings = @($lower | Where-Object {
                        ($_ -match '^-[mu].' -or $_ -match '^--(m|me|met|meth|metho|method|u|ur|url|uri)(=|$)') -and $_ -notin @('--method', '--url', '--uri')
                    })
                if ($methodFlags.Count -le 1 -and $urlFlags.Count -le 1 -and -not $otherSpellings.Count) {
                    $method = (Get-LabArgValue -ArgumentList $lower -Name @('--method', '-m')).ToLowerInvariant()
                    $url = Get-LabArgValue -ArgumentList $a -Name @('--url', '--uri', '-u')
                    if ($method -eq 'get' -and $url -match '^https://management\.azure\.com/') { $ok = $true }
                    elseif ($method -eq 'post' -and $url -match '^https://api\.loganalytics\.io/v1/workspaces/[^/?]+/query$') { $ok = $true }
                }
            }
        }
    }
    if (-not $ok) { throw "Refused: '$FilePath $(@($a | Select-Object -First 3) -join ' ') ...' is not on the read-only capture allowlist." }
}

function Invoke-LabNativeCommand {
    # Runs an allowlisted az / gh read. Returns exit code, stdout, stderr.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateSet('az', 'gh')][string]$FilePath,
        [Parameter(Mandatory)][string[]]$ArgumentList,
        [string]$WorkingDirectory = ''
    )
    Assert-LabReadOnlyCommand -FilePath $FilePath -ArgumentList $ArgumentList
    if (-not (Get-Command -Name $FilePath -CommandType Application -ErrorAction SilentlyContinue)) { throw "$FilePath is not on PATH." }
    $PSNativeCommandUseErrorActionPreference = $false
    if ($WorkingDirectory) { Push-Location -LiteralPath $WorkingDirectory }
    try { $out = & $FilePath @ArgumentList 2>&1 }
    finally { if ($WorkingDirectory) { Pop-Location } }
    $code = $LASTEXITCODE
    $err = (@($out | Where-Object { $_ -is [System.Management.Automation.ErrorRecord] }) | ForEach-Object { $_.ToString() }) -join "`n"
    $std = (@($out | Where-Object { $_ -isnot [System.Management.Automation.ErrorRecord] }) | ForEach-Object { [string]$_ }) -join "`n"
    return [pscustomobject]@{ ExitCode = $code; StdOut = $std; StdErr = $err }
}

function Invoke-LabAzJson {
    # az read -> parsed JSON (az adds -o json); throws with az's message.
    param([Parameter(Mandatory)][string[]]$ArgumentList)
    $r = Invoke-LabNativeCommand -FilePath 'az' -ArgumentList (@($ArgumentList) + @('--only-show-errors', '-o', 'json'))
    if ($r.ExitCode -ne 0) { throw "az $(@($ArgumentList | Select-Object -First 2) -join ' ') failed: $($r.StdErr)" }
    if (-not ([string]$r.StdOut).Trim()) { return $null }
    return ($r.StdOut | ConvertFrom-Json -AsHashtable -Depth 64)
}

# =============================================================================
# Graph: GET only
# =============================================================================
function Get-LabGraphResult {
    <#
    The only Invoke-MgGraphRequest call in the day runner: -Method GET. A
    collection is followed through @odata.nextLink up to -MaxPages (then
    Truncated = true); a single resource comes back as one item.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Uri, [ValidateRange(1, 200)][int]$MaxPages = 25)
    $items = [System.Collections.Generic.List[object]]::new()
    $next = $Uri; $pages = 0; $truncated = $false; $isCollection = $true
    while ($next) {
        if ($pages -ge $MaxPages) { $truncated = $true; break }
        $page = Invoke-MgGraphRequest -Method GET -Uri $next -OutputType HashTable
        $pages++
        if ($page -is [System.Collections.IDictionary] -and $page.Contains('value')) {
            foreach ($v in @($page['value'])) { if ($null -ne $v) { $items.Add($v) } }
            $next = if ($page.Contains('@odata.nextLink')) { [string]$page['@odata.nextLink'] } else { '' }
        }
        else {
            $isCollection = $false
            if ($null -ne $page) { $items.Add($page) }
            $next = ''
        }
    }
    return [pscustomobject]@{ Items = $items.ToArray(); Truncated = $truncated; IsCollection = $isCollection }
}

function Get-LabGraphScopeGap {
    # Scopes the current Graph session lacks for these recipes ('not
    # connected' when there is no session). Nothing connects here: the
    # operator signs in through the browser (never device code).
    [CmdletBinding()]
    [OutputType([string[]])]
    param([AllowNull()][AllowEmptyCollection()][string[]]$Required = @())
    $Required = @($Required | Where-Object { $_ })
    if (-not $Required.Count) { return @() }
    $ctx = $null
    try { $ctx = Get-MgContext } catch { Write-Verbose "Get-MgContext failed: $($_.Exception.Message)" }
    if (-not $ctx) { return @('not connected') }
    $have = @($ctx.Scopes)
    return @($Required | Where-Object { $_ -notin $have })
}

# =============================================================================
# Capture folder, items, manifest, hashes
# =============================================================================
function Initialize-LabCapture {
    <#
    Creates <EvidenceRoot>/<yyyyMMdd>/<Id>[-<Part>]/raw/ and returns the
    context the recipes write into. An existing capture of the same folder
    name (any day) makes this one <name>.rerun-<UTC>, never an overwrite.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$EvidenceRoot,
        [Parameter(Mandatory)][ValidatePattern('^[A-Za-z0-9][A-Za-z0-9-]{0,47}$')][string]$Id,
        [ValidatePattern('^$|^[a-z0-9][a-z0-9-]{0,39}$')][string]$Part = '',
        [Parameter(Mandatory)][datetime]$SinceUtc,
        [datetime]$NowUtc = [datetime]::UtcNow,
        [hashtable]$Settings = @{},
        [string]$LabRoot = '',
        [switch]$Rerun
    )
    $now = $NowUtc.ToUniversalTime()
    $base = if ($Part) { "$Id-$Part" } else { $Id }
    $prior = @()
    if (Test-Path -LiteralPath $EvidenceRoot) {
        $prior = @(Get-ChildItem -LiteralPath $EvidenceRoot -Directory | ForEach-Object {
                Get-ChildItem -LiteralPath $_.FullName -Directory | Where-Object { $_.Name -eq $base -or $_.Name -like "$base.rerun-*" }
            })
    }
    $rerunOf = ''
    $name = $base
    if ($prior.Count -or $Rerun) { $rerunOf = $base; $name = "$base.rerun-$($now.ToString('yyyyMMddTHHmmssZ'))" }
    $dayStamp = $now.ToString('yyyyMMdd')
    $dir = Join-Path $EvidenceRoot $dayStamp $name
    if (Test-Path -LiteralPath $dir) { throw "Capture folder $dayStamp/$name exists: a capture is never overwritten. Wait a second and capture again (a new re-run id)." }
    $raw = Join-Path $dir 'raw'
    New-Item -ItemType Directory -Path $raw -Force | Out-Null
    # Written first, so raw/ can never be staged even if the run stops here.
    Set-Content -LiteralPath (Join-Path $dir '.gitignore') -Value "# Written by Invoke-LabDay.ps1. raw/ holds tenant exports (object ids, UPNs, IPs):`n# private, uploaded to the WORM store, never committed.`nraw/`n" -Encoding utf8NoBOM -NoNewline
    $also = @()
    foreach ($k in @('OnMicrosoftDomain', 'Domain')) { if ($Settings.ContainsKey($k) -and $Settings[$k]) { $also += [string]$Settings[$k] } }
    return [pscustomobject]@{
        Id = $Id; Part = $Part; Name = $name; DayStamp = $dayStamp; Dir = $dir; Raw = $raw
        RerunOf = $rerunOf; SinceUtc = $SinceUtc.ToUniversalTime(); NowUtc = $now
        Settings = $Settings; LabRoot = $LabRoot; Also = $also
        Items = [System.Collections.Generic.List[object]]::new(); Cache = @{}
    }
}

function Get-LabSafeFileName {
    param([Parameter(Mandatory)][string]$Name)
    $n = ($Name -replace '[^A-Za-z0-9._-]', '-').Trim('-')
    if (-not $n) { $n = 'item' }
    return $n
}

function Save-LabCaptureText {
    # Writes raw/<Name><Extension>; returns the path relative to the capture
    # folder (forward slashes). An existing name gets -2, -3 ...
    param([Parameter(Mandatory)]$Context, [Parameter(Mandatory)][string]$Name, [AllowEmptyString()][string]$Text, [string]$Extension = '.json')
    $stem = Get-LabSafeFileName -Name $Name
    $file = Join-Path $Context.Raw "$stem$Extension"
    $i = 2
    while (Test-Path -LiteralPath $file) { $file = Join-Path $Context.Raw "$stem-$i$Extension"; $i++ }
    Set-Content -LiteralPath $file -Value $Text -Encoding utf8NoBOM -NoNewline
    return 'raw/' + (Split-Path -Leaf $file)
}

function Add-LabCaptureItem {
    param(
        [Parameter(Mandatory)]$Context,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][ValidateSet('ok', 'failed', 'absent')][string]$Status,
        [string]$File = '',
        [string]$Source = '',
        [int]$Count = -1,
        [bool]$Truncated = $false,
        [AllowNull()]$Summary = $null,
        [string]$Reason = '',
        [AllowNull()][Nullable[datetime]]$WindowStartUtc = $null
    )
    $item = [ordered]@{ name = $Name; status = $Status; source = $Source }
    if ($File) { $item['file'] = $File }
    if ($Count -ge 0) { $item['count'] = $Count }
    if ($Truncated) { $item['truncated'] = $true }
    # PowerShell unwraps [Nullable[datetime]]: the variable is a DateTime, with no .Value.
    if ($null -ne $WindowStartUtc) { $item['windowStartUtc'] = ([datetime]$WindowStartUtc).ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss'Z'") }
    if ($null -ne $Summary) { $item['summary'] = ConvertTo-LabSafeValue -Value $Summary -Also $Context.Also }
    if ($Reason) { $item['reason'] = ConvertTo-LabSafeText -Text $Reason -Also $Context.Also }
    $Context.Items.Add($item)
    $color = @{ ok = 'Green'; failed = 'Red'; absent = 'Yellow' }[$Status]
    $line = "    [$($Status.ToUpperInvariant())] $Name"
    if ($Count -ge 0) { $line += " ($Count)" }
    if ($Reason) { $line += " - $($item['reason'])" }
    Write-LabCaptureLine -Text $line -Color $color
}

function Get-LabWindowStart {
    param([Parameter(Mandatory)]$Context, [hashtable]$Spec = @{})
    if ($Spec.ContainsKey('LookbackHours') -and $Spec['LookbackHours']) { return $Context.NowUtc.AddHours(-[double]$Spec['LookbackHours']) }
    return $Context.SinceUtc
}

function Format-LabGraphTime {
    param([Parameter(Mandatory)][datetime]$Utc)
    return $Utc.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss'Z'")
}

function Test-LabSince {
    # True when $Value (a Graph / ARM / gh timestamp) is at or after $Since.
    param([AllowNull()]$Value, [Parameter(Mandatory)][datetime]$Since)
    if ($null -eq $Value -or [string]$Value -eq '') { return $false }
    try { return ([datetime]$Value).ToUniversalTime() -ge $Since.ToUniversalTime() } catch { return $false }
}

function Save-LabGraphItem {
    <#
    One Graph read into raw/<Name>.json. -Source is the request TEMPLATE for
    the manifest (ids shown as {id}). -SinceProperty filters the rows
    client-side to the window. Returns the items, unrolled (wrap the call
    in @()), so a recipe can chain.
    #>
    param(
        [Parameter(Mandatory)]$Context,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Uri,
        [Parameter(Mandatory)][string]$Source,
        [scriptblock]$Summarize,
        [string]$SinceProperty = '',
        [AllowNull()][Nullable[datetime]]$WindowStartUtc = $null,
        [int]$MaxPages = 25
    )
    try {
        $r = Get-LabGraphResult -Uri $Uri -MaxPages $MaxPages
        $items = @($r.Items)
        if ($SinceProperty -and $WindowStartUtc) { $items = @($items | Where-Object { Test-LabSince -Value $_[$SinceProperty] -Since ([datetime]$WindowStartUtc) }) }
        $data = if ($r.IsCollection) { , $items } elseif ($items.Count) { $items[0] } else { $null }
        $file = Save-LabCaptureText -Context $Context -Name $Name -Text (ConvertTo-Json -InputObject $data -Depth 40)
        $summary = if ($Summarize) { & $Summarize $items } else { $null }
        Add-LabCaptureItem -Context $Context -Name $Name -Status 'ok' -File $file -Source $Source -Count $items.Count -Truncated $r.Truncated -Summary $summary -WindowStartUtc $WindowStartUtc
        return $items
    }
    catch {
        Add-LabCaptureItem -Context $Context -Name $Name -Status 'failed' -Source $Source -Reason $_.Exception.Message -WindowStartUtc $WindowStartUtc
        return
    }
}

# ---- summaries: numbers and lab-defined names only --------------------------
function Get-LabCountBy {
    param([object[]]$Items, [Parameter(Mandatory)][scriptblock]$Key, [int]$Max = 40)
    $h = [ordered]@{}
    foreach ($i in @($Items)) {
        $k = [string](& $Key $i)
        if (-not $k) { $k = '(none)' }
        if ($h.Contains($k)) { $h[$k]++ } elseif ($h.Count -lt $Max) { $h[$k] = 1 }
    }
    return $h
}

function Get-LabCaSummary {
    param([object[]]$Items)
    $states = [ordered]@{}
    foreach ($p in @($Items)) {
        $m = [regex]::Match([string]$p['displayName'], '^(CA\d{3})\b')
        if ($m.Success) { $states[$m.Groups[1].Value] = [string]$p['state'] }
    }
    return [ordered]@{ policies = @($Items).Count; byState = (Get-LabCountBy -Items $Items -Key { param($p) $p['state'] }); labPolicies = $states }
}

function Get-LabSignInSummary {
    param([object[]]$Items)
    $ca = [ordered]@{}
    foreach ($s in @($Items)) {
        foreach ($p in @($s['appliedConditionalAccessPolicies'])) {
            if (-not $p) { continue }
            $m = [regex]::Match([string]$p['displayName'], '^(CA\d{3})\b')
            if (-not $m.Success) { continue }
            $id = $m.Groups[1].Value; $res = [string]$p['result']
            if (-not $ca.Contains($id)) { $ca[$id] = [ordered]@{} }
            if ($ca[$id].Contains($res)) { $ca[$id][$res]++ } else { $ca[$id][$res] = 1 }
        }
    }
    return [ordered]@{
        signIns           = @($Items).Count
        byErrorCode       = (Get-LabCountBy -Items $Items -Key { param($s) if ($s['status']) { [string]$s['status']['errorCode'] } })
        conditionalAccess = $ca
    }
}

function Get-LabScheduleSummary {
    param([object[]]$Items)
    $noExp = @($Items | Where-Object { $_['scheduleInfo'] -and $_['scheduleInfo']['expiration'] -and [string]$_['scheduleInfo']['expiration']['type'] -eq 'noExpiration' }).Count
    return [ordered]@{ schedules = @($Items).Count; withEndDate = (@($Items).Count - $noExp); noExpiration = $noExp }
}

function Get-LabFileSha256 {
    param([Parameter(Mandatory)][string]$Path)
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Complete-LabCapture {
    <#
    Seals a capture: manifest.json (public-safe; refuses to write one that
    carries an identifier), then SHA256SUMS over raw/** and the manifest.
    Returns the id, folder and the SHA-256 of SHA256SUMS (the capture-log
    value: it pins every file through the manifest and the sums).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Context, [hashtable]$Meta = @{})
    $rawFiles = @(Get-ChildItem -LiteralPath $Context.Raw -Recurse -File | Sort-Object FullName)
    $files = foreach ($f in $rawFiles) {
        $rel = 'raw/' + ([System.IO.Path]::GetRelativePath($Context.Raw, $f.FullName) -replace '\\', '/')
        [ordered]@{ path = $rel; sha256 = (Get-LabFileSha256 -Path $f.FullName); bytes = $f.Length }
    }
    $failed = @($Context.Items | Where-Object { $_['status'] -eq 'failed' }).Count
    $absent = @($Context.Items | Where-Object { $_['status'] -eq 'absent' }).Count
    $middot = [string][char]0x00B7
    $manifest = [ordered]@{
        schema         = $script:ManifestSchema
        id             = $Context.Id
        part           = $Context.Part
        folder         = $Context.Name
        rerunOf        = $Context.RerunOf
        status         = "RAN $middot tenant"
        complete       = ($failed -eq 0)
        labDay         = $Meta['labDay']
        step           = [string]$Meta['step']
        title          = [string]$Meta['title']
        note           = [string]$Meta['note']
        capturedAtUtc  = (Format-LabGraphTime -Utc $Context.NowUtc)
        windowStartUtc = (Format-LabGraphTime -Utc $Context.SinceUtc)
        generator      = 'lab/scripts/powershell/Invoke-LabDay.ps1 (evidence/LabEvidence.psm1)'
        private        = 'raw/ holds the exports and stays private (the .gitignore beside it); upload the whole folder to the WORM store under captures/<folder>/ the same day. This manifest and SHA256SUMS are public-safe.'
        counts         = [ordered]@{ ok = @($Context.Items | Where-Object { $_['status'] -eq 'ok' }).Count; failed = $failed; absent = $absent }
        items          = @($Context.Items)
        files          = @($files)
    }
    $text = ConvertTo-Json -InputObject $manifest -Depth 20
    if (-not (Test-LabPublicSafeText -Text $text -Also $Context.Also)) {
        throw "Refusing to write $($Context.Name)/manifest.json: it would carry an identifier (a GUID, UPN, domain or IP). The raw files are in place; nothing was published."
    }
    $manifestPath = Join-Path $Context.Dir 'manifest.json'
    Set-Content -LiteralPath $manifestPath -Value $text -Encoding utf8NoBOM -NoNewline
    $lines = @($files | ForEach-Object { "$($_['sha256'])  $($_['path'])" }) + @("$(Get-LabFileSha256 -Path $manifestPath)  manifest.json")
    $sums = Join-Path $Context.Dir 'SHA256SUMS'
    Set-Content -LiteralPath $sums -Value (($lines -join "`n") + "`n") -Encoding utf8NoBOM -NoNewline
    return [pscustomobject]@{
        Id = $Context.Id; Name = $Context.Name; Dir = $Context.Dir; DayStamp = $Context.DayStamp; RerunOf = $Context.RerunOf
        Sha256 = (Get-LabFileSha256 -Path $sums); Failed = $failed; Absent = $absent; Items = @($Context.Items).Count
    }
}

function Add-LabCaptureLogRow {
    <#
    One row in lab/evidence/capture-log.csv (capture rule 2): id, utc, what,
    sha256, stored_at, public, operator. Public-safe: 'what' is redacted and
    'operator' must be initials. Creates the file with its header; refuses a
    file whose header differs (a hand-edited log is never rewritten).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][ValidatePattern('^[A-Za-z0-9][A-Za-z0-9.-]{0,79}$')][string]$Id,
        [Parameter(Mandatory)][datetime]$Utc,
        [Parameter(Mandatory)][string]$What,
        [ValidatePattern('^$|^[0-9a-f]{64}$')][string]$Sha256 = '',
        [string]$StoredAt = '',
        [string]$Public = '',
        [ValidatePattern('^$|^[A-Za-z0-9 ._-]{1,32}$')][string]$Operator = ''
    )
    $row = [pscustomobject][ordered]@{
        id = $Id; utc = (Format-LabGraphTime -Utc $Utc); what = (ConvertTo-LabSafeText -Text $What); sha256 = $Sha256
        stored_at = (ConvertTo-LabSafeText -Text $StoredAt); public = $Public; operator = $Operator
    }
    if (Test-Path -LiteralPath $Path) {
        $head = ([string](Get-Content -LiteralPath $Path -TotalCount 1)) -replace '"', ''
        if ($head.Trim() -ne $script:CaptureLogHeader) { throw "capture log header is '$head', expected '$($script:CaptureLogHeader)': not appending to a log with other columns." }
        $line = @($row | ConvertTo-Csv -NoTypeInformation -UseQuotes AsNeeded)[1]
        Add-Content -LiteralPath $Path -Value $line -Encoding utf8NoBOM
    }
    else {
        $parent = Split-Path -Parent $Path
        if ($parent -and -not (Test-Path -LiteralPath $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
        $csv = @($row | ConvertTo-Csv -NoTypeInformation -UseQuotes AsNeeded)
        Set-Content -LiteralPath $Path -Value $csv -Encoding utf8NoBOM
    }
}

function Get-LabCaptureLogId {
    # The ids already in the capture log (empty when there is none yet).
    [CmdletBinding()]
    [OutputType([string[]])]
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return @() }
    return @(Import-Csv -LiteralPath $Path | ForEach-Object { [string]$_.id } | Where-Object { $_ })
}

# =============================================================================
# Repository reads the day runner needs
# =============================================================================
function Read-LabTfvarsState {
    <#
    lab/terraform/envs/dev/lab.tfvars as 00-Preflight.ps1 reads it: every
    top-level `name = true|false` is a staging flag; ca_policy_states is the
    one map. Line-based on purpose, no HCL parser.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    $flags = [ordered]@{}; $ca = [ordered]@{}; $inCa = $false
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    foreach ($raw in @(Get-Content -LiteralPath $Path)) {
        $line = ($raw -replace '^\s*(#|//).*$', '') -replace '\s+(#|//).*$', ''
        if ($line -match '^\s*$') { continue }
        if ($inCa) {
            if ($line -match '^\s*\}') { $inCa = $false; continue }
            if ($line -match '^\s*"?(CA\d+)"?\s*=\s*"([^"]*)"') { $ca[$Matches[1].ToUpperInvariant()] = $Matches[2] }
            continue
        }
        if ($line -match '^\s*ca_policy_states\s*=\s*\{') { $inCa = $true; continue }
        if ($line -match '^\s*([A-Za-z0-9_]+)\s*=\s*(true|false)\s*$') { $flags[$Matches[1]] = ($Matches[2] -eq 'true') }
    }
    return [pscustomobject]@{ Flags = $flags; CaStates = $ca }
}

function Find-LabKpiBaseline {
    # The newest KPI snapshot labelled 'baseline' (08-Measure-KPIs.ps1 names
    # them <yyyyMMddTHHmmssZ>.json under lab/evidence/kpis/).
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][string]$KpiDirectory)
    if (-not (Test-Path -LiteralPath $KpiDirectory)) { return '' }
    $candidates = @(Get-ChildItem -LiteralPath $KpiDirectory -File -Filter '*.json' | Where-Object { $_.Name -match '^\d{8}T\d{6}Z\.json$' } | Sort-Object Name -Descending)
    foreach ($f in $candidates) {
        try { if ([string]((Get-Content -LiteralPath $f.FullName -Raw | ConvertFrom-Json -AsHashtable)['label']) -eq 'baseline') { return $f.FullName } }
        catch { Write-Verbose "skipped $($f.Name): $($_.Exception.Message)" }
    }
    return ''
}
