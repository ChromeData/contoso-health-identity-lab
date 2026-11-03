# Pester 5 tests for the evidence-pack.yml pipeline scripts:
#   * Publish-EvidencePack.ps1 - new blobs only under the run's prefix
#     (--overwrite false, Entra auth), every fingerprint checked before
#     upload and read back after, companion evidence never copied, the
#     store's retention lock recorded; the firewall / permission refusals,
#     a tampered file and a bad read-back all stop it (exit 1).
#   * Write-EvidencePackSummary.ps1 - the plain-English job summary
#     ("Evidence pack filed (em dash) 7 records, each fingerprinted", "nobody can
#     change or delete these files for N days"), counts only: no name, UPN,
#     raw Graph error or token.
# az is a Pester mock backed by a folder that plays the blob store. No
# tenant, no storage account.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    $script:Publish = Get-LabScriptPath 'Publish-EvidencePack.ps1'
    $script:Summary = Get-LabScriptPath 'Write-EvidencePackSummary.ps1'
    . (Get-ScriptFunctionBlock -Path $script:Publish -Name 'Get-StoreFailureKind', 'Get-PackFileList')
    . (Get-ScriptFunctionBlock -Path $script:Summary -Name 'Get-RetentionInfo', 'Get-CollectFailureText', 'Get-StoreLink')
    $script:Dash = [string][char]0x2014
    $script:Upn = 'ava.lin@contosohealthlab.onmicrosoft.com'

    function New-TestPack {
        # A pack shaped like Export-EvidencePack.ps1's: the seven artifacts
        # (one failed stub on request), SUMMARY.md, a companion row, manifest.json.
        param([string]$Dir, [string]$FailedFile = '', [string]$FailedError = 'Response status code does not indicate success: Forbidden (403). Authorization_RequestDenied for ava.lin@contosohealthlab.onmicrosoft.com')
        New-Item -ItemType Directory -Path $Dir -Force | Out-Null
        $counts = [ordered]@{ 'pim_activation_history.json' = 12; 'pim_active_assignments.json' = 5; 'pim_activation_activities.json' = 31; 'access_review_decisions.json' = 8
            'conditional_access_policies.json' = 11; 'mfa_registration_coverage.json' = 41; 'privileged_role_assignments.json' = 4 }
        $arts = [System.Collections.Generic.List[object]]::new()
        foreach ($name in $counts.Keys) {
            $p = Join-Path $Dir $name
            $status = if ($name -eq $FailedFile) { 'failed' } else { 'ok' }
            if ($status -eq 'failed') { (@{ error = $FailedError; status = 'failed' } | ConvertTo-Json) | Set-Content -LiteralPath $p -Encoding utf8 }
            elseif ($name -eq 'mfa_registration_coverage.json') {
                (ConvertTo-Json -InputObject @(@{ _summary = $true; totalUsers = 40; mfaRegistered = 38; coveragePercent = 95 }, @{ userPrincipalName = $script:Upn; isMfaRegistered = $true }) -Depth 4) | Set-Content -LiteralPath $p -Encoding utf8
            }
            else { (ConvertTo-Json -InputObject @(@{ principal = 'Ava Lin'; userPrincipalName = $script:Upn }) -Depth 4) | Set-Content -LiteralPath $p -Encoding utf8 }
            $arts.Add([ordered]@{ file = $name; control = 'c'; status = $status; error = $(if ($status -eq 'failed') { $FailedError } else { $null }); recordCount = $(if ($status -eq 'ok') { $counts[$name] } else { 0 })
                    sizeBytes = (Get-Item $p).Length; sha256 = (Get-FileHash $p -Algorithm SHA256).Hash; generatedUtc = '2026-11-02T23:15:00Z' })
        }
        $arts.Add([ordered]@{ file = 'kpis/20261101T100000Z.json'; control = 'k'; status = 'ok'; error = $null; recordCount = $null; sizeBytes = 9; sha256 = ('A' * 64); generatedUtc = '2026-11-01T10:00:00Z'; source = 'companion' })
        $arts.Add([ordered]@{ file = 'drills/*.json'; control = 'd'; status = 'absent'; error = $null; recordCount = 0; sizeBytes = $null; sha256 = $null; generatedUtc = '2026-11-02T23:15:00Z'; source = 'companion' })
        $sm = Join-Path $Dir 'SUMMARY.md'; '# Contoso Health -- Identity Evidence Pack' | Set-Content -LiteralPath $sm -Encoding utf8
        $arts.Add([ordered]@{ file = 'SUMMARY.md'; control = 'control mapping (human readable)'; status = 'ok'; error = $null; recordCount = $null; sizeBytes = (Get-Item $sm).Length; sha256 = (Get-FileHash $sm -Algorithm SHA256).Hash; generatedUtc = '2026-11-02T23:15:00Z' })
        $m = [ordered]@{ evidencePack = [ordered]@{ organization = 'Contoso Health'; tenantId = '11111111-1111-1111-1111-111111111111'; generatedUtc = '2026-11-02T23:15:00Z'; generatedBy = 'EVIDENCE app, GitHub Actions run 42 (commit abc1234)'; hashAlgorithm = 'SHA256'; toolVersion = '1.0.0' }; artifacts = $arts }
        ($m | ConvertTo-Json -Depth 6) | Set-Content -LiteralPath (Join-Path $Dir 'manifest.json') -Encoding utf8
        return $Dir
    }

    function Set-StoreMock {
        # az storage blob upload / show / download against a folder. Records
        # every call's arguments. -FailUpload: the error text the Nth upload
        # returns (exit 1). -CorruptDownload: the read-back returns other bytes.
        param([string]$FailUpload = '', [int]$FailOnUpload = 1, [switch]$CorruptDownload, [string]$Expiry = '2032-10-31T23:15:05+00:00', [string]$Mode = 'Locked')
        $global:StoreTest = @{ Dir = (Join-Path $TestDrive ('store-' + [guid]::NewGuid().ToString('N'))); Calls = [System.Collections.Generic.List[object]]::new(); Uploads = 0
            FailUpload = $FailUpload; FailOnUpload = $FailOnUpload; Corrupt = [bool]$CorruptDownload; Expiry = $Expiry; Mode = $Mode; Out = [System.Collections.Generic.List[string]]::new() }
        New-Item -ItemType Directory -Path $global:StoreTest.Dir -Force | Out-Null
        Mock Write-Host { $global:StoreTest.Out.Add([string]$Object) }
        Mock az {
            $t = $global:StoreTest; $a = @($args); $t.Calls.Add($a)
            $arg = { param($n) $i = [array]::IndexOf($a, $n); if ($i -ge 0 -and $i + 1 -lt $a.Count) { [string]$a[$i + 1] } else { '' } }
            $blob = & $arg '--name'; $local = Join-Path $t.Dir ($blob -replace '/', '__')
            switch ($a[2]) {
                'upload' {
                    $t.Uploads++
                    if ($t.FailUpload -and $t.Uploads -ge $t.FailOnUpload) { $global:LASTEXITCODE = 1; return "ERROR: $($t.FailUpload)" }
                    if (Test-Path -LiteralPath $local) { $global:LASTEXITCODE = 1; return 'ERROR: The specified blob already exists. ErrorCode:BlobAlreadyExists' }
                    Copy-Item -LiteralPath (& $arg '--file') -Destination $local; $global:LASTEXITCODE = 0; return
                }
                'show' { $global:LASTEXITCODE = 0; return (@{ versionId = '2026-11-02T23:15:06.0000000Z'; expiry = $t.Expiry; mode = $t.Mode } | ConvertTo-Json) }
                'download' {
                    if ($t.Corrupt) { 'tampered' | Set-Content -LiteralPath (& $arg '--file') } else { Copy-Item -LiteralPath $local -Destination (& $arg '--file') }
                    $global:LASTEXITCODE = 0; return
                }
            }
            $global:LASTEXITCODE = 1; return "unexpected az call: $($a -join ' ')"
        }
    }

    function Invoke-Publish {
        param([string]$Dir, [hashtable]$Extra = @{})
        $script:PubResult = Join-Path $TestDrive ('published-' + [guid]::NewGuid().ToString('N') + '.json')
        $global:LASTEXITCODE = 0
        & $script:Publish -PackDirectory $Dir -StorageAccountName 'stidlabevidence' -Prefix 'evidence-packs/2026-11-02/231500Z-run42-1' -ResultPath $script:PubResult `
            -RunId '42-1' -Commit 'abc1234' -Confirm:$false -WarningAction SilentlyContinue @Extra
    }
    function Get-PubResult { Get-Content -LiteralPath $script:PubResult -Raw | ConvertFrom-Json -AsHashtable }

    function Invoke-Summary {
        param([hashtable]$Params)
        $script:SumPath = Join-Path $TestDrive ('summary-' + [guid]::NewGuid().ToString('N') + '.md')
        Mock Write-Host {}
        $p = @{ SummaryPath = $script:SumPath; SignInOutcome = 'success'; TenantId = '11111111-1111-1111-1111-111111111111'
            SubscriptionId = '22222222-2222-2222-2222-222222222222'; Now = [datetime]::new(2026, 11, 2, 23, 20, 0, [DateTimeKind]::Utc) }
        foreach ($k in $Params.Keys) { $p[$k] = $Params[$k] }
        $null = & $script:Summary @p
        return (Get-Content -LiteralPath $script:SumPath -Raw)
    }
}

AfterAll { Remove-Variable -Name StoreTest -Scope Global -ErrorAction SilentlyContinue }

Describe 'Publish-EvidencePack.ps1 - pure helpers' {
    It 'reads an az storage error as <Kind>' -ForEach @(
        @{ Kind = 'network'; Msg = 'This request is not authorized to perform this operation. RequestId:1 ErrorCode:AuthorizationFailure' }
        @{ Kind = 'permission'; Msg = 'This request is not authorized to perform this operation using this permission. ErrorCode:AuthorizationPermissionMismatch' }
        @{ Kind = 'exists'; Msg = 'The specified blob already exists. ErrorCode:BlobAlreadyExists' }
        @{ Kind = 'sign-in'; Msg = "Please run 'az login' to setup account." }
        @{ Kind = 'not-found'; Msg = 'The specified container does not exist. ErrorCode:ContainerNotFound' }
        @{ Kind = 'other'; Msg = 'Server busy' }
    ) { Get-StoreFailureKind $Msg | Should -Be $Kind }

    It 'files the collected artifacts and SUMMARY.md, never companion evidence' {
        $dir = New-TestPack (Join-Path $TestDrive 'p-list')
        $m = Get-Content (Join-Path $dir 'manifest.json') -Raw | ConvertFrom-Json -AsHashtable
        $l = @(Get-PackFileList -Manifest $m -Directory $dir)
        $l.Count | Should -Be 8
        @($l.file) | Should -Contain 'SUMMARY.md'
        @($l.file | Where-Object { $_ -like 'kpis/*' -or $_ -like 'drills/*' }).Count | Should -Be 0
        foreach ($f in $l) { $f.sha256 | Should -Match '^[0-9a-f]{64}$' }
    }
}

Describe 'Publish-EvidencePack.ps1 - filing in the WORM store' {
    It 'uploads every file as a NEW blob under the prefix (Entra auth, no overwrite, sha256 metadata), manifest last, then reads each back' {
        $dir = New-TestPack (Join-Path $TestDrive 'p-ok')
        Set-StoreMock
        Invoke-Publish $dir
        $LASTEXITCODE | Should -Be 0
        $ups = @($global:StoreTest.Calls | Where-Object { $_[2] -eq 'upload' })
        $ups.Count | Should -Be 9
        foreach ($u in $ups) {
            ($u -join ' ') | Should -Match '--auth-mode login'
            ($u -join ' ') | Should -Match '--overwrite false'
            ($u -join ' ') | Should -Match '--validate-content'
            ($u -join ' ') | Should -Match '--metadata sha256=[0-9a-f]{64} runid=42-1 commit=abc1234'
            ($u -join ' ') | Should -Match '--name evidence-packs/2026-11-02/231500Z-run42-1/'
            ($u -join ' ') | Should -Not -Match 'account-key|sas-token|connection-string'
        }
        ($ups[-1] -join ' ') | Should -Match '/manifest\.json '
        @($global:StoreTest.Calls | Where-Object { $_[2] -eq 'download' }).Count | Should -Be 9
        $r = Get-PubResult
        $r['outcome'] | Should -Be 'filed'
        $r['prefix'] | Should -Be 'evidence-packs/2026-11-02/231500Z-run42-1/'
        @($r['files'] | Where-Object { $_['uploaded'] -and $_['verified'] }).Count | Should -Be 9
        @($r['files'] | Where-Object { $_['policyMode'] -eq 'Locked' -and $_['immutabilityExpiry'] }).Count | Should -Be 9
    }

    It 'prints names, sizes and hashes only - never file content' {
        $dir = New-TestPack (Join-Path $TestDrive 'p-quiet')
        Set-StoreMock
        Invoke-Publish $dir
        ($global:StoreTest.Out -join "`n") | Should -Not -Match ([regex]::Escape($script:Upn))
        ($global:StoreTest.Out -join "`n") | Should -Not -Match 'Ava Lin'
        (Get-Content $script:PubResult -Raw) | Should -Not -Match ([regex]::Escape($script:Upn))
    }

    It 'stops at the first file when the store''s firewall refuses (kind network), exit 1' {
        $dir = New-TestPack (Join-Path $TestDrive 'p-fw')
        Set-StoreMock -FailUpload 'This request is not authorized to perform this operation. ErrorCode:AuthorizationFailure'
        Invoke-Publish $dir
        $LASTEXITCODE | Should -Be 1
        @($global:StoreTest.Calls | Where-Object { $_[2] -eq 'upload' }).Count | Should -Be 1
        $r = Get-PubResult
        $r['outcome'] | Should -Be 'refused'
        $r['refusal']['kind'] | Should -Be 'network'
        @($r['files'] | Where-Object { $_['uploaded'] }).Count | Should -Be 0
    }

    It 'a missing grant (or the ABAC condition) is kind permission' {
        $dir = New-TestPack (Join-Path $TestDrive 'p-perm')
        Set-StoreMock -FailUpload 'This request is not authorized to perform this operation using this permission. ErrorCode:AuthorizationPermissionMismatch'
        Invoke-Publish $dir
        $LASTEXITCODE | Should -Be 1
        (Get-PubResult)['refusal']['kind'] | Should -Be 'permission'
    }

    It 'a refusal after some files is partial: what was stored stays, the run still fails' {
        $dir = New-TestPack (Join-Path $TestDrive 'p-part')
        Set-StoreMock -FailUpload 'This request is not authorized to perform this operation. ErrorCode:AuthorizationFailure' -FailOnUpload 4
        Invoke-Publish $dir
        $LASTEXITCODE | Should -Be 1
        $r = Get-PubResult
        $r['outcome'] | Should -Be 'partial'
        @($r['files'] | Where-Object { $_['uploaded'] }).Count | Should -Be 3
    }

    It 'never replaces a file already in the store (same prefix again = refused, kind exists)' {
        $dir = New-TestPack (Join-Path $TestDrive 'p-twice')
        Set-StoreMock
        Invoke-Publish $dir
        $LASTEXITCODE | Should -Be 0
        Invoke-Publish $dir
        $LASTEXITCODE | Should -Be 1
        $r = Get-PubResult
        $r['outcome'] | Should -Be 'refused'
        $r['refusal']['kind'] | Should -Be 'exists'
    }

    It 'refuses a pack whose file changed after it was fingerprinted - before any upload' {
        $dir = New-TestPack (Join-Path $TestDrive 'p-tamper')
        Add-Content -LiteralPath (Join-Path $dir 'privileged_role_assignments.json') -Value ' '
        Set-StoreMock
        { Invoke-Publish $dir } | Should -Throw '*Fingerprint mismatch*privileged_role_assignments.json*Nothing was uploaded*'
        @($global:StoreTest.Calls).Count | Should -Be 0
        $r = Get-PubResult
        $r['outcome'] | Should -Be 'invalid'
        $r['refusal']['kind'] | Should -Be 'fingerprint-mismatch'
    }

    It 'fails when the copy read back from the store does not match its fingerprint' {
        $dir = New-TestPack (Join-Path $TestDrive 'p-corrupt')
        Set-StoreMock -CorruptDownload
        Invoke-Publish $dir
        $LASTEXITCODE | Should -Be 1
        (Get-PubResult)['outcome'] | Should -Be 'failed'
    }

    It '-WhatIf lists the blobs and calls nothing' {
        $dir = New-TestPack (Join-Path $TestDrive 'p-whatif')
        Set-StoreMock
        Invoke-Publish $dir -Extra @{ WhatIf = $true }
        $LASTEXITCODE | Should -Be 0
        @($global:StoreTest.Calls).Count | Should -Be 0
        (Get-PubResult)['outcome'] | Should -Be 'dry-run'
    }

    It 'refuses a prefix that could climb out of its folder' {
        $dir = New-TestPack (Join-Path $TestDrive 'p-prefix')
        Set-StoreMock
        { & $script:Publish -PackDirectory $dir -StorageAccountName 'stidlabevidence' -Prefix 'evidence-packs/../x' -Confirm:$false } | Should -Throw "*plain folder path*"
        @($global:StoreTest.Calls).Count | Should -Be 0
    }
}

Describe 'Write-EvidencePackSummary.ps1 - the plain-English story' {
    BeforeAll {
        $script:OkPack = New-TestPack (Join-Path $TestDrive 's-ok')
        Set-StoreMock
        Invoke-Publish $script:OkPack
        $script:OkResult = $script:PubResult
    }

    It 'files: "Evidence pack filed (em dash) 7 records, each fingerprinted" and the days the store reported' {
        $text = Invoke-Summary @{ ManifestPath = (Join-Path $script:OkPack 'manifest.json'); PublishResultPath = $script:OkResult }
        ($text -split "`n")[0] | Should -BeExactly "## Evidence pack filed $($script:Dash) 7 records, each fingerprinted"
        $text | Should -Match ([regex]::Escape('Stored in the locked evidence store: nobody can change or delete these files for 2190 days.'))
        $text | Should -Not -Match 'trial setting'
        $text | Should -Match ([regex]::Escape('| Admin rights switched on | every time someone turned on admin rights for a short time (just-in-time), with the reason they gave | 12 |'))
        $text | Should -Match ([regex]::Escape('| Multi-factor sign-in set up | how many accounts have set up a second sign-in step | 38 of 40 accounts (95%) |'))
        $text | Should -Match ([regex]::Escape('(https://portal.azure.com/#@11111111-1111-1111-1111-111111111111/resource/subscriptions/22222222-2222-2222-2222-222222222222/resourceGroups/rg-identity-lab/providers/Microsoft.Storage/storageAccounts/stidlabevidence/containersList)'))
        $text | Should -Match 'the \*\*evidence\*\* container and the folder \*\*evidence-packs/2026-11-02/231500Z-run42-1\*\*'
    }

    It 'keeps the technical details folded: store, read-back, lock, every SHA-256' {
        $text = Invoke-Summary @{ ManifestPath = (Join-Path $script:OkPack 'manifest.json'); PublishResultPath = $script:OkResult; TriggerText = 'manual run on `main` (abc1234), GitHub Actions run 42' }
        $details = $text.Substring($text.IndexOf('<details>'))
        $details | Should -Match '9 of 9 file\(s\) uploaded as new blobs \(overwrite refused\), 9 read back and matched'
        $details | Should -Match 'until 2032-10-31 \(earliest of 9 file\(s\)\), policy mode Locked'
        $details | Should -Match 'Companion evidence from the repository:\*\* 1 file\(s\) hashed into the manifest; 1 kind\(s\) not captured yet'
        $sha = (Get-FileHash (Join-Path $script:OkPack 'pim_activation_history.json') -Algorithm SHA256).Hash.ToLowerInvariant()
        $details | Should -Match "``pim_activation_history.json`` ``$sha`` \(stored, read back\)"
        $text.IndexOf('Stored in the locked') | Should -BeLessThan $text.IndexOf('<details>')
    }

    It 'never prints personal data or a raw Graph error: counts only' {
        $dir = New-TestPack (Join-Path $TestDrive 's-403') -FailedFile 'access_review_decisions.json'
        Set-StoreMock
        Invoke-Publish $dir
        $text = Invoke-Summary @{ ManifestPath = (Join-Path $dir 'manifest.json'); PublishResultPath = $script:PubResult }
        $text | Should -Not -Match ([regex]::Escape($script:Upn))
        $text | Should -Not -Match 'Ava Lin|Authorization_RequestDenied'
        ($text -split "`n")[0] | Should -BeExactly "## Evidence pack filed $($script:Dash) 6 of 7 records collected, each fingerprinted"
        $text | Should -Match ([regex]::Escape('| Access review decisions | keep-or-remove decisions on who still needs access | not collected: the EVIDENCE identity is missing a read permission |'))
    }

    It 'says so when the lock is still Unlocked (Microsoft''s trial state)' {
        $dir = New-TestPack (Join-Path $TestDrive 's-unl')
        Set-StoreMock -Mode 'Unlocked'
        Invoke-Publish $dir
        $text = Invoke-Summary @{ ManifestPath = (Join-Path $dir 'manifest.json'); PublishResultPath = $script:PubResult }
        $text | Should -Match 'nobody can change or delete these files for 2190 days\.'
        $text | Should -Match 'still in its trial setting: an Azure administrator could shorten it'
    }

    It 'never guesses the days when the store reported no lock' {
        $dir = New-TestPack (Join-Path $TestDrive 's-nolock')
        Set-StoreMock -Expiry '' -Mode ''
        Invoke-Publish $dir
        $text = Invoke-Summary @{ ManifestPath = (Join-Path $dir 'manifest.json'); PublishResultPath = $script:PubResult }
        $text | Should -Not -Match 'for \d+ days'
        $text | Should -Match 'did not report its retention lock'
    }

    It 'a firewall refusal says the store refused the connection, and claims nothing was stored' {
        $dir = New-TestPack (Join-Path $TestDrive 's-fw')
        Set-StoreMock -FailUpload 'ErrorCode:AuthorizationFailure'
        Invoke-Publish $dir
        $text = Invoke-Summary @{ ManifestPath = (Join-Path $dir 'manifest.json'); PublishResultPath = $script:PubResult }
        ($text -split "`n")[0] | Should -BeExactly '## Evidence pack not filed: the evidence store refused the connection'
        $text | Should -Match 'firewall only lets in the lab operator''s network'
        $text | Should -Not -Match 'Stored in the locked'
    }

    It 'names the missing setup, the main-only rule and a refused sign-in in plain words: <Case>' -ForEach @(
        @{ Case = 'missing setup'; P = @{ MissingSetup = 'EVIDENCE_CLIENT_ID' }; Head = '## Evidence pack not filed: the one-time setup is not finished'; Body = '*Missing repository variable(s): **EVIDENCE_CLIENT_ID***' }
        @{ Case = 'not main'; P = @{ Refused = 'not-main' }; Head = '## Evidence pack not filed: it is filed from main only'; Body = '*Run it again and pick*main*' }
        @{ Case = 'sign-in refused'; P = @{ SignInOutcome = 'failure' }; Head = '## Evidence pack not filed: GitHub could not sign in to Microsoft'; Body = '*nothing was collected*' }
        @{ Case = 'export stopped'; P = @{ ManifestPath = 'no-such-folder/manifest.json' }; Head = '## Evidence pack not filed: the export from Microsoft Entra stopped'; Body = '*Nothing was stored*' }
    ) {
        $text = Invoke-Summary $P
        ($text -split "`n")[0] | Should -BeExactly $Head
        $text | Should -BeLike $Body
    }

    It 'Get-RetentionInfo takes the EARLIEST expiry and needs every uploaded file to report one' {
        $now = [datetime]::new(2026, 11, 2, 0, 0, 0, [DateTimeKind]::Utc)
        $f = @(@{ uploaded = $true; immutabilityExpiry = '2032-11-01T00:00:00Z'; policyMode = 'Locked' }, @{ uploaded = $true; immutabilityExpiry = '2027-11-02T00:00:00Z'; policyMode = 'Locked' })
        (Get-RetentionInfo -Files $f -Now $now).Days | Should -Be 365
        $f += @{ uploaded = $true; immutabilityExpiry = $null; policyMode = $null }
        (Get-RetentionInfo -Files $f -Now $now).Days | Should -BeNullOrEmpty
    }
}

Describe 'Connect-GraphFromAzureCli parity' {
    It 'is identical in every lab/scripts/powershell script that carries a copy' {
        $canonical = (Get-ScriptFunctionBlock -Path (Get-LabScriptPath 'post-apply/Set-AutoAssignmentPolicies.ps1') -Name 'Connect-GraphFromAzureCli').ToString()
        $canonical | Should -Match 'get-access-token --resource-type ms-graph'
        (Get-ScriptFunctionBlock -Path (Get-LabScriptPath 'Export-EvidencePack.ps1') -Name 'Connect-GraphFromAzureCli').ToString() | Should -Be $canonical
    }
}
