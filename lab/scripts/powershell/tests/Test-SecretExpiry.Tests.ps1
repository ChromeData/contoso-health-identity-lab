# Pester 5 tests for ../Test-SecretExpiry.ps1 - the monthly expiry check of
# lab/iga/nhi-secrets-register.json (review finding H1). Offline: it reads a
# register file only.

BeforeAll {
    $script:Check = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..' 'Test-SecretExpiry.ps1'))
    function New-Register([object[]]$Secrets) {
        $f = Join-Path $TestDrive ("reg-" + [guid]::NewGuid().ToString('N') + '.json')
        (@{ schemaVersion = 1; secrets = $Secrets } | ConvertTo-Json -Depth 5) | Set-Content -LiteralPath $f
        return $f
    }
}

Describe 'Test-SecretExpiry.ps1' {
    BeforeEach { $env:GITHUB_STEP_SUMMARY = $null }

    It 'passes when nothing expires inside the window and every secret has an owner' {
        $f = New-Register @(@{ name = 'a'; system = 's'; store = 'kv:a'; owner = 'iam'; createdOn = '2026-10-01'; expiresOn = '2027-10-01'; rotation = 'P365D'; status = 'present' })
        $out = & $script:Check -RegisterPath $f -Now ([datetime]'2026-11-07')
        $LASTEXITCODE | Should -Be 0
        ($out -join "`n") | Should -Match 'Nothing expires in the next 60 days'
    }

    It 'fails on a secret that expires within 60 days (the 30-day-warning-on-a-monthly-run window)' {
        $f = New-Register @(@{ name = 'aws-scim-token'; system = 's'; store = 'kv:aws-scim-token'; owner = 'iam'; createdOn = '2025-12-20'; expiresOn = '2026-12-20'; rotation = 'P365D'; status = 'present' })
        $out = & $script:Check -RegisterPath $f -Now ([datetime]'2026-11-07')
        $LASTEXITCODE | Should -Be 1
        ($out -join "`n") | Should -Match 'SECRET-EXPIRING: aws-scim-token expires on 2026-12-20'
        ($out -join "`n") | Should -Match 'rotate-aws-scim-token\.md'
    }

    It 'fails on an expired secret, a missing owner and a present secret with no date; a planned undated one is only listed' {
        $f = New-Register @(
            @{ name = 'old'; system = 's'; store = 'kv:old'; owner = 'iam'; expiresOn = '2026-01-01'; rotation = 'P90D'; status = 'present' },
            @{ name = 'orphan'; system = 's'; store = 'kv:o'; owner = ''; expiresOn = '2027-09-01'; rotation = 'P90D'; status = 'present' },
            @{ name = 'undated'; system = 's'; store = 'kv:u'; owner = 'iam'; expiresOn = 'unknown (no metadata)'; rotation = 'P90D'; status = 'present' },
            @{ name = 'future'; system = 's'; store = 'kv:f'; owner = 'iam'; expiresOn = 'unknown (not created)'; rotation = 'P90D'; status = 'planned' })
        $out = (& $script:Check -RegisterPath $f -Now ([datetime]'2026-11-07')) -join "`n"
        $LASTEXITCODE | Should -Be 1
        $out | Should -Match '\*\*3 item\(s\) need action'
        $out | Should -Match 'SECRET-EXPIRED: old'
        $out | Should -Match 'SECRET-NO-OWNER: orphan'
        $out | Should -Match 'SECRET-NO-EXPIRY: undated'
        $out | Should -Not -Match 'SECRET-NO-EXPIRY: future'
    }

    It 'a missing register fails (never "nothing expires")' {
        { & $script:Check -RegisterPath (Join-Path $TestDrive 'nope.json') } | Should -Throw '*not found*'
    }

    It 'writes the table to the GitHub step summary' {
        $f = New-Register @(@{ name = 'a'; system = 's'; store = 'kv:a'; owner = 'iam'; expiresOn = '2027-10-01'; rotation = 'P365D'; status = 'present' })
        $env:GITHUB_STEP_SUMMARY = Join-Path $TestDrive 'summary.md'
        & $script:Check -RegisterPath $f -Now ([datetime]'2026-11-07') | Out-Null
        (Get-Content -LiteralPath $env:GITHUB_STEP_SUMMARY -Raw) | Should -Match '\| a \| iam \| present \| 2027-10-01 \|'
        $env:GITHUB_STEP_SUMMARY = $null
    }

    It 'the committed register has owners and dates for every present secret (2026-11-07)' {
        # A real due date inside the window may fail the run (that is the alert);
        # an expired, ownerless or undated present secret never may.
        $out = (& $script:Check -Now ([datetime]'2026-11-07')) -join "`n"
        $out | Should -Not -Match 'SECRET-EXPIRED:|SECRET-NO-OWNER:|SECRET-NO-EXPIRY:'
    }

    It 'the AD bind accounts use the privileged-access standard limits (90 days Vault bind, 30 days AD service account)' {
        $reg = Get-Content -Raw -LiteralPath ([System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..' '..' '..' 'iga' 'nhi-secrets-register.json'))) | ConvertFrom-Json
        $rot = $reg.secrets | Where-Object name -EQ 'svc-vault-rotator-password'
        $dis = $reg.secrets | Where-Object name -EQ 'svc-pam-discovery-password'
        $rot.rotation | Should -Match '^P90D'
        $dis.rotation | Should -Match '^P30D'
        ([datetime]$rot.expiresOn - [datetime]$rot.createdOn).TotalDays | Should -BeLessOrEqual 90
        ([datetime]$dis.expiresOn - [datetime]$dis.createdOn).TotalDays | Should -BeLessOrEqual 30
    }
}

Describe 'rotate-aws-scim-token.md step 3 (the token never shows or goes into argv)' {
    BeforeAll {
        $script:Runbook = Get-Content -Raw -LiteralPath ([System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..' '..' '..' 'docs' 'runbooks' 'rotate-aws-scim-token.md')))
        $script:SetLines = @($script:Runbook -split "`n" | Where-Object { $_ -match '^\s*(printf .*\| *)?az keyvault secret set ' })
    }

    It 'reads the token with a hidden prompt' {
        $script:Runbook | Should -Match "read -rs 'tok\?"
    }

    It 'every secret-set command reads stdin and prints nothing' {
        $script:SetLines.Count | Should -BeGreaterThan 0
        foreach ($l in $script:SetLines) {
            $l | Should -Match '--file /dev/stdin'
            $l | Should -Match '--output none'
            $l | Should -Not -Match '--value'
        }
    }

    It 'clears the shell variable after the write' {
        $script:Runbook | Should -Match '(?m)^\s*unset tok\s*$'
    }
}
