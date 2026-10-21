# Pester 5 tests for post-apply/New-AccessReviewDefinitions.ps1 - the parts
# added for ADR 0012 tiers and the modules/pim hand-off (the original
# behaviour is covered in PostApply.Tests.ps1):
#   * pim_eligible_review_bodies is picked up from a full `terraform output
#     -json`, or from a second file, and merged without duplicates;
#   * the T1 contract (default Deny, auto-apply, justification, reviewer +
#     fallback) is enforced on every body, whatever module rendered it;
#   * the self-review guard covers role-scoped bodies (direct Global
#     Administrator eligibility), not just PIM-for-Groups.
# Every Graph call is a Pester mock; no tenant is contacted.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
    $script:Ard = Get-LabScriptPath 'post-apply/New-AccessReviewDefinitions.ps1'
    . (Get-ScriptFunctionBlock -Path $script:Ard -Name 'Read-ReviewDefinitionFile', 'Read-ReviewDefinitionSet', 'Test-ReviewBodyContract', 'Get-RoleIdFromQuery', 'Get-GroupIdFromQuery')

    $script:ReviewerGid = '22222222-2222-2222-2222-222222222222'
    $script:FallbackGid = '33333333-3333-3333-3333-333333333333'
    $script:GaRole = '62e90394-69f5-4237-9190-012177145e10'

    function New-Body([string]$Name, [string]$Query, [string]$Prefix = 'Privileged access review: ') {
        [ordered]@{
            displayName       = "$Prefix$Name"
            scope             = [ordered]@{ '@odata.type' = '#microsoft.graph.accessReviewQueryScope'; query = $Query; queryType = 'MicrosoftGraph' }
            reviewers         = @([ordered]@{ query = "/groups/$script:ReviewerGid/transitiveMembers"; queryType = 'MicrosoftGraph' })
            fallbackReviewers = @([ordered]@{ query = "/groups/$script:FallbackGid/transitiveMembers"; queryType = 'MicrosoftGraph' })
            settings          = [ordered]@{
                justificationRequiredOnApproval = $true; defaultDecisionEnabled = $true; defaultDecision = 'Deny'; autoApplyDecisionsEnabled = $true
                instanceDurationInDays = 14
                recurrence = [ordered]@{ pattern = [ordered]@{ type = 'absoluteMonthly'; interval = 3 }; range = [ordered]@{ type = 'noEnd'; startDate = $null } }
            }
        }
    }
    function New-GaBody { New-Body 'Global Administrator (eligible)' "/roleManagement/directory/roleEligibilityScheduleInstances?`$expand=principal&`$filter=(isof(principal,'microsoft.graph.user') and roleDefinitionId eq '$script:GaRole')" }
    function New-GroupBody([string]$Name, [string]$Gid) { New-Body $Name "/groups/$Gid/transitiveMembers" }
    function Write-Json([string]$Path, $Object) { ($Object | ConvertTo-Json -Depth 20) | Set-Content -LiteralPath $Path -Encoding utf8NoBOM }
    function ConvertTo-Map([hashtable]$Bodies) { $m = [ordered]@{}; foreach ($k in $Bodies.Keys) { $m[$k] = ($Bodies[$k] | ConvertTo-Json -Depth 20 -Compress) }; return $m }

    function Set-GraphMock {
        param([string[]]$GroupEligible = @(), [string[]]$RoleEligible = @(), [string[]]$Reviewers = @())
        $global:ArdTest = @{ Posts = [System.Collections.Generic.List[object]]::new(); Gets = [System.Collections.Generic.List[string]]::new()
            GroupEligible = $GroupEligible; RoleEligible = $RoleEligible; Reviewers = $Reviewers; ReviewerGid = $script:ReviewerGid }
        Mock Write-Host {}
        Mock Get-MgContext { New-MgContextStub -Scopes @('AccessReview.ReadWrite.All', 'Group.Read.All', 'PrivilegedEligibilitySchedule.Read.AzureADGroup', 'RoleEligibilitySchedule.Read.Directory') }
        Mock Connect-MgGraph { throw 'tests must never connect' }
        Mock Invoke-MgGraphRequest {
            $t = $global:ArdTest; $u = [uri]::UnescapeDataString("$Uri")
            if ($Method -eq 'POST') { $t.Posts.Add(@{ Uri = $u; Body = ($Body | ConvertFrom-Json -AsHashtable) }); return @{ id = 'def-new'; status = 'NotStarted'; createdDateTime = '2026-11-02T10:00:00Z' } }
            $t.Gets.Add($u)
            if ($u -match 'accessReviews/definitions\?\$filter=displayName eq') { return @{ value = @() } }
            if ($u -like '*/identityGovernance/privilegedAccess/group/eligibilitySchedules*') { return @{ value = @($t.GroupEligible | ForEach-Object { @{ principalId = $_ } }) } }
            if ($u -like '*/roleManagement/directory/roleEligibilitySchedules*') { return @{ value = @($t.RoleEligible | ForEach-Object { @{ principalId = $_ } }) } }
            if ($u -like "*/groups/$($t.ReviewerGid)/transitiveMembers*") { return @{ value = @($t.Reviewers | ForEach-Object { @{ id = $_; userPrincipalName = "$_@contoso.test" } }) } }
            throw "unexpected Graph call in test: $Method $u"
        }
    }
}

AfterAll { Remove-Variable -Name ArdTest -Scope Global -ErrorAction SilentlyContinue }

Describe 'New-AccessReviewDefinitions.ps1 - reading the modules/pim hand-off' {
    It 'unwraps pim_eligible_review_bodies from a full terraform output and merges it with access_review_definitions' {
        $f = Join-Path $TestDrive 'full.json'
        Write-Json $f ([ordered]@{
                access_review_definitions  = @{ sensitive = $false; value = (ConvertTo-Map @{ 'privileged:Privileged-IAM-Admins' = (New-GroupBody 'Privileged-IAM-Admins' '44444444-4444-4444-4444-444444444444') }) }
                pim_eligible_review_bodies = @{ sensitive = $false; value = (ConvertTo-Map @{ 'privileged:Global Administrator (eligible)' = (New-GaBody) }) }
                unrelated_output           = @{ sensitive = $false; value = 'x' }
            })
        $m = Read-ReviewDefinitionFile -Path $f
        @($m.Keys) | Should -Be @('privileged:Privileged-IAM-Admins', 'privileged:Global Administrator (eligible)')
        $m['privileged:Global Administrator (eligible)']['scope']['query'] | Should -Match "roleDefinitionId eq '$script:GaRole'"
    }

    It 'the same key with the same body (already merged by modules/entitlement) is read once' {
        $body = New-GroupBody 'PIM-Tier0-CA-Admins' '11111111-1111-1111-1111-111111111111'
        $f = Join-Path $TestDrive 'dup-same.json'
        Write-Json $f ([ordered]@{
                access_review_definitions  = @{ value = (ConvertTo-Map @{ 'privileged:PIM-Tier0-CA-Admins' = $body }) }
                pim_eligible_review_bodies = @{ value = (ConvertTo-Map @{ 'privileged:PIM-Tier0-CA-Admins' = $body }) }
            })
        @((Read-ReviewDefinitionFile -Path $f).Keys).Count | Should -Be 1
    }

    It 'the same key with two different bodies stops the run' {
        $a = New-GroupBody 'PIM-Tier0-CA-Admins' '11111111-1111-1111-1111-111111111111'
        $b = New-GroupBody 'PIM-Tier0-CA-Admins' '11111111-1111-1111-1111-111111111111'; $b['settings']['instanceDurationInDays'] = 10
        $f = Join-Path $TestDrive 'dup-diff.json'
        Write-Json $f ([ordered]@{ access_review_definitions = @{ value = (ConvertTo-Map @{ 'privileged:X' = $a }) }; pim_eligible_review_bodies = @{ value = (ConvertTo-Map @{ 'privileged:X' = $b }) } })
        { Read-ReviewDefinitionFile -Path $f } | Should -Throw '*appears twice with different bodies*'
    }

    It 'merges several files, and refuses two keys that share a displayName' {
        $f1 = Join-Path $TestDrive 'one.json'; $f2 = Join-Path $TestDrive 'two.json'; $f3 = Join-Path $TestDrive 'three.json'
        Write-Json $f1 (ConvertTo-Map @{ 'privileged:Privileged-IAM-Admins' = (New-GroupBody 'Privileged-IAM-Admins' '44444444-4444-4444-4444-444444444444') })
        Write-Json $f2 (ConvertTo-Map @{ 'privileged:Global Administrator (eligible)' = (New-GaBody) })
        Write-Json $f3 (ConvertTo-Map @{ 'pim:iam' = (New-GroupBody 'Privileged-IAM-Admins' '44444444-4444-4444-4444-444444444444') })
        @((Read-ReviewDefinitionSet -Path $f1, $f2).Keys).Count | Should -Be 2
        { Read-ReviewDefinitionSet -Path $f1, $f3 } | Should -Throw '*share the displayName*'
    }

    It 'parses role ids out of both documented role scopes' {
        Get-RoleIdFromQuery ([string](New-GaBody)['scope']['query']) | Should -Be $script:GaRole
        Get-RoleIdFromQuery "/roleManagement/directory/roleDefinitions/$script:GaRole" | Should -Be $script:GaRole
        Get-RoleIdFromQuery '/groups/44444444-4444-4444-4444-444444444444/transitiveMembers' | Should -BeNullOrEmpty
    }
}

Describe 'Test-ReviewBodyContract (ADR 0012: never keep access on silence)' {
    It 'accepts the bodies reviews.tf and modules/pim render' {
        @(Test-ReviewBodyContract -Body (New-GaBody)) | Should -BeNullOrEmpty
        @(Test-ReviewBodyContract -Body (New-Body 'App-Okta-Federation-Users' '/groups/x/transitiveMembers' 'Inactive users review: ')) | Should -BeNullOrEmpty
    }

    It 'refuses <Case>' -ForEach @(
        @{ Case = 'default decision Approve'; Mutate = { param($b) $b['settings']['defaultDecision'] = 'Approve' }; Expect = '*Deny*' }
        @{ Case = 'no default decision'; Mutate = { param($b) $b['settings']['defaultDecisionEnabled'] = $false }; Expect = '*Deny*' }
        @{ Case = 'no auto-apply'; Mutate = { param($b) $b['settings']['autoApplyDecisionsEnabled'] = $false }; Expect = '*auto-apply*' }
        @{ Case = 'no justification'; Mutate = { param($b) $b['settings'].Remove('justificationRequiredOnApproval') }; Expect = '*justification*' }
        @{ Case = 'no fallback reviewer'; Mutate = { param($b) $b['fallbackReviewers'] = @() }; Expect = '*fallback*' }
        @{ Case = 'no reviewer'; Mutate = { param($b) $b['reviewers'] = @() }; Expect = '*no reviewers*' }
        @{ Case = 'an unknown display-name prefix'; Mutate = { param($b) $b['displayName'] = 'GA review' }; Expect = '*displayName*' }
    ) {
        $b = New-GaBody; & $Mutate $b
        (@(Test-ReviewBodyContract -Body $b) -join "`n") | Should -BeLike $Expect
    }
}

Describe 'New-AccessReviewDefinitions.ps1 - against a mocked tenant' {
    BeforeEach {
        $global:LASTEXITCODE = 0
        $script:pub = Join-Path $TestDrive "pub-$([guid]::NewGuid().ToString('N'))"
        $script:det = Join-Path $TestDrive "det-$([guid]::NewGuid().ToString('N'))"
    }

    It 'POSTs the modules/pim Global Administrator body unchanged (only startDate filled in)' {
        Set-GraphMock
        $f = Join-Path $TestDrive 'ga.json'
        Write-Json $f ([ordered]@{ pim_eligible_review_bodies = @{ value = (ConvertTo-Map @{ 'privileged:Global Administrator (eligible)' = (New-GaBody) }) } })
        & $script:Ard -DefinitionsPath $f -StartDate '2026-11-02' -EvidenceDirectory $pub -DetailDirectory $det
        $LASTEXITCODE | Should -Be 0
        $global:ArdTest.Posts.Count | Should -Be 1
        $expected = New-GaBody; $expected['settings']['recurrence']['range']['startDate'] = '2026-11-02'
        ($global:ArdTest.Posts[0].Body | ConvertTo-Json -Depth 20 -Compress) | Should -Be ($expected | ConvertTo-Json -Depth 20 -Compress)
    }

    It 'role-scoped self-review guard: warns when a reviewer is ELIGIBLE for the reviewed directory role' {
        Set-GraphMock -RoleEligible @('u-grace', 'u-other') -Reviewers @('u-grace', 'u-gov')
        Mock Write-Warning {}
        $f = Join-Path $TestDrive 'ga-guard.json'
        Write-Json $f (ConvertTo-Map @{ 'privileged:Global Administrator (eligible)' = (New-GaBody) })
        & $script:Ard -DefinitionsPath $f -EvidenceDirectory $pub -DetailDirectory $det
        Should -Invoke Write-Warning -ParameterFilter { $Message -match 'ELIGIBLE for the reviewed directory role' -and $Message -match 'u-grace@contoso.test' }
        @($global:ArdTest.Gets | Where-Object { $_ -like "*/roleManagement/directory/roleEligibilitySchedules?*roleDefinitionId eq '$script:GaRole'*" }).Count | Should -Be 1
    }

    It 'a body that keeps access on silence is refused (not POSTed, exit 1); the valid one is still created' {
        Set-GraphMock
        Mock Write-Warning {}
        $bad = New-GroupBody 'PIM-Tier1-Helpdesk' '55555555-5555-5555-5555-555555555555'; $bad['settings']['defaultDecision'] = 'Approve'
        $f = Join-Path $TestDrive 'mixed.json'
        Write-Json $f (ConvertTo-Map @{ 'privileged:Global Administrator (eligible)' = (New-GaBody); 'privileged:PIM-Tier1-Helpdesk' = $bad })
        & $script:Ard -DefinitionsPath $f -EvidenceDirectory $pub -DetailDirectory $det
        $LASTEXITCODE | Should -Be 1
        $global:ArdTest.Posts.Count | Should -Be 1
        $global:ArdTest.Posts[0].Body['displayName'] | Should -Be 'Privileged access review: Global Administrator (eligible)'
        Should -Invoke Write-Warning -ParameterFilter { $Message -match 'refused, not sent' -and $Message -match 'PIM-Tier1-Helpdesk' }
    }

    It 'takes several files (-DefinitionsPath a.json, b.json)' {
        Set-GraphMock
        $f1 = Join-Path $TestDrive 'ent.json'; $f2 = Join-Path $TestDrive 'pim.json'
        Write-Json $f1 (ConvertTo-Map @{ 'privileged:Privileged-IAM-Admins' = (New-GroupBody 'Privileged-IAM-Admins' '44444444-4444-4444-4444-444444444444') })
        Write-Json $f2 (ConvertTo-Map @{ 'privileged:Global Administrator (eligible)' = (New-GaBody) })
        & $script:Ard -DefinitionsPath $f1, $f2 -EvidenceDirectory $pub -DetailDirectory $det
        $LASTEXITCODE | Should -Be 0
        $global:ArdTest.Posts.Count | Should -Be 2
    }
}
