# Pester 5 tests for the post-apply orchestration:
#   * post-apply/New-AccessReviewDefinitions.ps1  (Terraform-rendered review bodies)
#   * post-apply/New-B2BConnectedOrganization.ps1 (connected org + guest lifecycle)
#   * post-apply/Invoke-PostApply.ps1             (order, flag gating, dry-run vs execute,
#                                                  hand-off files removed, build-account last)
# Every Graph call is answered by a Pester Mock (the real cmdlet's signature),
# and Invoke-PostApply.ps1 runs against STUB scripts generated from the real
# scripts' param blocks - so a parameter Invoke-PostApply.ps1 passes that the
# real script does not declare fails the test. No tenant is contacted.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    $script:Ard = Get-LabScriptPath 'post-apply/New-AccessReviewDefinitions.ps1'
    $script:B2b = Get-LabScriptPath 'post-apply/New-B2BConnectedOrganization.ps1'
    $script:Pa = Get-LabScriptPath 'post-apply/Invoke-PostApply.ps1'
    . (Get-ScriptFunctionBlock -Path $script:Ard -Name 'Read-ReviewDefinitionFile', 'Complete-ReviewBody', 'Get-GroupIdFromQuery', 'Compare-ReviewSetting', 'Test-PublicRecordSafe')
    . (Get-ScriptFunctionBlock -Path $script:Pa -Name 'Get-TfValue', 'Test-HasValue', 'ConvertTo-PlanStep', 'Split-WorkspaceId', 'Get-PostApplyPlan')

    # ---- Fixtures shaped exactly like modules/entitlement renders them ------
    $script:TargetGid = '11111111-1111-1111-1111-111111111111'
    $script:ReviewerGid = '22222222-2222-2222-2222-222222222222'
    $script:FallbackGid = '33333333-3333-3333-3333-333333333333'
    function New-PrivilegedBody([string]$Name, [string]$Gid) {
        [ordered]@{
            displayName             = "Privileged access review: $Name"
            descriptionForAdmins    = 'Terraform-rendered (modules/entitlement/reviews.tf).'
            descriptionForReviewers = 'Can this person still justify being able to activate this admin role?'
            scope                   = [ordered]@{ '@odata.type' = '#microsoft.graph.accessReviewQueryScope'; query = "/groups/$Gid/transitiveMembers"; queryType = 'MicrosoftGraph' }
            reviewers               = @([ordered]@{ query = "/groups/$script:ReviewerGid/transitiveMembers"; queryType = 'MicrosoftGraph' })
            fallbackReviewers       = @([ordered]@{ query = "/groups/$script:FallbackGid/transitiveMembers"; queryType = 'MicrosoftGraph' })
            settings                = [ordered]@{
                mailNotificationsEnabled = $true; reminderNotificationsEnabled = $true; justificationRequiredOnApproval = $true
                defaultDecisionEnabled = $true; defaultDecision = 'Deny'; autoApplyDecisionsEnabled = $true; recommendationsEnabled = $true
                instanceDurationInDays = 14; recommendationLookBackDuration = 'P30D'
                recurrence = [ordered]@{ pattern = [ordered]@{ type = 'absoluteMonthly'; interval = 3 }; range = [ordered]@{ type = 'noEnd'; startDate = $null } }
            }
        }
    }
    function Write-ReviewFile([string]$Path, [switch]$FullOutput) {
        $map = [ordered]@{
            'privileged:PIM-Tier0-CA-Admins'    = (New-PrivilegedBody 'PIM-Tier0-CA-Admins' $script:TargetGid | ConvertTo-Json -Depth 20 -Compress)
            'privileged:Privileged-IAM-Admins' = (New-PrivilegedBody 'Privileged-IAM-Admins' '44444444-4444-4444-4444-444444444444' | ConvertTo-Json -Depth 20 -Compress)
        }
        $doc = if ($FullOutput) { [ordered]@{ access_review_definitions = [ordered]@{ sensitive = $false; value = $map } } } else { $map }
        ($doc | ConvertTo-Json -Depth 20) | Set-Content -LiteralPath $Path -Encoding utf8NoBOM
    }

    function Set-GraphMock {
        # In-memory tenant: definitions that exist, PIM eligibility, reviewer
        # members, connected orgs, sponsors, the entitlement settings.
        param([string[]]$ExistingReviews = @(), [string[]]$EligibleIds = @(), [string[]]$ReviewerIds = @(),
            [hashtable[]]$ConnectedOrgs = @(), [string[]]$SponsorIds = @(), [switch]$RefuseGroupSponsor, [switch]$FailReads)
        $global:PaTest = @{
            Posts = [System.Collections.Generic.List[object]]::new(); Patches = [System.Collections.Generic.List[object]]::new()
            Existing = $ExistingReviews; Eligible = $EligibleIds; Reviewers = $ReviewerIds; Orgs = $ConnectedOrgs; Sponsors = $SponsorIds
            RefuseGroupSponsor = [bool]$RefuseGroupSponsor; FailReads = [bool]$FailReads; ReviewerGid = $script:ReviewerGid
            Settings = @{ externalUserLifecycleAction = 'none'; durationUntilExternalUserDeletedAfterBlocked = 'P30D' }
        }
        Mock Write-Host {}
        Mock Get-MgContext { New-MgContextStub -Scopes @('AccessReview.ReadWrite.All', 'Group.Read.All', 'PrivilegedEligibilitySchedule.Read.AzureADGroup', 'EntitlementManagement.ReadWrite.All', 'GroupMember.Read.All') }
        Mock Connect-MgGraph { throw 'tests must never connect' }
        Mock Invoke-MgGraphRequest {
            $t = $global:PaTest; $u = [uri]::UnescapeDataString("$Uri")
            if ($Method -eq 'POST') {
                if ($u -like '*/internalSponsors/$ref' -and $t.RefuseGroupSponsor -and $Body -match '/groups/') { throw 'Request_BadRequest: group not supported' }
                $t.Posts.Add(@{ Uri = $u; Body = ($Body | ConvertFrom-Json -AsHashtable) })
                if ($u -like '*/accessReviews/definitions') { return @{ id = 'def-new'; status = 'NotStarted'; createdDateTime = '2026-11-02T10:00:00Z' } }
                if ($u -like '*/connectedOrganizations') { return @{ id = 'org-new'; state = 'configured' } }
                return $null
            }
            if ($Method -eq 'PATCH') { $t.Patches.Add(@{ Uri = $u; Body = ($Body | ConvertFrom-Json -AsHashtable) }); return $null }
            if ($t.FailReads) { throw 'HTTP 503 Service Unavailable' }
            if ($u -match "accessReviews/definitions\?\`$filter=displayName eq '(?<n>.+)'$") {
                $n = $Matches.n.Replace("''", "'")
                if ($n -in $t.Existing) {
                    return @{ value = @(@{ id = 'def-existing'; displayName = $n; status = 'InProgress'; createdDateTime = '2026-11-01T10:00:00Z'
                                settings = @{ defaultDecisionEnabled = $true; defaultDecision = 'Approve'; autoApplyDecisionsEnabled = $true; instanceDurationInDays = 14; justificationRequiredOnApproval = $true; recommendationsEnabled = $true
                                    recurrence = @{ pattern = @{ type = 'absoluteMonthly'; interval = 3 } } } }) }
                }
                return @{ value = @() }
            }
            if ($u -like '*/eligibilitySchedules*') { return @{ value = @($t.Eligible | ForEach-Object { @{ principalId = $_; accessId = 'member' } }) } }
            if ($u -like "*/groups/$($t.ReviewerGid)/transitiveMembers*") { return @{ value = @($t.Reviewers | ForEach-Object { @{ id = $_; userPrincipalName = "$_@contoso.test" } }) } }
            if ($u -match "connectedOrganizations\?\`$filter=displayName eq '(?<n>.+)'$") { return @{ value = @($t.Orgs | Where-Object { $_.displayName -eq $Matches.n }) } }
            if ($u -like '*/internalSponsors') { return @{ value = @($t.Sponsors | ForEach-Object { @{ id = $_ } }) } }
            if ($u -like '*/members/microsoft.graph.user*') { return @{ value = @(@{ id = 'u-sponsor-1'; userPrincipalName = 'mso1@contoso.test' }, @{ id = 'u-sponsor-2'; userPrincipalName = 'mso2@contoso.test' }) } }
            if ($u -like '*/entitlementManagement/settings') { return $t.Settings }
            throw "unexpected Graph call in test: $Method $u"
        }
    }
}

AfterAll { Remove-Variable -Name PaTest -Scope Global -ErrorAction SilentlyContinue }

# =============================================================================
Describe 'New-AccessReviewDefinitions.ps1 - helpers' {
    It 'reads the single-output file and a full terraform output -json the same way' {
        $a = Join-Path $TestDrive 'single.json'; $b = Join-Path $TestDrive 'full.json'
        Write-ReviewFile $a; Write-ReviewFile $b -FullOutput
        $x = Read-ReviewDefinitionFile -Path $a; $y = Read-ReviewDefinitionFile -Path $b
        @($x.Keys) | Should -Be @('privileged:PIM-Tier0-CA-Admins', 'privileged:Privileged-IAM-Admins')
        ($x | ConvertTo-Json -Depth 20) | Should -Be ($y | ConvertTo-Json -Depth 20)
        $x['privileged:PIM-Tier0-CA-Admins']['scope']['query'] | Should -Be "/groups/$TargetGid/transitiveMembers"
    }

    It 'fills only a null startDate and leaves the rest of the Terraform body untouched' {
        $body = New-PrivilegedBody 'X' $TargetGid
        $before = ($body | ConvertTo-Json -Depth 20 -Compress)
        $done = Complete-ReviewBody -Body $body -StartDate '2026-11-02'
        $done['settings']['recurrence']['range']['startDate'] | Should -Be '2026-11-02'
        ($done | ConvertTo-Json -Depth 20 -Compress) | Should -Be $before.Replace('"startDate":null', '"startDate":"2026-11-02"')
        # A date Terraform rendered (access_review_start_date) wins.
        $b2 = New-PrivilegedBody 'X' $TargetGid; $b2['settings']['recurrence']['range']['startDate'] = '2026-12-01'
        (Complete-ReviewBody -Body $b2 -StartDate '2026-11-02')['settings']['recurrence']['range']['startDate'] | Should -Be '2026-12-01'
    }

    It 'parses group ids out of Graph queries' {
        Get-GroupIdFromQuery "/groups/$TargetGid/transitiveMembers" | Should -Be $TargetGid
        Get-GroupIdFromQuery '/users' | Should -BeNullOrEmpty
    }

    It 'reports decision-setting drift and nothing else' {
        $d = New-PrivilegedBody 'X' $TargetGid
        $same = @{ settings = @{ defaultDecisionEnabled = $true; defaultDecision = 'Deny'; autoApplyDecisionsEnabled = $true; instanceDurationInDays = 14; justificationRequiredOnApproval = $true; recommendationsEnabled = $true; recurrence = @{ pattern = @{ type = 'absoluteMonthly'; interval = 3 } } } }
        (Compare-ReviewSetting -Desired $d -Actual $same).Count | Should -Be 0
        $same.settings.defaultDecision = 'Approve'
        $diff = Compare-ReviewSetting -Desired $d -Actual $same
        $diff.Count | Should -Be 1
        $diff[0] | Should -Match '^defaultDecision'
    }

    It 'refuses GUIDs, UPNs and onmicrosoft domains in a public record' {
        @(Test-PublicRecordSafe -Json '{"displayName":"Privileged access review: PIM-Tier0-CA-Admins","createdDate":"2026-11-02"}').Count | Should -Be 0
        @(Test-PublicRecordSafe -Json "{`"id`":`"$TargetGid`",`"u`":`"a@b.test`",`"d`":`"x.onmicrosoft.com`"}").Count | Should -Be 3
    }
}

Describe 'New-AccessReviewDefinitions.ps1 - against a mocked tenant' {
    BeforeEach {
        $global:LASTEXITCODE = 0
        $script:defs = Join-Path $TestDrive "reviews-$([guid]::NewGuid().ToString('N')).json"
        Write-ReviewFile $script:defs
        $script:pub = Join-Path $TestDrive "pub-$([guid]::NewGuid().ToString('N'))"
        $script:det = Join-Path $TestDrive "det-$([guid]::NewGuid().ToString('N'))"
    }

    It 'skips a definition that exists (by displayName), reports its drift, and POSTs only the missing one - body byte-for-byte as rendered' {
        Set-GraphMock -ExistingReviews @('Privileged access review: Privileged-IAM-Admins')
        Mock Write-Warning {}
        & $Ard -DefinitionsPath $defs -StartDate '2026-11-02' -EvidenceDirectory $pub -DetailDirectory $det
        $LASTEXITCODE | Should -Be 0
        $global:PaTest.Posts.Count | Should -Be 1
        $posted = $global:PaTest.Posts[0]
        $posted.Uri | Should -Be 'https://graph.microsoft.com/v1.0/identityGovernance/accessReviews/definitions'
        $expected = New-PrivilegedBody 'PIM-Tier0-CA-Admins' $TargetGid
        $expected['settings']['recurrence']['range']['startDate'] = '2026-11-02'
        ($posted.Body | ConvertTo-Json -Depth 20 -Compress) | Should -Be ($expected | ConvertTo-Json -Depth 20 -Compress)
        Should -Invoke Write-Warning -ParameterFilter { $Message -match "\[~\].*defaultDecision" }
    }

    It 'writes a public-safe summary (+ sha256) and keeps ids in the gitignored detail file' {
        Set-GraphMock
        & $Ard -DefinitionsPath $defs -StartDate '2026-11-02' -EvidenceDirectory $pub -DetailDirectory $det
        $file = Get-ChildItem -LiteralPath $pub -Filter 'definitions-*.json' | Select-Object -First 1
        $file | Should -Not -BeNullOrEmpty
        $json = Get-Content -LiteralPath $file.FullName -Raw
        @(Test-PublicRecordSafe -Json $json).Count | Should -Be 0
        (Get-Content -LiteralPath "$($file.FullName).sha256" -Raw) | Should -Match ("^{0}  {1}" -f (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant(), [regex]::Escape($file.Name))
        (Get-Content -LiteralPath (Get-ChildItem -LiteralPath $det -Filter '*.json' | Select-Object -First 1).FullName -Raw) | Should -Match 'def-new'
    }

    It 'warns when a reviewer is also ELIGIBLE for the reviewed group (no self-certification)' {
        Set-GraphMock -EligibleIds @('u-grace', 'u-other') -ReviewerIds @('u-grace', 'u-gov')
        Mock Write-Warning {}
        & $Ard -DefinitionsPath $defs -EvidenceDirectory $pub -DetailDirectory $det
        Should -Invoke Write-Warning -ParameterFilter { $Message -match 'also ELIGIBLE' -and $Message -match 'u-grace@contoso.test' }
    }

    It '-WhatIf posts nothing and writes no evidence' {
        Set-GraphMock
        & $Ard -DefinitionsPath $defs -EvidenceDirectory $pub -DetailDirectory $det -WhatIf
        $global:PaTest.Posts.Count | Should -Be 0
        Test-Path -LiteralPath $pub | Should -BeFalse
    }

    It 'a failed READ is a failure (exit 1), never "does not exist" - so no duplicate series is created' {
        Set-GraphMock -FailReads
        Mock Write-Warning {}
        & $Ard -DefinitionsPath $defs -EvidenceDirectory $pub -DetailDirectory $det
        $LASTEXITCODE | Should -Be 1
        $global:PaTest.Posts.Count | Should -Be 0
    }
}

# =============================================================================
Describe 'New-B2BConnectedOrganization.ps1 - against a mocked tenant' {
    BeforeAll {
        $script:b2bFile = Join-Path $TestDrive 'b2b.json'
        ([ordered]@{
            connected_organization_body      = ([ordered]@{ displayName = 'Fabrikam Affiliated Clinic'; description = 'x'; identitySources = @(@{ '@odata.type' = '#microsoft.graph.domainIdentitySource'; displayName = 'fabrikam-clinic.example'; domainName = 'fabrikam-clinic.example' }); state = 'configured' } | ConvertTo-Json -Depth 10 -Compress)
            internal_sponsor_group_object_id = 'g-sponsors'
            entitlement_settings_body        = ([ordered]@{ externalUserLifecycleAction = 'blockSignInAndDelete'; durationUntilExternalUserDeletedAfterBlocked = 'P30D' } | ConvertTo-Json -Compress)
            access_package_id                = 'ap-b2b'
            assignment_policy_id             = 'pol-b2b'
            requestor_scope                  = 'AllConfiguredConnectedOrganizationSubjects'
        } | ConvertTo-Json -Depth 10) | Set-Content -LiteralPath $script:b2bFile -Encoding utf8NoBOM
    }
    BeforeEach { $global:LASTEXITCODE = 0 }

    It 'creates a missing org as configured, adds the sponsor GROUP, then sets the tenant lifecycle' {
        Set-GraphMock
        & $B2b -PostApplyPath $b2bFile -Confirm:$false
        $LASTEXITCODE | Should -Be 0
        @($global:PaTest.Posts | ForEach-Object Uri) | Should -Be @(
            'https://graph.microsoft.com/v1.0/identityGovernance/entitlementManagement/connectedOrganizations',
            'https://graph.microsoft.com/v1.0/identityGovernance/entitlementManagement/connectedOrganizations/org-new/internalSponsors/$ref')
        $global:PaTest.Posts[0].Body['state'] | Should -Be 'configured'
        $global:PaTest.Posts[1].Body['@odata.id'] | Should -Be 'https://graph.microsoft.com/v1.0/groups/g-sponsors'
        $global:PaTest.Patches.Count | Should -Be 1
        $global:PaTest.Patches[0].Body['externalUserLifecycleAction'] | Should -Be 'blockSignInAndDelete'
    }

    It 'promotes a PROPOSED org to configured and does not re-add an existing sponsor' {
        Set-GraphMock -ConnectedOrgs @(@{ id = 'org-1'; displayName = 'Fabrikam Affiliated Clinic'; state = 'proposed' }) -SponsorIds @('g-sponsors')
        & $B2b -PostApplyPath $b2bFile -Confirm:$false -SkipTenantSettings
        $global:PaTest.Posts.Count | Should -Be 0
        $global:PaTest.Patches.Count | Should -Be 1
        $global:PaTest.Patches[0].Uri | Should -BeLike '*/connectedOrganizations/org-1'
        $global:PaTest.Patches[0].Body['state'] | Should -Be 'configured'
    }

    It 'falls back to the group''s user members when Graph refuses a group sponsor (and says so)' {
        Set-GraphMock -ConnectedOrgs @(@{ id = 'org-1'; displayName = 'Fabrikam Affiliated Clinic'; state = 'configured' }) -RefuseGroupSponsor
        Mock Write-Warning {}
        & $B2b -PostApplyPath $b2bFile -Confirm:$false -SkipTenantSettings
        @($global:PaTest.Posts | ForEach-Object { $_.Body['@odata.id'] }) | Should -Be @('https://graph.microsoft.com/v1.0/users/u-sponsor-1', 'https://graph.microsoft.com/v1.0/users/u-sponsor-2')
        Should -Invoke Write-Warning -ParameterFilter { $Message -match 'Group refused' }
    }

    It 'keeps the TENANT-WIDE settings PATCH behind ShouldProcess (-WhatIf changes nothing)' {
        Set-GraphMock -ConnectedOrgs @(@{ id = 'org-1'; displayName = 'Fabrikam Affiliated Clinic'; state = 'proposed' })
        & $B2b -PostApplyPath $b2bFile -WhatIf
        $global:PaTest.Posts.Count | Should -Be 0
        $global:PaTest.Patches.Count | Should -Be 0
    }
}

# =============================================================================
Describe 'Invoke-PostApply.ps1 - plan' {
    BeforeAll {
        function New-Outputs([switch]$AllOn) {
            $o = [ordered]@{ log_analytics_workspace_id = @{ value = '/subscriptions/22222222-2222-2222-2222-222222222222/resourceGroups/rg-identity-lab/providers/Microsoft.OperationalInsights/workspaces/loga-idlab' } }
            if ($AllOn) {
                $o['break_glass_group_object_id'] = @{ value = 'g-bg' }
                $o['break_glass_user_principal_names'] = @{ value = @('bg-admin-01@contosohealthlab.onmicrosoft.com', 'bg-admin-02@contosohealthlab.onmicrosoft.com') }
                $o['access_package_ids'] = @{ value = @{ nurse = 'ap-1' } }
                $o['all_workforce_group_object_id'] = @{ value = 'g-wf' }
                $o['ca_policy_display_names'] = @{ value = @{ CA001 = 'CA001 - x'; CA006 = 'CA006 - User risk high' } }
                $o['pim_tier_group_mail_nicknames'] = @{ value = @{ 'PIM-Tier1-Helpdesk' = 'pim-tier1-helpdesk' } }
                $o['access_review_definitions'] = @{ value = @{ 'privileged:X' = '{}' } }
                $o['b2b_post_apply'] = @{ value = @{ access_package_id = 'ap-b2b' } }
                $o['aws_saml_signing_cert_activation_command'] = @{ value = 'Update-MgServicePrincipal -ServicePrincipalId sp -PreferredTokenSigningKeyThumbprint AB' }
                $o['app_consent_reviewers_group_object_id'] = @{ value = 'g-acr' }
                $o['agent_runtime_uami_principal_id'] = @{ value = 'mi-1' }
                $o['itdr_rule_keys'] = @{ value = @('app_credential_added') }
                $o['containment_automation_rule_id'] = @{ value = $null }
                $o['vault_ingestion'] = @{ value = @{ endpoint = 'https://dce.example'; dcr_immutable_id = 'dcr-1' } }
                $o['evidence_container_id'] = @{ value = '/subscriptions/x/containers/evidence' }
                $o['guacamole_psm_client_id'] = @{ value = 'cid-guac' }
                $o['admin_fido2_allowed_aaguids'] = @{ value = @('cb69481e-8ff7-4039-93ec-0a2729a154a8') }
                $o['accept_admin_synced_passkey_risk'] = @{ value = $false }
                $o['pim_auth_context_requests'] = @{ value = @{ policy_key = 'CA021'; auth_context_id = 'c1'; policy_match_prefix = 'CA021 - '; policy_state = 'enabledForReportingButNotEnforced'; auth_context_body = '{}'; policy_display_name = 'CA021 - x'; policy_body = '{}' } }
                $o['intune_vm_name'] = @{ value = 'vm-ch-win11-01' }
                $o['directory_role_pim_policies'] = @{ sensitive = $true; value = @{ '62e90394-69f5-4237-9190-012177145e10' = '{}' } }
                $o['pim_workforce_au_object_id'] = @{ value = 'au-wf' }
                $o['pim_workforce_au_membership_body'] = @{ value = '{"membershipType":"Dynamic"}' }
                $o['vault_ingest_signals'] = @{ value = 'all' }
                $o['protected_actions_auth_context_requests'] = @{ value = @{ policy_key = 'CA023'; auth_context_id = 'c2'; policy_match_prefix = 'CA023 - '; policy_state = 'enabledForReportingButNotEnforced'; auth_context_body = '{}'; policy_display_name = 'CA023 - x'; policy_body = '{}' } }
            }
            else {
                # Terraform prints null outputs as value = null and empty ones as [] / {}.
                foreach ($n in 'break_glass_group_object_id', 'access_package_ids', 'access_review_definitions', 'b2b_post_apply', 'app_consent_reviewers_group_object_id', 'agent_runtime_uami_principal_id', 'vault_ingestion', 'evidence_container_id', 'guacamole_psm_client_id', 'aws_saml_signing_cert_activation_command',
                    'pim_auth_context_requests', 'intune_vm_name', 'directory_role_pim_policies', 'pim_workforce_au_object_id', 'pim_workforce_au_membership_body', 'vault_ingest_signals') { $o[$n] = @{ value = $null } }
                $o['itdr_rule_keys'] = @{ value = @() }
            }
            return $o
        }
        # Every opt-in a full run can take.
        $script:AllOpts = @{
            PimEligibility        = @{ 'pim-tier1-helpdesk' = @('adm-raj.patel@contoso.test') }
            GlobalAdminEligible   = @('adm-grace@contoso.test')
            VipUserPrincipalNames = @('cno@contoso.test')
            BuildAccountUpn       = 'admin@contosohealthlab.onmicrosoft.com'
        }
    }

    It 'with lab.tfvars (everything off) applies NOTHING - not even the opt-in steps' {
        $o = $script:AllOpts
        $plan = Get-PostApplyPlan -Outputs (New-Outputs) -PimEligibility $o.PimEligibility -GlobalAdminEligible $o.GlobalAdminEligible -VipUserPrincipalNames $o.VipUserPrincipalNames -BuildAccountUpn $o.BuildAccountUpn
        @($plan | Where-Object Applies).Count | Should -Be 0
    }

    It 'with every flag on runs the steps in dependency order, baseline first and as the GATE, build-account last' {
        $o = $script:AllOpts
        $plan = Get-PostApplyPlan -Outputs (New-Outputs -AllOn) -PimEligibility $o.PimEligibility -GlobalAdminEligible $o.GlobalAdminEligible -VipUserPrincipalNames $o.VipUserPrincipalNames -BuildAccountUpn $o.BuildAccountUpn
        $ids = @($plan | Where-Object Applies | ForEach-Object Id)
        $ids | Should -Be @('baseline', 'admin-accounts', 'auth-methods', 'auth-context', 'protected-actions', 'token-protection', 'auto-assignment', 'sod', 'lifecycle-workflows', 'directory-role-pim', 'pim-eligibility', 'helpdesk-au', 'restricted-au', 'access-reviews', 'b2b', 'external-collab', 'aws-saml-cert', 'app-governance', 'consent', 'agent-identity', 'build-account', 'manual', 'manual', 'manual', 'manual')
        $plan[0].Gate | Should -BeTrue
        $plan[0].Params['OnMicrosoftDomain'] | Should -Be 'contosohealthlab.onmicrosoft.com'
        [array]::IndexOf($ids, 'pim-eligibility') | Should -BeLessThan ([array]::IndexOf($ids, 'access-reviews')) -Because 'the self-review guard reads PIM eligibility'
        [array]::IndexOf($ids, 'admin-accounts') | Should -BeLessThan ([array]::IndexOf($ids, 'auth-methods')) -Because 'the admin passkey target (Admin-Accounts) must hold the adm- and build accounts before it is targeted'
        [array]::IndexOf($ids, 'admin-accounts') | Should -BeLessThan ([array]::IndexOf($ids, 'pim-eligibility')) -Because 'eligibility goes to adm- accounts, which must exist first'
        ($plan | Where-Object Id -eq 'auth-methods').Params['BuildAccountUpn'] | Should -Be 'admin@contosohealthlab.onmicrosoft.com' -Because 'the passkey script FAILs while no target covers the build account'
        ($plan | Where-Object Id -eq 'admin-accounts').Params['BuildAccountUpn'] | Should -Be 'admin@contosohealthlab.onmicrosoft.com'
        ($plan | Where-Object Id -eq 'lifecycle-workflows').Params['EnableJoinerSchedule'] | Should -BeTrue -Because 'the joiner schedule is on in the tenant (E91); without the switch the step reports it as drift'
        # CA023 runs through the same script; the binding is manual and waits for an ENFORCED CA023.
        ($plan | Where-Object Id -eq 'protected-actions').Script | Should -Be 'post-apply/Set-AuthContextPolicies.ps1'
        (Split-Path -Leaf ($plan | Where-Object Id -eq 'protected-actions').Params['RequestsPath']) | Should -Be 'protected_actions_auth_context_requests.json'
        ($plan | Where-Object Name -like 'Bind the protected-actions context*').Applies | Should -BeFalse -Because 'CA023 is report-only: binding the context would apply no step-up'
        [array]::IndexOf($ids, 'aws-saml-cert') | Should -BeLessThan ([array]::IndexOf($ids, 'app-governance')) -Because 'the 180-day certificate cap must not block the SAML signing certificate'
        [array]::IndexOf($ids, 'auth-context') | Should -BeLessThan ([array]::IndexOf($ids, 'directory-role-pim')) -Because 'c1 must exist (and CA021 be enforced) before a PIM policy requires it'
        [array]::IndexOf($ids, 'auto-assignment') | Should -BeLessThan ([array]::IndexOf($ids, 'sod')) -Because 'SoD links are never put on a package with an automatic policy, so those must exist first'
        [array]::IndexOf($ids, 'directory-role-pim') | Should -BeLessThan ([array]::IndexOf($ids, 'access-reviews')) -Because 'the GA eligibility review should see the first eligibility'
        [array]::IndexOf($ids, 'b2b') | Should -BeLessThan ([array]::IndexOf($ids, 'external-collab')) -Because 'the guest lock-down follows the one open guest path'
        $ba = @($plan | Where-Object Applies | Where-Object { -not $_.Manual }) | Select-Object -Last 1
        $ba.Id | Should -Be 'build-account' -Because 'removing the build account''s standing GA must come after every step that needs it'
        $ba.RequiresClean | Should -BeTrue
    }

    It 'opt-in steps stay off without their inputs; the help-desk AU rule is a manual Graph PATCH' {
        $plan = Get-PostApplyPlan -Outputs (New-Outputs -AllOn)
        ($plan | Where-Object Id -eq 'restricted-au').Applies | Should -BeFalse
        ($plan | Where-Object Id -eq 'build-account').Applies | Should -BeFalse
        ($plan | Where-Object Id -eq 'build-account').Reason | Should -Match 'BuildAccountUpn'
        ($plan | Where-Object Id -eq 'directory-role-pim').Params.ContainsKey('EligibleUserPrincipalNames') | Should -BeFalse
        $au = $plan | Where-Object Id -eq 'helpdesk-au'
        $au.Applies | Should -BeTrue
        $au.Manual | Should -Match "PATCH -Uri 'https://graph.microsoft.com/v1.0/directory/administrativeUnits/au-wf'"
        # Without the GA policy the conversion would fail its own check [7/8].
        $noGa = New-Outputs -AllOn; $noGa['directory_role_pim_policies'] = @{ sensitive = $true; value = @{} }
        $p2 = Get-PostApplyPlan -Outputs $noGa -BuildAccountUpn 'admin@contosohealthlab.onmicrosoft.com'
        $s = $p2 | Where-Object Id -eq 'build-account'
        $s.Applies | Should -BeFalse
        $s.Reason | Should -Match 'enable_global_admin_pim_policy'
    }

    It 'the vault feed command asks for the extended signals once the v2 columns exist' {
        $plan = Get-PostApplyPlan -Outputs (New-Outputs -AllOn)
        ($plan | Where-Object Name -like 'Vault check-out feed*').Manual | Should -Match ' --signals all --follow 60'
        $o = New-Outputs -AllOn; $o['vault_ingest_signals'] = @{ value = 'checkout' }
        $p2 = Get-PostApplyPlan -Outputs $o
        ($p2 | Where-Object Name -like 'Vault check-out feed*').Manual | Should -Not -Match '--signals'
    }

    It 'dry run = -WhatIf / PLAN / offline preview; execute = real, Agent ID only with its second key' {
        $o = $script:AllOpts
        $dry = Get-PostApplyPlan -Outputs (New-Outputs -AllOn) -GlobalAdminEligible $o.GlobalAdminEligible -VipUserPrincipalNames $o.VipUserPrincipalNames -BuildAccountUpn $o.BuildAccountUpn
        foreach ($id in 'auth-context', 'auto-assignment', 'sod', 'directory-role-pim', 'restricted-au', 'external-collab', 'build-account') {
            ($dry | Where-Object Id -eq $id).Params['WhatIf'] | Should -BeTrue -Because "$id must be -WhatIf in a dry run"
        }
        ($dry | Where-Object Id -eq 'sod').Script | Should -Be 'post-apply/Set-IncompatibleAccessPackages.ps1' -Because 'Set-AccessPackageSoD.ps1 is only a forwarding shim now'
        ($dry | Where-Object Id -eq 'token-protection').Params.ContainsKey('Apply') | Should -BeFalse -Because 'without -Apply the token-protection script only plans'
        ($dry | Where-Object Id -eq 'directory-role-pim').Params['EligibleUserPrincipalNames'] | Should -Be @('adm-grace@contoso.test')
        ($dry | Where-Object Id -eq 'restricted-au').Params['MemberUserPrincipalNames'] | Should -Be @('cno@contoso.test')
        $b = ($dry | Where-Object Id -eq 'build-account').Params
        $b['BuildAccountUpn'] | Should -Be 'admin@contosohealthlab.onmicrosoft.com'
        $b['OnMicrosoftDomain'] | Should -Be 'contosohealthlab.onmicrosoft.com'
        $b['ResourceGroup'] | Should -Be 'rg-identity-lab' -Because 'the alert-rule check [6/8] reads the workspace the outputs name'
        $b['WorkspaceName'] | Should -Be 'loga-idlab'
        ($dry | Where-Object Id -eq 'auth-methods').Params.ContainsKey('Apply') | Should -BeFalse
        ($dry | Where-Object Id -eq 'auth-methods').Params['IncludeStaffRollout'] | Should -BeTrue
        ($dry | Where-Object Id -eq 'auth-methods').Params['EnableReportSuspiciousActivity'] | Should -BeTrue
        # Registration (methods policy) and sign-in (the admin strength: CA002/CA021/CA022) use ONE key-model list: the Terraform output.
        @(($dry | Where-Object Id -eq 'auth-methods').Params['AdminAllowedAaguids']) | Should -Be @('cb69481e-8ff7-4039-93ec-0a2729a154a8')
        ($dry | Where-Object Id -eq 'auth-methods').Params.ContainsKey('AcceptAdminSyncedPasskeyRisk') | Should -BeFalse
        ($dry | Where-Object Id -eq 'agent-identity').Params['OfflinePreview'] | Should -BeTrue
        ($dry | Where-Object Id -eq 'baseline').Params.ContainsKey('WhatIf') | Should -BeFalse -Because '01-Verify-Baseline is read-only and has no -WhatIf'

        $exec = Get-PostApplyPlan -Outputs (New-Outputs -AllOn) -Execute $true
        ($exec | Where-Object Id -eq 'sod').Params.ContainsKey('WhatIf') | Should -BeFalse
        ($exec | Where-Object Id -eq 'auth-context').Params.ContainsKey('WhatIf') | Should -BeFalse
        ($exec | Where-Object Id -eq 'token-protection').Params['Apply'] | Should -BeTrue
        ($exec | Where-Object Id -eq 'auth-methods').Params['Apply'] | Should -BeTrue
        ($exec | Where-Object Id -eq 'agent-identity').Applies | Should -BeFalse
        $ok = Get-PostApplyPlan -Outputs (New-Outputs -AllOn) -Execute $true -AcceptAgentIdPreview $true
        ($ok | Where-Object Id -eq 'agent-identity').Params['AcceptPreview'] | Should -BeTrue
        ($ok | Where-Object Id -eq 'agent-identity').Params['ManagedIdentityPrincipalId'] | Should -Be 'mi-1'
    }

    It 'accepts PIM-Demo-Readers eligibility only once its output names the group' {
        $o = New-Outputs -AllOn
        $before = Get-PostApplyPlan -Outputs $o -PimEligibility @{ 'pim-demo-readers' = @('adm-presenter@contoso.test') }
        ($before | Where-Object { $_.Id -eq 'pim-eligibility' }).Applies | Should -BeFalse -Because 'enable_pim_demo_readers off = no output = not a PIM-governed group yet'
        $o['pim_demo_readers_group_mail_nickname'] = @{ value = 'pim-demo-readers' }
        $after = Get-PostApplyPlan -Outputs $o -PimEligibility @{ 'pim-demo-readers' = @('adm-presenter@contoso.test') }
        $s = $after | Where-Object { $_.Id -eq 'pim-eligibility' }
        $s.Applies | Should -BeTrue
        $s.Params['GroupMailNickname'] | Should -Be 'pim-demo-readers'
        $s.Params['UserPrincipalNames'] | Should -Be @('adm-presenter@contoso.test')
        $s.Script | Should -Be 'post-apply/Set-PimGroupEligibility.ps1'
    }

    It 'refuses PIM eligibility for a group that is not PIM-governed in the outputs' {
        $plan = Get-PostApplyPlan -Outputs (New-Outputs -AllOn) -PimEligibility @{ 'app-servicenow-users' = @('x@contoso.test') }
        $s = $plan | Where-Object { $_.Id -eq 'pim-eligibility' }
        $s.Applies | Should -BeFalse
        $s.Reason | Should -Match 'not a PIM-governed group'
    }
}

Describe 'Invoke-PostApply.ps1 - runs the real scripts'' parameter contracts' {
    BeforeAll {
        # Stubs with the REAL param blocks: a parameter Invoke-PostApply.ps1 passes
        # that a script does not declare makes PowerShell refuse the call.
        $script:stubRoot = Join-Path $TestDrive 'stubs'
        $script:log = Join-Path $TestDrive 'calls.log'
        New-Item -ItemType Directory -Path (Join-Path $stubRoot 'post-apply') -Force | Out-Null
        $real = @('01-Verify-Baseline.ps1') + @(Get-ChildItem -LiteralPath (Get-LabScriptPath 'post-apply') -Filter '*.ps1' | Where-Object Name -ne 'Invoke-PostApply.ps1' | ForEach-Object { "post-apply/$($_.Name)" })
        foreach ($rel in $real) {
            $tokens = $null; $errs = $null
            $ast = [System.Management.Automation.Language.Parser]::ParseFile((Get-LabScriptPath $rel), [ref]$tokens, [ref]$errs)
            # [CmdletBinding(...)] sits on the param block but outside its extent.
            $attrs = @($ast.ParamBlock.Attributes | ForEach-Object { $_.Extent.Text }) -join [Environment]::NewLine
            $paramText = $attrs + [Environment]::NewLine + $ast.ParamBlock.Extent.Text
            # ValidateScript(Test-Path) on the input-file parameters stays:
            # Invoke-PostApply.ps1 must hand over a real file.
            $body = @"
$paramText
`$rec = [ordered]@{ script = '$rel'; params = @(`$PSBoundParameters.Keys | Sort-Object); whatIf = [bool]`$WhatIfPreference; paths = @(`$PSBoundParameters.GetEnumerator() | Where-Object { `$_.Key -like '*Path' } | ForEach-Object { [string]`$_.Value }) }
(`$rec | ConvertTo-Json -Compress) | Add-Content -LiteralPath `$env:POSTAPPLY_TEST_LOG -WhatIf:`$false
if (`$env:POSTAPPLY_FAIL -eq '$rel') { exit 1 }
"@
            Set-Content -LiteralPath (Join-Path $stubRoot $rel) -Value $body -Encoding utf8NoBOM
        }
        $script:outFile = Join-Path $TestDrive 'tf-out.json'
        $o = [ordered]@{
            break_glass_group_object_id              = @{ value = 'g-bg' }
            break_glass_user_principal_names         = @{ value = @('bg-admin-01@contosohealthlab.onmicrosoft.com') }
            access_package_ids                       = @{ value = @{ nurse = 'ap-1' } }
            all_workforce_group_object_id            = @{ value = 'g-wf' }
            ca_policy_display_names                  = @{ value = @{ CA006 = 'CA006 - x' } }
            pim_tier_group_mail_nicknames            = @{ value = @{ 'PIM-Tier1-Helpdesk' = 'pim-tier1-helpdesk' } }
            access_review_definitions                = @{ value = @{ 'privileged:X' = '{}' } }
            b2b_post_apply                           = @{ value = @{ access_package_id = 'ap-b2b' } }
            app_consent_reviewers_group_object_id    = @{ value = 'g-acr' }
            agent_runtime_uami_principal_id          = @{ value = '55555555-5555-5555-5555-555555555555' }
            aws_saml_signing_cert_activation_command = @{ value = $null }
            itdr_rule_keys                           = @{ value = @() }
            log_analytics_workspace_id               = @{ value = '/subscriptions/22222222-2222-2222-2222-222222222222/resourceGroups/rg-identity-lab/providers/Microsoft.OperationalInsights/workspaces/loga-idlab' }
            pim_auth_context_requests                = @{ value = @{ policy_key = 'CA021'; auth_context_id = 'c1'; policy_state = 'enabledForReportingButNotEnforced' } }
            intune_vm_name                           = @{ value = 'vm-ch-win11-01' }
            directory_role_pim_policies              = @{ sensitive = $true; value = @{ '62e90394-69f5-4237-9190-012177145e10' = '{}' } }
            pim_workforce_au_object_id               = @{ value = 'au-wf' }
            pim_workforce_au_membership_body         = @{ value = '{"membershipType":"Dynamic"}' }
        }
        $script:Opt = @{ PimEligibility = @{ 'pim-tier1-helpdesk' = @('adm-raj.patel@contoso.test') }; GlobalAdminEligible = @('adm-grace@contoso.test'); VipUserPrincipalNames = @('cno@contoso.test'); BuildAccountUpn = 'admin@contosohealthlab.onmicrosoft.com' }
        ($o | ConvertTo-Json -Depth 10) | Set-Content -LiteralPath $script:outFile -Encoding utf8NoBOM
    }
    BeforeEach {
        Remove-Item -LiteralPath $log -ErrorAction SilentlyContinue
        $env:POSTAPPLY_TEST_LOG = $log
        $env:POSTAPPLY_FAIL = ''
        $global:LASTEXITCODE = 0
        Mock Write-Host {}
    }
    AfterAll { Remove-Item Env:POSTAPPLY_TEST_LOG, Env:POSTAPPLY_FAIL -ErrorAction SilentlyContinue }

    It 'dry run calls every applicable script in order with parameters each script really declares' {
        & $Pa -OutputsPath $outFile -ScriptRoot $stubRoot @Opt
        $LASTEXITCODE | Should -Be 0
        $calls = @(Get-Content -LiteralPath $log | ForEach-Object { $_ | ConvertFrom-Json })
        @($calls | ForEach-Object script) | Should -Be @('01-Verify-Baseline.ps1', 'post-apply/New-AdminAccounts.ps1', 'post-apply/Set-AuthenticationMethodsPolicy.ps1', 'post-apply/Set-AuthContextPolicies.ps1',
            'post-apply/Set-TokenProtectionPolicy.ps1', 'post-apply/Set-AutoAssignmentPolicies.ps1', 'post-apply/Set-IncompatibleAccessPackages.ps1',
            'post-apply/New-LifecycleWorkflows.ps1', 'post-apply/Set-DirectoryRolePimPolicies.ps1', 'post-apply/Set-PimGroupEligibility.ps1',
            'post-apply/New-RestrictedAdminUnit.ps1', 'post-apply/New-AccessReviewDefinitions.ps1', 'post-apply/New-B2BConnectedOrganization.ps1',
            'post-apply/Set-ExternalCollaboration.ps1', 'post-apply/Set-AppGovernancePolicy.ps1', 'post-apply/Set-ConsentPolicy.ps1', 'post-apply/New-AgentIdentity.ps1',
            'post-apply/Convert-BuildAccountToEligible.ps1')
        foreach ($c in $calls | Where-Object { $_.script -notin '01-Verify-Baseline.ps1', 'post-apply/Set-AuthenticationMethodsPolicy.ps1', 'post-apply/Set-TokenProtectionPolicy.ps1', 'post-apply/New-AgentIdentity.ps1' }) { $c.whatIf | Should -BeTrue -Because "$($c.script) must run as -WhatIf in a dry run" }
        ($calls | Where-Object script -eq 'post-apply/Set-AuthenticationMethodsPolicy.ps1').params | Should -Not -Contain 'Apply'
        ($calls | Where-Object script -eq 'post-apply/Set-TokenProtectionPolicy.ps1').params | Should -Not -Contain 'Apply'
        # The rendered-body hand-off files existed for the call (ValidateScript
        # Test-Path in the real param blocks) and are gone afterwards - one of
        # them carries the sensitive pim_alert_mailbox.
        $handoff = @($calls | ForEach-Object { $_.paths } | Where-Object { $_ })
        @($handoff | ForEach-Object { Split-Path -Leaf $_ }) | Should -Contain 'directory_role_pim_policies.json'
        @($handoff | ForEach-Object { Split-Path -Leaf $_ }) | Should -Contain 'pim_auth_context_requests.json'
        foreach ($f in $handoff | Where-Object { $_ -like '*postapply-*' }) { Test-Path -LiteralPath $f | Should -BeFalse -Because "$f must be removed after the run" }
    }

    It 'never runs the build-account conversion after an earlier failure (it removes standing GA)' {
        $env:POSTAPPLY_FAIL = 'post-apply/Set-AuthContextPolicies.ps1'
        Mock Write-Warning {}
        & $Pa -OutputsPath $outFile -ScriptRoot $stubRoot @Opt
        $LASTEXITCODE | Should -Be 1
        $ran = @(Get-Content -LiteralPath $log | ForEach-Object { ($_ | ConvertFrom-Json).script })
        $ran | Should -Contain 'post-apply/New-AgentIdentity.ps1' -Because 'independent steps still run'
        $ran | Should -Not -Contain 'post-apply/Convert-BuildAccountToEligible.ps1'
        Should -Invoke Write-Warning -ParameterFilter { $Message -match 'build-account NOT run' }
    }

    It 'stops everything when the break-glass GATE fails' {
        $env:POSTAPPLY_FAIL = '01-Verify-Baseline.ps1'
        Mock Write-Warning {}
        & $Pa -OutputsPath $outFile -ScriptRoot $stubRoot
        $LASTEXITCODE | Should -Be 1
        @(Get-Content -LiteralPath $log).Count | Should -Be 1
        Should -Invoke Write-Warning -ParameterFilter { $Message -match 'GATE FAILED' }
    }

    It 'a non-gate failure is reported (exit 1) but later independent steps still run' {
        $env:POSTAPPLY_FAIL = 'post-apply/Set-IncompatibleAccessPackages.ps1'
        Mock Write-Warning {}
        & $Pa -OutputsPath $outFile -ScriptRoot $stubRoot
        $LASTEXITCODE | Should -Be 1
        @(Get-Content -LiteralPath $log | ForEach-Object { ($_ | ConvertFrom-Json).script }) | Should -Contain 'post-apply/New-AgentIdentity.ps1'
    }

    It '-ListOnly touches nothing' {
        & $Pa -OutputsPath $outFile -ScriptRoot $stubRoot -ListOnly
        Test-Path -LiteralPath $log | Should -BeFalse
    }
}
