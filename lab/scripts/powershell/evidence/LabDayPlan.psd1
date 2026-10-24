# =============================================================================
# The trial window as data: one entry per step, in the order the days run.
# Read by ../Invoke-LabDay.ps1 (Import-PowerShellDataFile: literals only).
#
# Status: BUILT. tests/Invoke-LabDay.Tests.ps1 checks this file against the
# code it names: every script exists and receives only parameters it
# declares, every flag exists in lab/terraform/envs/dev/lab.tfvars, every
# evidence id exists in lab/docs/evidence-capture-plan.md (and every Day 0-29
# id there is here), every capture recipe exists. No step has run against a
# tenant: none exists yet.
#
# Step fields
#   Id            unique; what -Step takes (an evidence id works too)
#   Day | Days    the trial day (Day 0 = both trials activated); Days = a
#                 window: the step is offered on each day until it is done
#   Kind          console   a portal step: the exact console path, then
#                           [d]one / [s]kip / [m]issed / [q]uit
#                 pr        a lab.tfvars change = one PR, planned and applied
#                           by the pipeline (Flags / FlagsOff / Enforce)
#                 terminal  a command the operator runs (local apply, the
#                           Windows assessment host, bash in lab/pam)
#                 script    an existing lab script, run by the day runner
#   Runs          for script steps: read (changes nothing in the tenant),
#                 dry (-WhatIf / no -Execute: changes nothing), real (asks
#                 first, then the script's own confirmations). Add = the
#                 parameters added to Args for that run
#   Evidence      ids from lab/docs/evidence-capture-plan.md; Part names a
#                 second folder for the same id; NewCaptureId = a new id the
#                 capture plan asks for ("a new capture ID")
#   Capture       read-only capture recipes run after the step is done
#                 (evidence/LabEvidence.psm1); CaptureBefore runs first
#   {Name}        placeholders filled from the settings file (gitignored
#                 lab/scripts/powershell/out/labday/settings.json); a few
#                 are computed ({StartUtc:<step>}, {NewestFile:<glob>},
#                 {KpiBaseline}, {PowerShellOut}) or asked ({ChangeTicket})
# =============================================================================
@{
    Schema         = 'contoso-lab-day/1'

    # Flipped before Day 0 (the DC build and the WORM store): preflight
    # expects them on from Day 0.
    PreWindowFlags = @('enable_dc', 'enable_evidence_store')

    Days           = @(
        @{ Day = 0; Title = 'Trials, licences, security defaults' }
        @{ Day = 1; Title = 'Baselines, then everything report-only' }
        @{ Day = 2; Title = 'Sentinel, PIM, the build account goes eligible' }
        @{ Day = 3; Title = 'Governance: birthright, SoD, joiner; DC01 security events (Days 3-5)' }
        @{ Day = 4; Title = 'Apps: AWS SSO + SCIM, the Clinical Portal' }
        @{ Day = 5; Title = 'Risk simulation, Intune' }
        @{ Day = 6; Title = 'CA insights, device code, the passwordless pilot' }
        @{ Day = 7; Title = 'Graduate CA003 (legacy authentication)' }
        @{ Day = 8; Title = 'Access reviews, B2B, Azure PIM, Splunk' }
        @{ Day = 9; Title = 'Graduate CA001 (MFA, all users)' }
        @{ Day = 10; Title = 'Graduate CA002 and CA007; CA021 and PIM on c1 (Days 10-11)' }
        @{ Day = 11; Title = 'Tier-0 activation on c1; Tor again' }
        @{ Day = 12; Title = 'Graduate CA006, CA009, CA010, CA020; the Pharmacy review' }
        @{ Day = 13; Title = 'Review KPIs, the SoD tripwire, the containment playbook' }
        @{ Day = 14; Title = 'Containment drill; the joiner and mover takes' }
        @{ Day = 15; Title = 'One event per ITDR rule' }
        @{ Day = 16; Title = 'Break-glass drill; CA004 through the pipeline' }
        @{ Day = 17; Title = 'PAM on DC01, the AD plane' }
        @{ Day = 18; Title = 'Restore drill, token protection, leaver' }
        @{ Day = 19; Title = 'NHI, Agent ID' }
        @{ Day = 20; Title = 'Buffer: re-takes only' }
        @{ Day = 21; Title = 'Buffer: re-takes only' }
        @{ Day = 22; Title = 'Buffer: re-takes only' }
        @{ Day = 23; Title = 'Buffer: re-takes only' }
        @{ Day = 24; Title = 'Buffer: re-takes only' }
        @{ Day = 25; Title = 'KPIs after' }
        @{ Day = 26; Title = 'Assessment after' }
        @{ Day = 27; Title = 'The evidence pack' }
        @{ Day = 28; Title = 'Close-out, the WORM decision, teardown or reserve' }
        @{ Day = 29; Title = 'Post-trial PRs' }
    )

    Steps          = @(
        # ------------------------------------------------------------- Day 0
        @{
            Id = 'trials'; Day = 0; Kind = 'console'; Evidence = @('E08')
            Title = 'Start both trials (the clock starts)'
            Do = @(
                'admin.microsoft.com > Billing > Purchase services > Microsoft 365 E5 > Start free trial; then the same for Microsoft Entra ID Governance.'
                'Billing > Your products > each trial > recurring billing Off. Note whether E5 says "(no Teams)".'
            )
            Success = 'Both trials listed with their end dates; recurring billing Off on both.'
            Note = 'Write both end dates at the top of the capture log (the subscriptions export carries them).'
            Rollback = 'None: the clock has started.'
            Capture = @(@{ Recipe = 'subscriptions' })
        }
        @{
            Id = 'licences'; Day = 0; Kind = 'console'
            Title = 'Licences for every account that signs in'
            Do = @(
                'M365 admin center > Users > Active users > each account > Licenses and apps > Microsoft 365 E5 + Microsoft Entra ID Governance: admin@, both break-glass accounts, approver-01, approver-02 and the tst- accounts.'
                'Never the adm- accounts: they carry no licence by design.'
            )
            Success = 'Each account shows both licences.'
            Rollback = 'Unassign the licence.'
        }
        @{
            Id = 'security-defaults'; Day = 0; Kind = 'console'
            Title = 'Security defaults off: Conditional Access takes over'
            Do = @(
                'First confirm the admin@ passkey works.'
                'Entra admin center > Overview > Properties > Manage security defaults > Disabled (reason: using Conditional Access).'
            )
            Success = 'Security defaults show Disabled.'
            Note = 'Until CA001 is enforced (Day 9) only report-only policies and the mandatory admin-portal MFA stand in front of ordinary users: the deliberate report-only soak. Test passwords stay long and unique.'
            Rollback = 'Turn security defaults back on (only before any CA policy exists).'
        }
        @{
            Id = 'signin-logs'; Day = 0; Kind = 'console'; Evidence = @('E09')
            Title = 'Sign-in logs reach Log Analytics'
            Do = @('Azure portal > Log Analytics workspaces > {WorkspaceName} > Logs: SigninLogs | summarize count() by bin(TimeGenerated, 1h)')
            Success = 'Rows arriving.'
            Capture = @(@{ Recipe = 'la'; Name = 'signin-volume'; LookbackHours = 24; Query = 'SigninLogs | summarize SignIns = count() by bin(TimeGenerated, 1h) | order by TimeGenerated asc' })
        }

        # ------------------------------------------------------------- Day 1
        @{
            Id = 'baseline-assessment'; Day = 1; Kind = 'terminal'; Evidence = @('E10')
            Title = 'Baseline assessment before any premium configuration (Windows x64 host)'
            Do = @(
                'On the Windows x64 assessment host, from lab/scripts/powershell (sign in through each browser prompt; never -UseDeviceCode):'
                './Invoke-BaselineAssessment.ps1 -Phase before -StorageAccountName {EvidenceStorageAccount}'
                'Commit the public summary folder it wrote under lab/evidence/assessments/, then pull it here.'
            )
            Success = 'A public summary folder under lab/evidence/assessments/; the raw ScubaGear and Zero Trust reports in the WORM store.'
            Note = 'First thing today: the delta to the after run must be configuration only.'
            Rollback = 'None (read-only).'
            Capture = @(@{ Recipe = 'files'; Name = 'assessment-before'; Path = 'evidence/assessments/*before*/*'; LookbackHours = 48 })
        }
        @{
            Id = 'kpi-baseline'; Day = 1; Kind = 'script'; Evidence = @('E11')
            Title = 'KPI baseline'
            Script = 'scripts/powershell/08-Measure-KPIs.ps1'
            Args = @{ Label = 'baseline'; SkipPam = '{SkipPam}' }
            Success = 'A hashed KPI snapshot under lab/evidence/kpis/: commit it today.'
            Rollback = 'None (read-only).'
            Capture = @(@{ Recipe = 'files'; Name = 'kpi-snapshot'; Path = 'evidence/kpis/2*.json*' })
        }
        @{
            Id = 'nhi-baseline'; Day = 1; Kind = 'script'; Evidence = @('E11'); Part = 'nhi'
            Title = 'NHI inventory baseline'
            Script = 'scripts/powershell/06-NHI-Inventory.ps1'
            Success = 'Findings by OWASP NHI id; the detail in the gitignored lab/evidence/out/.'
            Rollback = 'None (read-only).'
        }
        @{
            Id = 'shadow-admins-baseline'; Day = 1; Kind = 'script'; Evidence = @('E11'); Part = 'shadow-admins'
            Title = 'Shadow-admin baseline'
            Script = 'scripts/powershell/Find-ShadowAdmins.ps1'
            Success = 'Paths one step from a privileged role, by type.'
            Rollback = 'None (read-only).'
        }
        @{
            Id = 'ms-managed-policies'; Day = 1; Kind = 'console'
            Title = 'Microsoft-managed policies out of the way'
            Do = @(
                'Entra admin center > ID Protection: the Microsoft-managed user-risk policy to report-only or Off (CA006 must be the one user-risk policy).'
                'Entra admin center > Conditional Access > Policies: every Microsoft-managed policy gets the Break-Glass-Admins exclusion, or Off.'
            )
            Success = 'No Microsoft-managed policy can block break-glass.'
        }
        @{
            Id = 'ca-report-only'; Day = 1; Kind = 'pr'; Evidence = @('E12')
            Title = 'PR #1: every Conditional Access policy, report-only'
            Flags = @('enable_premium', 'enable_identity_protection_ca', 'enable_phishing_resistant_all_users', 'enable_registration_ca', 'enable_device_code_block', 'enable_admin_session_controls')
            Do = @(
                'In the same PR: admin_fido2_allowed_aaguids = your key models'' AAGUIDs, or accept_admin_synced_passkey_risk = true as a recorded risk acceptance (then add it to ExtraExpectedOnFlags in the settings file).'
                'Every ca_policy_states value stays enabledForReportingButNotEnforced.'
            )
            Success = 'The plan comment shows CA001-CA010 and CA020 report-only, each excluding Break-Glass-Admins; apply green.'
            Rollback = 'A PR setting the flags back to false (the policies are deleted).'
            Capture = @(@{ Recipe = 'pipeline' }, @{ Recipe = 'ca-policies' })
        }
        @{
            Id = 'break-glass-keys'; Day = 1; Kind = 'console'
            Title = 'Break-glass keys (lab/terraform/README.md, human step 6)'
            Do = @(
                'Private window: sign in as bg-admin-01, then bg-admin-02 > mysignins.microsoft.com > Security info > add each FIDO2 key (two per account if you bought four).'
                'If the portal wants a second factor first: a one-time Temporary Access Pass from admin@, register the key, delete the TAP.'
                'Rotate the seeded password into the sealed copies.'
            )
            Success = 'Each break-glass account lists its keys.'
        }
        @{
            Id = 'verify-baseline'; Day = 1; Kind = 'script'; Evidence = @('E13')
            Title = 'Verify the baseline: break-glass excluded from every CA policy'
            Script = 'scripts/powershell/01-Verify-Baseline.ps1'
            Args = @{ OnMicrosoftDomain = '{OnMicrosoftDomain}' }
            Success = '0 FAIL; break-glass excluded from every CA policy; the standing-vs-eligible step WARNs once, for admin@ (expected until Day 2).'
            Note = 'Any FAIL stops the day: nothing else today.'
            Capture = @(@{ Recipe = 'ca-policies' })
        }
        @{
            Id = 'idp-logs'; Day = 1; Kind = 'terminal'; Local = $true
            Title = 'Identity Protection logs (local bootstrap apply)'
            Do = @(
                'lab/terraform/envs/bootstrap/terraform.tfvars: enable_identity_protection_logs = true, then:'
                'terraform -chdir=lab/terraform/envs/bootstrap apply'
            )
            Success = 'The Entra diagnostic setting lists the risk categories.'
            Rollback = 'The same variable back to false, local apply.'
        }
        @{
            Id = 'hr-provisioning-app'; Day = 1; Kind = 'console'
            Title = 'HR inbound provisioning app, with both hire-date mappings'
            Do = @(
                'Entra admin center > Enterprise applications > + New application > "API-driven provisioning to on-premises Active Directory" (lab/scripts/mock-hr/README.md, One-time setup, steps 1-4).'
                'Both hire-date mappings: the app''s hireDate > msDS-cloudExtensionAttribute1, then Cloud Sync''s msDS-cloudExtensionAttribute1 > employeeHireDate.'
                'Put the app''s service principal object id and job id in the settings file (ProvisioningServicePrincipalId, ProvisioningJobId).'
            )
            Success = 'The app exists with both mappings saved.'
        }
        @{
            Id = 'hr-active'; Day = 1; Kind = 'script'
            Title = 'HR feed, active rows: the people who exist before the window'
            Script = 'scripts/mock-hr/Invoke-InboundProvisioning.ps1'
            Args = @{ ServicePrincipalId = '{ProvisioningServicePrincipalId}'; JobId = '{ProvisioningJobId}'; UpnDomain = '{Domain}'; StatusFilter = 'active' }
            Runs = @(@{ Mode = 'dry'; Add = @{ WhatIf = $true } }, @{ Mode = 'real' })
            Before = @('Connect-MgGraph -Scopes SynchronizationData-User.Upload (browser sign-in as a User Administrator; never device code).')
            Success = 'Provisioning log: Create success per row.'
            Rollback = 'None needed (the standing workforce); a re-push is idempotent.'
        }
        @{
            Id = 'provision-on-demand'; Day = 1; Kind = 'console'
            Title = 'Cloud Sync: provision on demand; licence Grace'
            Do = @(
                'Entra admin center > Entra Connect > Cloud sync > the configuration > Provision on demand: Ava Lin, Raj Patel and Mei Tanaka (or wait one cycle).'
                'M365 admin center: licence Grace Mwangi (Day 3''s joiner workflow emails her the new hire''s TAP).'
            )
            Success = 'Joan Ferris''s team in OU=Information Technology; each person in Entra with On-premises sync enabled = Yes and an employeeHireDate (verify the date format both mappings accept on this first push).'
        }
        @{
            Id = 'admin-accounts'; Day = 1; Kind = 'script'
            Title = 'Admin accounts from the register (lab/iga/admin-accounts.json)'
            Script = 'scripts/powershell/post-apply/Invoke-PostApply.ps1'
            Args = @{ Only = @('baseline', 'admin-accounts'); BuildAccountUpn = '{AdminUpn}' }
            Runs = @(@{ Mode = 'dry' }, @{ Mode = 'real'; Add = @{ Execute = $true } })
            Success = 'Admin-Accounts lists admin@, adm-ava.lin, adm-raj.patel and adm-mei.tanaka; each adm- account cloud-only, manager = its owner, no licence.'
        }
        @{
            Id = 'admin-passkeys'; Day = 1; Kind = 'console'
            Title = 'Passkeys for the admin accounts'
            Do = @(
                'Entra admin center > Users > adm-ava.lin > Authentication methods > + Add authentication method > Temporary Access Pass (one-time; never on screen).'
                'Private window as adm-ava.lin > mysignins.microsoft.com > Security info > add both everyday keys. The same for adm-raj.patel (one key is enough).'
            )
            Success = 'adm-ava.lin holds two passkeys; 01-Verify-Baseline.ps1 still 0 FAIL.'
            Rollback = 'Remove the accounts from Admin-Accounts, then delete them (none holds a role or eligibility yet).'
        }
        @{
            Id = 'itdr-telemetry'; Day = 1; Kind = 'pr'; Evidence = @('E15a')
            Title = 'ITDR telemetry, no trial'
            Flags = @('enable_itdr_detections')
            Do = @('In the same change: repository variable TF_IAC_PRINCIPAL_IDS = the bootstrap output iac_principal_ids.')
            Success = 'Plan and apply green.'
            Rollback = 'The flag back to false.'
            Capture = @(@{ Recipe = 'pipeline' })
        }
        @{
            Id = 'vault-feed'; Day = 1; Kind = 'terminal'; Evidence = @('E15a'); Part = 'feed'
            Title = 'The Vault audit feed into Log Analytics'
            Do = @(
                'Grant yourself Monitoring Metrics Publisher on the DCR (the command is in the lab/scripts/monitoring/ingest-vault-audit.sh header).'
                'In its own terminal tab: lab/scripts/monitoring/ingest-vault-audit.sh --follow 60 (endpoint and DCR id from terraform output vault_ingestion).'
            )
            Success = 'VaultCheckout_CL | take 5 returns heartbeat rows.'
            Rollback = 'Stop the script.'
            Capture = @(@{ Recipe = 'la'; Name = 'vault-heartbeat'; LookbackHours = 2; Query = 'VaultCheckout_CL | take 5' })
        }

        # ------------------------------------------------------------- Day 2
        @{
            Id = 'sentinel-onboard'; Day = 2; Kind = 'console'
            Title = 'Onboard Microsoft Sentinel (after a few hours of sign-in logs)'
            Do = @(
                'Defender portal (security.microsoft.com) > Settings > Microsoft Sentinel > onboard {WorkspaceName} (verify the current flow).'
                'Start the Teams trial if E5 said "(no Teams)"; put the Teams webhook into Key Vault {KeyVaultName} (lab/scripts/monitoring/README.md).'
            )
            Success = 'The workspace shows in the Defender portal.'
        }
        @{
            Id = 'notify-playbook'; Day = 2; Kind = 'script'
            Title = 'The notify playbook (Teams card + ServiceNow incident)'
            Script = 'scripts/monitoring/Deploy-Playbook.ps1'
            Args = @{ KeyVaultName = '{KeyVaultName}'; ServiceNowInstance = '{ServiceNowInstance}'; ServiceNowUser = '{ServiceNowUser}'; ResourceGroup = '{ResourceGroup}'; WorkspaceName = '{WorkspaceName}' }
            Runs = @(@{ Mode = 'dry'; Add = @{ WhatIf = $true } }, @{ Mode = 'real' })
            Success = 'The playbook deploys; its resource id goes into the TF_SENTINEL_PLAYBOOK_ID repository variable.'
        }
        @{
            Id = 'sentinel'; Day = 2; Kind = 'pr'; Evidence = @('E15')
            Title = 'PR #2: Sentinel (its 31-day clock starts)'
            Flags = @('enable_sentinel')
            Do = @('Leave itdr_exclude_rules as it is in lab.tfvars: it holds back the eight rules whose tables are still empty. Never a second itdr_exclude_rules line.')
            Success = 'The core rules and the ITDR rules with data listed Enabled; the trial start date noted.'
            Rollback = 'enable_sentinel = false stops the rules, not the 31-day clock.'
            Capture = @(@{ Recipe = 'pipeline' }, @{ Recipe = 'sentinel-rules' })
        }
        @{
            Id = 'assessment-checkpoint'; Day = 2; Kind = 'terminal'; Optional = $true; Evidence = @('E14')
            Title = 'Optional: checkpoint assessment (Windows x64 host)'
            Do = @('./Invoke-BaselineAssessment.ps1 -Phase checkpoint -StorageAccountName {EvidenceStorageAccount}')
            Success = 'Report-only policies do not move ScubaGear''s CA results: an honest midpoint.'
            Capture = @(@{ Recipe = 'files'; Name = 'assessment-checkpoint'; Path = 'evidence/assessments/*checkpoint*/*'; LookbackHours = 48 })
        }
        @{
            Id = 'pim-tiers'; Day = 2; Kind = 'pr'; Evidence = @('E16'); Part = 'pr'
            Title = 'PR #3: PIM tiers, the Global Administrator policy, the help-desk AU'
            Flags = @('enable_pim_tiers', 'enable_global_admin_pim_policy', 'enable_helpdesk_au_scoping')
            Do = @('First: TF_PIM_TIER0_APPROVER_OBJECT_IDS = approver-01 + approver-02 (two or more people, never anyone made eligible: not admin@, not an adm- account), and the same two in TF_PIM_APPROVER_OBJECT_IDS.')
            Success = 'The plan shows the tier groups and their policies; apply green.'
            Capture = @(@{ Recipe = 'pipeline' })
        }
        @{
            Id = 'pim-eligibility'; Day = 2; Kind = 'script'; Evidence = @('E16')
            Title = 'Eligibility from the register, nothing more'
            Script = 'scripts/powershell/post-apply/Invoke-PostApply.ps1'
            Args = @{ Only = @('baseline', 'pim-eligibility'); PimEligibility = @{ 'pim-tier0-ca-admins' = @('{EligibleAdminUpn}'); 'pim-tier0-security-admins' = @('{EligibleAdminUpn}'); 'pim-tier1-helpdesk' = @('{Tier1AdminUpn}') } }
            Runs = @(@{ Mode = 'dry' }, @{ Mode = 'real'; Add = @{ Execute = $true } })
            Success = 'Each eligibility has an end date (Tier 0 180 days, Tier 1 365); no warning that an approver was made eligible.'
            Rollback = 'Entra admin center > ID Governance > PIM > Groups > the group > Assignments > remove.'
            Capture = @(@{ Recipe = 'pim-group-eligibility' })
        }
        @{
            Id = 'pim-settings'; Day = 2; Kind = 'console'; Evidence = @('E16a')
            Title = 'Read the PIM settings back'
            Do = @('Entra admin center > ID Governance > Privileged Identity Management > Groups > one PIM-Tier0-* and one PIM-Tier1-* group > Settings.')
            Success = 'Approver = the Tier-0 approver group; eligibility expiry required; an active assignment must end (15 days at most); MFA (not yet c1); the alert mailbox among the recipients, and the first notification email arrives there.'
            Note = 'If TF_PIM_ALERT_MAILBOX was empty the plan warned: record "tenant-default notifications".'
            Capture = @(@{ Recipe = 'pim-group-policies' })
        }
        @{
            Id = 'ga-policy'; Day = 2; Kind = 'script'; Evidence = @('E16b'); Part = 'policy'
            Title = 'Global Administrator: its PIM policy and the named eligible admin'
            Script = 'scripts/powershell/post-apply/Invoke-PostApply.ps1'
            Args = @{ Only = @('baseline', 'directory-role-pim'); GlobalAdminEligible = @('{EligibleAdminUpn}') }
            Runs = @(@{ Mode = 'dry' }, @{ Mode = 'real'; Add = @{ Execute = $true } })
            Success = 'The role policy applied; the named admin eligible for 180 days (direct eligibility, never a group).'
            CaptureBefore = @(@{ Recipe = 'directory-role-pim'; Part = 'before' })
            Capture = @(@{ Recipe = 'directory-role-pim' })
        }
        @{
            Id = 'bg-preflight'; Day = 2; Kind = 'script'; Evidence = @('E16b'); Part = 'bg-preflight'
            Title = 'Break-glass preflight before touching the build account'
            Script = 'scripts/powershell/Invoke-BreakGlassDrill.ps1'
            Args = @{ Phase = 'Preflight'; OnMicrosoftDomain = '{OnMicrosoftDomain}'; ExpectedKeysPerAccount = '{BreakGlassKeysPerAccount}'; ResourceGroup = '{ResourceGroup}'; WorkspaceName = '{WorkspaceName}' }
            Success = 'Every preflight check PASS.'
        }
        @{
            Id = 'build-account'; Day = 2; Kind = 'script'; Evidence = @('E16b')
            Title = 'The build account goes eligible: the last standing human Global Administrator'
            Script = 'scripts/powershell/post-apply/Convert-BuildAccountToEligible.ps1'
            Args = @{ BuildAccountUpn = '{AdminUpn}'; OnMicrosoftDomain = '{OnMicrosoftDomain}'; ResourceGroup = '{ResourceGroup}'; WorkspaceName = '{WorkspaceName}' }
            Runs = @(@{ Mode = 'dry'; Add = @{ WhatIf = $true } }, @{ Mode = 'real'; Add = @{ ChangeTicket = '{ChangeTicket}' } })
            Before = @(
                'Run as admin@ or a second admin with Privileged Role Administrator active, NEVER as break-glass; az login (browser) holding Reader on {ResourceGroup}.'
                'Read all eight checks of the dry run; go on only if every one passes. The real run asks you to type the UPN.'
            )
            Success = 'admin@ eligible for Global Administrator with an end date, no standing GA; Break-Glass-Admins still permanent; a run record in lab/evidence/pim/.'
            Rollback = 'As a second admin: Entra admin center > Roles and administrators > Global Administrator > Add assignments > admin@ > Active, with an end date.'
            Capture = @(@{ Recipe = 'directory-role-pim' })
        }
        @{
            Id = 'evidence-pack-quick'; Day = 2; Kind = 'script'; Evidence = @('E16b'); Part = 'pack'
            Title = 'A quick evidence pack: no standing Global Administrator but break-glass'
            Script = 'scripts/powershell/Export-EvidencePack.ps1'
            Success = 'privileged_role_assignments.json shows no standing Global Administrator except Break-Glass-Admins (flagged).'
            Capture = @(@{ Recipe = 'files'; Name = 'evidence-pack'; Path = 'evidence/out/privileged_role_assignments.json' })
        }
        @{
            Id = 'helpdesk-au'; Day = 2; Kind = 'console'; Evidence = @('E16c')
            Title = 'The help-desk administrative unit''s membership rule'
            Do = @(
                'terraform -chdir=lab/terraform/envs/dev output -json pim_workforce_au_membership_body'
                'Graph Explorer (the browser UI for Graph) > PATCH /directory/administrativeUnits/<pim_workforce_au_object_id> with that body.'
            )
            Success = 'Entra admin center > Administrative units > AU-Workforce-Standard: a dynamic rule, HR-provisioned members only; PIM-Tier1-Helpdesk''s two roles scoped to the AU, not /.'
            Rollback = 'Clear the rule; enable_helpdesk_au_scoping = false.'
            Capture = @(@{ Recipe = 'admin-units' })
        }
        @{
            Id = 'vip-au'; Day = 2; Kind = 'script'; Optional = $true; Evidence = @('E16c'); Part = 'vip'
            Title = 'Optional: the VIP restricted-management AU'
            Script = 'scripts/powershell/post-apply/New-RestrictedAdminUnit.ps1'
            Args = @{ MemberUserPrincipalNames = '{VipUserPrincipalNames}' }
            Runs = @(@{ Mode = 'dry'; Add = @{ WhatIf = $true } }, @{ Mode = 'real' })
            Note = 'Read its help first: members drop out of PIM, access reviews and Lifecycle Workflows.'
            Capture = @(@{ Recipe = 'admin-units' })
        }
        @{
            Id = 'first-activation'; Day = 2; Kind = 'console'; Evidence = @('E17', 'E17b', 'E18')
            Title = 'First PIM activation: Tier 0 with approval, Tier 1 without'
            Do = @(
                'Private window as {EligibleAdminUpn} > Entra admin center > ID Governance > PIM > My roles > Groups > Eligible > PIM-Tier0-CA-Admins > Activate (justification + ticket number).'
                'approver-01 approves (PIM > Approve requests). Side by side, {Tier1AdminUpn} activates PIM-Tier1-Helpdesk.'
                'Then sign in to the Entra admin center as {EligibleAdminUpn} (E17b). Wait for the incident (E18).'
            )
            Success = 'Tier 1 immediate (8 h); Tier 0 waits for approval (4 h cap); the requester cannot approve their own request; CA020''s report-only result on the sign-in; the pim-activation.kql incident with its Teams card and ServiceNow INC.'
            Note = 'Copy the real ActivityDisplayName strings from the audit export: pim-activation.kql may need them.'
            Rollback = 'PIM > My roles > Active > Deactivate.'
            Capture = @(
                @{ Recipe = 'directory-audits'; Service = 'PIM'; Evidence = 'E17' }
                @{ Recipe = 'pim-group-activations'; Evidence = 'E17' }
                @{ Recipe = 'la'; Evidence = 'E17'; Name = 'pim-auditlogs'; Query = 'AuditLogs | where LoggedByService == "PIM" | project TimeGenerated, OperationName, ActivityDisplayName, Result, InitiatedBy, TargetResources' }
                @{ Recipe = 'sign-ins'; User = '{EligibleAdminUpn}'; Evidence = 'E17b' }
                @{ Recipe = 'incidents'; Evidence = 'E18' }
            )
        }
        @{
            Id = 'pim-step-up-pr'; Day = 2; Kind = 'pr'; Evidence = @('E17c'); Part = 'pr'
            Title = 'The PIM step-up context, report-only'
            Flags = @('enable_pim_auth_context')
            Success = 'Plan and apply green; CA021 stays report-only.'
            Capture = @(@{ Recipe = 'pipeline' })
        }
        @{
            Id = 'pim-step-up'; Day = 2; Kind = 'script'; Evidence = @('E17c')
            Title = 'Authentication context c1 and CA021, report-only'
            Script = 'scripts/powershell/post-apply/Invoke-PostApply.ps1'
            Args = @{ Only = @('baseline', 'auth-context') }
            Runs = @(@{ Mode = 'dry' }, @{ Mode = 'real'; Add = @{ Execute = $true } })
            Success = 'Context c1 published; CA021 report-only, break-glass excluded. PIM still asks for MFA, not c1.'
            Rollback = 'Flag off; delete CA021 and c1 in the portal.'
            Capture = @(@{ Recipe = 'auth-contexts' }, @{ Recipe = 'ca-policies' })
        }

        # ------------------------------------------------------------- Day 3
        @{
            Id = 'governance'; Day = 3; Kind = 'pr'; Evidence = @('E19'); Part = 'pr'
            Title = 'PR #4: Governance'
            Flags = @('enable_governance', 'enable_nhi_governance')
            Success = 'Plan and apply green: the catalog, packages and App-Consent-Reviewers exist.'
            Rollback = 'Flags off (packages and policies go).'
            Capture = @(@{ Recipe = 'pipeline' })
        }
        @{
            Id = 'governance-post-apply'; Day = 3; Kind = 'script'; Evidence = @('E19')
            Title = 'Birthright policies, SoD links, Lifecycle Workflows'
            Script = 'scripts/powershell/post-apply/Invoke-PostApply.ps1'
            Args = @{ Only = @('baseline', 'auto-assignment', 'sod', 'lifecycle-workflows') }
            Runs = @(@{ Mode = 'dry' }, @{ Mode = 'real'; Add = @{ Execute = $true } })
            Before = @('Needs Identity Governance Administrator.')
            Success = 'Nurse and ICU with only an automatic policy (department + job title + hire date); ICU - Float Access and Pharmacy requestable; incompatibility links only on the requestable packages; the joiner and leaver workflows listed.'
            Rollback = 'Flags off: the packages, their policies and their links go.'
            Capture = @(@{ Recipe = 'access-packages' }, @{ Recipe = 'lifecycle-workflows' })
        }
        @{
            Id = 'joiner-feed'; Day = 3; Kind = 'script'; Evidence = @('E20'); Part = 'hr'
            Title = 'Joiner: the HR feed pushes the new hire'
            Script = 'scripts/mock-hr/Invoke-InboundProvisioning.ps1'
            Args = @{ ServicePrincipalId = '{ProvisioningServicePrincipalId}'; JobId = '{ProvisioningJobId}'; UpnDomain = '{Domain}'; StatusFilter = 'joiner' }
            Runs = @(@{ Mode = 'dry'; Add = @{ WhatIf = $true } }, @{ Mode = 'real' })
            Before = @('Connect-MgGraph -Scopes SynchronizationData-User.Upload (browser).')
            Success = 'Provisioning log Create success; Dana in OU=Nursing, synced to Entra with an employeeHireDate, in All-Nurses.'
            Capture = @(@{ Recipe = 'provisioning-logs' })
        }
        @{
            Id = 'joiner'; Day = 3; Kind = 'script'; Evidence = @('E20')
            Title = 'Joiner: the licence, then the automatic package'
            Script = 'scripts/powershell/02-Joiner.ps1'
            Args = @{ UserPrincipalName = '{JoinerUpn}'; LicenseSkuPartNumber = '{E5SkuPartNumber}' }
            Runs = @(@{ Mode = 'dry'; Add = @{ WhatIf = $true } }, @{ Mode = 'real' })
            Success = 'Nurse - Clinical Apps assigned by the automatic policy (no request, no approval); the TAP event, never its value; Dana registers a passkey with it: CA009 report-only Success.'
            Note = 'If the package does not arrive, the Day 1 hire-date mappings are the first suspect: never hand-assign it. The script exits 1 and names the attribute after 15 minutes.'
            Rollback = 'lab/scripts/demo/Reset-DemoState.ps1 -Segment Joiner (with the provisioning ids and the UPN domain).'
            Capture = @(@{ Recipe = 'access-package-assignments' }, @{ Recipe = 'directory-audits' }, @{ Recipe = 'sign-ins'; User = '{JoinerUpn}' })
        }
        @{
            Id = 'ca009-weak-method'; Day = 3; Kind = 'console'; Evidence = @('E20b')
            Title = 'CA009 against a weak method'
            Do = @('{TestSmsUpn} (password + SMS only) tries to add a method at mysignins.microsoft.com.')
            Success = 'CA009 report-only "would fail", exactly as shown.'
            Capture = @(@{ Recipe = 'sign-ins'; User = '{TestSmsUpn}' }, @{ Recipe = 'incidents' })
        }
        @{
            Id = 'auth-methods-consent'; Day = 3; Kind = 'script'; Evidence = @('E21')
            Title = 'Authentication methods and consent'
            Script = 'scripts/powershell/post-apply/Invoke-PostApply.ps1'
            Args = @{ Only = @('baseline', 'admin-accounts', 'auth-methods', 'consent'); BuildAccountUpn = '{AdminUpn}' }
            Runs = @(@{ Mode = 'dry' }, @{ Mode = 'real'; Add = @{ Execute = $true } })
            Note = 'admin-accounts runs again on purpose: the admin passkey profile targets Admin-Accounts. The dry run''s PLAN output is the before-state; the transcript keeps it.'
            Success = 'Passkey profiles (admins device-bound + attested; staff synced allowed), TAP, the campaign; user consent restricted, the admin-consent workflow to App-Consent-Reviewers.'
            Rollback = 'Set-AuthenticationMethodsPolicy.ps1 writes a pre-change backup: re-apply it in the portal. Consent: Enterprise applications > Consent and permissions.'
            CaptureBefore = @(@{ Recipe = 'auth-methods-policy'; Part = 'before' }, @{ Recipe = 'consent-policies'; Part = 'before' })
            Capture = @(@{ Recipe = 'auth-methods-policy' }, @{ Recipe = 'consent-policies' })
        }

        # ------------------------------------------------------- Days 3 to 5
        @{
            Id = 'dc01-security-events'; Days = @(3, 4, 5); Kind = 'pr'; Evidence = @('E15b')
            Title = 'AMA connector, then release the four DC01 rules'
            Do = @(
                'Defender portal > Microsoft Sentinel > Content hub / Data connectors > "Windows Security Events via AMA".'
                'When SecurityEvent | where Computer startswith "DC01" returns rows: a PR deleting tier0_logon_without_checkout, ad_privileged_group_change, kerberoast_rc4_service_ticket and dcsync_replication_request from itdr_exclude_rules in lab.tfvars.'
                'Keep identity_risk (Days 5-6) and the three second-wave keys. [s]kip until the rows exist: the step comes back each day of the window.'
            )
            Success = 'The four rules listed Enabled.'
            Capture = @(
                @{ Recipe = 'la'; Name = 'dc01-security-events'; LookbackHours = 24; Query = 'SecurityEvent | where Computer startswith "DC01" | summarize Events = count() by EventID | order by Events desc' }
                @{ Recipe = 'pipeline' }
                @{ Recipe = 'sentinel-rules' }
            )
        }
        @{
            Id = 'itdr-second-wave'; Days = @(3, 4, 5); Kind = 'pr'; Evidence = @('E15c')
            Title = 'The second-wave ITDR rules'
            Flags = @('enable_itdr_detections_v2')
            Do = @('Leave dc_logon_outside_operator_allowlist, vault_privileged_access_anomaly and pim_activation_without_auth_context in itdr_exclude_rules.')
            Success = 'The other three listed Enabled; the operator_ips watchlist exists with its expiry (operator_ips_expires_on).'
            Rollback = 'Flag off.'
            Capture = @(@{ Recipe = 'pipeline' }, @{ Recipe = 'sentinel-rules' })
        }

        # ------------------------------------------------------------- Day 4
        @{
            Id = 'app-management-roles'; Day = 4; Kind = 'terminal'; Local = $true
            Title = 'App-management roles for the pipeline (local bootstrap apply)'
            Do = @(
                'lab/terraform/envs/bootstrap/terraform.tfvars: enable_app_management_roles = true, then terraform -chdir=lab/terraform/envs/bootstrap apply'
                'Entra admin center > App registrations > the APPLY app > API permissions > Grant admin consent for the new roles.'
            )
            Success = 'Every new permission row says Granted.'
        }
        @{
            Id = 'sso-apps'; Day = 4; Kind = 'pr'; Evidence = @('E22'); Part = 'pr'
            Title = 'SSO apps'
            Flags = @('enable_sso_apps')
            Do = @('Secrets TF_APP_OWNER_OBJECT_IDS and TF_SAML_CERT_NOTIFICATION_EMAILS first. After the apply, run the aws_saml_signing_cert_activation_command output.')
            Success = 'Plan and apply green; the AWS signing certificate active.'
            Capture = @(@{ Recipe = 'pipeline' })
        }
        @{
            Id = 'aws-identity-source'; Day = 4; Kind = 'console'
            Title = 'AWS IAM Identity Center trusts Entra'
            Do = @('AWS console > IAM Identity Center > Settings > Identity source > External identity provider: copy the values, set the three TF_AWS_* repository variables, PR, upload the Entra metadata, ACCEPT.')
            Success = 'Identity source = External identity provider.'
        }
        @{
            Id = 'scim'; Day = 4; Kind = 'pr'; Evidence = @('E23')
            Title = 'SCIM provisioning to AWS'
            Flags = @('enable_scim_provisioning', 'aws_scim_job_enabled')
            Do = @(
                'SCIM endpoint and token straight into Key Vault {KeyVaultName}; TF_AWS_SCIM_TEMPLATE_ID.'
                'The local seeding apply with enable_scim_provisioning = true, then merge the same flag at once.'
                'Entra admin center > Enterprise applications > the AWS app > Provisioning > Provision on demand > Dana; then a PR with aws_scim_job_enabled = true.'
            )
            Success = 'Identity Center shows Dana Created by SCIM and the App-AWS-IdentityCenter-Users group.'
            Capture = @(@{ Recipe = 'provisioning-logs' }, @{ Recipe = 'pipeline' })
        }
        @{
            Id = 'aws-permission-set'; Day = 4; Kind = 'terminal'; Local = $true; Evidence = @('E24', 'E22')
            Title = 'The AWS permission set (local apply, your AWS SSO session)'
            Do = @(
                'Once Identity Center > Groups shows App-AWS-IdentityCenter-Users:'
                'aws sso login --profile idlab-admin; copy lab/terraform/aws/terraform.tfvars.example to terraform.tfvars (region, account id)'
                'terraform -chdir=lab/terraform/aws init; terraform -chdir=lab/terraform/aws plan -out aws.tfplan; terraform -chdir=lab/terraform/aws apply aws.tfplan'
                'Never also click the permission set in the console. Then, as Dana: My Apps > AWS tile (E22).'
            )
            Success = 'The test user reaches the AWS console as ViewOnly through SSO; a second plan says No changes.'
            Note = 'E24 is the apply output in your terminal: no API reads it, so save and hash it yourself and add its capture-log row (the close-out check lists E24 until then).'
            Rollback = 'terraform -chdir=lab/terraform/aws destroy'
            Capture = @(@{ Recipe = 'sign-ins'; User = '{JoinerUpn}'; Evidence = 'E22' })
        }
        @{
            Id = 'oidc-preauth-on'; Day = 4; Kind = 'pr'; Evidence = @('E25'); Part = 'pr'
            Title = 'Clinical Portal: let the Azure CLI request a token (for E25 only)'
            Flags = @('clinical_portal_preauthorize_azure_cli')
            Capture = @(@{ Recipe = 'pipeline' })
        }
        @{
            Id = 'oidc-token'; Day = 4; Kind = 'console'; Evidence = @('E25')
            Title = 'The Clinical Portal token carries the app role'
            Do = @('As Dana: az login --tenant {OnMicrosoftDomain} --allow-no-subscriptions (browser), then decode the token (lab/terraform/modules/apps/README.md, Demo).')
            Success = 'The token shows roles: ["Clinician"].'
            Capture = @(@{ Recipe = 'sign-ins'; User = '{JoinerUpn}' })
        }
        @{
            Id = 'oidc-preauth-off'; Day = 4; Kind = 'pr'
            Title = 'Clinical Portal pre-authorisation off again'
            FlagsOff = @('clinical_portal_preauthorize_azure_cli')
        }
        @{
            Id = 'app-governance'; Day = 4; Kind = 'script'; Evidence = @('E21'); Part = 'app-governance'
            Title = 'The app management policy (after the AWS signing certificate is active)'
            Script = 'scripts/powershell/post-apply/Invoke-PostApply.ps1'
            Args = @{ Only = @('baseline', 'app-governance') }
            Runs = @(@{ Mode = 'dry' }, @{ Mode = 'real'; Add = @{ Execute = $true } })
            Success = 'No secrets on new apps, a 180-day certificate cap, 90 days for new secrets on existing apps; a pre-change backup written.'
            CaptureBefore = @(@{ Recipe = 'app-management-policy'; Part = 'app-governance-before' })
            Capture = @(@{ Recipe = 'app-management-policy' })
        }

        # ------------------------------------------------------------- Day 5
        @{
            Id = 'risk-tor'; Day = 5; Kind = 'console'; Evidence = @('E26')
            Title = 'Risk simulation, report-only: a Tor sign-in by a test account'
            Do = @('{TestAccountA} (no MFA registered) signs in to myapps.microsoft.com through Tor Browser. Wait 10-15 minutes.')
            Success = 'The detection "Anonymous IP address" at the level it got; CA007''s report-only result exactly as shown (CA007 acts only on High: Medium = "not applied").'
            Note = 'Test accounts only. Report-only is reported as report-only; thresholds are never lowered for a screenshot.'
            Capture = @(@{ Recipe = 'risk-detections' }, @{ Recipe = 'sign-ins'; User = '{TestAccountA}' })
        }
        @{
            Id = 'identity-risk-rule'; Day = 5; Kind = 'pr'
            Title = 'Release identity_risk once the risk tables have rows'
            Do = @('A PR deleting identity_risk from itdr_exclude_rules in lab.tfvars (the rule cannot fire while held back; verify: Sentinel accepts it once those rows exist).')
        }
        @{
            Id = 'confirm-compromised'; Day = 5; Kind = 'console'; Evidence = @('E27')
            Title = 'confirmCompromised on a test account'
            Do = @('Graph Explorer: POST /identityProtection/riskyUsers/confirmCompromised for {TestAccountB} only; then {TestAccountB} signs in.')
            Success = 'riskyUsers shows the account High / confirmed compromised; CA006''s report-only result on its sign-in; the identity-risk.kql incident.'
            Rollback = 'ID Protection > Risky users > Dismiss (after E38).'
            Capture = @(@{ Recipe = 'risky-users' }, @{ Recipe = 'sign-ins'; User = '{TestAccountB}' }, @{ Recipe = 'incidents' })
        }
        @{
            Id = 'intune-prereqs'; Day = 5; Kind = 'terminal'; Local = $true
            Title = 'Intune prerequisites (lab/scripts/intune/README.md)'
            Do = @(
                'MDM user scope; an E5 licence on the pilot user {PilotUpn}; the local envs/bootstrap re-apply the README names.'
                'Never admin@ in the pilot group, and never a clinical manager (SOD-08).'
            )
            Note = 'adm- accounts carry no licence by design: licensing adm-ava.lin as the pilot is a recorded lab exception.'
        }
        @{
            Id = 'intune-baseline'; Day = 5; Kind = 'script'
            Title = 'The Intune compliance baseline'
            Script = 'scripts/intune/New-IntuneComplianceBaseline.ps1'
            Args = @{ PilotMemberUserPrincipalNames = @('{PilotUpn}') }
            Runs = @(@{ Mode = 'dry'; Add = @{ WhatIf = $true } }, @{ Mode = 'real' })
            Success = 'The compliance policy assigned to the pilot group.'
        }
        @{
            Id = 'intune-vm'; Day = 5; Kind = 'pr'
            Title = 'The Windows 11 Intune VM'
            Flags = @('enable_intune_vm')
            Success = 'Intune > Devices > CH-WIN11-01 Compliant.'
            Rollback = 'Flag off, then delete CH-WIN11-01 from Intune and Entra.'
        }

        # ------------------------------------------------------------- Day 6
        @{
            Id = 'ca-insights'; Day = 6; Kind = 'console'; Evidence = @('E28')
            Title = 'CA insights: the go / no-go for every graduation'
            Do = @('Entra admin center > Conditional Access > Insights and reporting, workspace {WorkspaceName}, last 5 days: screenshot and export.')
            Success = 'Counts per policy: Success, Failure, User action required, Not applied.'
            Capture = @(@{ Recipe = 'la'; Name = 'ca-results-5d'; LookbackHours = 120; Query = 'SigninLogs | mv-expand CA = ConditionalAccessPolicies | extend Policy = tostring(CA.displayName), Result = tostring(CA.result) | where Policy startswith "CA" | summarize SignIns = count() by Policy, Result | order by Policy asc, Result asc' })
        }
        @{
            Id = 'device-code'; Day = 6; Kind = 'console'; Evidence = @('E28b')
            Title = 'Device code, on purpose, from a test account'
            Do = @('On a lab test box (never your operator session): {TestAccountD} runs az login --use-device-code.')
            Success = 'CA010''s report-only result; the device-code-signin.kql incident.'
            Capture = @(@{ Recipe = 'sign-ins'; User = '{TestAccountD}' }, @{ Recipe = 'incidents' })
        }
        @{
            Id = 'passwordless-readiness'; Day = 6; Kind = 'script'; Evidence = @('E29')
            Title = 'Passwordless pilot readiness'
            Script = 'scripts/powershell/07-Passwordless-Rollout.ps1'
            Args = @{ Stage = 'Pilot' }
            Success = 'Registration status per group and the go / no-go verdict for CA008.'
        }
        @{
            Id = 'passwordless-promote'; Day = 6; Kind = 'script'; Evidence = @('E29'); Part = 'promote'
            Title = 'Promote the ready users into the CA008 pilot'
            Script = 'scripts/powershell/07-Passwordless-Rollout.ps1'
            Args = @{ Stage = 'Pilot'; PromoteReadyToPilot = $true }
            Runs = @(@{ Mode = 'dry'; Add = @{ WhatIf = $true } }, @{ Mode = 'real' })
            Success = 'Only ready users added to the CA008 pilot group.'
        }
        @{
            Id = 'fourteen-day-exception'; Day = 6; Kind = 'console'
            Title = 'File the 14-day-rule exception before the first graduation'
            Do = @('lab/docs/standards/exception-process.md, with the E28 counts attached: this window graduates after 5-11 days of report-only data, not 14.')
            Success = 'The exception filed, with its expiry.'
        }

        # ------------------------------------------------------- Days 7 to 12
        @{
            Id = 'graduate-ca003'; Day = 7; Kind = 'pr'; Evidence = @('E30')
            Title = 'Graduate CA003 (block legacy authentication)'
            Enforce = @('CA003')
            Do = @('lab/docs/runbooks/graduate-a-ca-policy.md, its section 7 (Review checklist, every CA PR) filled in on the PR; the plan shows ONE state change; the PR states its real number of report-only days.')
            Rollback = 'A PR setting it back to enabledForReportingButNotEnforced.'
            Capture = @(@{ Recipe = 'pipeline' }, @{ Recipe = 'ca-policies' })
        }
        @{
            Id = 'legacy-auth'; Day = 7; Kind = 'console'; Evidence = @('E31')
            Title = 'A test account tries a legacy protocol'
            Do = @('From a lab test box, a test account attempts a legacy protocol (verify which legacy client still produces a sign-in event, for example SMTP AUTH).')
            Success = 'Blocked by CA003, or zero rows recorded as zero: never fake an event.'
            Capture = @(@{ Recipe = 'sign-ins' }, @{ Recipe = 'incidents' })
        }
        @{
            Id = 'reviews-privileged'; Day = 8; Kind = 'pr'; Evidence = @('E32'); Part = 'pr-privileged'
            Title = 'Access reviews: privileged'
            Flags = @('enable_access_reviews_privileged')
            Do = @('Set TF_ACCESS_REVIEW_FALLBACK_GROUP_OBJECT_ID and TF_PRIVILEGED_REVIEW_REVIEWER_GROUP_OBJECT_ID first.')
            Capture = @(@{ Recipe = 'pipeline' })
        }
        @{
            Id = 'reviews-inactive'; Day = 8; Kind = 'pr'; Evidence = @('E32'); Part = 'pr-inactive'
            Title = 'Access reviews: inactive users'
            Flags = @('enable_access_reviews_inactive')
            Capture = @(@{ Recipe = 'pipeline' })
        }
        @{
            Id = 'reviews-post-apply'; Day = 8; Kind = 'script'; Evidence = @('E32')
            Title = 'The review definitions Terraform renders'
            Script = 'scripts/powershell/post-apply/Invoke-PostApply.ps1'
            Args = @{ Only = @('baseline', 'access-reviews') }
            Runs = @(@{ Mode = 'dry' }, @{ Mode = 'real'; Add = @{ Execute = $true } })
            Success = 'Deny-by-default, auto-apply reviews for every PIM group and the eligible Global Administrators.'
            Capture = @(@{ Recipe = 'access-reviews' })
        }
        @{
            Id = 'review-portal-diff'; Day = 8; Kind = 'console'; Evidence = @('E32'); Part = 'portal-diff'
            Title = 'One privileged review created in the portal, to diff against the rendered body'
            Do = @('Entra admin center > ID Governance > Access reviews > + New access review: one privileged review, as the rendered body describes.')
            Success = 'The export holds both definitions side by side (verify: whether an API-created review expands eligible members).'
            Capture = @(@{ Recipe = 'access-reviews' })
        }
        @{
            Id = 'b2b'; Day = 8; Kind = 'pr'; Evidence = @('E33'); Part = 'pr'
            Title = 'B2B governance'
            Flags = @('enable_b2b_governance')
            Do = @('First: repository variable TF_B2B_CONNECTED_ORGANIZATION = the Fabrikam tenant as JSON (display_name, domain_name, tenant_id). Unset, CI keeps the fictional fabrikam-clinic.example.')
            Capture = @(@{ Recipe = 'pipeline' })
        }
        @{
            Id = 'b2b-post-apply'; Day = 8; Kind = 'script'; Evidence = @('E33')
            Title = 'The connected organization and external collaboration'
            Script = 'scripts/powershell/post-apply/Invoke-PostApply.ps1'
            Args = @{ Only = @('baseline', 'b2b', 'external-collab') }
            Runs = @(@{ Mode = 'dry' }, @{ Mode = 'real'; Add = @{ Execute = $true } })
            Success = 'It prints the connected-organization id for TF_B2B_CONNECTED_ORGANIZATION_ID.'
            Capture = @(@{ Recipe = 'external-collab' })
        }
        @{
            Id = 'b2b-org-id'; Day = 8; Kind = 'pr'
            Title = 'The connected-organization id into the pipeline'
            Do = @('Repository variable TF_B2B_CONNECTED_ORGANIZATION_ID = the printed id, then a PR.')
        }
        @{
            Id = 'guest-request'; Day = 8; Kind = 'console'; Evidence = @('E33'); Part = 'guest'
            Title = 'A guest requests Affiliated Physicians; the sponsor approves'
            Do = @('A guest from the Fabrikam tenant: myaccess.microsoft.com > Affiliated Physicians > Request. The internal sponsor approves.')
            Success = 'The assignment with its 90-day expiry; invites limited to admins and Guest Inviters; no self-service sign-up.'
            Capture = @(@{ Recipe = 'assignment-requests' }, @{ Recipe = 'access-package-assignments' })
        }
        @{
            Id = 'azure-pim'; Day = 8; Kind = 'pr'; Local = $true; Evidence = @('E34')
            Title = 'Azure resource PIM'
            Flags = @('enable_pim_azure_resources')
            Do = @(
                'A local (human) apply with enable_pim_azure_resources = true, then the same flag in a PR.'
                'Add one member to PIM-Azure-RG-Contributors; activate Contributor on {ResourceGroup}. Then convert your standing Owner to eligible.'
            )
            Note = 'From now on teardown needs an activation.'
            Capture = @(
                @{ Recipe = 'azure-pim' }
                @{ Recipe = 'la'; Name = 'azure-activity'; Query = 'AzureActivity | where OperationNameValue has "roleAssignmentScheduleRequests" or OperationNameValue has "roleEligibilityScheduleRequests" | project TimeGenerated, OperationNameValue, ActivityStatusValue, Caller, ResourceGroup' }
            )
        }
        @{
            Id = 'splunk'; Day = 8; Kind = 'terminal'
            Title = 'Splunk (its 60-day clock starts)'
            Do = @('cd lab/splunk && ./splunk-up.sh; accept the terms in lab/splunk/.env yourself; run it again.')
            Success = '"Detections: 22 loaded, 22 scheduled" (verify the count it prints).'
        }
        @{
            Id = 'graduate-ca001'; Day = 9; Kind = 'pr'; Evidence = @('E35')
            Title = 'Graduate CA001 (MFA, all users)'
            Enforce = @('CA001')
            Do = @('The graduation runbook and checklist; ONE state change; the PR states its real number of report-only days. Then one sign-in.')
            Success = 'A sign-in with CA001 enforced.'
            Rollback = 'A PR setting it back to enabledForReportingButNotEnforced.'
            Capture = @(@{ Recipe = 'pipeline' }, @{ Recipe = 'ca-policies' }, @{ Recipe = 'sign-ins' })
        }
        @{
            Id = 'graduate-ca002'; Day = 10; Kind = 'pr'; Evidence = @('E36'); Part = 'ca002'
            Title = 'Graduate CA002 (phishing-resistant MFA, admins)'
            Enforce = @('CA002')
            Do = @('First check every in-scope admin (admin@ and {EligibleAdminUpn} included) signs in with a key model in admin_fido2_allowed_aaguids. Then the graduation runbook: ONE state change.')
            Success = 'An admin sign-in satisfying CA002 with a passkey (sign-in log, Authentication details).'
            Rollback = 'A PR setting it back to enabledForReportingButNotEnforced.'
            Capture = @(@{ Recipe = 'pipeline' }, @{ Recipe = 'ca-policies' }, @{ Recipe = 'sign-ins'; User = '{EligibleAdminUpn}' })
        }
        @{
            Id = 'graduate-ca007'; Day = 10; Kind = 'pr'; Evidence = @('E36'); Part = 'ca007'
            Title = 'Graduate CA007 (sign-in risk High: block)'
            Enforce = @('CA007')
            Do = @('The graduation runbook: ONE state change, its own PR.')
            Rollback = 'A PR setting it back to enabledForReportingButNotEnforced.'
            Capture = @(@{ Recipe = 'pipeline' }, @{ Recipe = 'ca-policies' })
        }
        @{
            Id = 'graduate-ca021'; Days = @(10, 11); Kind = 'pr'; Evidence = @('E36b'); Part = 'ca021'
            Title = 'CA021 enforced (PR 1 of 4, in this order; each plans only its own change)'
            Enforce = @('CA021')
            Capture = @(@{ Recipe = 'pipeline' }, @{ Recipe = 'ca-policies' })
        }
        @{
            Id = 'ca021-readback'; Days = @(10, 11); Kind = 'script'; Evidence = @('E36b'); Part = 'readback'
            Title = 'Read CA021 back from the tenant'
            Script = 'scripts/powershell/post-apply/Invoke-PostApply.ps1'
            Args = @{ Only = @('baseline', 'auth-context') }
            Runs = @(@{ Mode = 'dry' }, @{ Mode = 'real'; Add = @{ Execute = $true } })
            Success = 'It reports CA021 enabled in the tenant and c1 available.'
            Capture = @(@{ Recipe = 'auth-contexts' }, @{ Recipe = 'ca-policies' })
        }
        @{
            Id = 'ca021-attest'; Days = @(10, 11); Kind = 'pr'; Evidence = @('E36b'); Part = 'attest'
            Title = 'Attest CA021 is enforced in the tenant (PR 2 of 4)'
            Flags = @('ca021_enforced_in_tenant')
            Do = @('Your attestation of what the read-back reported: Terraform cannot see the tenant, and the next two PRs refuse to plan without it.')
            Capture = @(@{ Recipe = 'pipeline' })
        }
        @{
            Id = 'pim-switch-step1'; Days = @(10, 11); Kind = 'pr'; Evidence = @('E36b'); Part = 'step1'
            Title = 'Tier 0 drops plain MFA (PR 3 of 4)'
            Flags = @('pim_tier0_auth_context_switchover_step1')
            Note = 'The plan warns there is no step-up until PR 4: merge PR 4 straight after, nothing in between.'
            Capture = @(@{ Recipe = 'pipeline' })
        }
        @{
            Id = 'pim-switch-c1'; Days = @(10, 11); Kind = 'pr'; Evidence = @('E36b'); Part = 'c1'
            Title = 'Tier 0 activation requires c1 (PR 4 of 4)'
            Do = @('pim_tier0_activation_auth_context_id = "c1", merged straight after PR 3.')
            Rollback = 'ONE PR setting pim_tier0_activation_auth_context_id = "", pim_tier0_auth_context_switchover_step1 = false and ca021_enforced_in_tenant = false (Tier 0 back on MFA), applied BEFORE CA021 goes back to report-only.'
            Capture = @(@{ Recipe = 'pipeline' }, @{ Recipe = 'pim-group-policies' })
        }
        @{
            Id = 'pim-c1-activation'; Days = @(10, 11); Kind = 'console'; Evidence = @('E36b')
            Title = 'Activate Tier 0 on c1, then release the preview rule'
            Do = @(
                'Activate a Tier-0 group as {EligibleAdminUpn}.'
                'Then a PR releasing pim_activation_without_auth_context from itdr_exclude_rules (fix its activity strings from E17 first), and activate once more.'
            )
            Success = 'The activation forces a fresh phishing-resistant sign-in carrying c1; the rule stays quiet (an alert means its field mapping needs fixing: record it as such).'
            Capture = @(@{ Recipe = 'sign-ins'; User = '{EligibleAdminUpn}' }, @{ Recipe = 'directory-audits'; Service = 'PIM' }, @{ Recipe = 'incidents' })
        }
        @{
            Id = 'tor-again'; Day = 11; Kind = 'console'; Evidence = @('E37')
            Title = 'Tor again, CA007 enforced'
            Do = @('{TestAccountA} signs in through Tor Browser again.')
            Success = 'The result exactly as shown: blocked if the risk is High, otherwise "not applied" with the risk level. Record either way.'
            Capture = @(@{ Recipe = 'risk-detections' }, @{ Recipe = 'sign-ins'; User = '{TestAccountA}' })
        }
        @{
            Id = 'graduate-ca006'; Day = 12; Kind = 'pr'; Evidence = @('E38'); Part = 'pr'
            Title = 'Graduate CA006 (user risk High)'
            Enforce = @('CA006')
            Rollback = 'A PR setting it back to enabledForReportingButNotEnforced.'
            Capture = @(@{ Recipe = 'pipeline' }, @{ Recipe = 'ca-policies' })
        }
        @{
            Id = 'risk-remediation'; Day = 12; Kind = 'console'; Evidence = @('E38')
            Title = 'The compromised test account remediates'
            Do = @('{TestAccountB} (still confirmed compromised) signs in.')
            Success = 'Forced MFA + secure password change; its risk state moves to remediated; note the time taken.'
            Capture = @(@{ Recipe = 'risky-users' }, @{ Recipe = 'sign-ins'; User = '{TestAccountB}' })
        }
        @{
            Id = 'graduate-ca009'; Day = 12; Kind = 'pr'; Evidence = @('E38b'); Part = 'ca009'
            Title = 'Graduate CA009 (register security info)'
            Enforce = @('CA009')
            Capture = @(@{ Recipe = 'pipeline' }, @{ Recipe = 'ca-policies' })
        }
        @{
            Id = 'graduate-ca010'; Day = 12; Kind = 'pr'; Evidence = @('E38b'); Part = 'ca010'
            Title = 'Graduate CA010 (block the device code flow)'
            Enforce = @('CA010')
            Do = @('Before this PR: confirm nothing you run uses device code.')
            Capture = @(@{ Recipe = 'pipeline' }, @{ Recipe = 'ca-policies' })
        }
        @{
            Id = 'graduate-ca020'; Day = 12; Kind = 'pr'; Evidence = @('E38b'); Part = 'ca020'
            Title = 'Graduate CA020 (admin sign-in every 4 h)'
            Enforce = @('CA020')
            Capture = @(@{ Recipe = 'pipeline' }, @{ Recipe = 'ca-policies' })
        }
        @{
            Id = 'enforced-tests'; Day = 12; Kind = 'console'; Evidence = @('E38b')
            Title = 'The three graduations, tested'
            Do = @(
                'A TAP holder registers a method; {TestSmsUpn} tries the same.'
                '{TestAccountD} tries a device-code sign-in from the test box.'
                'An admin on the admin portals 4 hours after the last sign-in.'
            )
            Success = 'The TAP holder can register, the SMS-only account cannot; the device-code sign-in is blocked (the incident shows it as a failure); the admin is asked to sign in again.'
            Capture = @(@{ Recipe = 'sign-ins' }, @{ Recipe = 'incidents' })
        }
        @{
            Id = 'pharmacy-review'; Day = 12; Kind = 'console'; Evidence = @('E39')
            Title = 'The access-review result on Pharmacy (T2)'
            Do = @(
                'Blocked until the Pharmacy package allows extension (extension_enabled, in a PR before today): no T2 review exists without it. Still blocked: answer [m]issed and keep E32 as the access-review evidence.'
                'Unblocking is that PR (verify how envs/dev passes access_packages) plus enable_access_reviews_requestable = true, the T2 review flag: add it to ExtraExpectedOnFlags in the settings file (no step of the plan flips it, so preflight would not expect it).'
                'Unblocked: approve one, deny one, leave one unanswered, then stop the instance early in the portal so the decisions apply.'
            )
            MissedReason = 'blocked: the Pharmacy package does not allow extension, so no T2 review exists'
            Success = 'Decisions with justifications; the unanswered person removed by default-deny; Nurse - Clinical Apps shows only its automatic policy and no review.'
            Capture = @(@{ Recipe = 'access-reviews' }, @{ Recipe = 'directory-audits' })
        }

        # ------------------------------------------------------------ Day 13
        @{
            Id = 'review-kpis'; Day = 13; Kind = 'script'; Evidence = @('E39b')
            Title = 'Review KPIs (ADR 0012)'
            Script = 'scripts/powershell/10-Review-KPIs.ps1'
            Success = 'A hashed snapshot under lab/evidence/kpis/; rubber-stamp rate "not measurable" where no reviewer has 10 items. Compare with the midPoint harness run (L01).'
            Capture = @(@{ Recipe = 'files'; Name = 'review-kpis'; Path = 'evidence/kpis/reviews-*.json*' })
        }
        @{
            Id = 'sod-request'; Day = 13; Kind = 'console'; Evidence = @('E39c'); Part = 'refusal'
            Title = 'SoD: a nurse requests Pharmacy (refused)'
            Do = @('A nurse test user (Nurse package less than 14 days old): myaccess.microsoft.com > Pharmacy - Controlled Substances Apps > Request.')
            Success = 'Refused by the incompatibility link.'
            Capture = @(@{ Recipe = 'assignment-requests' })
        }
        @{
            Id = 'sod-direct-add'; Day = 13; Kind = 'console'
            Title = 'SoD tripwire: an admin adds the same user directly to the group'
            Do = @('Entra admin center > Groups > App-Pharmacy-Dispensing-Users > Members > + Add members: the same test user (outside the package).')
            Success = 'The user is a direct member.'
        }
        @{
            Id = 'sod-report-open'; Day = 13; Kind = 'script'; Evidence = @('E39c')
            Title = 'The SoD report while the violation is open'
            Script = 'scripts/powershell/09-SoD-Report.ps1'
            OkExitCodeMax = 254
            Success = 'The report names SOD-01 (its exit code is the number of open violations; 255 = no valid report); the sod-violation-granted.kql incident.'
            Capture = @(@{ Recipe = 'files'; Name = 'sod-report'; Path = 'evidence/sod/*/*' }, @{ Recipe = 'incidents' })
        }
        @{
            Id = 'sod-remove'; Day = 13; Kind = 'console'
            Title = 'Remove the direct membership'
            Do = @('Entra admin center > Groups > App-Pharmacy-Dispensing-Users > Members: remove the test user.')
            Success = 'The user is no longer a member.'
        }
        @{
            Id = 'sod-report-closed'; Day = 13; Kind = 'script'; Evidence = @('E39c'); Part = 'after-removal'
            Title = 'The SoD report after the removal'
            Script = 'scripts/powershell/09-SoD-Report.ps1'
            OkExitCodeMax = 254
            Success = 'One violation fewer than the first report.'
            Capture = @(@{ Recipe = 'files'; Name = 'sod-report'; Path = 'evidence/sod/*/*' })
        }
        @{
            Id = 'containment-approvers'; Day = 13; Kind = 'console'
            Title = 'The containment approver group'
            Do = @('Entra admin center > Groups > New group: ITDR-Containment-Approvers. Never the people it could contain.')
            Success = 'The group exists with its approvers.'
        }
        @{
            Id = 'containment-playbook'; Day = 13; Kind = 'script'; Evidence = @('E40'); Part = 'deploy'
            Title = 'Deploy the containment playbook (no disable role)'
            Script = 'scripts/monitoring/Deploy-ContainmentPlaybook.ps1'
            Args = @{ KeyVaultName = '{KeyVaultName}'; TeamsGroupId = '{TeamsGroupId}'; TeamsChannelId = '{TeamsChannelId}'; ServiceNowInstance = '{ServiceNowInstance}'; ServiceNowUser = '{ServiceNowUser}'; ResourceGroup = '{ResourceGroup}'; WorkspaceName = '{WorkspaceName}' }
            Runs = @(@{ Mode = 'dry'; Add = @{ WhatIf = $true } }, @{ Mode = 'real' })
            Note = 'Never -GrantDisableRole: ADR 0017 keeps the playbook''s disable role off by default, and its scope would default to the whole tenant.'
            Success = 'The script ends with "Disable step will answer 403 until a directory role is assigned". Then authorize the Teams connection in the portal.'
        }
        @{
            Id = 'containment-flag'; Day = 13; Kind = 'pr'; Evidence = @('E40')
            Title = 'Wire the containment playbook to the incidents'
            Flags = @('enable_itdr_containment')
            Do = @('Repository variable TF_CONTAINMENT_PLAYBOOK_ID first.')
            Rollback = 'Flag off.'
            Capture = @(@{ Recipe = 'pipeline' }, @{ Recipe = 'logic-apps' })
        }

        # ------------------------------------------------------------ Day 14
        @{
            Id = 'containment-drill'; Day = 14; Kind = 'console'; Evidence = @('E41')
            Title = 'The containment drill (lab/docs/runbooks/compromised-identity.md)'
            Do = @('confirmCompromised on {TestAccountC}; a non-approver answers Contain first (it must be ignored), then an approver approves.')
            Success = 'Revoke sessions 204, confirmCompromised 204, disable 403 (the ADR 0017 default: role off), recorded on the incident; the next sign-in is challenged by CA006 (MFA + secure password change), not refused. Say exactly that.'
            Note = 'KPI: incident to contained, in minutes (by hand: incident created to the Logic App run end). Never -GrantDisableRole tenant-wide to get a 204.'
            Rollback = 'ID Protection > Risky users > the account > Dismiss user risk.'
            Capture = @(
                @{ Recipe = 'incidents' }
                @{ Recipe = 'logic-app-runs'; Workflow = 'pb-identity-contain' }
                @{ Recipe = 'directory-audits' }
                @{ Recipe = 'risky-users' }
                @{ Recipe = 'sign-ins'; User = '{TestAccountC}' }
            )
        }
        @{
            Id = 'reset-joiner'; Day = 14; Kind = 'script'
            Title = 'Reset the joiner for the take'
            Script = 'scripts/demo/Reset-DemoState.ps1'
            Args = @{ Segment = 'Joiner'; ServicePrincipalId = '{ProvisioningServicePrincipalId}'; JobId = '{ProvisioningJobId}'; UpnDomain = '{Domain}' }
            Runs = @(@{ Mode = 'dry'; Add = @{ WhatIf = $true } }, @{ Mode = 'real' })
            Success = 'Dana back to a joiner with no packages.'
        }
        @{
            Id = 'joiner-take'; Day = 14; Kind = 'script'; Evidence = @('E20'); Rerun = $true
            Title = 'The joiner, live (a re-run of E20: a new capture id)'
            Script = 'scripts/powershell/02-Joiner.ps1'
            Args = @{ UserPrincipalName = '{JoinerUpn}'; LicenseSkuPartNumber = '{E5SkuPartNumber}' }
            Runs = @(@{ Mode = 'dry'; Add = @{ WhatIf = $true } }, @{ Mode = 'real' })
            Success = 'The package by its automatic policy; never hand-assigned (no package shot without it).'
            Capture = @(@{ Recipe = 'access-package-assignments' }, @{ Recipe = 'sign-ins'; User = '{JoinerUpn}' })
        }
        @{
            Id = 'mover-feed'; Day = 14; Kind = 'script'; Evidence = @('E52'); Part = 'mover-hr'
            Title = 'Mover: Marcus Nursing > ICU, through the HR feed'
            Script = 'scripts/mock-hr/Invoke-InboundProvisioning.ps1'
            Args = @{ ServicePrincipalId = '{ProvisioningServicePrincipalId}'; JobId = '{ProvisioningJobId}'; UpnDomain = '{Domain}'; StatusFilter = 'active' }
            Runs = @(@{ Mode = 'dry'; Add = @{ WhatIf = $true } }, @{ Mode = 'real' })
            Before = @('Edit Marcus Bello''s row in lab/scripts/mock-hr/hr_feed.csv: Nursing > ICU.', 'Connect-MgGraph -Scopes SynchronizationData-User.Upload (browser).')
            Capture = @(@{ Recipe = 'provisioning-logs' })
        }
        @{
            Id = 'mover-provision'; Day = 14; Kind = 'console'; Evidence = @('E52'); Part = 'mover'
            Title = 'Mover: provision on demand; ICU arrives by policy'
            Do = @('Entra admin center > Entra Connect > Cloud sync > Provision on demand: Marcus Bello.')
            Success = 'Marcus gets ICU by its automatic policy; Nurse stays inside the 72-hour grace (read it again on Day 17).'
            Rollback = 'lab/scripts/demo/Reset-DemoState.ps1 -Segment Mover (with the provisioning ids and the UPN domain).'
            Capture = @(@{ Recipe = 'access-package-assignments' })
        }
        @{
            Id = 'intune-evening'; Day = 14; Kind = 'console'
            Title = 'Evening: the Intune VM for tomorrow'
            Do = @('Start the Intune VM; {PilotUpn} signs in to portal.azure.com from the VM and from the Mac.')
            Success = 'Both sign-ins recorded.'
        }

        # ------------------------------------------------------------ Day 15
        @{
            Id = 'recording-apps-ca'; Day = 15; Kind = 'console'; Optional = $true
            Title = 'Recording: the apps segment (morning), the Conditional Access segment (afternoon)'
            Do = @('CA004 must still be report-only: its graduation is the pipeline segment on Day 16.')
        }
        @{
            Id = 'itdr-app-credential'; Day = 15; Kind = 'console'; Evidence = @('E42')
            Title = 'A certificate on a test app, and the secret the policy refuses'
            Do = @('Entra admin center > App registrations > a test app > Certificates & secrets: upload a certificate; then try to add a client secret.')
            Success = 'The app-credential-added.kql incident; the app management policy refuses the secret.'
            Rollback = 'Remove the certificate.'
            Capture = @(@{ Recipe = 'incidents' }, @{ Recipe = 'directory-audits' })
        }
        @{
            Id = 'itdr-consent'; Day = 15; Kind = 'console'; Evidence = @('E43')
            Title = 'An admin grants consent to a test app'
            Do = @('Entra admin center > Enterprise applications > a test app > Permissions > Grant admin consent.')
            Success = 'The app-consent-granted.kql incident.'
            Rollback = 'Revoke the grant.'
            Capture = @(@{ Recipe = 'incidents' }, @{ Recipe = 'directory-audits' })
        }
        @{
            Id = 'itdr-ca-drift'; Day = 15; Kind = 'console'; Evidence = @('E44')
            Title = 'Deliberate drift: a portal edit of a report-only CA policy'
            Do = @('Entra admin center > Conditional Access > a report-only policy (not CA004) > change one setting > Save.')
            Success = 'The ca-policy-changed.kql incident.'
            Capture = @(@{ Recipe = 'ca-policies' }, @{ Recipe = 'incidents' }, @{ Recipe = 'directory-audits' })
        }
        @{
            Id = 'itdr-ca-drift-revert'; Day = 15; Kind = 'pr'; Evidence = @('E44'); Part = 'revert'
            Title = 'The plan shows the drift; the apply reverts it'
            Do = @('A PR touching lab/terraform/**: the plan shows the drift; merge, approve prod.')
            Capture = @(@{ Recipe = 'pipeline' }, @{ Recipe = 'ca-policies' })
        }
        @{
            Id = 'itdr-role-outside-pim'; Day = 15; Kind = 'console'; Evidence = @('E45')
            Title = 'Helpdesk Administrator outside PIM, then permanent active in PIM'
            Do = @(
                'Entra admin center > Roles and administrators > Helpdesk Administrator > Add assignments: a test user, Active (not through PIM). Remove it.'
                'Then in PIM: a permanent ACTIVE assignment of the same role; remove it.'
            )
            Success = 'Two role-assigned-outside-pim.kql incidents (Direct, then PimPermanentActive); the removals.'
            Note = 'Copy the PIM record''s exact OperationName into the rule if Microsoft''s differs.'
            Capture = @(@{ Recipe = 'incidents' }, @{ Recipe = 'directory-audits' })
        }
        @{
            Id = 'itdr-pim-group-bypass'; Day = 15; Kind = 'console'; Evidence = @('E45b')
            Title = 'The PIM-for-Groups bypass'
            Do = @('{TestAccountF} added DIRECTLY to Privileged-IAM-Admins (Groups blade, not PIM), removed; then to Break-Glass-Admins, removed at once.')
            Success = 'pim-group-member-added-outside-pim.kql incidents, Break-Glass-Admins always High; the removals.'
            Capture = @(@{ Recipe = 'incidents' }, @{ Recipe = 'directory-audits' })
        }
        @{
            Id = 'itdr-phone-method'; Day = 15; Kind = 'console'; Evidence = @('E46')
            Title = 'An admin adds a phone method to a test account'
            Do = @('Entra admin center > Users > {TestAccountE} > Authentication methods > + Add authentication method > Phone number.')
            Success = 'The auth-method-changed-by-admin.kql incident.'
            Capture = @(@{ Recipe = 'incidents' }, @{ Recipe = 'directory-audits' })
        }
        @{
            Id = 'itdr-helpdesk-scope'; Day = 15; Kind = 'console'; Evidence = @('E46b')
            Title = 'Help-desk scope: allowed on the workforce, refused on an admin'
            Do = @('A test service-desk member activates PIM-Tier1-Helpdesk, resets the methods of a standard workforce user, then tries the same on a Tier-1 admin.')
            Success = 'The first succeeds and the second is refused (portal error and audit log), with the role assignment''s AU scope shown.'
            Capture = @(@{ Recipe = 'directory-audits' }, @{ Recipe = 'admin-units' }, @{ Recipe = 'incidents' })
        }
        @{
            Id = 'itdr-risky-registration'; Day = 15; Kind = 'console'; Evidence = @('E46c')
            Title = 'A risky Authenticator registration'
            Do = @('A test account registers a new Authenticator method from an unmanaged device through a VPN exit in a country it has not used in 14 days.')
            Success = 'The security-info-registered-risky.kql incident with the signals it counted.'
            Capture = @(@{ Recipe = 'incidents' }, @{ Recipe = 'sign-ins' })
        }
        @{
            Id = 'itdr-failed-spike'; Day = 15; Kind = 'console'; Evidence = @('E47')
            Title = 'Failed sign-in spike from one address'
            Do = @('From one IP, 10 or more failed sign-ins inside one 10-minute bin, spread across {TestAccountD}, {TestAccountE} and {TestAccountF} so smart lockout locks none of them.')
            Success = 'The failed-signin-spike.kql incident.'
            Capture = @(@{ Recipe = 'sign-ins' }, @{ Recipe = 'incidents' })
        }
        @{
            Id = 'itdr-blocked-country'; Day = 15; Kind = 'console'; Optional = $true; Evidence = @('E48')
            Title = 'Optional: a sign-in from a blocked country'
            Do = @('A test account signs in through a VPN exit in a blocked country.')
            Success = 'CA004''s result (report-only today) and the blocked-country-signin.kql incident.'
            Capture = @(@{ Recipe = 'sign-ins' }, @{ Recipe = 'incidents' })
        }

        # ------------------------------------------------------------ Day 16
        @{
            Id = 'bg-drill-preflight'; Day = 16; Kind = 'script'; Evidence = @('E49'); Part = 'preflight'
            Title = 'Break-glass drill: preflight'
            Script = 'scripts/powershell/Invoke-BreakGlassDrill.ps1'
            Args = @{ Phase = 'Preflight'; OnMicrosoftDomain = '{OnMicrosoftDomain}'; ExpectedKeysPerAccount = '{BreakGlassKeysPerAccount}'; ResourceGroup = '{ResourceGroup}'; WorkspaceName = '{WorkspaceName}' }
            Success = 'Every check PASS: only then the sign-ins.'
        }
        @{
            Id = 'bg-drill-signins'; Day = 16; Kind = 'console'
            Title = 'The break-glass sign-ins (lab/docs/runbooks/break-glass-drill.md)'
            Do = @('Each account with each key, in private windows: bg-admin-01 key 1 and key 2, bg-admin-02 key 1 and key 2.')
            Note = 'The day runner records when this step starts: that is the drill start the verify phase reads.'
            Success = 'Every sign-in done; nothing changed while signed in.'
        }
        @{
            Id = 'bg-drill-verify'; Day = 16; Kind = 'script'; Evidence = @('E49')
            Title = 'Break-glass drill: verify and record'
            Script = 'scripts/powershell/Invoke-BreakGlassDrill.ps1'
            Args = @{ Phase = 'Verify'; OnMicrosoftDomain = '{OnMicrosoftDomain}'; ResourceGroup = '{ResourceGroup}'; WorkspaceName = '{WorkspaceName}'; DrillStartUtc = '{StartUtc:bg-drill-signins}'; DeclaredSignIns = '{BreakGlassDeclaredSignIns}'; ChangeTicket = '{ChangeTicket}' }
            Success = 'The rows in lab/evidence/drills/README.md; minutes from sign-in to incident.'
            Capture = @(@{ Recipe = 'incidents' }, @{ Recipe = 'files'; Name = 'drill-record'; Path = 'evidence/drills/*.json' })
        }
        @{
            Id = 'recording-pim'; Day = 16; Kind = 'console'; Optional = $true
            Title = 'Recording: the PIM activation and approval'
            Do = @('Write the approval time in UTC.')
        }
        @{
            Id = 'graduate-ca004'; Day = 16; Kind = 'pr'; NewCaptureId = 'CA004-graduation'
            Title = 'CA004 enforced through the pipeline (recorded: a new capture id)'
            Enforce = @('CA004')
            Do = @('VS Code > lab/terraform/envs/dev/lab.tfvars > CA004 = "enabled" > PR > plan > merge > approve prod > apply.')
            Rollback = 'A revert PR.'
            Capture = @(@{ Recipe = 'pipeline' }, @{ Recipe = 'ca-policies' })
        }
        @{
            Id = 'recording-itdr'; Day = 16; Kind = 'console'; Optional = $true
            Title = 'Recording: detect and respond, 20-30 minutes after the signals'
            Do = @('Splunk side by side (one line).')
        }

        # ------------------------------------------------------------ Day 17
        @{
            Id = 'ca005-device'; Day = 17; Kind = 'console'; Evidence = @('E50')
            Title = 'CA005: the compliant VM, then the Mac'
            Do = @('{PilotUpn} signs in to an admin portal from the compliant VM, then from the Mac.')
            Success = 'CA005''s result on both, as displayed (pilot scope).'
            Capture = @(@{ Recipe = 'sign-ins'; User = '{PilotUpn}' }, @{ Recipe = 'managed-devices' })
        }
        @{
            Id = 'ca060'; Day = 17; Kind = 'pr'; Evidence = @('E50b')
            Title = 'CA060 shared clinical workstations, report-only'
            Flags = @('enable_shared_clinical_ca')
            Note = 'Without a device enrolled with the CH-SharedClinical Autopilot profile the result is "not exercised" plus the plan; never point the filter at another device.'
            MissedReason = 'device filter not exercised: no CH-SharedClinical device'
            Rollback = 'Flag off.'
            Capture = @(@{ Recipe = 'pipeline' }, @{ Recipe = 'ca-policies' })
        }
        @{
            Id = 'pam-oidc'; Day = 17; Kind = 'pr'; Evidence = @('E51a'); Part = 'pr'
            Title = 'The PAM broker''s Entra app (needs enable_sso_apps)'
            Flags = @('enable_pam_oidc_app')
            Do = @('After the apply: add the operators to PAM-Operators.')
            Capture = @(@{ Recipe = 'pipeline' })
        }
        @{
            Id = 'pam-ops'; Day = 17; Kind = 'terminal'; Evidence = @('E51a')
            Title = 'The PAM operations pack on DC01 (lab/pam/README.md)'
            Do = @(
                'In lab/pam: the svc-pam-discovery secret from Key Vault piped into ./discover.sh; the dependency scan through az vm run-command; ./onboard.sh --dry-run, then ./onboard.sh; ./reconcile.sh --verify --strict'
                'OIDC: the .env values, then docker compose -f docker-compose.yml -f docker-compose.oidc.yml up -d guacamole'
                'ServiceNow PDI: a change in Implement, assigned to the operator, approved by the two Tier-0 approvers (dual control).'
                './psm-session.sh checkout --operator <upn> --ticket CHG...; Guacamole (127.0.0.1:8081/guacamole) > sign in with Entra > the recorded RDP session; ./psm-session.sh checkin'
            )
            Success = 'GAP 0; Guacamole History names the operator''s UPN; the Vault audit line carries the change number and both approvers; the recording plays; CA022''s report-only result.'
            Note = 'A terminal step on purpose: Vault Community has no discovery or onboarding UI (lab/docs/STAND-INS.md).'
            Rollback = './psm-session.sh checkin; flag off.'
            Capture = @(@{ Recipe = 'files'; Name = 'reconcile'; Path = 'pam/out/reconcile-latest.*' }, @{ Recipe = 'sign-ins' })
        }
        @{
            Id = 'tier0-logon'; Day = 17; Kind = 'console'; Evidence = @('E51')
            Title = 'A Tier-0 logon with and without a check-out'
            Do = @('RDP to DC01 as a Tier-0 admin WITHOUT a Vault check-out; then as the account you checked out.')
            Success = 'tier0-logon-without-checkout.kql alerts once (Class Vaulted); the checked-out logon stays quiet.'
            Capture = @(@{ Recipe = 'incidents' })
        }
        @{
            Id = 'vault-dc-rules'; Day = 17; Kind = 'pr'; Evidence = @('E51f')
            Title = 'The Vault and DC-allowlist rules'
            Flags = @('vault_feed_v2_columns')
            Do = @(
                'One PR: vault_feed_v2_columns = true and both rules released from itdr_exclude_rules; in the same change restart the feed as lab/scripts/monitoring/ingest-vault-audit.sh --signals all --follow 60.'
                'Then read a Tier-0 credential with a token that has no ticketed check-out; expire one operator_ips watchlist row and RDP to DC01 from that address. Restore the row.'
            )
            Success = 'The vault-privileged-access-anomaly.kql (Tier0CredReadUncovered) and dc-logon-outside-operator-allowlist.kql incidents.'
            Capture = @(@{ Recipe = 'pipeline' }, @{ Recipe = 'sentinel-rules' }, @{ Recipe = 'incidents' })
        }
        @{
            Id = 'ad-plane'; Day = 17; Kind = 'console'; Evidence = @('E51b')
            Title = 'The AD plane, from a lab test box only'
            Do = @('A disposable test account into Domain Admins, then a logon with it; a lab Kerberoast of the planted SPN accounts (RC4); one Purple Knight or PingCastle run. Remove the test account afterwards.')
            Success = 'ad-privileged-group-change.kql (4728) and tier0-logon-without-checkout.kql Class Unvaulted incidents; kerberoast-rc4-service-ticket.kql (High: 3+ SPNs); the AD assessment report hashed (the raw report stays private).'
            Capture = @(@{ Recipe = 'incidents' })
        }
        @{
            Id = 'dcsync'; Day = 17; Kind = 'console'; Optional = $true; Evidence = @('E51c')
            Title = 'Optional: DCSync and the krbtgt double reset (lab DC only)'
            Do = @('DCSync from a test account granted the replication rights for the drill (removed afterwards); then the krbtgt double reset.')
            Success = 'The dcsync-replication-request.kql incident; the rights removed.'
            Capture = @(@{ Recipe = 'incidents' })
        }
        @{
            Id = 'recording-pam'; Day = 17; Kind = 'console'; Optional = $true
            Title = 'Recording: the PAM segment, now that DC01 has passed'
            Do = @('The PAM half of the PIM + credential-plane segment, and the PAM cut.')
        }
        @{
            Id = 'mover-grace'; Day = 17; Kind = 'console'; Evidence = @('E52'); Part = 'mover-grace'
            Title = 'Marcus''s Nurse package again (the 72-hour grace from Day 14)'
            Do = @('Entra admin center > ID Governance > Access packages > Nurse - Clinical Apps > Assignments: Marcus Bello.')
            Success = 'The old birthright package removed only after the grace.'
            Capture = @(@{ Recipe = 'access-package-assignments' })
        }

        # ------------------------------------------------------------ Day 18
        @{
            Id = 'ca-snapshot'; Day = 18; Kind = 'script'; Evidence = @('E51d'); Part = 'snapshot'
            Title = 'CA restore drill: snapshot every policy'
            Script = 'scripts/powershell/Invoke-CaRestoreDrill.ps1'
            Args = @{ Mode = 'Snapshot' }
            Before = @('If the tenant has Microsoft Entra Backup and Recovery (verify), drill with it instead and [s]kip the four restore-drill steps.')
            Success = 'A ca-policies-<utc>.json snapshot with its .sha256 under lab/evidence/out/ca-restore/.'
        }
        @{
            Id = 'ca-portal-change'; Day = 18; Kind = 'console'
            Title = 'CA restore drill: change a report-only policy in the portal'
            Do = @('Entra admin center > Conditional Access > a report-only policy > change its exclusions > Save. Put its display name in the settings file (CaRestorePolicyName) or type it when asked.')
            Success = 'The change saved.'
        }
        @{
            Id = 'ca-compare'; Day = 18; Kind = 'script'; Evidence = @('E51d'); Part = 'compare'
            Title = 'CA restore drill: detect the drift'
            Script = 'scripts/powershell/Invoke-CaRestoreDrill.ps1'
            Args = @{ Mode = 'Compare'; SnapshotPath = '{NewestFile:evidence/out/ca-restore/ca-policies-*.json}' }
            Success = 'The changed policy named.'
        }
        @{
            Id = 'ca-restore'; Day = 18; Kind = 'script'; Evidence = @('E51d')
            Title = 'CA restore drill: restore it, timed'
            Script = 'scripts/powershell/Invoke-CaRestoreDrill.ps1'
            Args = @{ Mode = 'Restore'; SnapshotPath = '{NewestFile:evidence/out/ca-restore/ca-policies-*.json}'; PolicyName = '{CaRestorePolicyName}'; Apply = $true }
            Runs = @(@{ Mode = 'dry'; Add = @{ WhatIf = $true } }, @{ Mode = 'real' })
            Success = 'The restore time printed; then terraform plan shows no drift (a PR or the plan workflow).'
            Capture = @(@{ Recipe = 'files'; Name = 'restore-record'; Path = 'evidence/out/ca-restore/ca-restore-*.json' }, @{ Recipe = 'ca-policies' }, @{ Recipe = 'incidents' })
        }
        @{
            Id = 'token-protection'; Day = 18; Kind = 'script'; Evidence = @('E51e')
            Title = 'The Token Protection pilot (CA011)'
            Script = 'scripts/powershell/post-apply/Set-TokenProtectionPolicy.ps1'
            Runs = @(@{ Mode = 'read' }, @{ Mode = 'dry'; Add = @{ Apply = $true; WhatIf = $true } }, @{ Mode = 'real'; Add = @{ Apply = $true } })
            Before = @('Its plan must CREATE CA011 and leave CA010 alone.')
            Success = 'CA011 created report-only. Then sign in from the VM''s Outlook / Teams and from a browser: Token Protection satisfied / would fail per sign-in.'
            Rollback = 'Delete CA011 in the portal.'
            Capture = @(@{ Recipe = 'ca-policies' }, @{ Recipe = 'sign-ins'; User = '{PilotUpn}' })
        }
        @{
            Id = 'protected-actions'; Day = 18; Kind = 'console'; Optional = $true; Evidence = @('E51g')
            Title = 'Protected actions (CA023 + c2), only once CA023 is enforced'
            Do = @(
                'CA023 still report-only: answer [m]issed (recorded as not bound).'
                'CA023 enforced: bind c2 to the protected actions for CA policies and named locations (verify the Graph beta resourceActions PATCH shape), then edit one CA policy.'
            )
            MissedReason = 'not bound: CA023 report-only'
            Success = 'The CA policy edit asks for the step-up.'
            Capture = @(@{ Recipe = 'auth-contexts' }, @{ Recipe = 'ca-policies' })
        }
        @{
            Id = 'leaver-feed'; Day = 18; Kind = 'script'; Evidence = @('E52'); Part = 'leaver-hr'
            Title = 'Leaver: the HR row turns to leaver'
            Script = 'scripts/mock-hr/Invoke-InboundProvisioning.ps1'
            Args = @{ ServicePrincipalId = '{ProvisioningServicePrincipalId}'; JobId = '{ProvisioningJobId}'; UpnDomain = '{Domain}'; StatusFilter = 'leaver' }
            Runs = @(@{ Mode = 'dry'; Add = @{ WhatIf = $true } }, @{ Mode = 'real' })
            Before = @(
                'Dana''s row in lab/scripts/mock-hr/hr_feed.csv set to leaver first.'
                'Dana co-owns "Ward Rota Sync (test)" and Application.ReadWrite.All is consented (the leaver hand-off needs both).'
                'Connect-MgGraph -Scopes SynchronizationData-User.Upload (browser).'
            )
            Capture = @(@{ Recipe = 'provisioning-logs' })
        }
        @{
            Id = 'leaver-provision'; Day = 18; Kind = 'console'
            Title = 'Leaver: provision on demand'
            Do = @('Entra admin center > Entra Connect > Cloud sync > Provision on demand: Dana Okafor.')
            Success = 'Dana disabled in AD and in Entra.'
        }
        @{
            Id = 'leaver'; Day = 18; Kind = 'script'; Evidence = @('E52'); Part = 'leaver'
            Title = 'Leaver: everything Dana held, timed'
            Script = 'scripts/powershell/04-Leaver.ps1'
            Args = @{ UserPrincipalName = '{JoinerUpn}'; NhiHandoff = 'ReassignToManager'; ReportPath = '{PowerShellOut}/leaver_dana.csv' }
            Runs = @(@{ Mode = 'dry'; Add = @{ WhatIf = $true } }, @{ Mode = 'real'; Add = @{ Confirm = $false } })
            Success = 'First-to-last as printed by [8/8], said exactly (never rounded); the AWS SCIM disable arrives on the next provisioning cycle (about 40 minutes: note the time).'
            Note = 'No -ProvisionOnDemandApps: it cannot act on a user Entra already disabled. ServiceNow is not provisioned (designed, not built): there is no ServiceNow deprovisioning to show.'
            Rollback = 'lab/scripts/demo/Reset-DemoState.ps1 -Segment Leaver (with -LicenseSkuPartNumber), then re-seed Dana''s app ownership by hand.'
            Capture = @(@{ Recipe = 'provisioning-logs' }, @{ Recipe = 'directory-audits' }, @{ Recipe = 'files'; Name = 'leaver-report'; Path = 'scripts/powershell/out/leaver_dana.csv' })
        }
        @{
            Id = 'evidence-pack-take'; Day = 18; Kind = 'script'; NewCaptureId = 'evidence-pack-take'
            Title = 'An evidence pack for the evidence segment (E56 is the final one)'
            Script = 'scripts/powershell/Export-EvidencePack.ps1'
            Success = 'manifest.json and SUMMARY.md under lab/evidence/out/.'
            Capture = @(@{ Recipe = 'files'; Name = 'pack-manifest'; Path = 'evidence/out/manifest.json' })
        }

        # ------------------------------------------------------------ Day 19
        @{
            Id = 'nhi'; Day = 19; Kind = 'script'; Evidence = @('E53')
            Title = 'NHI inventory'
            Script = 'scripts/powershell/06-NHI-Inventory.ps1'
            Success = 'Counts by OWASP NHI id (public), the detail private.'
        }
        @{
            Id = 'shadow-admins'; Day = 19; Kind = 'script'; Evidence = @('E53'); Part = 'shadow-admins'
            Title = 'Shadow admins'
            Script = 'scripts/powershell/Find-ShadowAdmins.ps1'
            Success = 'Counts by path type (public), the detail private.'
        }
        @{
            Id = 'agent-id-pr'; Day = 19; Kind = 'pr'; Evidence = @('E53b'); Part = 'pr'
            Title = 'Agent ID runtime identity'
            Flags = @('enable_agent_identity')
            Capture = @(@{ Recipe = 'pipeline' })
        }
        @{
            Id = 'agent-id-preview'; Day = 19; Kind = 'script'; Evidence = @('E53b'); Part = 'preview'
            Title = 'Agent ID: the offline preview'
            Script = 'scripts/powershell/post-apply/New-AgentIdentity.ps1'
            Args = @{ OfflinePreview = $true }
            Success = 'What it would create; read the preview terms before the next step.'
        }
        @{
            Id = 'agent-id'; Day = 19; Kind = 'script'; Evidence = @('E53b')
            Title = 'Agent ID: identity only'
            Script = 'scripts/powershell/post-apply/New-AgentIdentity.ps1'
            Args = @{ AcceptPreview = $true }
            Runs = @(@{ Mode = 'dry'; Add = @{ WhatIf = $true } }, @{ Mode = 'real' })
            Success = 'The blueprint and agent identity with its human sponsor and managed-identity federated credential; no secret, no permission. Say "identity-only".'
            Rollback = 'New-AgentIdentity.ps1 -Remove'
        }
        @{
            Id = 'midpoint-entra'; Day = 19; Kind = 'terminal'; Optional = $true; Evidence = @('E53c')
            Title = 'Optional: midPoint reads Entra'
            Do = @('midPoint aggregates the Entra users through the Graph connector (lab/pam/README.md, the midPoint section).')
            Success = 'The import task result; the users linked to their shadows.'
            Note = 'The result lives in midPoint, not the tenant: save and hash it yourself and add its capture-log row (or [m]issed).'
        }

        # ------------------------------------------------------ Days 20 to 24
        @{
            Id = 'buffer'; Days = @(20, 21, 22, 23, 24); Kind = 'console'; Optional = $true
            Title = 'Buffer: re-takes and anything that failed'
            Do = @(
                'Every re-run gets a new capture id: the day runner names it <id>.rerun-<UTC> and marks it a re-run of the original. Use -Day <n> -Step <id> for the step you re-run.'
                'Optional: the atypical-travel simulation on {TestAccountA}.'
            )
        }

        # ------------------------------------------------------ Days 25 to 29
        @{
            Id = 'kpis-after'; Day = 25; Kind = 'script'; Evidence = @('E54')
            Title = 'KPIs after, against the baseline'
            Script = 'scripts/powershell/08-Measure-KPIs.ps1'
            Args = @{ Label = 'after'; CompareTo = '{KpiBaseline}'; SkipPam = '{SkipPam}' }
            Success = 'The snapshot, its sidecar and the delta table.'
            Capture = @(@{ Recipe = 'files'; Name = 'kpi-snapshot'; Path = 'evidence/kpis/2*.json*' })
        }
        @{
            Id = 'assessment-after'; Day = 26; Kind = 'terminal'; Evidence = @('E55')
            Title = 'Assessment after (Windows x64 host, browser sign-in only)'
            Do = @('./Invoke-BaselineAssessment.ps1 -Phase after -StorageAccountName {EvidenceStorageAccount}; commit the public folder, pull it here.')
            Success = 'The before / after delta per MS.AAD control. MS.AAD.3.1 stays failing (CA008 is a pilot), 3.8 too (CA009 is a compensating control); 3.9 passes only because CA010 was enforced (E38b). Record what it reports.'
            Capture = @(@{ Recipe = 'files'; Name = 'assessment-after'; Path = 'evidence/assessments/*after*/*'; LookbackHours = 48 })
        }
        @{
            Id = 'evidence-pack'; Day = 27; Kind = 'script'; Evidence = @('E56')
            Title = 'The evidence pack'
            Script = 'scripts/powershell/Export-EvidencePack.ps1'
            Success = 'The pack and its manifest under lab/evidence/out/.'
            Capture = @(@{ Recipe = 'files'; Name = 'pack-manifest'; Path = 'evidence/out/manifest.json' }, @{ Recipe = 'evidence-store' })
        }
        @{
            Id = 'evidence-pack-upload'; Day = 27; Kind = 'terminal'
            Title = 'The pack and its companions into the WORM store'
            Do = @(
                'az storage blob upload-batch --auth-mode login --overwrite false -d evidence --destination-path packs/<utc> -s lab/evidence/out --account-name {EvidenceStorageAccount}'
                'The same for lab/evidence/kpis/, drills/ and access-reviews/ (each file with its .sha256) to captures/E56/.'
            )
            Success = 'Every upload accepted; nothing overwritten.'
        }
        @{
            Id = 'recording-close'; Days = @(26, 27); Kind = 'console'; Optional = $true
            Title = 'Recording: the opening, the close and the executive cut, now that the after numbers exist'
            Do = @('Say each value exactly as measured.')
        }
        @{
            Id = 'close-out'; Day = 28; Kind = 'console'; Evidence = @('E57')
            Title = 'Close-out: every id has a log row or missed; the WORM decision'
            Check = 'capture-log-coverage'
            Do = @(
                'Commit the public artefacts (manifests, SHA256SUMS, the capture log, KPI snapshots, summaries).'
                'The WORM lock is IRREVERSIBLE: with the default 2190-day retention a Locked store cannot be deleted for six years. To lock: first a PR shortening evidence_immutability_days (while Unlocked), then the lock PR (evidence_immutability_state = "Locked" + evidence_immutability_lock_acknowledged = true). Or stay Unlocked and say so. Never lock from a local apply.'
            )
            Success = 'The decision and its reason in the capture log.'
            Capture = @(@{ Recipe = 'evidence-store' })
        }
        @{
            Id = 'teardown-decision'; Day = 28; Kind = 'console'
            Title = 'Reserve the P2 trial, or tear down now'
            Do = @('Teardown runs while P2 is active (the Azure Owner and admin@''s Global Administrator are PIM-eligible; whether they can be activated after P2 lapses is unverified).')
            Success = 'Decided, and the teardown done or scheduled while P2 is active.'
        }
        @{
            Id = 'post-trial-prs'; Day = 29; Kind = 'pr'; Evidence = @('E58')
            Title = 'Post-trial PRs: opened, not merged early'
            Do = @(
                'One PR with enable_la_alerts = true and enable_sentinel = false, merged by Day 32.'
                'Decide each CA policy''s state for after the P2 licences lapse (verify how risk-based CA behaves then).'
            )
            Success = 'The PRs open.'
            Capture = @(@{ Recipe = 'open-prs' })
        }
    )
}
