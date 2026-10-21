# Pester 5 tests for post-apply/Set-AuthenticationMethodsPolicy.ps1.
#   * Desired-state helpers (pure, from the syntax tree).
#   * Offline preview.
#   * Plan / apply against a SIMULATED authentication methods policy: the
#     Invoke-MgGraphRequest mock keeps the policy in memory, applies each
#     PATCH to it and serves the result on the next GET, so read-after-write
#     and the break-glass invariants are exercised end to end.
# No tenant is contacted.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    $script:Amp = Get-LabScriptPath 'post-apply/Set-AuthenticationMethodsPolicy.ps1'
    . (Get-ScriptFunctionBlock -Path $script:Amp -Name 'Get-Field', 'Get-NameBasedGuid', 'ConvertTo-Canonical', 'Select-DesiredShape', 'Get-Drift', 'Merge-ExcludeTarget', 'Test-PimGovernedNickname', 'Test-PasskeyCoverage')

    function Set-AmpMocks {
        # A fresh tenant as Microsoft ships it (after the 2026 passkey changes):
        # passkey profiles on with only the Default profile targeted at
        # all_users, TAP off, Authenticator on for all_users, SMS/voice on.
        param([switch]$NoPasskeyProfiles, [hashtable]$Registration = @{},
            # Registered passkeys per user id (aaGuid list) and group membership.
            [hashtable]$Keys = @{ 'bg-1' = @('cb69481e-8ff7-4039-93ec-0a2729a154a8') },
            [string[]]$BuildGroups = @('gid-admins'))
        $fido2 = @{ id = 'Fido2'; state = 'enabled'; isSelfServiceRegistrationAllowed = $true; excludeTargets = @()
            includeTargets = @(@{ id = 'all_users'; targetType = 'group'; isRegistrationRequired = $false; allowedPasskeyProfiles = @('00000000-0000-0000-0000-000000000001') })
        }
        if (-not $NoPasskeyProfiles) {
            $fido2['passkeyProfiles'] = @(@{ id = '00000000-0000-0000-0000-000000000001'; name = 'Default passkey profile'; passkeyTypes = 'synced,deviceBound'; attestationEnforcement = 'disabled'; keyRestrictions = @{ isEnforced = $false; enforcementType = 'allow'; aaGuids = @() } })
        }
        $global:AmpTest = @{
            Patches      = [System.Collections.Generic.List[string]]::new()
            Registration = $Registration
            Keys         = $Keys
            BuildGroups  = $BuildGroups
            Configs      = [ordered]@{
                Fido2                  = $fido2
                TemporaryAccessPass    = @{ id = 'TemporaryAccessPass'; state = 'disabled'; includeTargets = @(); excludeTargets = @(); defaultLifetimeInMinutes = 60; minimumLifetimeInMinutes = 60; maximumLifetimeInMinutes = 480; defaultLength = 8; isUsableOnce = $false }
                MicrosoftAuthenticator = @{ id = 'MicrosoftAuthenticator'; state = 'enabled'; isSoftwareOathEnabled = $true; excludeTargets = @(); includeTargets = @(@{ id = 'all_users'; targetType = 'group'; isRegistrationRequired = $false; authenticationMode = 'any' }); featureSettings = @{} }
                Sms                    = @{ id = 'Sms'; state = 'enabled'; includeTargets = @(@{ id = 'all_users'; targetType = 'group' }); excludeTargets = @() }
                Voice                  = @{ id = 'Voice'; state = 'enabled'; includeTargets = @(@{ id = 'all_users'; targetType = 'group' }); excludeTargets = @() }
            }
            Policy       = @{ policyMigrationState = 'migrationComplete'; registrationEnforcement = @{ authenticationMethodsRegistrationCampaign = @{ state = 'default'; snoozeDurationInDays = 1; includeTargets = @(); excludeTargets = @() } } }
        }
        Mock Write-Host {}
        Mock Get-MgContext { New-MgContextStub }
        Mock Connect-MgGraph { throw 'tests must never connect' }
        Mock Invoke-MgGraphRequest {
            $t = $global:AmpTest
            $base = 'https://graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy'
            if ($Method -eq 'PATCH') {
                $b = $Body | ConvertFrom-Json -AsHashtable
                $t.Patches.Add($Uri)
                if ($Uri -match '/authenticationMethodConfigurations/(?<id>\w+)$') {
                    $key = @($t.Configs.Keys | Where-Object { $_ -ieq $Matches.id })[0]
                    foreach ($k in $b.Keys) { $t.Configs[$key][$k] = $b[$k] }
                }
                elseif ($Uri -eq $base) { foreach ($k in $b.Keys) { $t.Policy[$k] = $b[$k] } }
                return $null
            }
            # -Uri is a [uri]: some escapes (%20) come back decoded, others (%27) do not.
            if ("$Uri" -match "groups\?.*mailNickname(%20| )eq(%20| )(%27|')(?<nick>[^%']+)(%27|')") {
                $known = @{ 'break-glass-admins' = 'gid-bg'; 'admin-accounts' = 'gid-admins'; 'all-workforce' = 'gid-workforce' }
                return @{ value = @(if ($known.ContainsKey($Matches.nick)) { @{ id = $known[$Matches.nick]; displayName = $Matches.nick } }) }
            }
            if ($Uri -eq $base) {
                $p = @{} + $t.Policy
                $p['authenticationMethodConfigurations'] = @($t.Configs.Values)
                return $p
            }
            if ($Uri -match '/authenticationMethodConfigurations/(?<id>\w+)$') { return $t.Configs[@($t.Configs.Keys | Where-Object { $_ -ieq $Matches.id })[0]] }
            if ($Uri -like '*/groups/gid-bg/members*') { return @{ value = @(@{ id = 'bg-1'; userPrincipalName = 'bg-admin-01@contosolab.onmicrosoft.com' }) } }
            if ($Uri -like '*/groups/gid-admins/transitiveMembers*') { return @{ value = @(@{ id = 'u-adm'; userPrincipalName = 'adm-ava.lin@contosolab.onmicrosoft.com' }) } }
            if ("$Uri" -match '/users/(?<u>[^/?]+)/authentication/fido2Methods') {
                return @{ value = @(foreach ($g in @($t.Keys[$Matches.u])) { if ($g) { @{ id = "k-$g"; aaGuid = $g } } }) }
            }
            if ("$Uri" -match '/users/u-build/transitiveMemberOf') { return @{ value = @(foreach ($g in $t.BuildGroups) { @{ id = $g } }) } }
            if ("$Uri" -match '/users/admin%40') { return @{ id = 'u-build'; userPrincipalName = 'admin@contosolab.onmicrosoft.com' } }
            if ($Uri -like '*userRegistrationDetails*') { return @{ value = @(foreach ($k in $t.Registration.Keys) { @{ id = $k; methodsRegistered = $t.Registration[$k] } }) } }
            throw "unexpected Graph call in test: $Method $Uri"
        }
    }
}

AfterAll { Remove-Variable -Name AmpTest -Scope Global -ErrorAction SilentlyContinue }

Describe 'Desired-state helpers' {
    It 'derives a stable RFC 4122 v5-style id from a profile name' {
        $a = Get-NameBasedGuid 'Contoso - Admins (device-bound, attested)'
        $a | Should -Be (Get-NameBasedGuid 'Contoso - Admins (device-bound, attested)')
        $a | Should -Match '^[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
        $a | Should -Not -Be (Get-NameBasedGuid 'Contoso - Workforce (synced or device-bound)')
    }

    It 'treats flag order, GUID case, @odata noise and server-side extras as no drift' {
        $desired = [ordered]@{ '@odata.type' = '#x'; passkeyProfiles = @([ordered]@{ id = 'AAAAAAAA-0000-0000-0000-000000000001'; passkeyTypes = 'deviceBound,synced' }) }
        $current = @{ passkeyProfiles = @(@{ '@odata.type' = '#y'; id = 'aaaaaaaa-0000-0000-0000-000000000001'; passkeyTypes = 'synced,deviceBound'; extra = 1 }); lastModified = 'x' }
        # Get-Drift returns its list as ONE object (", $drift"), so assign, then count.
        $drift = Get-Drift -Current $current -Desired $desired
        $drift.Count | Should -Be 0
    }

    It 'keeps a one-element array an array when projecting (regression: false "re-read still differs")' {
        $desired = [ordered]@{ includeTargets = @([ordered]@{ id = 'g-1'; targetType = 'group'; allowedPasskeyProfiles = @('p-1') }) }
        $current = @{ includeTargets = @(@{ id = 'g-1'; targetType = 'group'; allowedPasskeyProfiles = @('p-1'); isRegistrationRequired = $false }) }
        $drift = Get-Drift -Current $current -Desired $desired
        $drift.Count | Should -Be 0
    }

    It 'reports the keys that really differ' {
        $d = Get-Drift -Current @{ state = 'disabled'; isUsableOnce = $true } -Desired ([ordered]@{ state = 'enabled'; isUsableOnce = $true })
        @($d) | Should -Be @('state')
    }

    It 'adds break-glass to existing exclusions once, without dropping anyone else''s' {
        $m = Merge-ExcludeTarget -Existing @(@{ id = 'g-other'; targetType = 'group' }) -GroupId 'g-bg'
        @($m).Count | Should -Be 2
        $again = Merge-ExcludeTarget -Existing $m -GroupId 'g-bg'
        $again.Count | Should -Be 2
    }
}

Describe 'Admin targets: never a PIM-for-Groups group' {
    It 'recognises <Nick> as PIM-governed = <Expect>' -ForEach @(
        @{ Nick = 'pim-tier0-ca-admins'; Expect = $true }
        @{ Nick = 'pim-tier1-helpdesk'; Expect = $true }
        @{ Nick = 'privileged-iam-admins'; Expect = $true }
        @{ Nick = 'admin-accounts'; Expect = $false }
        @{ Nick = 'pim-azure-rg-contributors'; Expect = $false }   # standing members (azure.tf)
        @{ Nick = 'pim-approvers-tier0'; Expect = $false }
    ) {
        Test-PimGovernedNickname $Nick | Should -Be $Expect
    }
}

Describe 'Test-PasskeyCoverage (pure)' {
    BeforeAll {
        $script:P = 'p-admin-profile'
        $script:Yubi = 'cb69481e-8ff7-4039-93ec-0a2729a154a8'
        $script:Other = '99999999-9999-9999-9999-999999999999'
        function New-Cfg {
            param([string[]]$Targets = @('g-admins'), [bool]$Enforced = $true, [string]$Type = 'allow', [string[]]$List = @($script:Yubi), [string[]]$Exclude = @(), [string]$State = 'enabled', [switch]$NoProfiles)
            $cfg = @{ state = $State; excludeTargets = @($Exclude | ForEach-Object { @{ id = $_; targetType = 'group' } })
                includeTargets = @($Targets | ForEach-Object { @{ id = $_; targetType = 'group'; allowedPasskeyProfiles = @($script:P) } }) }
            $kr = @{ isEnforced = $Enforced; enforcementType = $Type; aaGuids = @($List) }
            if ($NoProfiles) { $cfg['keyRestrictions'] = $kr } else { $cfg['passkeyProfiles'] = @(@{ id = $script:P; name = 'Admins'; keyRestrictions = $kr }) }
            return $cfg
        }
    }
    It 'covers a member of a target and accepts a key on the allow-list' {
        $r = Test-PasskeyCoverage -Fido2Config (New-Cfg) -GroupIds 'G-ADMINS' -Keys @(@{ aaGuid = $script:Yubi.ToUpperInvariant() })
        $r.Covered | Should -BeTrue
        $r.AcceptedKeys | Should -Be 1
        @($r.RejectedAaguids).Count | Should -Be 0
    }
    It 'rejects a key outside an enforced allow-list (the break-glass lockout case)' {
        $r = Test-PasskeyCoverage -Fido2Config (New-Cfg) -GroupIds 'g-admins' -Keys @(@{ aaGuid = $script:Other }, @{ aaGuid = $script:Yubi })
        $r.AcceptedKeys | Should -Be 1
        @($r.RejectedAaguids) | Should -Be @($script:Other)
    }
    It 'honours a block list and an unenforced list' {
        (Test-PasskeyCoverage -Fido2Config (New-Cfg -Type 'block') -GroupIds 'g-admins' -Keys @(@{ aaGuid = $script:Yubi })).AcceptedKeys | Should -Be 0
        (Test-PasskeyCoverage -Fido2Config (New-Cfg -Enforced $false) -GroupIds 'g-admins' -Keys @(@{ aaGuid = $script:Other })).AcceptedKeys | Should -Be 1
    }
    It 'reads method-level keyRestrictions when passkey profiles are off' {
        (Test-PasskeyCoverage -Fido2Config (New-Cfg -NoProfiles) -GroupIds 'g-admins' -Keys @(@{ aaGuid = $script:Other })).RejectedAaguids | Should -Be @($script:Other)
    }
    It 'is not covered when <Case>' -ForEach @(
        @{ Case = 'the account is in no target group'; CfgArgs = @{}; Groups = @('g-pim-tier0'); Reason = 'no passkey include target' }
        @{ Case = 'the account is excluded'; CfgArgs = @{ Exclude = @('g-admins') }; Groups = @('g-admins'); Reason = 'excluded' }
        @{ Case = 'the method is disabled'; CfgArgs = @{ State = 'disabled' }; Groups = @('g-admins'); Reason = 'not enabled' }
    ) {
        $a = $CfgArgs
        $r = Test-PasskeyCoverage -Fido2Config (New-Cfg @a) -GroupIds $Groups
        $r.Covered | Should -BeFalse
        $r.Reason | Should -Match $Reason
    }
    It 'treats all_users as covering everyone' {
        (Test-PasskeyCoverage -Fido2Config (New-Cfg -Targets 'all_users') -GroupIds @()).Covered | Should -BeTrue
    }
    It 'is identical in every script that carries a copy (parity)' {
        $canonical = (Get-ScriptFunctionBlock -Path $script:Amp -Name 'Test-PasskeyCoverage').ToString()
        foreach ($rel in 'post-apply/Convert-BuildAccountToEligible.ps1', '01-Verify-Baseline.ps1', 'Invoke-BreakGlassDrill.ps1') {
            (Get-ScriptFunctionBlock -Path (Get-LabScriptPath $rel) -Name 'Test-PasskeyCoverage').ToString() | Should -Be $canonical -Because "$rel must carry the same coverage logic"
        }
    }
}

Describe 'Set-AuthenticationMethodsPolicy.ps1' {
    BeforeEach { $global:LASTEXITCODE = 0 }

    It '-OfflinePreview prints the desired JSON without any Graph call' {
        Mock Write-Host {}
        Mock Invoke-MgGraphRequest { throw 'offline preview must not call Graph' }
        & $script:Amp -OfflinePreview -IncludeStaffRollout
        $LASTEXITCODE | Should -Be 0
        Should -Invoke Write-Host -ParameterFilter { "$Object" -match '"attestationEnforcement": "registrationOnly"' }
        Should -Invoke Invoke-MgGraphRequest -Times 0
    }

    It 'plan mode on a fresh tenant: reports drift, changes nothing, fails the break-glass invariants' {
        Set-AmpMocks
        & $script:Amp -WarningAction SilentlyContinue
        $LASTEXITCODE | Should -Be 1
        $global:AmpTest.Patches.Count | Should -Be 0
        Should -Invoke Write-Host -ParameterFilter { "$Object" -match '\[FAIL\] BG: passkeys enabled' }
        Should -Invoke Write-Host -ParameterFilter { "$Object" -match '\[FAIL\] BG: excluded from MicrosoftAuthenticator' }
    }

    It '-Apply keeps a Microsoft-created all_users passkey target by default - and the invariant check says why that is unsafe' {
        Set-AmpMocks
        & $script:Amp -Apply -Confirm:$false -WarningAction SilentlyContinue
        $LASTEXITCODE | Should -Be 1
        $targets = @($global:AmpTest.Configs['Fido2']['includeTargets'] | ForEach-Object { $_['id'] })
        $targets | Should -Contain 'all_users'
        $targets | Should -Contain 'gid-bg'
        Should -Invoke Write-Host -ParameterFilter { "$Object" -match '\[FAIL\] BG: passkeys enabled - an all_users passkey target' }
    }

    It '-Apply -ReplaceExistingTargets converges, verifies by re-read, and passes every break-glass invariant' {
        Set-AmpMocks
        & $script:Amp -Apply -ReplaceExistingTargets -Confirm:$false -WarningAction SilentlyContinue
        $LASTEXITCODE | Should -Be 0
        $f = $global:AmpTest.Configs['Fido2']
        $admin = @($f['passkeyProfiles'] | Where-Object { $_['name'] -eq 'Contoso - Admins (device-bound, attested)' })[0]
        $admin['passkeyTypes'] | Should -Be 'deviceBound'
        $admin['attestationEnforcement'] | Should -Be 'registrationOnly'
        @($f['passkeyProfiles'] | Where-Object { $_['name'] -eq 'Default passkey profile' }).Count | Should -Be 1   # never dropped
        $bg = @($f['includeTargets'] | Where-Object { $_['id'] -eq 'gid-bg' })[0]
        @($bg['allowedPasskeyProfiles']) | Should -Be @($admin['id'])
        $tap = $global:AmpTest.Configs['TemporaryAccessPass']
        $tap['state'] | Should -Be 'enabled'
        $tap['maximumLifetimeInMinutes'] | Should -BeGreaterOrEqual 480   # the joiner workflow's TAP must fit
        @($tap['excludeTargets'] | ForEach-Object { $_['id'] }) | Should -Contain 'gid-bg'
        $global:AmpTest.Configs['MicrosoftAuthenticator']['isSoftwareOathEnabled'] | Should -BeFalse
        $global:AmpTest.Policy['registrationEnforcement']['authenticationMethodsRegistrationCampaign']['state'] | Should -Be 'enabled'
        # Without -IncludeStaffRollout there is no workforce profile and SMS/voice are untouched.
        @($f['passkeyProfiles'] | Where-Object { $_['name'] -like 'Contoso - Workforce*' }).Count | Should -Be 0
        $global:AmpTest.Configs['Sms']['state'] | Should -Be 'enabled'
        # A second run is a no-op.
        $before = $global:AmpTest.Patches.Count
        & $script:Amp -Apply -ReplaceExistingTargets -Confirm:$false -WarningAction SilentlyContinue
        $global:AmpTest.Patches.Count | Should -Be $before
    }

    It '-IncludeStaffRollout adds the workforce profile (synced allowed, attestation off) for the workforce group only' {
        Set-AmpMocks
        & $script:Amp -Apply -ReplaceExistingTargets -IncludeStaffRollout -AdminAllowedAaguids 'cb69481e-8ff7-4039-93ec-0a2729a154a8' -Confirm:$false -WarningAction SilentlyContinue
        $LASTEXITCODE | Should -Be 0
        $f = $global:AmpTest.Configs['Fido2']
        $staff = @($f['passkeyProfiles'] | Where-Object { $_['name'] -like 'Contoso - Workforce*' })[0]
        $staff['attestationEnforcement'] | Should -Be 'disabled'
        (($staff['passkeyTypes'] -split ',') | Sort-Object) | Should -Be @('deviceBound', 'synced')
        $wf = @($f['includeTargets'] | Where-Object { $_['id'] -eq 'gid-workforce' })[0]
        @($wf['allowedPasskeyProfiles']) | Should -Be @($staff['id'])
        @($f['includeTargets'] | Where-Object { $_['id'] -eq 'all_users' }).Count | Should -Be 0
    }

    It '-IncludeStaffRollout WITHOUT an admin AAGUID list is a FAIL and the workforce target is not applied' {
        Set-AmpMocks
        & $script:Amp -Apply -ReplaceExistingTargets -IncludeStaffRollout -Confirm:$false -WarningAction SilentlyContinue
        $LASTEXITCODE | Should -Be 1
        Should -Invoke Write-Host -ParameterFilter { "$Object" -match '\[FAIL\] Admin assurance' }
        $f = $global:AmpTest.Configs['Fido2']
        @($f['passkeyProfiles'] | Where-Object { $_['name'] -like 'Contoso - Workforce*' }).Count | Should -Be 0
        @($f['includeTargets'] | Where-Object { $_['id'] -eq 'gid-workforce' }).Count | Should -Be 0
        # The admin side is still converged (the refusal is scoped to the staff target).
        @($f['includeTargets'] | Where-Object { $_['id'] -eq 'gid-bg' }).Count | Should -Be 1
    }

    It '-AcceptAdminSyncedPasskeyRisk lets the rollout proceed, flagged WARN (a recorded risk acceptance)' {
        Set-AmpMocks
        & $script:Amp -Apply -ReplaceExistingTargets -IncludeStaffRollout -AcceptAdminSyncedPasskeyRisk -Confirm:$false -WarningAction SilentlyContinue
        $LASTEXITCODE | Should -Be 0
        Should -Invoke Write-Host -ParameterFilter { "$Object" -match '\[WARN\] Admin assurance' }
        @($global:AmpTest.Configs['Fido2']['includeTargets'] | Where-Object { $_['id'] -eq 'gid-workforce' }).Count | Should -Be 1
    }

    It 'stops the passkey section (and changes nothing there) when passkey profiles are not turned on' {
        Set-AmpMocks -NoPasskeyProfiles
        & $script:Amp -Apply -Confirm:$false -WarningAction SilentlyContinue
        $LASTEXITCODE | Should -Be 1
        @($global:AmpTest.Patches | Where-Object { $_ -like '*/fido2' }).Count | Should -Be 0
        Should -Invoke Write-Host -ParameterFilter { "$Object" -match 'passkey profiles are not turned on' }
    }

    It '-DisableSmsVoice refuses while someone still has phone methods only' {
        Set-AmpMocks -Registration @{ 'u-1' = @('mobilePhone'); 'u-2' = @('passKeyDeviceBound'); 'bg-1' = @('mobilePhone') }
        & $script:Amp -Apply -ReplaceExistingTargets -DisableSmsVoice -Confirm:$false -WarningAction SilentlyContinue
        $LASTEXITCODE | Should -Be 1
        $global:AmpTest.Configs['Sms']['state'] | Should -Be 'enabled'
        Should -Invoke Write-Host -ParameterFilter { "$Object" -match '1 user\(s\) have only phone methods' }   # break-glass not counted
    }

    It '-DisableSmsVoice turns SMS and voice off once nobody depends on them' {
        Set-AmpMocks -Registration @{ 'u-1' = @('passKeySynced', 'mobilePhone') }
        & $script:Amp -Apply -ReplaceExistingTargets -DisableSmsVoice -Confirm:$false -WarningAction SilentlyContinue
        $LASTEXITCODE | Should -Be 0
        $global:AmpTest.Configs['Sms']['state'] | Should -Be 'disabled'
        $global:AmpTest.Configs['Voice']['state'] | Should -Be 'disabled'
    }

    It '-Apply -WhatIf sends no PATCH' {
        Set-AmpMocks
        & $script:Amp -Apply -WhatIf -WarningAction SilentlyContinue
        $global:AmpTest.Patches.Count | Should -Be 0
    }

    It 'refuses a PIM-for-Groups group as an admin target before any Graph call' {
        Set-AmpMocks
        { & $script:Amp -AdminGroupMailNicknames 'admin-accounts', 'pim-tier0-ca-admins' } | Should -Throw '*no standing members*'
        Should -Invoke Invoke-MgGraphRequest -Times 0
    }

    It 'targets the STANDING Admin-Accounts group with the admin profile and the campaign' {
        Set-AmpMocks
        & $script:Amp -Apply -ReplaceExistingTargets -Confirm:$false -WarningAction SilentlyContinue
        $LASTEXITCODE | Should -Be 0
        $f = $global:AmpTest.Configs['Fido2']
        $admin = @($f['passkeyProfiles'] | Where-Object { $_['name'] -like 'Contoso - Admins*' })[0]
        $t = @($f['includeTargets'] | Where-Object { $_['id'] -eq 'gid-admins' })[0]
        @($t['allowedPasskeyProfiles']) | Should -Be @($admin['id'])
        @($global:AmpTest.Policy['registrationEnforcement']['authenticationMethodsRegistrationCampaign']['includeTargets'] | ForEach-Object { $_['id'] }) | Should -Be @('gid-admins')
    }

    It 'FAILs when Admin-Accounts does not exist (no admin would have a passkey target)' {
        Set-AmpMocks
        Mock Invoke-MgGraphRequest -ParameterFilter { "$Uri" -match 'mailNickname(%20| )eq(%20| )(%27|'')admin-accounts(%27|'')' } { @{ value = @() } }
        & $script:Amp -Apply -ReplaceExistingTargets -Confirm:$false -WarningAction SilentlyContinue
        $LASTEXITCODE | Should -Be 1
        Should -Invoke Write-Host -ParameterFilter { "$Object" -match '\[FAIL\] Group admin-accounts - missing' }
    }

    It 'refuses the passkey PATCH when a break-glass key is a model outside -AdminAllowedAaguids' {
        Set-AmpMocks -Keys @{ 'bg-1' = @('cb69481e-8ff7-4039-93ec-0a2729a154a8', '99999999-9999-9999-9999-999999999999') }
        & $script:Amp -Apply -ReplaceExistingTargets -AdminAllowedAaguids 'cb69481e-8ff7-4039-93ec-0a2729a154a8' -Confirm:$false -WarningAction SilentlyContinue
        $LASTEXITCODE | Should -Be 1
        @($global:AmpTest.Patches | Where-Object { $_ -like '*/fido2' }).Count | Should -Be 0
        Should -Invoke Write-Host -ParameterFilter { "$Object" -match '\[FAIL\] BG: key models - bg-admin-01.*99999999' }
        # The other sections (break-glass EXCLUSIONS) still converge.
        @($global:AmpTest.Configs['TemporaryAccessPass']['excludeTargets'] | ForEach-Object { $_['id'] }) | Should -Contain 'gid-bg'
    }

    It 'sends the allow-list when every break-glass key is an issued model' {
        Set-AmpMocks
        & $script:Amp -Apply -ReplaceExistingTargets -AdminAllowedAaguids 'CB69481E-8FF7-4039-93EC-0A2729A154A8' -Confirm:$false -WarningAction SilentlyContinue
        $LASTEXITCODE | Should -Be 0
        $admin = @($global:AmpTest.Configs['Fido2']['passkeyProfiles'] | Where-Object { $_['name'] -like 'Contoso - Admins*' })[0]
        $admin['keyRestrictions']['isEnforced'] | Should -BeTrue
        @($admin['keyRestrictions']['aaGuids']) | Should -Be @('cb69481e-8ff7-4039-93ec-0a2729a154a8')
        Should -Invoke Write-Host -ParameterFilter { "$Object" -match '\[PASS\] BG: key models' }
    }

    It '-BuildAccountUpn FAILs while the build account is in no admin target group, PASSes once it is' {
        Set-AmpMocks -BuildGroups @('gid-other')
        & $script:Amp -Apply -ReplaceExistingTargets -BuildAccountUpn 'admin@contosolab.onmicrosoft.com' -Confirm:$false -WarningAction SilentlyContinue
        $LASTEXITCODE | Should -Be 1
        Should -Invoke Write-Host -ParameterFilter { "$Object" -match '\[FAIL\] Build account passkey target' }
        Set-AmpMocks
        & $script:Amp -Apply -ReplaceExistingTargets -BuildAccountUpn 'admin@contosolab.onmicrosoft.com' -Confirm:$false -WarningAction SilentlyContinue
        $LASTEXITCODE | Should -Be 0
        Should -Invoke Write-Host -ParameterFilter { "$Object" -match '\[PASS\] Build account passkey target - covered by gid-admins' }
    }
}
