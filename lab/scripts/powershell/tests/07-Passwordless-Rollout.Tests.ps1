# Pester 5 tests for 07-Passwordless-Rollout.ps1: the readiness maths (pure
# functions from the syntax tree) and full runs against a mocked Graph -
# TAP issuance guard rails and the CA008 go/no-go. No tenant is contacted.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    $script:Rollout = Get-LabScriptPath '07-Passwordless-Rollout.ps1'
    . (Get-ScriptFunctionBlock -Path $script:Rollout -Name 'Get-AuthMethodClass', 'Test-StrengthSatisfied', 'Get-Ca008Readiness')

    function Set-RolloutMocks {
        param([string]$TapState = 'enabled', [hashtable]$Registration = $null, [object[]]$SignIns = @())
        $global:RolloutTest = @{
            TapState     = $TapState
            Registration = $(if ($Registration) { $Registration } else { @{ 'u-dana' = @('passKeyDeviceBound'); 'u-marcus' = @('mobilePhone'); 'bg-1' = @('fido2SecurityKey') } })
            SignIns      = $SignIns
            Posts        = [System.Collections.Generic.List[object]]::new()
            PilotAdds    = [System.Collections.Generic.List[string]]::new()
        }
        Mock Write-Host {}
        Mock Out-Host {}
        Mock Get-MgContext { New-MgContextStub -Scopes @('User.Read.All', 'GroupMember.Read.All', 'AuditLog.Read.All', 'Policy.Read.All', 'UserAuthenticationMethod.ReadWrite.All') }
        Mock Connect-MgGraph { throw 'tests must never connect' }
        Mock Invoke-MgGraphRequest {
            $t = $global:RolloutTest
            $users = @{
                'u-dana'   = @{ id = 'u-dana'; userPrincipalName = 'dana.okafor@contoso.test'; accountEnabled = $true; userType = 'Member' }
                'u-marcus' = @{ id = 'u-marcus'; userPrincipalName = 'marcus.bello@contoso.test'; accountEnabled = $true; userType = 'Member' }
                'bg-1'     = @{ id = 'bg-1'; userPrincipalName = 'bg-admin-01@lab.onmicrosoft.com'; accountEnabled = $true; userType = 'Member' }
            }
            if ($Method -eq 'POST' -and "$Uri" -match '/groups/g-pilot/members/\$ref') {
                $t.PilotAdds.Add(($Body | ConvertFrom-Json -AsHashtable)['@odata.id'])
                return $null
            }
            if ($Method -eq 'POST' -and $Uri -match '/users/(?<id>[^/]+)/authentication/temporaryAccessPassMethods') {
                $t.Posts.Add(@{ User = $Matches.id; Body = ($Body | ConvertFrom-Json -AsHashtable) })
                return @{ temporaryAccessPass = 'TAP-PLAINTEXT-123'; lifetimeInMinutes = 480 }
            }
            switch -Regex ($Uri) {
                'groups\?.*break-glass-admins' { return @{ value = @(@{ id = 'g-bg'; displayName = 'Break-Glass-Admins' }) } }
                'groups\?.*all-nurses' { return @{ value = @(@{ id = 'g-nurses'; displayName = 'All-Nurses' }) } }
                'groups\?.*ca008-pilot-phishingresistant' { return @{ value = @(@{ id = 'g-pilot'; displayName = 'CA008-Pilot-PhishingResistant' }) } }
                '/groups/g-pilot/transitiveMembers' { return @{ value = @() } }
                '/groups/g-bg/transitiveMembers' { return @{ value = @($users['bg-1']) } }
                '/groups/g-nurses/transitiveMembers' { return @{ value = @($users['u-dana'], $users['u-marcus']) } }
                '/userRegistrationDetails' { return @{ value = @(foreach ($k in $t.Registration.Keys) { @{ id = $k; methodsRegistered = $t.Registration[$k] } }) } }
                'authenticationMethodConfigurations/TemporaryAccessPass' {
                    return @{ state = $t.TapState; minimumLifetimeInMinutes = 60; maximumLifetimeInMinutes = 480; isUsableOnce = $true
                        includeTargets = @(@{ id = 'all_users'; targetType = 'group' }); excludeTargets = @(@{ id = 'g-bg'; targetType = 'group' }) }
                }
                'users\?.*filter=.*marcus' { return @{ value = @($users['u-marcus']) } }
                'users\?.*filter=.*dana' { return @{ value = @($users['u-dana']) } }
                'users\?.*filter=.*bg-admin-01' { return @{ value = @($users['bg-1']) } }
                '/users/u-marcus/transitiveMemberOf' { return @{ value = @(@{ id = 'g-nurses' }) } }
                '/users/u-dana/transitiveMemberOf' { return @{ value = @(@{ id = 'g-nurses' }) } }
                '/users/bg-1/transitiveMemberOf' { return @{ value = @(@{ id = 'g-bg' }) } }
                'temporaryAccessPassMethods' { return @{ value = @() } }
                '/conditionalAccess/policies' {
                    return @{ value = @(@{ id = 'ca-008'; displayName = 'CA008 - Phishing-resistant authentication strength - all users (report-only)'; state = 'enabledForReportingButNotEnforced'
                                grantControls = @{ operator = 'OR'; builtInControls = @(); authenticationStrength = @{ id = 'str-pr' } }
                                conditions = @{ users = @{ includeUsers = @('All'); excludeUsers = @(); includeGroups = @(); excludeGroups = @('g-bg'); includeRoles = @()
                                        excludeGuestsOrExternalUsers = @{ guestOrExternalUserTypes = 'internalGuest,b2bCollaborationGuest,b2bCollaborationMember,b2bDirectConnectUser,otherExternalUser,serviceProvider' } } } }) }
                }
                'authenticationStrength/policies/str-pr' { return @{ id = 'str-pr'; allowedCombinations = @('fido2', 'windowsHelloForBusiness', 'x509CertificateMultiFactor') } }
                '/v1\.0/users\?\$select' { return @{ value = @($users.Values) + @(@{ id = 'g-guest'; userPrincipalName = 'vendor_x#EXT#@contoso.test'; accountEnabled = $true; userType = 'Guest' }) } }
                '/auditLogs/signIns' { return @{ value = @($t.SignIns) } }
                default { throw "unexpected Graph call in test: $Method $Uri" }
            }
        }
    }
}

AfterAll { Remove-Variable -Name RolloutTest -Scope Global -ErrorAction SilentlyContinue }

Describe 'Readiness maths' {
    It 'classifies <Methods> as <Class>' -ForEach @(
        @{ Methods = @('passKeyDeviceBoundAuthenticator'); Class = 'PhishingResistantDeviceBound' }
        @{ Methods = @('passKeySynced', 'mobilePhone'); Class = 'PhishingResistantSyncedOnly' }
        @{ Methods = @('mobilePhone', 'officePhone'); Class = 'PhoneOnly' }
        @{ Methods = @('microsoftAuthenticatorPush', 'mobilePhone'); Class = 'PhishableMfaOnly' }
        @{ Methods = @('temporaryAccessPass'); Class = 'None' }   # a TAP is a bootstrap, not MFA
        @{ Methods = @(); Class = 'None' }
    ) {
        (Get-AuthMethodClass -MethodsRegistered $Methods).Class | Should -Be $Class
    }

    It 'maps registered methods onto authentication-strength combinations' {
        Test-StrengthSatisfied -MethodsRegistered @('passKeySynced') -AllowedCombinations @('fido2') | Should -BeTrue
        Test-StrengthSatisfied -MethodsRegistered @('windowsHelloForBusiness') -AllowedCombinations @('fido2') | Should -BeFalse
        Test-StrengthSatisfied -MethodsRegistered @('microsoftAuthenticatorPush') -AllowedCombinations @('fido2', 'windowsHelloForBusiness') | Should -BeFalse
    }

    It 'is NOT READY while anyone in scope lacks an accepted method, READY when nobody does' {
        $users = @([pscustomobject]@{ Id = 'a'; UserPrincipalName = 'a@x'; UserType = 'Member' }, [pscustomobject]@{ Id = 'b'; UserPrincipalName = 'b@x'; UserType = 'Guest' })
        $r = Get-Ca008Readiness -InScopeUsers $users -RegistrationById @{ a = @('passKeyDeviceBound') } -AllowedCombinations @('fido2') -ReportOnlyFailureUserIds @('b')
        $r.Verdict | Should -Be 'NOT READY'
        $r.PctSatisfying | Should -Be 50
        $r.GuestsLacking | Should -Be 1
        $r.ReportOnlyBlocked | Should -Be 1
        (Get-Ca008Readiness -InScopeUsers $users[0] -RegistrationById @{ a = @('passKeyDeviceBound') } -AllowedCombinations @('fido2')).Verdict | Should -Be 'READY'
    }

    It 'does not count a report-only failure for someone who has registered since' {
        $users = @([pscustomobject]@{ Id = 'a'; UserPrincipalName = 'a@x'; UserType = 'Member' })
        $r = Get-Ca008Readiness -InScopeUsers $users -RegistrationById @{ a = @('passKeyDeviceBound') } -AllowedCombinations @('fido2') -ReportOnlyFailureUserIds @('a')
        $r.Verdict | Should -Be 'READY'
        $r.ReportOnlyBlocked | Should -Be 0
    }

    It 'is never READY with nobody in scope' {
        (Get-Ca008Readiness -InScopeUsers @() -RegistrationById @{} -AllowedCombinations @('fido2')).Verdict | Should -Be 'NOT READY'
    }
}

Describe '07-Passwordless-Rollout.ps1 (mocked Graph)' {
    BeforeEach { $global:LASTEXITCODE = 0 }

    It 'reports pilot registration status per group, excluding break-glass' {
        Set-RolloutMocks
        $r = & $script:Rollout -Stage Pilot -OutputDirectory (Join-Path $TestDrive 'pw') -WarningAction SilentlyContinue
        $g = $r.GroupSummary | Where-Object Population -eq 'All-Nurses'
        $g.Users | Should -Be 2
        $g.PhishingResistant | Should -Be 1
        $g.PhoneOnly | Should -Be 1
        $g.PctPhishingResistant | Should -Be 50
    }

    It 'CA008 is NOT READY while Marcus has phone MFA only, and -FailIfNotReady exits 1' {
        Set-RolloutMocks -SignIns @(@{ userId = 'u-marcus'; appliedConditionalAccessPolicies = @(@{ id = 'ca-008'; result = 'reportOnlyFailure' }) })
        $r = & $script:Rollout -OutputDirectory (Join-Path $TestDrive 'pw2') -FailIfNotReady -WarningAction SilentlyContinue
        $LASTEXITCODE | Should -Be 1
        $r.Ca008.Verdict | Should -Be 'NOT READY'
        $r.Ca008.InScope | Should -Be 2              # break-glass excluded by the policy
        $r.Ca008.ReportOnlyBlocked | Should -Be 1
    }

    It 'CA008 is READY once everyone in scope has a passkey' {
        Set-RolloutMocks -Registration @{ 'u-dana' = @('passKeyDeviceBound'); 'u-marcus' = @('passKeySynced') }
        $r = & $script:Rollout -OutputDirectory (Join-Path $TestDrive 'pw3') -FailIfNotReady -WarningAction SilentlyContinue
        $r.Ca008.Verdict | Should -Be 'READY'
        $LASTEXITCODE | Should -Be 0
    }

    It 'leaves guests out of CA008 scope, as the policy itself does' {
        Set-RolloutMocks
        $r = & $script:Rollout -OutputDirectory (Join-Path $TestDrive 'pw-guest') -WarningAction SilentlyContinue
        $r.Ca008.InScope | Should -Be 2
        $r.Ca008.GuestsLacking | Should -Be 0
    }

    It 'lists ready users missing from the CA008 pilot, and adds them only with -PromoteReadyToPilot' {
        Set-RolloutMocks
        $r = & $script:Rollout -OutputDirectory (Join-Path $TestDrive 'pw-pilot1') -WarningAction SilentlyContinue
        $r.ReadyNotInPilot | Should -Be 1          # Dana (passkey); Marcus has phone MFA only
        $global:RolloutTest.PilotAdds.Count | Should -Be 0
        $r = & $script:Rollout -OutputDirectory (Join-Path $TestDrive 'pw-pilot2') -PromoteReadyToPilot -WarningAction SilentlyContinue
        $r.PromotedToPilot | Should -Be 1
        @($global:RolloutTest.PilotAdds) | Should -Be @('https://graph.microsoft.com/v1.0/directoryObjects/u-dana')
    }

    It 'issues a one-time 480-minute TAP and never returns or prints it as plain text' {
        Set-RolloutMocks
        $r = & $script:Rollout -IssueTapFor 'marcus.bello@contoso.test' -OutputDirectory (Join-Path $TestDrive 'pw4') -WarningAction SilentlyContinue
        $global:RolloutTest.Posts.Count | Should -Be 1
        $global:RolloutTest.Posts[0].Body['lifetimeInMinutes'] | Should -Be 480
        $global:RolloutTest.Posts[0].Body['isUsableOnce'] | Should -BeTrue
        $tap = $r.TapsIssued[0]
        $tap.Status | Should -Be 'issued'
        $tap.TemporaryAccessPass | Should -BeOfType [securestring]
        ($tap.TemporaryAccessPass | ConvertFrom-SecureString -AsPlainText) | Should -Be 'TAP-PLAINTEXT-123'
        ($r | ConvertTo-Json -Depth 6) | Should -Not -Match 'TAP-PLAINTEXT-123'
        Should -Invoke Write-Host -Times 0 -ParameterFilter { "$Object" -match 'TAP-PLAINTEXT-123' }
        @(Get-ChildItem -Path (Join-Path $TestDrive 'pw4') -Recurse -File | Select-String -SimpleMatch 'TAP-PLAINTEXT-123').Count | Should -Be 0
    }

    It 'refuses a TAP for break-glass outright' {
        Set-RolloutMocks
        $r = & $script:Rollout -IssueTapFor 'bg-admin-01@lab.onmicrosoft.com' -OutputDirectory (Join-Path $TestDrive 'pw5') -WarningAction SilentlyContinue
        $r.TapsIssued[0].Status | Should -Be 'REFUSED-break-glass'
        $global:RolloutTest.Posts.Count | Should -Be 0
    }

    It 'skips a user who already has a phishing-resistant method (no needless credential)' {
        Set-RolloutMocks
        $r = & $script:Rollout -IssueTapFor 'dana.okafor@contoso.test' -OutputDirectory (Join-Path $TestDrive 'pw6') -WarningAction SilentlyContinue
        $r.TapsIssued[0].Status | Should -Be 'SKIPPED-already-registered'
        $global:RolloutTest.Posts.Count | Should -Be 0
    }

    It 'fails (exit 1) and issues nothing when the TAP policy is disabled' {
        Set-RolloutMocks -TapState 'disabled'
        $r = & $script:Rollout -IssueTapFor 'marcus.bello@contoso.test' -OutputDirectory (Join-Path $TestDrive 'pw7') -WarningAction SilentlyContinue
        $LASTEXITCODE | Should -Be 1
        $r.TapsIssued[0].Status | Should -Be 'FAILED-policy'
        $global:RolloutTest.Posts.Count | Should -Be 0
    }

    It '-WhatIf issues nothing and writes nothing' {
        Set-RolloutMocks
        $dir = Join-Path $TestDrive 'pw8'
        $null = & $script:Rollout -IssueTapFor 'marcus.bello@contoso.test' -OutputDirectory $dir -WhatIf -WarningAction SilentlyContinue
        $global:RolloutTest.Posts.Count | Should -Be 0
        Test-Path $dir | Should -BeFalse
    }
}
