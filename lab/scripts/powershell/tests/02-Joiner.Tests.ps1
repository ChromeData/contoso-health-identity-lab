# Pester 5 tests for 02-Joiner.ps1 - every Graph call is mocked; no tenant.
# The assignment model comes from the real lab/iga/access-catalog.json:
# "Nurse - Clinical Apps" is T3 automatic (birthright: verify delivery, never
# adminAdd), "ICU - Float Access" is T2 request (adminAdd via the request policy).
# Run: lab/scripts/powershell/tests/Invoke-LabTests.ps1

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    # Real SDK modules so Mock copies the true cmdlet signatures.
    Import-Module Microsoft.Graph.Users, Microsoft.Graph.Groups, Microsoft.Graph.Identity.Governance,
        Microsoft.Graph.Identity.DirectoryManagement -ErrorAction Stop
    $script:Joiner = Get-LabScriptPath '02-Joiner.ps1'

    function Get-AssignmentField($Body, [string]$Name) {
        $a = $Body.Assignment
        if ($a -is [System.Collections.IDictionary]) { return $a[$Name] }
        return $a.AdditionalProperties[$Name]
    }

    function Set-JoinerMocks {
        param(
            [bool]$PackageExists = $true,
            [object[]]$ExistingAssignments = @(),
            [bool]$AlreadyLicensed = $false,
            [string]$PackageName = 'Nurse - Clinical Apps',
            # Policies on the package: an automatic (birthright) one and/or a request one.
            [bool]$HasAutoPolicy = $true,
            [bool]$HasRequestPolicy = $false
        )
        # Mock bodies run inside the script under test, where $script: is THAT
        # script's scope, so per-test state lives in one global hashtable.
        $global:JoinerTest = @{ PackageExists = $PackageExists; ExistingAssignments = $ExistingAssignments; AlreadyLicensed = $AlreadyLicensed; Requests = [System.Collections.Generic.List[object]]::new()
            PackageName = $PackageName; HasAutoPolicy = $HasAutoPolicy; HasRequestPolicy = $HasRequestPolicy }
        Mock Start-Sleep {}
        Mock Write-Host {}
        Mock Get-MgContext { New-MgContextStub }
        Mock Connect-MgGraph { throw 'tests must never connect' }
        Mock Get-MgUser {
            [pscustomobject]@{
                Id = 'u-dana'; DisplayName = 'Dana Okafor'; Department = 'Nursing'; UsageLocation = $null
                AssignedLicenses = @(if ($global:JoinerTest.AlreadyLicensed) { [pscustomobject]@{ SkuId = 'sku-e5' } })
            }
        }
        Mock Get-MgSubscribedSku { @([pscustomobject]@{ SkuPartNumber = 'SPE_E5'; SkuId = 'sku-e5'; ConsumedUnits = 1; PrepaidUnits = [pscustomobject]@{ Enabled = 25 } }) }
        Mock Update-MgUser {}
        Mock Set-MgUserLicense { [pscustomobject]@{ Id = 'u-dana' } }
        Mock Get-MgGroup { [pscustomobject]@{ Id = "g-$($Filter -replace '.*''(.+)''.*', '$1')"; DisplayName = 'grp' } }
        # Dana is already in All-Nurses (dynamic) and in no app group.
        Mock Get-MgGroupMember { @(if ($GroupId -eq 'g-all-nurses') { [pscustomobject]@{ Id = 'u-dana' } }) }
        Mock New-MgGroupMember {}
        Mock Get-MgEntitlementManagementAccessPackage {
            if ($global:JoinerTest.PackageExists) { [pscustomobject]@{ Id = 'ap-1'; DisplayName = $global:JoinerTest.PackageName } }
        } -ParameterFilter { $Filter }
        Mock Get-MgEntitlementManagementAccessPackage {
            $t = $global:JoinerTest
            [pscustomobject]@{ Id = 'ap-1'; AssignmentPolicies = @(
                    if ($t.HasAutoPolicy) { [pscustomobject]@{ Id = 'pol-auto'; DisplayName = "Birthright - $($t.PackageName)"; AutomaticRequestSettings = [pscustomobject]@{ RequestAccessForAllowedTargets = $true } } }
                    if ($t.HasRequestPolicy) { [pscustomobject]@{ Id = 'pol-180'; DisplayName = "$($t.PackageName) - 180 day"; AutomaticRequestSettings = $null } }
                ) }
        } -ParameterFilter { $AccessPackageId }
        Mock Get-MgEntitlementManagementAssignment { $global:JoinerTest.ExistingAssignments }
        Mock New-MgEntitlementManagementAssignmentRequest { $global:JoinerTest.Requests.Add($BodyParameter); [pscustomobject]@{ Id = 'req-1'; State = 'submitted' } }
    }
}

AfterAll { Remove-Variable -Name JoinerTest -Scope Global -ErrorAction SilentlyContinue }

Describe '02-Joiner.ps1' {
    BeforeEach { $global:LASTEXITCODE = 0 }

    It 'birthright package: licenses the joiner, confirms the AUTOMATIC assignment was delivered, and sends no request' {
        Set-JoinerMocks -ExistingAssignments @([pscustomobject]@{ Id = 'asg-auto'; State = 'delivered' })
        & $script:Joiner -UserPrincipalName 'dana.okafor@contoso.test' -LicenseSkuPartNumber 'SPE_E5' -WarningAction SilentlyContinue
        $LASTEXITCODE | Should -Be 0
        Should -Invoke Update-MgUser -Times 1 -Exactly -ParameterFilter { $UsageLocation -eq 'US' }
        Should -Invoke Set-MgUserLicense -Times 1 -Exactly
        Should -Invoke New-MgEntitlementManagementAssignmentRequest -Times 0
        Should -Invoke Write-Host -ParameterFilter { "$Object" -match 'delivered by the automatic \(birthright\) policy' }
        # Governed path: the package owns the app-group grant, never a direct add.
        Should -Invoke New-MgGroupMember -Times 0
    }

    It 'birthright package not delivered in time: exits 1 (INCOMPLETE, names employeeHireDate) and still never adminAdds' {
        Set-JoinerMocks
        & $script:Joiner -UserPrincipalName 'dana.okafor@contoso.test' -LicenseSkuPartNumber 'SPE_E5' -WaitForAssignmentSeconds 0 -WarningVariable wv -WarningAction SilentlyContinue
        $LASTEXITCODE | Should -Be 1
        ($wv -join "`n") | Should -Match 'employeeHireDate'
        ($wv -join "`n") | Should -Match 'Joiner INCOMPLETE'
        Should -Invoke New-MgEntitlementManagementAssignmentRequest -Times 0
    }

    It 'birthright package without an automatic policy: exits 1, no request (even if a stray request policy exists)' {
        Set-JoinerMocks -HasAutoPolicy $false -HasRequestPolicy $true
        & $script:Joiner -UserPrincipalName 'dana.okafor@contoso.test' -LicenseSkuPartNumber 'SPE_E5' -WarningVariable wv -WarningAction SilentlyContinue
        $LASTEXITCODE | Should -Be 1
        ($wv -join "`n") | Should -Match 'Set-AutoAssignmentPolicies'
        Should -Invoke New-MgEntitlementManagementAssignmentRequest -Times 0
    }

    It 'requestable (T2) package: adminAdd through the REQUEST policy, never the automatic one' {
        Set-JoinerMocks -PackageName 'ICU - Float Access' -HasAutoPolicy $true -HasRequestPolicy $true
        & $script:Joiner -UserPrincipalName 'dana.okafor@contoso.test' -AccessPackageName 'ICU - Float Access' -LicenseSkuPartNumber 'SPE_E5' -WarningAction SilentlyContinue
        $LASTEXITCODE | Should -Be 0
        Should -Invoke New-MgEntitlementManagementAssignmentRequest -Times 1 -Exactly
        $body = $global:JoinerTest.Requests[0]
        $body.RequestType | Should -Be 'adminAdd'
        # The SDK converts the hashtable into its request model; v1.0 fields the
        # model lacks (targetId, assignmentPolicyId) ride in AdditionalProperties,
        # which the SDK serialises into the request body.
        Get-AssignmentField $body 'targetId' | Should -Be 'u-dana'
        Get-AssignmentField $body 'accessPackageId' | Should -Be 'ap-1'
        Get-AssignmentField $body 'assignmentPolicyId' | Should -Be 'pol-180'
    }

    It 'requestable package: does not request again when an assignment is already delivered' {
        Set-JoinerMocks -PackageName 'ICU - Float Access' -HasRequestPolicy $true -AlreadyLicensed $true -ExistingAssignments @([pscustomobject]@{ Id = 'asg-1'; State = 'delivered' })
        & $script:Joiner -UserPrincipalName 'dana.okafor@contoso.test' -AccessPackageName 'ICU - Float Access' -LicenseSkuPartNumber 'SPE_E5' -WarningAction SilentlyContinue
        $LASTEXITCODE | Should -Be 0
        Should -Invoke Set-MgUserLicense -Times 0
        Should -Invoke New-MgEntitlementManagementAssignmentRequest -Times 0
    }

    It 'refuses a package the access catalog does not know (never guesses the model)' {
        Set-JoinerMocks -PackageName 'Mystery - Apps'
        & $script:Joiner -UserPrincipalName 'dana.okafor@contoso.test' -AccessPackageName 'Mystery - Apps' -LicenseSkuPartNumber 'SPE_E5' -WarningVariable wv -WarningAction SilentlyContinue
        $LASTEXITCODE | Should -Be 1
        ($wv -join "`n") | Should -Match 'not in .*access-catalog\.json'
        Should -Invoke New-MgEntitlementManagementAssignmentRequest -Times 0
    }

    It 'never sends adminAdd for any package the catalog marks automatic' {
        $cat = Get-Content -LiteralPath (Join-Path $PSScriptRoot '..' '..' '..' 'iga' 'access-catalog.json') -Raw | ConvertFrom-Json -AsHashtable
        $auto = @($cat['accessPackages'] | Where-Object { [string]$_['assignment'] -eq 'automatic' } | ForEach-Object { [string]$_['name'] })
        $auto | Should -Contain 'Nurse - Clinical Apps'
        $auto | Should -Contain 'ICU - Critical Care Apps'
        foreach ($name in $auto) {
            Set-JoinerMocks -PackageName $name -HasAutoPolicy $true -HasRequestPolicy $true
            & $script:Joiner -UserPrincipalName 'dana.okafor@contoso.test' -AccessPackageName $name -LicenseSkuPartNumber 'SPE_E5' -WaitForAssignmentSeconds 0 -WarningAction SilentlyContinue
            Should -Invoke New-MgEntitlementManagementAssignmentRequest -Times 0 -Because "$name is birthright (automatic)"
        }
    }

    It 'exits 1 with INCOMPLETE (never "complete") when the package is missing' {
        Set-JoinerMocks -PackageExists $false
        & $script:Joiner -UserPrincipalName 'dana.okafor@contoso.test' -LicenseSkuPartNumber 'SPE_E5' -WarningVariable wv -WarningAction SilentlyContinue
        $LASTEXITCODE | Should -Be 1
        ($wv -join "`n") | Should -Match 'Joiner INCOMPLETE'
        Should -Invoke New-MgEntitlementManagementAssignmentRequest -Times 0
    }

    It 'exits 1 when the package lookup itself fails (a 403 must not read as "not found")' {
        Set-JoinerMocks
        Mock Get-MgEntitlementManagementAccessPackage { throw 'Forbidden' } -ParameterFilter { $Filter }
        & $script:Joiner -UserPrincipalName 'dana.okafor@contoso.test' -LicenseSkuPartNumber 'SPE_E5' -WarningVariable wv -WarningAction SilentlyContinue
        $LASTEXITCODE | Should -Be 1
        ($wv -join "`n") | Should -Match 'Access-package step failed'
    }

    It 'P1/P2 fallback (-UseAccessPackage:$false) adds the app groups directly and requests nothing' {
        Set-JoinerMocks
        & $script:Joiner -UserPrincipalName 'dana.okafor@contoso.test' -LicenseSkuPartNumber 'SPE_E5' -UseAccessPackage:$false -WarningAction SilentlyContinue
        $LASTEXITCODE | Should -Be 0
        Should -Invoke New-MgGroupMember -Times 1 -Exactly
        Should -Invoke New-MgGroupMember -ParameterFilter { $GroupId -eq 'g-app-servicenow-users' -and $DirectoryObjectId -eq 'u-dana' }
        Should -Invoke New-MgEntitlementManagementAssignmentRequest -Times 0
    }

    It '-WhatIf makes no change' {
        Set-JoinerMocks
        & $script:Joiner -UserPrincipalName 'dana.okafor@contoso.test' -LicenseSkuPartNumber 'SPE_E5' -WhatIf -WarningAction SilentlyContinue
        Should -Invoke Update-MgUser -Times 0
        Should -Invoke Set-MgUserLicense -Times 0
        Should -Invoke New-MgEntitlementManagementAssignmentRequest -Times 0
        Should -Invoke New-MgGroupMember -Times 0
    }

    It 'throws when the joiner has not been provisioned yet' {
        Set-JoinerMocks
        Mock Get-MgUser { $null }
        { & $script:Joiner -UserPrincipalName 'ghost@contoso.test' -LicenseSkuPartNumber 'SPE_E5' } | Should -Throw '*not found*'
    }

    It 'skips licensing (and says which SKUs exist) without -LicenseSkuPartNumber' {
        Set-JoinerMocks
        & $script:Joiner -UserPrincipalName 'dana.okafor@contoso.test' -WarningVariable wv -WarningAction SilentlyContinue
        Should -Invoke Set-MgUserLicense -Times 0
        ($wv -join "`n") | Should -Match 'SPE_E5'
    }
}
