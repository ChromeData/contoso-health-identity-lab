# Pester 5 tests for 03-Mover.ps1 - every Graph call is mocked; no tenant.
# The mover is VERIFICATION + FALLBACK: birthright (automatic) packages follow
# the HR attribute and are never removed or requested by the script; only
# requestable (T2) packages get adminRemove / adminAdd. The assignment model
# comes from the real lab/iga/access-catalog.json.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Import-Module Microsoft.Graph.Users, Microsoft.Graph.Identity.Governance -ErrorAction Stop
    $script:Mover = Get-LabScriptPath '03-Mover.ps1'
    $script:Joiner = Get-LabScriptPath '02-Joiner.ps1'

    function Set-MoverMocks {
        param(
            [bool]$Synced = $false,
            [string]$Department = 'Nursing',
            [bool]$OldPackageExists = $true,
            [bool]$HoldsOld = $true,
            [bool]$HoldsNew = $false,
            # The automatic policy delivers the new package after this many reads.
            [int]$DeliverNewAfter = -1
        )
        # Mock bodies run inside the script under test ($script: is its scope),
        # so per-test state lives in one global hashtable.
        $global:MoverTest = @{ Synced = $Synced; Department = $Department; OldPackageExists = $OldPackageExists; HoldsOld = $HoldsOld; HoldsNew = $HoldsNew
            DeliverNewAfter = $DeliverNewAfter; NewReads = 0; Requests = [System.Collections.Generic.List[object]]::new() }
        Mock Write-Host {}
        Mock Start-Sleep {}
        Mock Get-MgContext { New-MgContextStub }
        Mock Connect-MgGraph { throw 'tests must never connect' }
        Mock Get-MgUser {
            [pscustomobject]@{ Id = 'u-marcus'; DisplayName = 'Marcus Bello'; Department = $global:MoverTest.Department; JobTitle = 'Registered Nurse'; OnPremisesSyncEnabled = $global:MoverTest.Synced }
        }
        Mock Update-MgUser {}
        # Old packages: Nurse (automatic) / ICU - Float Access (request). New: ICU (automatic) / Pharmacy (request).
        Mock Get-MgEntitlementManagementAccessPackage { if ($global:MoverTest.OldPackageExists) { [pscustomobject]@{ Id = 'ap-old' } } } -ParameterFilter { $Filter -like '*Nurse - Clinical Apps*' -or $Filter -like '*ICU - Float Access*' }
        Mock Get-MgEntitlementManagementAccessPackage { [pscustomobject]@{ Id = 'ap-new' } } -ParameterFilter { $Filter -like '*ICU - Critical Care Apps*' -or $Filter -like '*Pharmacy - Controlled Substances Apps*' }
        Mock Get-MgEntitlementManagementAccessPackage {
            [pscustomobject]@{ Id = 'ap-new'; AssignmentPolicies = @(
                    [pscustomobject]@{ Id = 'pol-auto'; DisplayName = 'Birthright'; AutomaticRequestSettings = [pscustomobject]@{ RequestAccessForAllowedTargets = $true } },
                    [pscustomobject]@{ Id = 'pol-req'; DisplayName = 'Request - 180 day'; AutomaticRequestSettings = $null }) }
        } -ParameterFilter { $AccessPackageId }
        Mock Get-MgEntitlementManagementAssignment { if ($global:MoverTest.HoldsOld) { [pscustomobject]@{ Id = 'asg-old'; State = 'delivered' } } } -ParameterFilter { $Filter -like "*'ap-old'*" }
        Mock Get-MgEntitlementManagementAssignment {
            $t = $global:MoverTest; $t.NewReads++
            if ($t.HoldsNew -or ($t.DeliverNewAfter -ge 0 -and $t.NewReads -gt $t.DeliverNewAfter)) { [pscustomobject]@{ Id = 'asg-new'; State = 'delivered' } }
        } -ParameterFilter { $Filter -like "*'ap-new'*" }
        Mock New-MgEntitlementManagementAssignmentRequest { $global:MoverTest.Requests.Add($BodyParameter); [pscustomobject]@{ Id = "req-$($global:MoverTest.Requests.Count)"; State = 'submitted' } }
    }
}

AfterAll { Remove-Variable -Name MoverTest -Scope Global -ErrorAction SilentlyContinue }

Describe '03-Mover.ps1' {
    BeforeEach { $global:LASTEXITCODE = 0 }

    It 'birthright move (cloud-only user): writes the department, verifies the new package ARRIVES, sends no request at all' {
        Set-MoverMocks -DeliverNewAfter 2
        & $script:Mover -UserPrincipalName 'marcus.bello@contoso.test' -NewDepartment 'ICU' -WarningAction SilentlyContinue
        $LASTEXITCODE | Should -Be 0
        Should -Invoke Update-MgUser -Times 1 -Exactly
        Should -Invoke New-MgEntitlementManagementAssignmentRequest -Times 0
        Should -Invoke Write-Host -ParameterFilter { "$Object" -match 'removal pending \(automatic policy, grace period\)' }
        Should -Invoke Write-Host -ParameterFilter { "$Object" -match 'delivered by the birthright policy' }
    }

    It 'birthright move: new package not delivered -> INCOMPLETE, exit 1, and still no adminAdd' {
        Set-MoverMocks
        & $script:Mover -UserPrincipalName 'marcus.bello@contoso.test' -NewDepartment 'ICU' -WaitForAssignmentSeconds 60 -PollSeconds 30 -WarningVariable wv -WarningAction SilentlyContinue
        $LASTEXITCODE | Should -Be 1
        ($wv -join "`n") | Should -Match 'Mover INCOMPLETE'
        ($wv -join "`n") | Should -Match 'employeeHireDate'
        Should -Invoke New-MgEntitlementManagementAssignmentRequest -Times 0
    }

    It 'synced user: never writes the HR-owned department; birthright access already moved -> exit 0' {
        Set-MoverMocks -Synced $true -Department 'ICU' -HoldsOld $false -HoldsNew $true
        & $script:Mover -UserPrincipalName 'marcus.bello@contoso.test' -NewDepartment 'ICU' -WarningAction SilentlyContinue
        $LASTEXITCODE | Should -Be 0
        Should -Invoke Update-MgUser -Times 0
        Should -Invoke New-MgEntitlementManagementAssignmentRequest -Times 0
    }

    It 'synced user whose department has not arrived: birthright cannot move yet -> says so, exit 1, no requests' {
        Set-MoverMocks -Synced $true -Department 'Nursing'
        & $script:Mover -UserPrincipalName 'marcus.bello@contoso.test' -NewDepartment 'ICU' -WaitForSyncSeconds 0 -WarningVariable wv -WarningAction SilentlyContinue
        $LASTEXITCODE | Should -Be 1
        Should -Invoke Update-MgUser -Times 0
        ($wv -join "`n") | Should -Match 'still'
        ($wv -join "`n") | Should -Match 'STILL HELD'
        Should -Invoke New-MgEntitlementManagementAssignmentRequest -Times 0
    }

    It 'requestable (T2) packages: falls back to adminRemove FIRST, then adminAdd through the request policy' {
        Set-MoverMocks
        & $script:Mover -UserPrincipalName 'marcus.bello@contoso.test' -NewDepartment 'ICU' -OldAccessPackageName 'ICU - Float Access' -NewAccessPackageName 'Pharmacy - Controlled Substances Apps' -WarningAction SilentlyContinue
        $LASTEXITCODE | Should -Be 0
        $types = @($global:MoverTest.Requests | ForEach-Object RequestType)
        $types | Should -Be @('adminRemove', 'adminAdd')   # remove FIRST: no window holding both roles
        $add = $global:MoverTest.Requests[1].Assignment
        $pid_ = if ($add -is [System.Collections.IDictionary]) { $add['assignmentPolicyId'] } else { $add.AdditionalProperties['assignmentPolicyId'] }
        $pid_ | Should -Be 'pol-req'   # never the automatic policy
    }

    It 'exits 1 (INCOMPLETE) when the old package cannot be found, instead of claiming old access is gone' {
        Set-MoverMocks -OldPackageExists $false -HoldsNew $true
        & $script:Mover -UserPrincipalName 'marcus.bello@contoso.test' -NewDepartment 'ICU' -WarningVariable wv -WarningAction SilentlyContinue
        $LASTEXITCODE | Should -Be 1
        ($wv -join "`n") | Should -Match 'Mover INCOMPLETE'
        ($wv -join "`n") | Should -Match 'NOT verified'
    }

    It 'is idempotent: nothing held to remove and new package already held -> no requests, exit 0' {
        Set-MoverMocks -HoldsOld $false -HoldsNew $true -Department 'ICU'
        & $script:Mover -UserPrincipalName 'marcus.bello@contoso.test' -NewDepartment 'ICU' -WarningAction SilentlyContinue
        $LASTEXITCODE | Should -Be 0
        Should -Invoke New-MgEntitlementManagementAssignmentRequest -Times 0
    }

    It '-WhatIf submits nothing and still exits 0 (dry run)' {
        Set-MoverMocks
        & $script:Mover -UserPrincipalName 'marcus.bello@contoso.test' -NewDepartment 'ICU' -WhatIf -WarningAction SilentlyContinue
        $LASTEXITCODE | Should -Be 0
        Should -Invoke Update-MgUser -Times 0
        Should -Invoke New-MgEntitlementManagementAssignmentRequest -Times 0
    }

    It 'a failed assignment lookup stops the run (it must not read as "none held")' {
        Set-MoverMocks
        Mock Get-MgEntitlementManagementAssignment { throw 'Forbidden' } -ParameterFilter { $Filter -like "*'ap-old'*" }
        { & $script:Mover -UserPrincipalName 'marcus.bello@contoso.test' -NewDepartment 'ICU' -WarningAction SilentlyContinue } | Should -Throw '*Forbidden*'
        Should -Invoke New-MgEntitlementManagementAssignmentRequest -Times 0
    }

    It 'refuses a package the access catalog does not know, before changing anything' {
        Set-MoverMocks
        { & $script:Mover -UserPrincipalName 'marcus.bello@contoso.test' -NewDepartment 'ICU' -NewAccessPackageName 'Mystery - Apps' } | Should -Throw '*not in*access-catalog.json*'
        Should -Invoke Update-MgUser -Times 0
    }

    It 'carries the same assignment-model helpers as 02-Joiner.ps1 (parity)' {
        foreach ($n in 'Get-PackageAssignmentModel', 'Test-IsAutomaticPolicy') {
            (Get-ScriptFunctionBlock -Path $script:Mover -Name $n).ToString() | Should -Be (Get-ScriptFunctionBlock -Path $script:Joiner -Name $n).ToString()
        }
    }
}
