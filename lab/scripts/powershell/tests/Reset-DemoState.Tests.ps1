# Pester 5 tests for ../demo/Reset-DemoState.ps1 - the recording re-take tool.
# No tenant: every Graph call goes to a mocked Invoke-MgGraphRequest that
# simulates the three managed access packages, Dana / Marcus and their
# assignments; the HR feed is a synthetic copy in TestDrive (never the
# committed hr_feed.csv); the provisioning child is a recording stub (the
# real one is only checked for the parameter contract).
# What is held:
#   * -WhatIf writes nothing - not the feed, not Graph - and works with no
#     Graph context at all (cloud side described offline);
#   * only the two protagonist rows change, every other line byte-for-byte;
#   * birthright (automatic) packages are left to the HR attributes: never
#     adminAdd, never adminRemove - only requestable packages are reconciled;
#   * the hybrid rule: no cloud write to department / accountEnabled;
#   * a failed step is FAILED + exit 1, never a silent pass.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Import-Module Microsoft.Graph.Authentication -ErrorAction Stop   # mocks copy the real cmdlet signatures
    $script:Reset = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..' '..' 'demo' 'Reset-DemoState.ps1'))
    $script:RealProvisioning = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..' '..' 'mock-hr' 'Invoke-InboundProvisioning.ps1'))
    $script:RealCatalog = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..' '..' '..' 'iga' 'access-catalog.json'))

    # Synthetic HR feed, as it looks right AFTER a Leaver take: Dana is a
    # leaver with an end date, Marcus already moved to ICU. A comment line and
    # two other workers must survive byte-for-byte.
    function New-RdsFeed {
        param([string[]]$ExtraRows = @())
        $lines = @(
            'employeeId,givenName,surname,dept,jobTitle,manager,status,startDate,endDate',
            '# synthetic feed for Reset-DemoState.Tests.ps1 - kept as is',
            '100492,Dana,Okafor,Nursing,Registered Nurse,200015,leaver,2026-10-19,2026-10-20',
            '200015,Grace,Lee,Nursing,Nurse Manager,,active,2015-03-01,',
            '100310,Marcus,Bello,ICU,Registered Nurse,200015,active,2022-01-10,',
            '100777,Ava,Lin,Pharmacy,Pharmacist,200016,leaver,2019-05-01,2026-09-30') + $ExtraRows
        $f = Join-Path $TestDrive ("hr_feed_{0}.csv" -f [guid]::NewGuid().ToString('N'))
        [System.IO.File]::WriteAllText($f, (($lines -join "`n") + "`n"), [System.Text.UTF8Encoding]::new($false))
        return $f
    }

    function New-RdsCatalog {
        # Same names as the real catalog; the assignment model per package is the knob.
        param([string]$Nurse = 'automatic', [string]$Icu = 'automatic', [string]$Pharmacy = 'request', [switch]$NoPharmacy)
        $pk = [System.Collections.Generic.List[object]]::new()
        $pk.Add(@{ name = 'Nurse - Clinical Apps'; assignment = $Nurse })
        $pk.Add(@{ name = 'ICU - Critical Care Apps'; assignment = $Icu })
        if (-not $NoPharmacy) { $pk.Add(@{ name = 'Pharmacy - Controlled Substances Apps'; assignment = $Pharmacy }) }
        $f = Join-Path $TestDrive ("catalog_{0}.json" -f [guid]::NewGuid().ToString('N'))
        (@{ accessPackages = $pk } | ConvertTo-Json -Depth 5) | Set-Content -LiteralPath $f
        return $f
    }

    # A simulated tenant. Holds = package keys each person has an ACTIVE
    # assignment for (nurse / icu / pharmacy / other = an unmanaged package).
    function Set-RdsMocks {
        param(
            [string]$DanaDept = 'Nursing', [bool]$DanaEnabled = $true, [string[]]$DanaHolds = @(), [AllowNull()][string]$DanaUsageLocation = 'US', [string[]]$DanaLicenses = @(),
            [string]$MarcusDept = 'Nursing', [bool]$MarcusEnabled = $true, [string[]]$MarcusHolds = @(), [string[]]$MarcusLicenses = @(),
            [switch]$NoContext, [string]$RequestError = '', [string]$ProvisioningError = ''
        )
        $pkgs = [ordered]@{
            nurse    = @{ id = 'ap-nurse'; displayName = 'Nurse - Clinical Apps'; policies = @(
                    @{ id = 'pol-nurse-auto'; displayName = 'Nurse - Clinical Apps - birthright'; automaticRequestSettings = @{ requestAccessForAllowedTargets = $true } },
                    @{ id = 'pol-nurse-req'; displayName = 'Nurse - Clinical Apps - 365 day'; automaticRequestSettings = $null }) }
            icu      = @{ id = 'ap-icu'; displayName = 'ICU - Critical Care Apps'; policies = @(
                    @{ id = 'pol-icu-auto'; displayName = 'ICU - Critical Care Apps - birthright'; automaticRequestSettings = @{ requestAccessForAllowedTargets = $true } }) }
            pharmacy = @{ id = 'ap-pharm'; displayName = 'Pharmacy - Controlled Substances Apps'; policies = @(
                    @{ id = 'pol-pharm-req'; displayName = 'Pharmacy - Controlled Substances Apps - 30 day'; automaticRequestSettings = $null }) }
            other    = @{ id = 'ap-other'; displayName = 'Radiology - Imaging Apps'; policies = @() }
        }
        $asg = @{ 'u-dana' = @(); 'u-marcus' = @() }
        foreach ($k in $DanaHolds) { $asg['u-dana'] += @{ id = "asg-dana-$k"; state = 'delivered'; accessPackage = @{ id = $pkgs[$k].id } } }
        foreach ($k in $MarcusHolds) { $asg['u-marcus'] += @{ id = "asg-marcus-$k"; state = 'delivered'; accessPackage = @{ id = $pkgs[$k].id } } }
        # An expired assignment is history, not access: it must be ignored.
        $asg['u-marcus'] += @{ id = 'asg-marcus-old-pharm'; state = 'expired'; accessPackage = @{ id = 'ap-pharm' } }
        $global:RdsTest = @{
            Packages          = $pkgs
            Assignments       = $asg
            Users             = @{
                'dana.okafor@contoso.test'  = @{ id = 'u-dana'; displayName = 'Dana Okafor'; department = $DanaDept; jobTitle = 'Registered Nurse'; accountEnabled = $DanaEnabled; onPremisesSyncEnabled = $true; usageLocation = $DanaUsageLocation; assignedLicenses = @($DanaLicenses | ForEach-Object { @{ skuId = $_ } }) }
                'marcus.bello@contoso.test' = @{ id = 'u-marcus'; displayName = 'Marcus Bello'; department = $MarcusDept; jobTitle = 'Registered Nurse'; accountEnabled = $MarcusEnabled; onPremisesSyncEnabled = $true; usageLocation = 'US'; assignedLicenses = @($MarcusLicenses | ForEach-Object { @{ skuId = $_ } }) }
            }
            Skus              = @(@{ skuId = 'sku-e5'; skuPartNumber = 'SPE_E5' })
            RequestError      = $RequestError
            ProvisioningError = $ProvisioningError
            Reads             = [System.Collections.Generic.List[string]]::new()
            Writes            = [System.Collections.Generic.List[object]]::new()
            Provisioning      = [System.Collections.Generic.List[object]]::new()
        }

        Mock Write-Host {}
        Mock Out-Host {}
        Mock Start-Sleep {}
        Mock Connect-MgGraph { throw 'tests must never connect' }
        if ($NoContext) { Mock Get-MgContext { $null } }
        else { Mock Get-MgContext { New-MgContextStub -Scopes @('EntitlementManagement.ReadWrite.All', 'User.Read.All', 'User.ReadWrite.All', 'Organization.Read.All', 'SynchronizationData-User.Upload') } }
        Mock Invoke-MgGraphRequest {
            $t = $global:RdsTest
            $u = [uri]::UnescapeDataString($(if ($Uri -is [uri]) { $Uri.OriginalString } else { [string]$Uri }))
            $m = "$Method"
            if ($m -ne 'GET') {
                $t.Writes.Add([pscustomobject]@{ Method = $m; Uri = $u; Body = $(if ($Body) { $Body | ConvertFrom-Json -AsHashtable } else { $null }) })
                if ($u -like '*/assignmentRequests') {
                    if ($t.RequestError) { throw $t.RequestError }
                    return @{ id = "req-$($t.Writes.Count)"; state = 'submitted' }
                }
                return @{}
            }
            $t.Reads.Add($u)
            if ($u -match "/accessPackages\?\`$filter=displayName eq '(?<n>.+)'$") {
                $n = $Matches.n.Replace("''", "'")
                return @{ value = @($t.Packages.Values | Where-Object { $_['displayName'] -eq $n } | ForEach-Object { @{ id = $_['id']; displayName = $_['displayName'] } }) }
            }
            if ($u -match '/accessPackages/(?<id>[^?/]+)\?\$expand=assignmentPolicies') {
                $id = $Matches.id
                $p = @($t.Packages.Values | Where-Object { $_['id'] -eq $id })[0]
                return @{ id = $p['id']; displayName = $p['displayName']; assignmentPolicies = $p['policies'] }
            }
            if ($u -match "/assignments\?\`$filter=target/objectId eq '(?<uid>[^']+)'") { return @{ value = @($t.Assignments[$Matches.uid]) } }
            if ($u -match '/users/(?<upn>[^?/]+)\?\$select=') {
                $usr = $t.Users[$Matches.upn]
                if (-not $usr) { throw "Request_ResourceNotFound: $($Matches.upn)" }
                return $usr.Clone()
            }
            if ($u -like '*/subscribedSkus') { return @{ value = $t.Skus } }
            throw "unexpected Graph GET in test: $u"
        }
    }
}

AfterAll { Remove-Variable -Name RdsTest -Scope Global -ErrorAction SilentlyContinue }

Describe 'Reset-DemoState.ps1' {
    BeforeAll {
        # Recording stand-in for ../mock-hr/Invoke-InboundProvisioning.ps1:
        # same parameters, ShouldProcess-aware, sends nothing.
        $script:Stub = Join-Path $TestDrive 'Invoke-InboundProvisioning.stub.ps1'
        Set-Content -LiteralPath $script:Stub -Value @'
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param([string]$ServicePrincipalId, [string]$JobId, [string]$CsvPath, [string]$StatusFilter, [string]$UpnDomain)
$global:RdsTest.Provisioning.Add([pscustomobject]@{
        ServicePrincipalId = $ServicePrincipalId; JobId = $JobId; StatusFilter = $StatusFilter; UpnDomain = $UpnDomain
        CsvPath = $CsvPath; Csv = [System.IO.File]::ReadAllText($CsvPath); WhatIf = [bool]$WhatIfPreference; ConfirmPreference = [string]$ConfirmPreference })
if ($global:RdsTest.ProvisioningError) { throw $global:RdsTest.ProvisioningError }
'@
        $script:Real = @{ ServicePrincipalId = '11111111-1111-1111-1111-111111111111'; JobId = 'API2AD.test.job'; UpnDomain = 'contoso.test'; ProvisioningScriptPath = $script:Stub; Confirm = $false }
        function Get-FileHash256([string]$Path) { (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash }
    }
    BeforeEach { $global:LASTEXITCODE = 0 }

    Context '-WhatIf' {
        It 'with no Graph context: writes nothing, never connects, describes the cloud side offline' {
            Set-RdsMocks -NoContext
            $feed = New-RdsFeed; $before = Get-FileHash256 $feed
            $r = & $script:Reset -Segment Leaver -CsvPath $feed -ProvisioningScriptPath $script:Stub -CatalogPath $script:RealCatalog -UpnDomain 'contoso.test' -WhatIf
            Get-FileHash256 $feed | Should -Be $before
            Should -Invoke Invoke-MgGraphRequest -Times 0 -Exactly
            Should -Invoke Connect-MgGraph -Times 0 -Exactly
            ($r | Where-Object Step -EQ 'HR feed').Status | Should -Be 'whatif'
            ($r | Where-Object Step -EQ 'Provisioning').Status | Should -Be 'whatif'
            @($r | Where-Object { $_.Step -eq 'Packages' -and $_.Status -eq 'whatif-offline' }).Count | Should -Be 2
            # The diff is printed, and birthright packages are described as HR-driven, never as a reset target.
            Should -Invoke Write-Host -ParameterFilter { "$Object" -eq '  + 100492,Dana,Okafor,Nursing,Registered Nurse,200015,active,2026-10-19,' }
            Should -Invoke Write-Host -ParameterFilter { "$Object" -match '^  Dana <dana\.okafor@contoso\.test>: ensure \[\]; .*birthright \(HR-driven, not reset\) expected \[Nurse - Clinical Apps\]' }
            Should -Invoke Write-Host -ParameterFilter { "$Object" -match '^  Marcus <marcus\.bello@contoso\.test>: ensure \[\]; adminRemove any of \[Pharmacy - Controlled Substances Apps\]; birthright \(HR-driven, not reset\) expected \[ICU - Critical Care Apps\]' }
        }

        It 'hands the child ONLY the two edited rows, with -WhatIf, and deletes the scratch feed' {
            Set-RdsMocks -NoContext
            $feed = New-RdsFeed
            & $script:Reset -Segment Mover -CsvPath $feed -ProvisioningScriptPath $script:Stub -CatalogPath $script:RealCatalog -UpnDomain 'contoso.test' -WhatIf | Out-Null
            $global:RdsTest.Provisioning.Count | Should -Be 1
            $call = $global:RdsTest.Provisioning[0]
            $call.WhatIf | Should -BeTrue
            $call.StatusFilter | Should -Be 'all'
            $call.UpnDomain | Should -Be 'contoso.test'
            $call.Csv | Should -Be ((@(
                        'employeeId,givenName,surname,dept,jobTitle,manager,status,startDate,endDate',
                        '100310,Marcus,Bello,Nursing,Registered Nurse,200015,active,2022-01-10,',
                        '100492,Dana,Okafor,Nursing,Registered Nurse,200015,active,2026-10-19,') -join "`n") + "`n")
            $call.CsvPath | Should -Not -Exist
        }

        It 'with a Graph context: reads the tenant but sends no write' {
            Set-RdsMocks -DanaEnabled $false -MarcusDept 'ICU' -MarcusHolds 'icu', 'pharmacy'
            $feed = New-RdsFeed; $before = Get-FileHash256 $feed
            $r = & $script:Reset -Segment Mover -CsvPath $feed -ProvisioningScriptPath $script:Stub -CatalogPath $script:RealCatalog -UpnDomain 'contoso.test' -WhatIf -WarningAction SilentlyContinue
            Get-FileHash256 $feed | Should -Be $before
            $global:RdsTest.Writes.Count | Should -Be 0
            $global:RdsTest.Reads.Count | Should -BeGreaterThan 0
            ($r | Where-Object { $_.Target -eq 'Marcus' -and $_.Action -eq 'remove Pharmacy - Controlled Substances Apps' }).Status | Should -Be 'whatif'
            ($r | Where-Object { $_.Target -eq 'Marcus' -and $_.Action -eq 'remove ICU - Critical Care Apps' }).Status | Should -Be 'birthright-hr-driven'
        }
    }

    Context 'HR feed edit' {
        It 'changes only the two protagonist rows; every other line, the comment and the trailing newline stay byte-for-byte' {
            Set-RdsMocks
            $feed = New-RdsFeed
            $old = [System.IO.File]::ReadAllText($feed) -split "`n"
            $r = & $script:Reset -Segment Mover -CsvPath $feed -CatalogPath $script:RealCatalog -UpnDomain 'contoso.test' -SkipProvisioning -SkipCloud -Confirm:$false
            $raw = [System.IO.File]::ReadAllText($feed)
            $raw.EndsWith("`n") | Should -BeTrue
            $new = $raw -split "`n"
            $new.Count | Should -Be $old.Count
            for ($i = 0; $i -lt $old.Count; $i++) {
                if ($old[$i] -match '^(100492|100310),') { continue }
                $new[$i] | Should -BeExactly $old[$i] -Because "line $i is not a protagonist row"
            }
            $new | Should -Contain '100492,Dana,Okafor,Nursing,Registered Nurse,200015,active,2026-10-19,'   # endDate cleared, re-enabled through HR
            $new | Should -Contain '100310,Marcus,Bello,Nursing,Registered Nurse,200015,active,2022-01-10,'
            ($r | Where-Object Step -EQ 'HR feed').Status | Should -Be 'updated'
            ($r | Where-Object Step -EQ 'Provisioning').Status | Should -Be 'skipped'
        }

        It 'is idempotent: a second run finds both rows already correct and rewrites nothing' {
            Set-RdsMocks
            $feed = New-RdsFeed
            & $script:Reset -Segment Leaver -CsvPath $feed -CatalogPath $script:RealCatalog -UpnDomain 'contoso.test' -SkipProvisioning -SkipCloud -Confirm:$false | Out-Null
            $after1 = Get-FileHash256 $feed
            $r = & $script:Reset -Segment Leaver -CsvPath $feed -CatalogPath $script:RealCatalog -UpnDomain 'contoso.test' -SkipProvisioning -SkipCloud -Confirm:$false
            Get-FileHash256 $feed | Should -Be $after1
            ($r | Where-Object Step -EQ 'HR feed').Status | Should -Be 'already-correct'
        }

        It 'refuses a real run with placeholder provisioning ids BEFORE changing anything' {
            Set-RdsMocks
            $feed = New-RdsFeed; $before = Get-FileHash256 $feed
            { & $script:Reset -Segment Mover -CsvPath $feed -ProvisioningScriptPath $script:Stub -CatalogPath $script:RealCatalog -Confirm:$false } | Should -Throw '*Pass -ServicePrincipalId and -JobId*'
            Get-FileHash256 $feed | Should -Be $before
            $global:RdsTest.Provisioning.Count | Should -Be 0
            $global:RdsTest.Writes.Count | Should -Be 0
        }

        It 'refuses a duplicated protagonist row and writes nothing' {
            Set-RdsMocks
            $feed = New-RdsFeed -ExtraRows '100492,Dana,Okafor,Nursing,Registered Nurse,200015,active,2026-10-19,'
            $before = Get-FileHash256 $feed
            { & $script:Reset -Segment Mover -CsvPath $feed -CatalogPath $script:RealCatalog -SkipProvisioning -SkipCloud -Confirm:$false } | Should -Throw '*100492*appears 2 times*'
            Get-FileHash256 $feed | Should -Be $before
        }

        It 'stops when a managed package is missing from the access catalog (the model is never guessed)' {
            Set-RdsMocks
            { & $script:Reset -Segment Mover -CsvPath (New-RdsFeed) -CatalogPath (New-RdsCatalog -NoPharmacy) -SkipProvisioning -SkipCloud -WhatIf } | Should -Throw "*Pharmacy - Controlled Substances Apps*is not in*"
        }
    }

    Context 'provisioning hand-off' {
        It 'a confirmed real run calls the child once without a second prompt, with the run''s ids' {
            Set-RdsMocks
            $r = & $script:Reset -Segment Mover -CsvPath (New-RdsFeed) -CatalogPath $script:RealCatalog -SkipCloud @Real
            $global:RdsTest.Provisioning.Count | Should -Be 1
            $c = $global:RdsTest.Provisioning[0]
            $c.WhatIf | Should -BeFalse
            $c.ConfirmPreference | Should -Be 'None'
            $c.ServicePrincipalId | Should -Be $Real.ServicePrincipalId
            $c.JobId | Should -Be $Real.JobId
            ($r | Where-Object Step -EQ 'Provisioning').Status | Should -Be 'submitted (async)'
        }

        It 'a failed push is a FAILED step and exit 1, not a silent pass' {
            Set-RdsMocks -ProvisioningError 'bulkUpload 403'
            & $script:Reset -Segment Mover -CsvPath (New-RdsFeed) -CatalogPath $script:RealCatalog -SkipCloud @Real -WarningVariable wv -WarningAction SilentlyContinue | Out-Null
            $LASTEXITCODE | Should -Be 1
            ($wv -join "`n") | Should -Match 'Inbound provisioning failed: bulkUpload 403'
        }

        It 'matches the real Invoke-InboundProvisioning.ps1 parameter contract' {
            $cmd = Get-Command -Name $script:RealProvisioning
            foreach ($p in 'ServicePrincipalId', 'JobId', 'CsvPath', 'StatusFilter', 'UpnDomain', 'WhatIf', 'Confirm') {
                $cmd.Parameters.Keys | Should -Contain $p -Because "Reset-DemoState.ps1 passes -$p to the provisioning script"
            }
        }
    }

    Context 'access packages: birthright is left to the HR attributes' {
        It 'never adminRemoves a birthright package the segment does not want; it leaves via the automatic policy' {
            # Mover re-take after a Leaver take: Marcus still holds ICU (birthright) from his move.
            Set-RdsMocks -DanaHolds 'nurse' -MarcusDept 'ICU' -MarcusHolds 'icu', 'nurse'
            $r = & $script:Reset -Segment Mover -CsvPath (New-RdsFeed) -CatalogPath $script:RealCatalog -SkipProvisioning @Real -WarningAction SilentlyContinue
            $global:RdsTest.Writes.Count | Should -Be 0
            ($r | Where-Object { $_.Target -eq 'Marcus' -and $_.Action -eq 'remove ICU - Critical Care Apps' }).Status | Should -Be 'birthright-hr-driven'
            Should -Invoke Write-Host -ParameterFilter { "$Object" -match 'is birthright: it leaves when the HR attributes stop matching' }
        }

        It 'never adminAdds a birthright package: pending until HR -> AD -> Cloud Sync matches the rule' {
            # Leaver re-take after a Leaver take: Dana disabled with nothing; Marcus (ICU) holds ICU + a stray Pharmacy + an unmanaged package.
            Set-RdsMocks -DanaEnabled $false -MarcusDept 'ICU' -MarcusHolds 'icu', 'pharmacy', 'other'
            $r = & $script:Reset -Segment Leaver -CsvPath (New-RdsFeed) -CatalogPath $script:RealCatalog -SkipProvisioning @Real -WarningAction SilentlyContinue
            $LASTEXITCODE | Should -Be 0
            # Exactly one write: the requestable (T2) Pharmacy assignment is removed.
            $global:RdsTest.Writes.Count | Should -Be 1
            $w = $global:RdsTest.Writes[0]
            $w.Uri | Should -BeLike '*/identityGovernance/entitlementManagement/assignmentRequests'
            $w.Body.requestType | Should -Be 'adminRemove'
            $w.Body.assignment.id | Should -Be 'asg-marcus-pharmacy'
            @($global:RdsTest.Writes | Where-Object { $_.Body.requestType -eq 'adminAdd' }).Count | Should -Be 0
            ($r | Where-Object { $_.Target -eq 'Dana' -and $_.Action -eq 'add Nurse - Clinical Apps' }).Status | Should -Be 'birthright-pending-hr'
            ($r | Where-Object { $_.Target -eq 'Marcus' -and $_.Action -eq 'add ICU - Critical Care Apps' }).Status | Should -Be 'birthright-held'
            # Dana is still disabled in Entra (HR-owned, arrives via Cloud Sync): not ready, and never written from the cloud side.
            ($r | Where-Object Step -EQ 'Readiness').Status | Should -Be 'NOT-READY'
            @($global:RdsTest.Writes | Where-Object { $_.Uri -like '*/users/*' }).Count | Should -Be 0
        }

        It 'requests a missing REQUESTABLE package through its request policy, never the automatic one' {
            # A catalog where Nurse is requestable (T2): the Mover segment wants it for Dana, who holds nothing.
            Set-RdsMocks -MarcusHolds 'nurse'
            $r = & $script:Reset -Segment Mover -CsvPath (New-RdsFeed) -CatalogPath (New-RdsCatalog -Nurse request) -SkipProvisioning @Real -WarningAction SilentlyContinue
            $adds = @($global:RdsTest.Writes | Where-Object { $_.Body.requestType -eq 'adminAdd' })
            $adds.Count | Should -Be 1
            $adds[0].Body.assignment.targetId | Should -Be 'u-dana'
            $adds[0].Body.assignment.accessPackageId | Should -Be 'ap-nurse'
            $adds[0].Body.assignment.assignmentPolicyId | Should -Be 'pol-nurse-req'
            ($r | Where-Object { $_.Target -eq 'Marcus' -and $_.Action -eq 'add Nurse - Clinical Apps' }).Status | Should -Be 'already-assigned'
        }

        It 'an already-open request is reported, not failed; any other Graph error is FAILED and exit 1' {
            Set-RdsMocks -MarcusDept 'ICU' -MarcusHolds 'icu', 'pharmacy' -RequestError 'ExistingOpenRequest: a request is already open'
            $r = & $script:Reset -Segment Leaver -CsvPath (New-RdsFeed) -CatalogPath $script:RealCatalog -SkipProvisioning @Real -WarningAction SilentlyContinue
            $LASTEXITCODE | Should -Be 0
            ($r | Where-Object { $_.Action -eq 'remove Pharmacy - Controlled Substances Apps' }).Status | Should -Be 'already-pending'

            Set-RdsMocks -MarcusDept 'ICU' -MarcusHolds 'icu', 'pharmacy' -RequestError 'Forbidden'
            & $script:Reset -Segment Leaver -CsvPath (New-RdsFeed) -CatalogPath $script:RealCatalog -SkipProvisioning @Real -WarningVariable wv -WarningAction SilentlyContinue | Out-Null
            $LASTEXITCODE | Should -Be 1
            ($wv -join "`n") | Should -Match "adminRemove 'Pharmacy - Controlled Substances Apps' failed: Forbidden"
        }
    }

    Context 'readiness and the hybrid rule' {
        It 'READY when department, accountEnabled and requestable packages match; birthright is listed for information only' {
            Set-RdsMocks -DanaHolds 'nurse' -MarcusHolds 'nurse'
            $r = & $script:Reset -Segment Mover -CsvPath (New-RdsFeed) -CatalogPath $script:RealCatalog -SkipProvisioning @Real
            $global:RdsTest.Writes.Count | Should -Be 0
            ($r | Where-Object Step -EQ 'Readiness').Status | Should -Be 'READY'
            Should -Invoke Write-Host -ParameterFilter { "$Object" -eq "READY - roll the camera for 'Mover'." }
        }

        It 'NOT-READY while an HR-owned value has not arrived, and the department is never written from the cloud side' {
            Set-RdsMocks -DanaHolds 'nurse' -MarcusDept 'ICU' -MarcusHolds 'nurse'
            $r = & $script:Reset -Segment Mover -CsvPath (New-RdsFeed) -CatalogPath $script:RealCatalog -SkipProvisioning @Real -WarningVariable wv -WarningAction SilentlyContinue
            ($r | Where-Object Step -EQ 'Readiness').Status | Should -Be 'NOT-READY'
            ($wv -join "`n") | Should -Match 'NOT READY: 1 check\(s\) differ'
            $global:RdsTest.Writes.Count | Should -Be 0
        }

        It '-LicenseSkuPartNumber writes only cloud-side attributes: usageLocation (when missing) and the license' {
            Set-RdsMocks -DanaHolds 'nurse' -MarcusHolds 'nurse' -DanaUsageLocation $null -MarcusLicenses 'sku-e5'
            $r = & $script:Reset -Segment Mover -CsvPath (New-RdsFeed) -CatalogPath $script:RealCatalog -SkipProvisioning -LicenseSkuPartNumber SPE_E5 @Real
            $userWrites = @($global:RdsTest.Writes | Where-Object { $_.Uri -like '*/users/*' })
            $userWrites.Count | Should -Be 2
            ($userWrites | Where-Object Method -EQ 'PATCH').Body.Keys | Should -Be @('usageLocation')
            ($userWrites | Where-Object Uri -Like '*/users/u-dana/assignLicense').Body.addLicenses[0].skuId | Should -Be 'sku-e5'
            foreach ($w in $userWrites) { @($w.Body.Keys) | Should -Not -Contain 'department'; @($w.Body.Keys) | Should -Not -Contain 'accountEnabled' }
            ($r | Where-Object { $_.Step -eq 'License' -and $_.Target -eq 'Marcus' }).Status | Should -Be 'already-assigned'
        }
    }
}
