# Pester 5 tests for -UseAzureCliToken on the three tenant reports the lab
# operator runs unattended (lab/scripts/operator/op): 06-NHI-Inventory.ps1,
# 08-Measure-KPIs.ps1 and 09-SoD-Report.ps1. Each test signs in with a fake
# Azure CLI token (az is mocked), then stops at the first Graph read: the
# point is the sign-in path, the reads are covered by each script's own
# tests. Plus Get-MissingGraphScope, the warning helper that knows a
# ReadWrite application role covers its Read counterpart.
# Every Graph call and az is mocked; no tenant is contacted.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    $script:Reports = [ordered]@{
        '06-NHI-Inventory.ps1' = Get-LabScriptPath '06-NHI-Inventory.ps1'
        '08-Measure-KPIs.ps1'  = Get-LabScriptPath '08-Measure-KPIs.ps1'
        '09-SoD-Report.ps1'    = Get-LabScriptPath '09-SoD-Report.ps1'
    }
    # The lab operator's application roles (envs/operator variables.tf), the
    # identity these reports run as: ReadWrite roles where a delegated admin
    # would consent to Read ones.
    $global:AppOnlyOperatorRoles = @('AccessReview.Read.All', 'AdministrativeUnit.ReadWrite.All', 'AppRoleAssignment.ReadWrite.All', 'Application.ReadWrite.All',
        'AuditLog.Read.All', 'Directory.Read.All', 'EntitlementManagement.ReadWrite.All', 'GroupMember.ReadWrite.All', 'Policy.Read.All',
        'PrivilegedEligibilitySchedule.Read.AzureADGroup', 'RoleEligibilitySchedule.Read.Directory', 'RoleManagement.ReadWrite.Directory',
        'User.ReadWrite.All', 'UserAuthenticationMethod.ReadWrite.All')
    $global:AppOnlyFakeToken = 'eyFAKE.operator-token.never-printed'
    . (Get-ScriptFunctionBlock -Path (Get-LabScriptPath '06-NHI-Inventory.ps1') -Name 'Get-MissingGraphScope')

    function Set-AppOnlyMocks {
        $global:AppOnlyOut = [System.Collections.Generic.List[string]]::new()
        Mock Write-Host { $global:AppOnlyOut.Add([string]$Object) }
        Mock Write-Warning { $global:AppOnlyOut.Add("WARNING: $Message") }
        Mock az { $global:LASTEXITCODE = 0; $global:AppOnlyFakeToken }
        Mock Connect-MgGraph {}
        Mock Get-MgContext { [pscustomobject]@{ Scopes = $global:AppOnlyOperatorRoles; TenantId = '11111111-1111-1111-1111-111111111111'; Account = $null; AuthType = 'UserProvidedAccessToken' } }
        # Stop at the first read: everything after sign-in has its own tests.
        Mock Invoke-MgGraphRequest { throw 'STOP-AFTER-SIGN-IN' }
    }
    function Invoke-Report([string]$Name, [hashtable]$Extra = @{}) {
        $dir = Join-Path $TestDrive ("r-" + [guid]::NewGuid().ToString('N').Substring(0, 6))
        $a = @{ UseAzureCliToken = $true }
        switch ($Name) {
            '06-NHI-Inventory.ps1' { $a.OutputDirectory = $dir; $a.SkipSignInActivity = $true }
            '08-Measure-KPIs.ps1' { $a.OutputDirectory = $dir; $a.DetailDirectory = (Join-Path $dir 'detail'); $a.SkipPam = $true }
            '09-SoD-Report.ps1' { $a.OutputDirectory = $dir; $a.DetailDirectory = (Join-Path $TestDrive 'out-sod') }
        }
        foreach ($k in $Extra.Keys) { $a[$k] = $Extra[$k] }
        try { $null = & $script:Reports[$Name] @a 2>$null 3>$null } catch { $global:AppOnlyOut.Add("THROWN: $($_.Exception.Message)") }
    }
}

AfterAll { Remove-Variable -Name AppOnlyOut, AppOnlyFakeToken, AppOnlyOperatorRoles -Scope Global -ErrorAction SilentlyContinue }

Describe '-UseAzureCliToken: app-only sign-in on the tenant reports' {
    BeforeEach { $env:GITHUB_ACTIONS_SAVED = $env:GITHUB_ACTIONS; $env:GITHUB_ACTIONS = $null; Set-AppOnlyMocks }
    AfterEach { $env:GITHUB_ACTIONS = $env:GITHUB_ACTIONS_SAVED; Remove-Item Env:GITHUB_ACTIONS_SAVED -ErrorAction SilentlyContinue }

    It '<_> takes the Graph token from the Azure CLI, connects with it as a SecureString, never prints it' -ForEach @('06-NHI-Inventory.ps1', '08-Measure-KPIs.ps1', '09-SoD-Report.ps1') {
        Invoke-Report $_
        Should -Invoke az -Times 1 -Exactly -ParameterFilter { $args -contains 'get-access-token' -and $args -contains 'ms-graph' }
        Should -Invoke Connect-MgGraph -Times 1 -Exactly -ParameterFilter { $AccessToken -is [securestring] -and [System.Net.NetworkCredential]::new('', $AccessToken).Password -eq $global:AppOnlyFakeToken }
        Should -Invoke Connect-MgGraph -Times 0 -ParameterFilter { $Scopes }
        ($global:AppOnlyOut -join "`n") | Should -Not -Match ([regex]::Escape($global:AppOnlyFakeToken))
    }

    It '<_>: the operator''s ReadWrite roles raise no "does not list" warning' -ForEach @('06-NHI-Inventory.ps1', '09-SoD-Report.ps1') {
        Invoke-Report $_
        ($global:AppOnlyOut -join "`n") | Should -Not -Match 'does not list'
    }

    It '08 warns about exactly the one read the operator does not hold by name (PrivilegedAssignmentSchedule.Read.AzureADGroup)' {
        Invoke-Report '08-Measure-KPIs.ps1'
        $w = @($global:AppOnlyOut | Where-Object { $_ -match 'does not list' })
        $w.Count | Should -Be 1
        $w[0] | Should -Match 'does not list: PrivilegedAssignmentSchedule\.Read\.AzureADGroup\.'
    }

    It '<_> masks the token in GitHub Actions: the ::add-mask:: line is the only one carrying it' -ForEach @('06-NHI-Inventory.ps1', '08-Measure-KPIs.ps1', '09-SoD-Report.ps1') {
        $env:GITHUB_ACTIONS = 'true'
        Invoke-Report $_
        $hits = @($global:AppOnlyOut | Where-Object { $_ -match [regex]::Escape($global:AppOnlyFakeToken) })
        $hits.Count | Should -Be 1
        $hits[0] | Should -BeExactly "::add-mask::$($global:AppOnlyFakeToken)"
    }

    It '<_> stops before any Graph read when the Azure CLI has no session' -ForEach @('06-NHI-Inventory.ps1', '08-Measure-KPIs.ps1', '09-SoD-Report.ps1') {
        Mock az { $global:LASTEXITCODE = 1 }
        Invoke-Report $_
        Should -Invoke Connect-MgGraph -Times 0
        Should -Invoke Invoke-MgGraphRequest -Times 0
    }

    It '06 refuses -Offline with -UseAzureCliToken (a mock run never looks signed in)' {
        Invoke-Report -Name '06-NHI-Inventory.ps1' -Extra @{ Offline = $true }
        ($global:AppOnlyOut -join "`n") | Should -Match 'exclude each other'
        Should -Invoke az -Times 0
    }

    It '09 refuses -InputPath with -UseAzureCliToken (a fixture run never looks signed in)' {
        Invoke-Report -Name '09-SoD-Report.ps1' -Extra @{ InputPath = [System.IO.Path]::Combine($PSScriptRoot, '..', '..', '..', 'iga', 'fixtures', 'sod-tenant.json') }
        ($global:AppOnlyOut -join "`n") | Should -Match 'exclude each other'
        Should -Invoke az -Times 0
    }
}

Describe 'Get-MissingGraphScope (the "does not list" warning)' {
    It 'a ReadWrite role covers its Read counterpart' {
        @(Get-MissingGraphScope -Have @('Application.ReadWrite.All', 'RoleManagement.ReadWrite.Directory') -Required 'Application.Read.All', 'RoleManagement.Read.Directory') | Should -BeNullOrEmpty
    }
    It 'Directory.Read.All covers the user, group, membership and application reads (Learn), nothing else' {
        @(Get-MissingGraphScope -Have @('Directory.Read.All') -Required 'User.Read.All', 'Group.Read.All', 'GroupMember.Read.All', 'Application.Read.All') | Should -BeNullOrEmpty
        @(Get-MissingGraphScope -Have @('Directory.Read.All') -Required 'AuditLog.Read.All', 'Policy.Read.All') | Should -Be @('AuditLog.Read.All', 'Policy.Read.All')
    }
    It 'a Read role never covers a ReadWrite requirement' {
        @(Get-MissingGraphScope -Have @('EntitlementManagement.Read.All') -Required 'EntitlementManagement.ReadWrite.All') | Should -Be @('EntitlementManagement.ReadWrite.All')
    }
    It 'reports what is really missing, and stays quiet on an unknown (empty) context' {
        @(Get-MissingGraphScope -Have @('AuditLog.Read.All') -Required 'AuditLog.Read.All', 'PrivilegedAssignmentSchedule.Read.AzureADGroup') | Should -Be @('PrivilegedAssignmentSchedule.Read.AzureADGroup')
        @(Get-MissingGraphScope -Have @() -Required 'AuditLog.Read.All') | Should -BeNullOrEmpty
    }
    It 'the operator lacks only PrivilegedAssignmentSchedule.Read.AzureADGroup among 08''s reads (recorded, never hidden)' {
        $req = @('User.Read.All', 'Group.Read.All', 'Directory.Read.All', 'AuditLog.Read.All', 'RoleManagement.Read.Directory',
            'PrivilegedEligibilitySchedule.Read.AzureADGroup', 'PrivilegedAssignmentSchedule.Read.AzureADGroup', 'Policy.Read.All', 'AccessReview.Read.All', 'Application.Read.All')
        @(Get-MissingGraphScope -Have $global:AppOnlyOperatorRoles -Required $req) | Should -Be @('PrivilegedAssignmentSchedule.Read.AzureADGroup')
    }
}
