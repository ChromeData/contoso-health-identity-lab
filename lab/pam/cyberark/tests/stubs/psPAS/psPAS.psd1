@{
    RootModule        = 'psPAS.psm1'
    ModuleVersion     = '0.0.0'
    GUID              = '3f5c1a7e-9b2d-4c8e-a1f6-7d0e2b4c9a13'
    Author            = 'contoso-health-identity-lab'
    Description       = 'Stub CyberArk vault standing in for psPAS. Test use only, see psPAS.psm1.'
    PowerShellVersion = '7.0'
    FunctionsToExport = @(
        'Get-PASSession', 'Get-PASSafe', 'Get-PASSafeMember', 'Get-PASAccount',
        'Add-PASSafe', 'Add-PASSafeMember', 'Set-PASSafeMember', 'Add-PASAccount'
    )
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
}
