# Pester 5 tests for dependency-scan/Get-AccountDependencies.ps1: the run-as
# matching and the map it builds, with the Windows inventory faked. Nothing
# here needs Windows, a domain or a server - the real scan is a tenant-time
# step (README, "Dependency discovery on DC01").
#
#   pwsh -NoProfile -c "Invoke-Pester lab/pam/test/Get-AccountDependencies.Tests.ps1"

BeforeAll {
    $script:Scan = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../dependency-scan/Get-AccountDependencies.ps1'))
    # Only the function definitions: the script body would scan this machine.
    $tokens = $null; $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($script:Scan, [ref]$tokens, [ref]$errors)
    if ($errors) { throw "Parse errors in $($script:Scan): $($errors[0].Message)" }
    $defs = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $false)
    . ([scriptblock]::Create((@($defs | ForEach-Object { $_.Extent.Text }) -join [Environment]::NewLine)))

    # Windows-only cmdlets do not exist on Linux/macOS pwsh, and Pester can
    # only mock a command that exists: give the test host empty stand-ins.
    foreach ($c in 'Get-CimInstance', 'Get-ScheduledTask') {
        if (-not (Get-Command $c -ErrorAction SilentlyContinue)) {
            New-Item -Path "Function:\global:$c" -Value { param([string]$ClassName) $null = $ClassName } | Out-Null
        }
    }

    $script:Inventory = @(
        [pscustomobject]@{ Type = 'windows-service'; Name = 'MSSQLSERVER'; RunAs = 'CORP\svc-sql01' }
        [pscustomobject]@{ Type = 'windows-service'; Name = 'Spooler'; RunAs = 'LocalSystem' }
        [pscustomobject]@{ Type = 'scheduled-task'; Name = '\Contoso\NightlyIndexMaintenance'; RunAs = 'svc-sql01@corp.test.local' }
        [pscustomobject]@{ Type = 'scheduled-task'; Name = '\Contoso\Other'; RunAs = 'OTHERDOM\svc-sql01' }
        [pscustomobject]@{ Type = 'iis-app-pool'; Name = 'ClinicalPortal'; RunAs = 'corp\SVC-IIS-APP' }
        [pscustomobject]@{ Type = 'scheduled-task'; Name = '\NoPrincipal'; RunAs = $null }
    )
}

Describe 'Test-AccountMatch' {
    It 'matches DOMAIN\sam, sam@suffix and a bare sam, case-insensitively' {
        Test-AccountMatch -Value 'CORP\svc-sql01' -Sam 'svc-sql01' -Domain 'CORP' | Should -BeTrue
        Test-AccountMatch -Value 'corp\SVC-SQL01' -Sam 'svc-sql01' -Domain 'CORP' | Should -BeTrue
        Test-AccountMatch -Value 'svc-sql01@corp.test.local' -Sam 'svc-sql01' -Domain 'CORP' | Should -BeTrue
        Test-AccountMatch -Value 'svc-sql01' -Sam 'svc-sql01' -Domain 'CORP' | Should -BeTrue
    }
    It 'does not match another domain, a local account, a different name or an empty value' {
        Test-AccountMatch -Value 'OTHERDOM\svc-sql01' -Sam 'svc-sql01' -Domain 'CORP' | Should -BeFalse
        Test-AccountMatch -Value '.\svc-sql01' -Sam 'svc-sql01' -Domain 'CORP' | Should -BeFalse
        Test-AccountMatch -Value 'CORP\svc-sql011' -Sam 'svc-sql01' -Domain 'CORP' | Should -BeFalse
        Test-AccountMatch -Value '' -Sam 'svc-sql01' -Domain 'CORP' | Should -BeFalse
        Test-AccountMatch -Value $null -Sam 'svc-sql01' -Domain 'CORP' | Should -BeFalse
    }
}

Describe 'ConvertTo-DependencyMap' {
    BeforeAll {
        $script:Map = ConvertTo-DependencyMap -Sam @('svc-sql01', 'svc-iis-app', 'svc-backup') -Domain 'CORP' -HostName 'app01.corp.test.local' -Inventory $script:Inventory
        $script:Json = $script:Map | ConvertTo-Json -Depth 6 | ConvertFrom-Json
    }
    It 'lists every consumer of svc-sql01 on this host and ignores the other domain' {
        $deps = @($script:Json.accounts.'svc-sql01')
        $deps.Count | Should -Be 2
        ($deps | Where-Object type -EQ 'windows-service').name | Should -Be 'MSSQLSERVER'
        ($deps | Where-Object type -EQ 'scheduled-task').name | Should -Be '\Contoso\NightlyIndexMaintenance'
    }
    It 'finds an IIS application pool regardless of case' {
        @($script:Json.accounts.'svc-iis-app').Count | Should -Be 1
        $script:Json.accounts.'svc-iis-app'[0].type | Should -Be 'iis-app-pool'
    }
    It 'records an account with no consumers explicitly as an empty list (scanned, nothing found)' {
        $script:Json.accounts.PSObject.Properties.Name | Should -Contain 'svc-backup'
        @($script:Json.accounts.'svc-backup').Count | Should -Be 0
    }
    It 'marks every finding unresolved: a scan cannot know a consumer already reads from Vault' {
        $all = @($script:Json.accounts.'svc-sql01') + @($script:Json.accounts.'svc-iis-app')
        $all | ForEach-Object { $_.resolved | Should -BeFalse; $_.source | Should -Be 'scan'; $_.host | Should -Be 'app01.corp.test.local' }
    }
    It 'emits the field names onboard.sh / rotate.sh read (type, host, name, owner, resolved)' {
        $e = $script:Json.accounts.'svc-sql01'[0]
        foreach ($f in 'type', 'host', 'name', 'owner', 'resolved') { $e.PSObject.Properties.Name | Should -Contain $f }
    }
}

Describe 'Get-RunAsInventory' {
    It 'reads services and scheduled tasks, and survives a source that fails' {
        Mock Get-CimInstance { @([pscustomobject]@{ Name = 'MSSQLSERVER'; StartName = 'CORP\svc-sql01' }) }
        Mock Get-ScheduledTask { throw 'Task Scheduler unavailable' }
        Mock Get-Module { $null } -ParameterFilter { $Name -eq 'WebAdministration' }
        Mock Write-Warning {}
        $inv = @(Get-RunAsInventory)
        $inv.Count | Should -Be 1
        $inv[0].Type | Should -Be 'windows-service'
        Should -Invoke Write-Warning -Times 1 -Exactly
    }
}
