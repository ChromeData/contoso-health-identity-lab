# Pester 5. The Connect Health agent check in 12-Install-ConnectHealthAgent.ps1
# and 19-Remove-Adfs.ps1. Both scripts run only on DC01, so the test lifts the
# one function out of each file (AST) and runs it against a mocked Get-Service.
# Why: 19 reported the agent installed on DC01 as absent, because it looked
# only for the older AdHealthAdfs* service names (Greptile, PR #221).
BeforeDiscovery {
    $script:Files = @('12-Install-ConnectHealthAgent.ps1', '19-Remove-Adfs.ps1') | ForEach-Object { @{ File = $_ } }
}

BeforeAll {
    $script:Dir = Join-Path $PSScriptRoot '../scripts'
    function Get-FunctionText([string]$Path, [string]$Name) {
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$null, [ref]$null)
        $f = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $Name }, $true)
        @($f).ForEach({ $_.Extent.Text })
    }
    # Get-Service does not exist on Linux/macOS pwsh: a stub so Mock has a target.
    if (-not (Get-Command Get-Service -ErrorAction SilentlyContinue)) {
        function global:Get-Service { param([string[]]$Name, $ErrorAction) $null = $Name, $ErrorAction }
    }
}

Describe 'Get-ConnectHealthAdfsService in <File>' -ForEach $script:Files {
    BeforeAll {
        $path = Join-Path $script:Dir $File
        $text = @(Get-FunctionText $path 'Get-ConnectHealthAdfsService')
        $text.Count | Should -Be 1
        . ([scriptblock]::Create($text[0]))
        $script:Installed = @()
        Mock Get-Service {
            foreach ($n in $Name) { $script:Installed | Where-Object { $_.Name -like $n } }
        }
    }

    It 'finds the current agent (AzureADConnectHealthAgent)' {
        $script:Installed = @([pscustomobject]@{ Name = 'AzureADConnectHealthAgent' })
        (Get-ConnectHealthAdfsService).Name | Should -Be 'AzureADConnectHealthAgent'
    }

    It 'finds the older agent (AdHealthAdfs* services)' {
        $script:Installed = @([pscustomobject]@{ Name = 'AdHealthAdfsDiagnosticsService' }, [pscustomobject]@{ Name = 'AdHealthAdfsInsightsService' })
        (Get-ConnectHealthAdfsService).Count | Should -Be 2
    }

    It 'returns nothing when no agent is installed' {
        $script:Installed = @([pscustomobject]@{ Name = 'adfssrv' })
        @(Get-ConnectHealthAdfsService).Count | Should -Be 0
    }

    It 'is the only place the file looks up a Connect Health service' {
        $src = Get-Content -Raw (Join-Path $script:Dir $File)
        $outside = $src.Replace(@(Get-FunctionText (Join-Path $script:Dir $File) 'Get-ConnectHealthAdfsService')[0], '')
        $outside | Should -Not -Match "Get-Service\s+(-Name\s+)?'AdHealthAdfs"
    }
}

Describe 'callers count the services safely under Set-StrictMode -Version Latest (<File>)' -ForEach $script:Files {
    BeforeAll {
        $path = Join-Path $script:Dir $File
        . ([scriptblock]::Create(@(Get-FunctionText $path 'Get-ConnectHealthAdfsService')[0]))
        # Every expression in the file that counts the function's output, run as written.
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$null, [ref]$null)
        $script:Counts = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.MemberExpressionAst] -and $n.Member.Extent.Text -eq 'Count' -and $n.Expression.Extent.Text -match 'Get-ConnectHealthAdfsService' }, $true) | ForEach-Object { $_.Extent.Text })
        $script:Installed = @()
        Mock Get-Service {
            foreach ($n in $Name) { $script:Installed | Where-Object { $_.Name -like $n } }
        }
    }

    It 'has at least one count expression' { $script:Counts.Count | Should -BeGreaterThan 0 }

    It 'gives <Expected> with <Case>' -ForEach @(
        @{ Case = 'no agent'; Names = @(); Expected = 0 }
        @{ Case = 'the current agent (one service)'; Names = @('AzureADConnectHealthAgent'); Expected = 1 }
        @{ Case = 'the older agent (two services)'; Names = @('AdHealthAdfsDiagnosticsService', 'AdHealthAdfsInsightsService'); Expected = 2 }
    ) {
        $script:Installed = @($Names | ForEach-Object { [pscustomobject]@{ Name = $_ } })
        foreach ($expr in $script:Counts) {
            $sb = [scriptblock]::Create("Set-StrictMode -Version Latest; $expr")
            & $sb | Should -Be $Expected -Because $expr
        }
    }
}

Describe '19-Remove-Adfs.ps1 inventory' {
    It 'reports connectHealth from the shared check, wrapped in @()' {
        Get-Content -Raw (Join-Path $script:Dir '19-Remove-Adfs.ps1') | Should -Match 'connectHealth\s+=\s+\(@\(Get-ConnectHealthAdfsService\)\.Count -gt 0\)'
    }
}

Describe 'the two copies of the function' {
    It 'are identical' {
        $a = @(Get-FunctionText (Join-Path $script:Dir '12-Install-ConnectHealthAgent.ps1') 'Get-ConnectHealthAdfsService')
        $b = @(Get-FunctionText (Join-Path $script:Dir '19-Remove-Adfs.ps1') 'Get-ConnectHealthAdfsService')
        $a[0] | Should -BeExactly $b[0]
    }
}
