# Guard rail for PSScriptAnalyzer suppressions in lab/scripts/powershell.
# Write-Host is how the operator scripts talk to the person running them
# (colour, -NoNewline), so PSAvoidUsingWriteHost is suppressed - but only per
# FUNCTION, with a justification: script-level lines go through one
# Write-Console wrapper per script, functions carry the attribute on their own
# param block. A suppression on a script's param block would silence the rule
# for the whole file, so it is refused here. Pure AST reads, no tenant.

BeforeDiscovery {
    $root = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
    $script:Scripts = @(Get-ChildItem -LiteralPath $root -Recurse -Filter '*.ps1' | Where-Object { $_.Name -notlike '*.Tests.ps1' } |
            ForEach-Object { @{ Name = $_.FullName.Substring($root.Length + 1); Path = $_.FullName } })
}

Describe 'analyzer suppressions are scoped' {
    BeforeAll {
        function Get-SuppressionAttribute {
            param([System.Management.Automation.Language.Ast]$Ast)
            @($Ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.AttributeAst] -and $n.TypeName.Name -match '(^|\.)SuppressMessage(Attribute)?$' }, $true))
        }
    }

    It '<Name>: no file-level suppression, every suppression justified' -ForEach $Scripts {
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$null, [ref]$null)
        if ($ast.ParamBlock) { @(Get-SuppressionAttribute $ast.ParamBlock).Count | Should -Be 0 -Because 'a script-level suppression silences the rule for the whole file' }
        foreach ($a in (Get-SuppressionAttribute $ast)) {
            $just = @($a.NamedArguments | Where-Object ArgumentName -EQ 'Justification')
            $just.Count | Should -Be 1 -Because "line $($a.Extent.StartLineNumber) needs a Justification"
            $just[0].Argument.Extent.Text.Trim("'", '"').Trim() | Should -Not -BeNullOrEmpty
        }
    }

    It '<Name>: script-level output goes through Write-Console, which only passes through to Write-Host' -ForEach $Scripts {
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$null, [ref]$null)
        $direct = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq 'Write-Host' }, $true) | Where-Object {
                $p = $_.Parent; while ($p -and $p -isnot [System.Management.Automation.Language.FunctionDefinitionAst]) { $p = $p.Parent }; -not $p })
        $direct.Count | Should -Be 0 -Because 'script-level Write-Host would need a file-level suppression; use Write-Console'
        $wrapper = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Write-Console' }, $true))
        if ($wrapper) {
            $wrapper.Count | Should -Be 1
            @($wrapper[0].Body.EndBlock.Statements).Count | Should -Be 1
            $wrapper[0].Body.EndBlock.Statements[0].Extent.Text | Should -BeExactly 'Write-Host @args'
        }
    }
}
