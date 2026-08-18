#requires -Modules Pester
<#
.SYNOPSIS
    Repository wide tests that apply to every script of the collection.

.DESCRIPTION
    These tests give a baseline safety net for all scripts, including the ones that
    cannot be executed outside of a domain: every script has to be parseable by the
    PowerShell parser, must not define the same function twice and, when it ships
    comment based help, that help has to be well formed.
#>

BeforeDiscovery {
    Import-Module (Join-Path $PSScriptRoot '..\TestHelpers\ScriptFunctions.psm1') -Force
    $script:RepositoryScripts = Get-RepositoryScript | ForEach-Object {
        @{
            Name = (Resolve-Path -LiteralPath $_.FullName -Relative)
            Path = $_.FullName
        }
    }
}

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..\TestHelpers\ScriptFunctions.psm1') -Force

    # Scripts that ship a comment based help block with an empty .SYNOPSIS. Remove the
    # entry as soon as the help of the script is filled in.
    $script:EmptySynopsisKnownIssue = @(
        'install-AD.ps1'
        'install-DC.ps1'
        'Set-Ex2013Vdir.ps1'
    )
}

Describe 'Repository scripts' {
    It 'finds the scripts of the repository' {
        (Get-RepositoryScript).Count | Should -BeGreaterThan 10
    }

    It 'excludes the test suite from the script inventory' {
        Get-RepositoryScript | Where-Object { $_.Name -like '*.Tests.ps1' } | Should -BeNullOrEmpty
    }
}

Describe '<Name>' -ForEach $script:RepositoryScripts {
    It 'parses without syntax errors' {
        $parsed = Get-ScriptAst -Path $Path
        $messages = $parsed.Errors | ForEach-Object { "$($_.Extent.StartLineNumber): $($_.Message)" }

        $messages -join [Environment]::NewLine | Should -BeNullOrEmpty
    }

    It 'does not define the same function twice' {
        $ast = (Get-ScriptAst -Path $Path).Ast
        $functionNames = $ast.FindAll({
                param($node)
                $node -is [System.Management.Automation.Language.FunctionDefinitionAst]
            }, $true).Name

        $duplicates = $functionNames | Group-Object -CaseSensitive:$false |
            Where-Object Count -gt 1 | Select-Object -ExpandProperty Name

        $duplicates -join ',' | Should -BeNullOrEmpty
    }

    It 'has a well formed comment based help when it declares one' {
        $content = Get-Content -LiteralPath $Path -Raw
        if ($content -notmatch '\.SYNOPSIS') {
            Set-ItResult -Skipped -Because 'the script does not declare comment based help'
        }
        if ($script:EmptySynopsisKnownIssue -contains (Split-Path -Leaf $Path)) {
            Set-ItResult -Skipped -Because 'the synopsis of this script is a known gap'
        }

        $help = Get-Help -Name $Path -ErrorAction Stop

        $help.Synopsis | Should -Not -BeNullOrEmpty
        $help.Synopsis.Trim() | Should -Not -Match '^\s*$'
    }
}
