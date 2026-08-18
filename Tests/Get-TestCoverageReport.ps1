<#
.SYNOPSIS
    Reports the test coverage of the script collection.

.DESCRIPTION
    The repository consists of stand-alone scripts, so classic line coverage is not
    meaningful: most script bodies can only run against a domain controller, WSUS,
    Exchange or Intune. This report therefore measures coverage on two levels:

      * script level  - does a Tests\<Area>\<Script>.Tests.ps1 file exist?
      * function level - is each function defined in the script exercised by a test?

    A function counts as covered when a test file references it by name.

.EXAMPLE
    .\Tests\Get-TestCoverageReport.ps1

.EXAMPLE
    .\Tests\Get-TestCoverageReport.ps1 -UncoveredOnly

.PARAMETER UncoveredOnly
    Only list scripts and functions without tests.

.NOTES
    Author     :    Fabian Niesen
    Filename   :    Get-TestCoverageReport.ps1
    Requires   :    PowerShell Version 5.1
    License    :    MIT License, Copyright (c) 2026 Fabian Niesen
    GitHub     :    https://github.com/InfrastructureHeroes/Scipts

.LINK
    https://github.com/InfrastructureHeroes/Scipts/blob/master/Tests/Get-TestCoverageReport.ps1
#>
[CmdletBinding()]
param(
    [switch]$UncoveredOnly
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'TestHelpers/ScriptFunctions.psm1') -Force

$repositoryRoot = Get-RepositoryRoot

$report = foreach ($script in Get-RepositoryScript) {
    $ast = (Get-ScriptAst -Path $script.FullName).Ast
    $functions = @($ast.FindAll({
                param($node)
                $node -is [System.Management.Automation.Language.FunctionDefinitionAst]
            }, $true) | ForEach-Object { $_.Name })

    $area = Split-Path -Leaf (Split-Path -Parent $script.FullName)
    if ((Split-Path -Parent $script.FullName) -eq $repositoryRoot) { $area = '(root)' }

    # Tests follow the convention Tests\<Area>\<ScriptName>.Tests.ps1
    $testFile = Join-Path (Join-Path $PSScriptRoot $area) ($script.BaseName + '.Tests.ps1')
    $hasTestFile = Test-Path -LiteralPath $testFile
    $testText = if ($hasTestFile) { Get-Content -LiteralPath $testFile -Raw } else { '' }

    $coveredFunctions = @($functions | Where-Object { $testText -match ('\b' + [regex]::Escape($_) + '\b') })

    [PSCustomObject]@{
        Script            = $script.Name
        Area              = $area
        Functions         = $functions.Count
        TestedFunctions   = $coveredFunctions.Count
        UntestedFunctions = (@($functions | Where-Object { $coveredFunctions -notcontains $_ }) -join ', ')
        HasTestFile       = $hasTestFile
    }
}

if ($UncoveredOnly) {
    $report = $report | Where-Object { -not $_.HasTestFile -or $_.TestedFunctions -lt $_.Functions }
}

$report | Sort-Object HasTestFile, Area, Script |
    Format-Table Area, Script, Functions, TestedFunctions, HasTestFile, UntestedFunctions -AutoSize

$total = @($report).Count
$withTests = @($report | Where-Object HasTestFile).Count
$functionTotal = ($report | Measure-Object -Property Functions -Sum).Sum
$functionTested = ($report | Measure-Object -Property TestedFunctions -Sum).Sum

Write-Output ''
Write-Output "Scripts with a test file : $withTests of $total"
Write-Output "Functions under test     : $functionTested of $functionTotal"
