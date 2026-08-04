<#
.SYNOPSIS
    Runs the Pester test suite of this repository.

.DESCRIPTION
    Runs all Pester tests below the Tests folder and optionally writes a NUnit test
    result file. Works on Windows PowerShell 5.1 and on PowerShell 7 (Windows, Linux,
    macOS). Use Get-TestCoverageReport.ps1 for the coverage overview of the collection.

.EXAMPLE
    .\Tests\Invoke-Tests.ps1

.EXAMPLE
    .\Tests\Invoke-Tests.ps1 -CI

.PARAMETER Path
    Path to the tests to run. Defaults to the Tests folder next to this script.

.PARAMETER CI
    Write testResults.xml and exit with a non zero exit code on failure.

.NOTES
    Author     :    Fabian Niesen
    Filename   :    Invoke-Tests.ps1
    Requires   :    PowerShell Version 5.1, Pester 5.0 or newer
    License    :    MIT License, Copyright (c) 2026 Fabian Niesen
    GitHub     :    https://github.com/InfrastructureHeroes/Scipts

.LINK
    https://github.com/InfrastructureHeroes/Scipts/blob/master/Tests/Invoke-Tests.ps1
#>
[CmdletBinding()]
param(
    [string]$Path = $PSScriptRoot,
    [switch]$CI
)

$ErrorActionPreference = 'Stop'

$pester = Get-Module -ListAvailable -Name Pester |
    Where-Object { $_.Version -ge [version]'5.0.0' } |
    Sort-Object Version -Descending | Select-Object -First 1
if (-not $pester) {
    throw 'Pester 5.0 or newer is required. Install it with: Install-Module Pester -Scope CurrentUser -Force -SkipPublisherCheck'
}
Import-Module $pester.Path -Force

$repositoryRoot = Split-Path -Parent $PSScriptRoot
$configuration = New-PesterConfiguration
$configuration.Run.Path = $Path
$configuration.Output.Verbosity = 'Detailed'

if ($CI) {
    $configuration.Run.Exit = $true
    $configuration.TestResult.Enabled = $true
    $configuration.TestResult.OutputPath = Join-Path $repositoryRoot 'testResults.xml'
}

Invoke-Pester -Configuration $configuration
