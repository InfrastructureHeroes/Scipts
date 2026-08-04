# Tests

Pester test suite for this script collection.

## Requirements

- Windows PowerShell 5.1 or PowerShell 7 (Windows, Linux, macOS)
- Pester 5.0 or newer

```powershell
Install-Module Pester -Scope CurrentUser -Force -SkipPublisherCheck
```

## Running the tests

```powershell
# all tests
.\Tests\Invoke-Tests.ps1

# a single area
.\Tests\Invoke-Tests.ps1 -Path .\Tests\WSUS

# CI mode: writes testResults.xml and fails the process on a failed test
.\Tests\Invoke-Tests.ps1 -CI
```

## Coverage overview

```powershell
.\Tests\Get-TestCoverageReport.ps1
.\Tests\Get-TestCoverageReport.ps1 -UncoveredOnly
```

Classic line coverage is not meaningful here: the scripts are stand-alone `.ps1`
files whose bodies require a domain controller, WSUS, Exchange or Intune, so they
cannot be executed on a build agent. `Get-TestCoverageReport.ps1` therefore reports
coverage on two levels:

- **script level** - does `Tests\<Area>\<Script>.Tests.ps1` exist?
- **function level** - is every function of the script exercised by that test file?

## Layout and conventions

```
Tests\
  Invoke-Tests.ps1              test runner
  Get-TestCoverageReport.ps1    coverage overview
  TestHelpers\
    ScriptFunctions.psm1        parses scripts and extracts single functions
  <Area>\<Script>.Tests.ps1     unit tests, mirroring the repository layout
  Repository\
    ScriptQuality.Tests.ps1     tests that apply to every script of the repository
```

Because dot-sourcing a script would run it, the tests never load the script itself.
`ScriptFunctions.psm1` parses the file with the PowerShell parser and returns only
the source of the requested function:

```powershell
BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..\TestHelpers\ScriptFunctions.psm1') -Force
    $script:ScriptPath = Join-Path (Get-RepositoryRoot) 'WSUS/Get-WsusHealth.ps1'
}

Describe 'Get-WsusHealth.ps1 - New-CheckResult' {
    BeforeAll {
        . (Get-ScriptFunctionScriptBlock -Path $script:ScriptPath -Name 'New-CheckResult')
    }

    It 'returns the check name' {
        (New-CheckResult -Name 'Sync' -Status 'OK' -Message 'fine').Check | Should -Be 'Sync'
    }
}
```

Cmdlets that only exist on a server (`Get-Queue`, `Get-GPRegistryValue`, ...) are
declared as empty stub functions in `BeforeAll` and then replaced with `Mock`.

## Known gaps

Functions that talk to WMI/`StdRegProv`, the Windows event log or SMTP
(`Get-HKLMValue`, `Get-PendingRebootStatus`, `SendEmailStatus`, `Load-ExchangeModule`,
`Test-LDAP`) are not unit tested yet; they need a Windows agent or an SMTP stub.
`Repository\ScriptQuality.Tests.ps1` also lists three scripts whose comment based
help has an empty `.SYNOPSIS` (`install-AD.ps1`, `install-DC.ps1`,
`Set-Ex2013Vdir.ps1`); the test skips them until the help is filled in.
