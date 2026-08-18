#requires -Modules Pester
<#
.SYNOPSIS
    Unit tests for the helper functions of GPO\Check-LocalGroupPolicy.ps1.
#>

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..\TestHelpers\ScriptFunctions.psm1') -Force
    $script:ScriptPath = Join-Path (Get-RepositoryRoot) 'GPO/Check-LocalGroupPolicy.ps1'
}

Describe 'Check-LocalGroupPolicy.ps1 - Start-CliApplication' {
    BeforeAll {
        . (Get-ScriptFunctionScriptBlock -Path $script:ScriptPath -Name 'Start-CliApplication')

        if ($IsWindows -or $null -eq $IsWindows) {
            $script:SuccessCommand = 'cmd.exe'
            $script:SuccessArguments = '/c exit 0'
            $script:FailureArguments = '/c exit 3'
        } else {
            $script:SuccessCommand = '/bin/sh'
            $script:SuccessArguments = '-c "exit 0"'
            $script:FailureArguments = '-c "exit 3"'
        }
    }

    It 'returns exit code 0 for a successful application' {
        Start-CliApplication -application $script:SuccessCommand -arguments $script:SuccessArguments |
            Should -Be 0
    }

    It 'returns the exit code of a failing application' {
        Start-CliApplication -application $script:SuccessCommand -arguments $script:FailureArguments |
            Should -Be 3
    }

    It 'waits for the process to exit before returning' {
        if ($IsWindows -or $null -eq $IsWindows) {
            $arguments = '/c ping -n 2 127.0.0.1 >nul & exit 0'
        } else {
            $arguments = '-c "sleep 1; exit 0"'
        }

        $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        $exitCode = Start-CliApplication -application $script:SuccessCommand -arguments $arguments
        $stopwatch.Stop()

        $exitCode | Should -Be 0
        $stopwatch.Elapsed.TotalMilliseconds | Should -BeGreaterThan 500
    }

    It 'throws for an application that does not exist' {
        { Start-CliApplication -application 'this-application-does-not-exist' -arguments '' } |
            Should -Throw
    }
}

Describe 'Check-LocalGroupPolicy.ps1 - script contract' {
    It 'parses without errors' {
        (Get-ScriptAst -Path $script:ScriptPath).Errors | Should -BeNullOrEmpty
    }

    It 'exposes needfix and logpath parameters' {
        $ast = (Get-ScriptAst -Path $script:ScriptPath).Ast
        $names = $ast.ParamBlock.Parameters.Name.VariablePath.UserPath

        $names | Should -Contain 'needfix'
        $names | Should -Contain 'logpath'
    }
}
