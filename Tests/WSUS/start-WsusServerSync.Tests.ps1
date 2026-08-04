#requires -Modules Pester
<#
.SYNOPSIS
    Unit tests for the helper functions of WSUS\start-WsusServerSync.ps1.
#>

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..\TestHelpers\ScriptFunctions.psm1') -Force
    $script:ScriptPath = Join-Path (Get-RepositoryRoot) 'WSUS/start-WsusServerSync.ps1'
}

Describe 'start-WsusServerSync.ps1 - Start-Pause' {
    BeforeAll {
        . (Get-ScriptFunctionScriptBlock -Path $script:ScriptPath -Name 'Start-Pause')
        # Start-Pause calls the Windows only "Sleep" alias of Start-Sleep, so the tests
        # provide it as a stub that can be mocked and does not slow the suite down.
        function Sleep { param([int]$Seconds) }
    }

    It 'writes one progress record per second and completes' {
        Mock -CommandName Write-Progress -MockWith {}
        Mock -CommandName Sleep -MockWith {}

        Start-Pause -SleepTime 3

        # three countdown records plus the final "Done sleeping..." record
        Should -Invoke -CommandName Write-Progress -Times 4 -Exactly
        Should -Invoke -CommandName Sleep -Times 3 -Exactly
    }

    It 'uses the given activity text' {
        Mock -CommandName Write-Progress -MockWith {}
        Mock -CommandName Sleep -MockWith {}

        Start-Pause -SleepTime 1 -Activity 'Waiting for WSUS'

        Should -Invoke -CommandName Write-Progress -Times 2 -Exactly -ParameterFilter {
            $Activity -eq 'Waiting for WSUS'
        }
    }

    It 'passes the ParentId through when one is given' {
        Mock -CommandName Write-Progress -MockWith {}
        Mock -CommandName Sleep -MockWith {}

        Start-Pause -SleepTime 1 -ID 5 -ParentID 2

        Should -Invoke -CommandName Write-Progress -Times 1 -Exactly -ParameterFilter {
            $ParentId -eq 2 -and $ID -eq 5
        }
    }

    It 'does not sleep at all for a sleep time of 0' {
        Mock -CommandName Write-Progress -MockWith {}
        Mock -CommandName Sleep -MockWith {}

        Start-Pause -SleepTime 0

        Should -Invoke -CommandName Sleep -Times 0 -Exactly
        Should -Invoke -CommandName Write-Progress -Times 1 -Exactly
    }
}

Describe 'start-WsusServerSync.ps1 - script contract' {
    It 'parses without errors' {
        (Get-ScriptAst -Path $script:ScriptPath).Errors | Should -BeNullOrEmpty
    }

    It 'defines the expected helper functions' {
        $ast = (Get-ScriptAst -Path $script:ScriptPath).Ast
        $functions = $ast.FindAll({
                param($node)
                $node -is [System.Management.Automation.Language.FunctionDefinitionAst]
            }, $true).Name

        $functions | Should -Contain 'Get-HKLMValue'
        $functions | Should -Contain 'Start-Pause'
        $functions | Should -Contain 'Sync-WsusServer'
    }
}
