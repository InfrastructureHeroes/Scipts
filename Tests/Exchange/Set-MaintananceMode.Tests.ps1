#requires -Modules Pester
<#
.SYNOPSIS
    Unit tests for the helper functions of Exchange\Set-MaintananceMode.ps1.
#>

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..\TestHelpers\ScriptFunctions.psm1') -Force
    $script:ScriptPath = Join-Path (Get-RepositoryRoot) 'Exchange/Set-MaintananceMode.ps1'
}

Describe 'Set-MaintananceMode.ps1 - checkqueue' {
    BeforeAll {
        . (Get-ScriptFunctionScriptBlock -Path $script:ScriptPath -Name 'checkqueue')
        # Stubs for the Exchange Management Shell cmdlets used by checkqueue.
        function Get-Queue { param([string]$Server) }
    }

    It 'reports empty queues without waiting' {
        Mock -CommandName Get-Queue -MockWith {
            [PSCustomObject]@{ Identity = 'EX01\Submission'; MessageCount = 0 }
        }
        Mock -CommandName Start-Sleep -MockWith {}

        checkqueue | Should -Be 'All queues empty'
        Should -Invoke -CommandName Start-Sleep -Times 0 -Exactly
    }

    It 'waits and rechecks until all queues are drained' {
        $script:Calls = 0
        Mock -CommandName Get-Queue -MockWith {
            $script:Calls++
            if ($script:Calls -lt 3) {
                [PSCustomObject]@{ Identity = 'EX01\Submission'; MessageCount = 5 }
            } else {
                [PSCustomObject]@{ Identity = 'EX01\Submission'; MessageCount = 0 }
            }
        }
        Mock -CommandName Start-Sleep -MockWith {}

        $output = checkqueue

        $output[-1] | Should -Be 'All queues empty'
        $output[0] | Should -Be 'Still 5 messages in the queque, please wait. Recheck in 30 seconds.'
        Should -Invoke -CommandName Start-Sleep -Times 2 -Exactly -ParameterFilter { $Seconds -eq 30 }
    }

    It 'sums the message count over all queues' {
        Mock -CommandName Get-Queue -MockWith {
            [PSCustomObject]@{ Identity = 'EX01\Submission'; MessageCount = 2 }
            [PSCustomObject]@{ Identity = 'EX01\Retry'; MessageCount = 3 }
            [PSCustomObject]@{ Identity = 'EX01\Unreachable'; MessageCount = 0 }
        }
        Mock -CommandName Start-Sleep -MockWith { throw 'stop recursion' }

        { checkqueue } | Should -Throw 'stop recursion'
    }

    It 'ignores poison and shadow queues' {
        Mock -CommandName Get-Queue -MockWith {
            [PSCustomObject]@{ Identity = 'EX01\Poison'; MessageCount = 7 }
            [PSCustomObject]@{ Identity = 'EX01\Shadow\1'; MessageCount = 9 }
            [PSCustomObject]@{ Identity = 'EX01\Submission'; MessageCount = 0 }
        }
        Mock -CommandName Start-Sleep -MockWith {}

        checkqueue | Should -Be 'All queues empty'
        Should -Invoke -CommandName Start-Sleep -Times 0 -Exactly
    }

    It 'queries the queues of the requested source server' {
        $Source = 'EX02'
        Mock -CommandName Get-Queue -MockWith {
            [PSCustomObject]@{ Identity = 'EX02\Submission'; MessageCount = 0 }
        }

        checkqueue | Out-Null

        Should -Invoke -CommandName Get-Queue -Times 1 -Exactly -ParameterFilter { $Server -eq 'EX02' }
    }
}

Describe 'Set-MaintananceMode.ps1 - script contract' {
    It 'parses without errors' {
        (Get-ScriptAst -Path $script:ScriptPath).Errors | Should -BeNullOrEmpty
    }

    It 'exposes the maintenance mode parameters' {
        $ast = (Get-ScriptAst -Path $script:ScriptPath).Ast
        $names = $ast.ParamBlock.Parameters.Name.VariablePath.UserPath

        $names | Should -Contain 'targetsite'
        $names | Should -Contain 'dag'
    }
}
