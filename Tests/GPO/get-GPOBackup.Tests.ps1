#requires -Modules Pester
<#
.SYNOPSIS
    Unit tests for the helper functions of GPO\get-GPOBackup.ps1.
#>

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..\TestHelpers\ScriptFunctions.psm1') -Force
    $script:ScriptPath = Join-Path (Get-RepositoryRoot) 'GPO/get-GPOBackup.ps1'
}

Describe 'get-GPOBackup.ps1 - Get-GPPolicyKey' {
    BeforeAll {
        . (Get-ScriptFunctionScriptBlock -Path $script:ScriptPath -Name 'Get-GPPolicyKey')
        # Stub for the GroupPolicy cmdlet, which is only available on Windows with RSAT.
        function Get-GPRegistryValue { param([string]$Name, [string]$Key) }
    }

    It 'returns the values of a flat key' {
        Mock -CommandName Get-GPRegistryValue -MockWith {
            [PSCustomObject]@{ FullKeyPath = $Key; ValueName = 'EnableLUA'; Value = 1 }
            [PSCustomObject]@{ FullKeyPath = $Key; ValueName = 'ConsentPromptBehaviorAdmin'; Value = 2 }
        }

        $result = Get-GPPolicyKey -gpoName 'Default Domain Policy' -key 'HKLM\Software\Policies'

        $result.Count | Should -Be 2
        $result.ValueName | Should -Contain 'EnableLUA'
        $result.ValueName | Should -Contain 'ConsentPromptBehaviorAdmin'
    }

    It 'recurses into sub keys that carry no value name' {
        Mock -CommandName Get-GPRegistryValue -MockWith {
            if ($Key -eq 'HKLM\Root') {
                [PSCustomObject]@{ FullKeyPath = 'HKLM\Root\Child'; ValueName = $null }
            } else {
                [PSCustomObject]@{ FullKeyPath = $Key; ValueName = 'NestedValue'; Value = 'set' }
            }
        }

        $result = Get-GPPolicyKey -gpoName 'GPO' -key 'HKLM\Root'

        $result.ValueName | Should -Be 'NestedValue'
        Should -Invoke -CommandName Get-GPRegistryValue -Times 2 -Exactly
    }

    It 'returns nothing when the key holds no settings' {
        Mock -CommandName Get-GPRegistryValue -MockWith { }

        Get-GPPolicyKey -gpoName 'GPO' -key 'HKLM\Empty' | Should -BeNullOrEmpty
    }

    It 'queries the requested GPO and key' {
        Mock -CommandName Get-GPRegistryValue -MockWith {
            [PSCustomObject]@{ FullKeyPath = $Key; ValueName = 'A'; Value = 1 }
        }

        Get-GPPolicyKey -gpoName 'Firewall Policy' -key 'HKLM\Software\Policies\Firewall' | Out-Null

        Should -Invoke -CommandName Get-GPRegistryValue -Times 1 -Exactly -ParameterFilter {
            $Name -eq 'Firewall Policy' -and $Key -eq 'HKLM\Software\Policies\Firewall'
        }
    }

    It 'lets errors of the GroupPolicy cmdlet surface, because ErrorActionPreference is Stop' {
        Mock -CommandName Get-GPRegistryValue -MockWith { Write-Error 'Key not found' }

        { Get-GPPolicyKey -gpoName 'GPO' -key 'HKLM\Missing' } | Should -Throw
    }
}

Describe 'get-GPOBackup.ps1 - script contract' {
    It 'parses without errors' {
        (Get-ScriptAst -Path $script:ScriptPath).Errors | Should -BeNullOrEmpty
    }

    It 'exposes a BackupPath parameter' {
        $ast = (Get-ScriptAst -Path $script:ScriptPath).Ast

        $ast.ParamBlock.Parameters.Name.VariablePath.UserPath | Should -Contain 'BackupPath'
    }
}
