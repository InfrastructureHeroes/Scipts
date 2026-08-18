#requires -Modules Pester
<#
.SYNOPSIS
    Unit tests for the helper functions of Network\Check-Network.ps1.
#>

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..\TestHelpers\ScriptFunctions.psm1') -Force
    $script:ScriptPath = Join-Path (Get-RepositoryRoot) 'Network/Check-Network.ps1'
}

Describe 'Check-Network.ps1 - New-CheckResult' {
    BeforeAll {
        . (Get-ScriptFunctionScriptBlock -Path $script:ScriptPath -Name 'New-CheckResult')
    }

    It 'returns the check name, status and message' {
        $result = New-CheckResult -Name 'MTU' -Status 'OK' -Message 'MTU is 1500'

        $result.Check | Should -Be 'MTU'
        $result.Status | Should -Be 'OK'
        $result.Message | Should -Be 'MTU is 1500'
    }

    It 'stamps the result with the current time' {
        $before = Get-Date
        $result = New-CheckResult -Name 'DNS' -Status 'Failed' -Message 'No DNS server'

        $result.Time | Should -BeOfType [datetime]
        $result.Time | Should -BeGreaterOrEqual $before.AddSeconds(-5)
        $result.Time | Should -BeLessOrEqual (Get-Date).AddSeconds(5)
    }

    It 'exposes exactly the documented properties' {
        $result = New-CheckResult -Name 'IPv6' -Status 'Warning' -Message 'IPv6 disabled'

        ($result.PSObject.Properties.Name | Sort-Object) -join ',' |
            Should -Be 'Check,Message,Status,Time'
    }

    It 'accepts positional arguments in the order Name, Status, Message' {
        $result = New-CheckResult 'NetBios' 'OK' 'Disabled'

        $result.Check | Should -Be 'NetBios'
        $result.Status | Should -Be 'OK'
        $result.Message | Should -Be 'Disabled'
    }

    It 'tolerates empty messages' {
        $result = New-CheckResult -Name 'Proxy' -Status 'OK' -Message ''

        $result.Message | Should -Be ''
    }
}

Describe 'Check-Network.ps1 - Test-LDAPPorts' {
    BeforeAll {
        . (Get-ScriptFunctionScriptBlock -Path $script:ScriptPath -Name 'Test-LDAPPorts')
    }

    It 'returns nothing when no server name is passed' {
        Test-LDAPPorts -ServerName '' -Port 389 | Should -BeNullOrEmpty
    }

    It 'returns nothing when the port is 0' {
        Test-LDAPPorts -ServerName 'dc01.contoso.com' -Port 0 | Should -BeNullOrEmpty
    }

    It 'returns false and warns when the server is not reachable' {
        $warnings = @()
        $result = Test-LDAPPorts -ServerName 'dc-does-not-exist.invalid' -Port 389 -WarningVariable warnings -WarningAction SilentlyContinue

        $result | Should -BeFalse
        $warnings.Count | Should -BeGreaterThan 0
    }
}

Describe 'Check-Network.ps1 - Test-UDP' {
    BeforeAll {
        . (Get-ScriptFunctionScriptBlock -Path $script:ScriptPath -Name 'Test-UDP')
    }

    It 'reports success for a resolvable target, because UDP is connectionless' {
        Test-UDP -target '127.0.0.1' -UDPport 53 | Should -BeTrue
    }

    It 'reports failure for a target that cannot be resolved' {
        Test-UDP -target 'udp-target-does-not-exist.invalid' -UDPport 53 -ErrorAction SilentlyContinue |
            Should -BeFalse
    }

    It 'requires target and port' {
        { Test-UDP -target '127.0.0.1' } | Should -Throw
    }
}

Describe 'Check-Network.ps1 - script contract' {
    It 'parses without errors' {
        (Get-ScriptAst -Path $script:ScriptPath).Errors | Should -BeNullOrEmpty
    }

    It 'declares the documented parameters with their default values' {
        $ast = (Get-ScriptAst -Path $script:ScriptPath).Ast
        $parameters = @{}
        foreach ($parameter in $ast.ParamBlock.Parameters) {
            $parameters[$parameter.Name.VariablePath.UserPath] = $parameter
        }

        $parameters.Keys | Should -Contain 'targetMTU'
        $parameters.Keys | Should -Contain 'mtuoh'
        $parameters.Keys | Should -Contain 'DNSDomain'
        $parameters.Keys | Should -Contain 'logpath'
        $parameters['mtuoh'].DefaultValue.Extent.Text | Should -Be '28'
    }
}
