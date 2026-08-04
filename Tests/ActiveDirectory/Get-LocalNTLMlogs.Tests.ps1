#requires -Modules Pester
<#
.SYNOPSIS
    Unit tests for the helper functions of ActiveDirectory\Get-LocalNTLMlogs.ps1.
#>

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..\TestHelpers\ScriptFunctions.psm1') -Force
    $script:ScriptPath = Join-Path (Get-RepositoryRoot) 'ActiveDirectory/Get-LocalNTLMlogs.ps1'
}

Describe 'Get-LocalNTLMlogs.ps1 - Get-FirstValue' {
    BeforeAll {
        . (Get-ScriptFunctionScriptBlock -Path $script:ScriptPath -Name 'Get-FirstValue')
    }

    It 'returns the value of the first matching name' {
        $map = @{ 'Secure Channel Name' = 'DC01'; 'SChannelName' = 'DC02' }

        Get-FirstValue -Map $map -Names @('Secure Channel Name', 'SChannelName') | Should -Be 'DC01'
    }

    It 'falls back to later names when the first key is missing' {
        $map = @{ 'SChannelName' = 'DC02' }

        Get-FirstValue -Map $map -Names @('Secure Channel Name', 'SChannelName') | Should -Be 'DC02'
    }

    It 'skips keys with a null value' {
        $map = @{ 'UserName' = $null; 'User' = 'contoso\alice' }

        Get-FirstValue -Map $map -Names @('UserName', 'User') | Should -Be 'contoso\alice'
    }

    It 'skips keys that only contain whitespace' {
        $map = @{ 'Domain' = "  `t "; 'DomainName' = 'CONTOSO' }

        Get-FirstValue -Map $map -Names @('Domain', 'DomainName') | Should -Be 'CONTOSO'
    }

    It 'returns null when none of the names is present' {
        Get-FirstValue -Map @{ 'A' = '1' } -Names @('B', 'C') | Should -BeNullOrEmpty
    }

    It 'returns null for an empty map' {
        Get-FirstValue -Map @{} -Names @('A') | Should -BeNullOrEmpty
    }

    It 'returns non string values unchanged' {
        $map = @{ 'Count' = 42 }

        $result = Get-FirstValue -Map $map -Names @('Count')

        $result | Should -Be 42
        $result | Should -BeOfType [int]
    }

    It 'treats keys case insensitively like the underlying hashtable' {
        $map = @{ 'workstation' = 'CLIENT01' }

        Get-FirstValue -Map $map -Names @('Workstation') | Should -Be 'CLIENT01'
    }

    It 'requires the Map parameter' {
        { Get-FirstValue -Names @('A') } | Should -Throw
    }
}
