#requires -Modules Pester
<#
.SYNOPSIS
    Unit tests for the helper functions of ActiveDirectory\Repair-DFSR.ps1.
#>

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..\TestHelpers\ScriptFunctions.psm1') -Force
    $script:ScriptPath = Join-Path (Get-RepositoryRoot) 'ActiveDirectory/Repair-DFSR.ps1'
}

Describe 'Repair-DFSR.ps1 - IsNull' {
    BeforeAll {
        . (Get-ScriptFunctionScriptBlock -Path $script:ScriptPath -Name 'IsNull')
    }

    It 'returns true for $null' {
        IsNull $null | Should -BeTrue
    }

    It 'returns true for an empty string' {
        IsNull '' | Should -BeTrue
    }

    It 'returns true for [System.Management.Automation.Language.NullString]::Value' {
        IsNull ([System.Management.Automation.Language.NullString]::Value) | Should -BeTrue
    }

    It 'returns true for [DBNull]::Value' {
        IsNull ([DBNull]::Value) | Should -BeTrue
    }

    It 'returns false for a non empty string' {
        IsNull 'DFSR' | Should -BeFalse
    }

    It 'returns false for whitespace, which is not considered empty' {
        IsNull ' ' | Should -BeFalse
    }

    It 'returns false for the number 0' {
        IsNull 0 | Should -BeFalse
    }

    It 'returns false for $false' {
        IsNull $false | Should -BeFalse
    }

    It 'returns false for an object' {
        IsNull ([PSCustomObject]@{ Name = 'SYSVOL' }) | Should -BeFalse
    }

    It 'returns false for an empty array' {
        IsNull @() | Should -BeFalse
    }
}

Describe 'Repair-DFSR.ps1 - Start-Log' {
    BeforeAll {
        . (Get-ScriptFunctionScriptBlock -Path $script:ScriptPath -Name 'Start-Log')
    }

    BeforeEach {
        $script:LogFile = Join-Path ([IO.Path]::GetTempPath()) "Repair-DFSR-$([guid]::NewGuid()).log"
    }

    AfterEach {
        Remove-Item -LiteralPath $script:LogFile -Force -ErrorAction SilentlyContinue
    }

    It 'creates the log file for an explicit path' {
        Start-Log -FilePath $script:LogFile

        Test-Path -LiteralPath $script:LogFile | Should -BeTrue
    }

    It 'keeps an existing log file' {
        Set-Content -LiteralPath $script:LogFile -Value 'previous run'

        Start-Log -FilePath $script:LogFile

        Get-Content -LiteralPath $script:LogFile -Raw | Should -Match 'previous run'
    }

    It 'recreates the log file with -DeleteExistingFile' {
        Set-Content -LiteralPath $script:LogFile -Value 'previous run'

        Start-Log -FilePath $script:LogFile -DeleteExistingFile

        Test-Path -LiteralPath $script:LogFile | Should -BeTrue
        Get-Content -LiteralPath $script:LogFile -Raw | Should -BeNullOrEmpty
    }
}

Describe 'Repair-DFSR.ps1 - Write-Log' {
    BeforeAll {
        . (Get-ScriptFunctionScriptBlock -Path $script:ScriptPath -Name 'Write-Log')
        $script:LogFile = Join-Path ([IO.Path]::GetTempPath()) "Repair-DFSR-$([guid]::NewGuid()).log"
    }

    AfterAll {
        Remove-Item -LiteralPath $script:LogFile -Force -ErrorAction SilentlyContinue
    }

    It 'appends a CMTrace formatted line to the log file' {
        $global:logFile = $script:LogFile
        $logFile = $script:LogFile

        Write-Log -Message 'Replication check started' -LogLevel 1 6>$null

        $content = Get-Content -LiteralPath $script:LogFile -Raw
        $content | Should -Match '\<!\[LOG\[Replication check started\]LOG\]!\>'
        $content | Should -Match 'type="1"'
    }

    It 'logs warnings on the warning stream for log level 2' {
        $global:logFile = $script:LogFile
        $logFile = $script:LogFile
        $warnings = @()

        Write-Log -Message 'Backlog detected' -LogLevel 2 -WarningVariable warnings -WarningAction SilentlyContinue

        [string[]]$warnings | Should -Contain 'Backlog detected'
        Get-Content -LiteralPath $script:LogFile -Raw | Should -Match 'type="2"'
    }

    It 'rejects log levels outside of 1..3' {
        $global:logFile = $script:LogFile
        $logFile = $script:LogFile

        { Write-Log -Message 'Invalid' -LogLevel 4 } | Should -Throw
    }

    It 'writes every message as an additional line' {
        $global:logFile = $script:LogFile
        $logFile = $script:LogFile

        Write-Log -Message 'First' -LogLevel 1 6>$null
        Write-Log -Message 'Second' -LogLevel 1 6>$null

        $lines = Get-Content -LiteralPath $script:LogFile
        ($lines | Where-Object { $_ -match 'First|Second' }).Count | Should -BeGreaterOrEqual 2
    }
}
