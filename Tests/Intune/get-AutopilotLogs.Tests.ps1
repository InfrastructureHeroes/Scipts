#requires -Modules Pester
<#
.SYNOPSIS
    Unit tests for the logging functions of Intune\get-AutopilotLogs.ps1.
#>

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..\TestHelpers\ScriptFunctions.psm1') -Force
    $script:ScriptPath = Join-Path (Get-RepositoryRoot) 'Intune/get-AutopilotLogs.ps1'
}

Describe 'get-AutopilotLogs.ps1 - Start-Log' {
    BeforeAll {
        . (Get-ScriptFunctionScriptBlock -Path $script:ScriptPath -Name @('Start-Log', 'Write-Log'))
    }

    BeforeEach {
        $script:LogFile = Join-Path ([IO.Path]::GetTempPath()) "autopilot-$([guid]::NewGuid()).log"
    }

    AfterEach {
        Remove-Item -LiteralPath $script:LogFile -Force -ErrorAction SilentlyContinue
    }

    It 'creates the log file when it does not exist' {
        Start-Log -FilePath $script:LogFile

        Test-Path -LiteralPath $script:LogFile | Should -BeTrue
    }

    It 'stores the log path for the following Write-Log calls' {
        Start-Log -FilePath $script:LogFile

        Write-Log -Message 'Collecting Autopilot logs' 6>$null

        Get-Content -LiteralPath $script:LogFile -Raw | Should -Match 'Collecting Autopilot logs'
    }

    It 'removes an existing file with -DeleteExistingFile' {
        Set-Content -LiteralPath $script:LogFile -Value 'stale content'

        Start-Log -FilePath $script:LogFile -DeleteExistingFile

        Test-Path -LiteralPath $script:LogFile | Should -BeFalse
    }

    It 'creates missing files even in an existing directory tree' {
        $nested = Join-Path ([IO.Path]::GetTempPath()) "autopilot-$([guid]::NewGuid())/nested.log"
        try {
            Start-Log -FilePath $nested

            Test-Path -LiteralPath $nested | Should -BeTrue
        } finally {
            Remove-Item -LiteralPath (Split-Path -Parent $nested) -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'reports an error instead of throwing for an invalid path' {
        $errors = @()

        Start-Log -FilePath ([string]::Empty) -ErrorVariable errors -ErrorAction SilentlyContinue

        $errors.Count | Should -BeGreaterThan 0
    }
}

Describe 'get-AutopilotLogs.ps1 - Write-Log' {
    BeforeAll {
        . (Get-ScriptFunctionScriptBlock -Path $script:ScriptPath -Name @('Start-Log', 'Write-Log'))
    }

    BeforeEach {
        $script:LogFile = Join-Path ([IO.Path]::GetTempPath()) "autopilot-$([guid]::NewGuid()).log"
        Start-Log -FilePath $script:LogFile
    }

    AfterEach {
        Remove-Item -LiteralPath $script:LogFile -Force -ErrorAction SilentlyContinue
    }

    It 'writes the message in CMTrace format' {
        Write-Log -Message 'Autopilot diagnostics collected' 6>$null

        $content = Get-Content -LiteralPath $script:LogFile -Raw
        $content | Should -Match '<!\[LOG\[Autopilot diagnostics collected\]LOG\]!>'
        $content | Should -Match 'time="\d{2}:\d{2}:\d{2}\.\d+\+000"'
        $content | Should -Match 'date="\d{2}-\d{2}-\d{4}"'
    }

    It 'records the log level in the type attribute' {
        Write-Log -Message 'A warning' -LogLevel 2 6>$null

        Get-Content -LiteralPath $script:LogFile -Raw | Should -Match 'type="2"'
    }

    It 'rejects log levels outside of 1..3' {
        { Write-Log -Message 'Invalid level' -LogLevel 0 } | Should -Throw
    }

    It 'requires a message' {
        { Write-Log -Message '' } | Should -Throw
    }

    It 'appends one line per call' {
        Write-Log -Message 'First' 6>$null
        Write-Log -Message 'Second' 6>$null
        Write-Log -Message 'Third' 6>$null

        (Get-Content -LiteralPath $script:LogFile).Count | Should -Be 3
    }

    It 'writes the message to the host as well' {
        $output = Write-Log -Message 'Visible message' 6>&1

        $output | Should -Match 'Visible message'
    }
}
