<#
.SYNOPSIS
    Pester tests for the shared IH.Common module.
.DESCRIPTION
    Pester tests for the shared IH.Common module. Run with: Invoke-Pester .\Modules\IH.Common
.NOTES
    Author     :    Fabian Niesen
    Filename   :    IH.Common.Tests.ps1
    Version    :    1.0 FN 04.08.2026 Initial version
.LINK
    https://github.com/InfrastructureHeroes/Scipts
#>
BeforeAll {
    Import-Module (Join-Path $PSScriptRoot "IH.Common.psd1") -Force
    $script:TestRoot = Join-Path ([IO.Path]::GetTempPath()) "IH.Common.Tests-$(Get-Random)"
    New-Item -Path $script:TestRoot -ItemType Directory -Force | Out-Null
}

AfterAll {
    Remove-Item -Path $script:TestRoot -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Module IH.Common -Force -ErrorAction SilentlyContinue
}

Describe "New-CheckResult" {
    It "returns the standardized properties" {
        $result = New-CheckResult -Name "MyCheck" -Status "OK" -Message "all fine"
        $result.Check | Should -Be "MyCheck"
        $result.Status | Should -Be "OK"
        $result.Message | Should -Be "all fine"
        $result.Time | Should -BeOfType [datetime]
    }

    It "rejects an unknown status" {
        { New-CheckResult -Name "MyCheck" -Status "Broken" -Message "x" } | Should -Throw
    }
}

Describe "Get-HtmlReportStyle" {
    It "returns a single HTML style block" {
        $style = Get-HtmlReportStyle
        $style | Should -BeOfType [string]
        $style | Should -BeLike "<Style>*</Style>"
    }
}

Describe "Start-Log and Write-Log" {
    It "creates the log file and reports it" {
        $file = Join-Path $script:TestRoot "start-log.log"
        $log = Start-Log -FilePath $file -PassThru
        $file | Should -Exist
        $log.LogFile | Should -Be $file
        $log.LogPath | Should -Be $script:TestRoot
        $log.LogName | Should -Be "start-log"
        Get-LogFilePath | Should -Be $file
    }

    It "writes a CMTrace compatible line" {
        $file = Join-Path $script:TestRoot "write-log.log"
        Start-Log -FilePath $file
        Write-Log -Message "hello world" 6> $null
        (Get-Content $file -Raw) | Should -Match '<!\[LOG\[hello world\]LOG\]!>.*type="1"'
    }

    It "writes warnings for LogLevel 3" {
        $file = Join-Path $script:TestRoot "write-log-error.log"
        Start-Log -FilePath $file
        Write-Log -Message "broken" -LogLevel 3 -WarningAction SilentlyContinue
        (Get-Content $file -Raw) | Should -BeLike '*type="3"*'
    }

    It "truncates an existing file with -DeleteExistingFile" {
        $file = Join-Path $script:TestRoot "delete-log.log"
        Start-Log -FilePath $file
        Write-Log -Message "first run" 6> $null
        Start-Log -FilePath $file -DeleteExistingFile
        (Get-Content $file -Raw) | Should -BeNullOrEmpty
    }
}

Describe "New-SmtpCredential" {
    It "builds a credential from user name and secure password" {
        $secure = ConvertTo-SecureString "Pa55w0rd" -AsPlainText -Force
        $credential = New-SmtpCredential -UserName "wsus@domain.local" -Password $secure
        $credential | Should -BeOfType [System.Management.Automation.PSCredential]
        $credential.UserName | Should -Be "wsus@domain.local"
        $credential.GetNetworkCredential().Password | Should -Be "Pa55w0rd"
    }
}

Describe "Start-Wait" {
    It "waits the requested amount of seconds" {
        $duration = Measure-Command { Start-Wait -Seconds 1 -Comment "unit test" 6> $null }
        $duration.TotalSeconds | Should -BeGreaterOrEqual 1
    }
}
