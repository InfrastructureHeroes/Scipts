#requires -Modules Pester
<#
.SYNOPSIS
    Unit tests for the helper functions of WSUS\Get-WsusHealth.ps1.
#>

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..\TestHelpers\ScriptFunctions.psm1') -Force
    $script:ScriptPath = Join-Path (Get-RepositoryRoot) 'WSUS/Get-WsusHealth.ps1'
}

Describe 'Get-WsusHealth.ps1 - New-CheckResult' {
    BeforeAll {
        . (Get-ScriptFunctionScriptBlock -Path $script:ScriptPath -Name 'New-CheckResult')
    }

    It 'returns a result object for a successful check' {
        $result = New-CheckResult -Name 'WSUS Service' -Status 'OK' -Message 'Service is running'

        $result.Check | Should -Be 'WSUS Service'
        $result.Status | Should -Be 'OK'
        $result.Message | Should -Be 'Service is running'
        $result.Time | Should -BeOfType [datetime]
    }

    It 'returns a result object for a failed check' {
        $result = New-CheckResult -Name 'Sync' -Status 'Failed' -Message 'Last sync failed'

        $result.Status | Should -Be 'Failed'
        $result.Message | Should -Be 'Last sync failed'
    }

    It 'produces objects that can be collected and filtered by status' {
        $results = @(
            New-CheckResult -Name 'A' -Status 'OK' -Message 'fine'
            New-CheckResult -Name 'B' -Status 'Warning' -Message 'hmm'
            New-CheckResult -Name 'C' -Status 'Failed' -Message 'broken'
        )

        ($results | Where-Object Status -eq 'Failed').Check | Should -Be 'C'
        $results.Count | Should -Be 3
    }

    It 'produces objects that can be exported to CSV' {
        $csvPath = Join-Path ([IO.Path]::GetTempPath()) "wsushealth-$([guid]::NewGuid()).csv"
        try {
            New-CheckResult -Name 'Disk' -Status 'Warning' -Message 'Low space' |
                Export-Csv -Path $csvPath -NoTypeInformation -Delimiter ';'

            $imported = Import-Csv -Path $csvPath -Delimiter ';'
            $imported.Check | Should -Be 'Disk'
            $imported.Status | Should -Be 'Warning'
        } finally {
            Remove-Item -LiteralPath $csvPath -Force -ErrorAction SilentlyContinue
        }
    }
}

Describe 'Get-WsusHealth.ps1 - script contract' {
    It 'parses without errors' {
        (Get-ScriptAst -Path $script:ScriptPath).Errors | Should -BeNullOrEmpty
    }

    It 'offers the mail and CSV export switches' {
        $ast = (Get-ScriptAst -Path $script:ScriptPath).Ast
        $names = $ast.ParamBlock.Parameters.Name.VariablePath.UserPath

        $names | Should -Contain 'EmailLog'
        $names | Should -Contain 'TestMail'
        $names | Should -Contain 'CSVExportPath'
    }
}
