@{
    RootModule        = 'IH.Common.psm1'
    ModuleVersion     = '1.0.0'
    GUID              = 'f0c1f3a2-0f1d-4d3b-9d3e-2b6c9a5c74d1'
    Author            = 'Fabian Niesen'
    CompanyName       = 'Infrastrukturhelden.de'
    Copyright         = '(c) 2022-2026 Fabian Niesen. Licensed under the MIT license.'
    Description       = 'Shared helper functions (logging, checks, reporting, mail) for the Infrastrukturhelden script collection.'
    PowerShellVersion = '5.1'
    FunctionsToExport = @(
        'Test-AdminRights',
        'Get-DefaultLogPath',
        'Start-Log',
        'Get-LogFilePath',
        'Write-Log',
        'Start-Wait',
        'New-CheckResult',
        'Get-HtmlReportStyle',
        'Send-EmailStatus',
        'New-SmtpCredential'
    )
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
    PrivateData       = @{
        PSData = @{
            LicenseUri = 'https://github.com/InfrastructureHeroes/Scipts'
            ProjectUri = 'https://github.com/InfrastructureHeroes/Scipts'
        }
    }
}
