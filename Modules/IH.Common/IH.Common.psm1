<#
.SYNOPSIS
    Shared helper functions for the Infrastrukturhelden script collection.

.DESCRIPTION
    Shared helper functions for the Infrastrukturhelden script collection. This module
    contains the helpers that were previously copied into several scripts:
    CMTrace compatible logging, progress waits, standardized check results,
    HTML report styling and SMTP mail delivery.

.NOTES
    Author     :    Fabian Niesen
    Filename   :    IH.Common.psm1
    Requires   :    PowerShell Version 5.1
    Version    :    1.0 FN 04.08.2026 Initial version, consolidated from the existing scripts
    License    :    The MIT License (MIT)
                    Copyright (c) 2022-2026 Fabian Niesen
                    Portions of Start-Log / Write-Log:
                    Original Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT license.
                    See LICENSE in the project https://github.com/gregnottage/IntuneScripts for license information.
    Disclaimer :    This module is provided "as is" without warranty. Use at your own risk.
    GitHub     :    https://github.com/InfrastructureHeroes/Scipts

.LINK
    https://github.com/InfrastructureHeroes/Scipts
#>

$script:LogFilePath = $null

function Test-AdminRights {
    <#
    .SYNOPSIS
        Checks whether the current session runs with local administrator rights.
    .DESCRIPTION
        Checks whether the current session runs with local administrator rights.
        Returns $true when the current user is member of the local Administrators group.
    .EXAMPLE
        IF (-not (Test-AdminRights)) { Write-Warning "Admin rights required" ; break }
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    ([Security.Principal.WindowsPrincipal]$identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-DefaultLogPath {
    <#
    .SYNOPSIS
        Determines a writable log directory.
    .DESCRIPTION
        Determines a writable log directory. The PowerShell transcription output directory
        from group policy is preferred, otherwise the local machine log folder is used.
        Sessions without administrator rights fall back to the user profile.
    .PARAMETER SubFolder
        Name of the sub folder that is appended to the detected base folder.
    .EXAMPLE
        Get-DefaultLogPath -SubFolder "SecureAD"
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [string]$SubFolder = "SecureAD"
    )
    Try {
        $transcription = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription\" -Name "OutputDirectory" -ErrorAction Stop).OutputDirectory
        $logPath = Join-Path (Split-Path -Parent $transcription) $SubFolder
        If (!(Test-Path $logPath)) { New-Item $logPath -Type Directory -Force | Out-Null }
        "Test $(Get-Date) from $env:COMPUTERNAME" | Out-File -FilePath (Join-Path $logPath "test.log") -Append -ErrorAction Stop
        Write-Verbose "Log path autodetected from transcription policy: $logPath"
        return $logPath
    }
    Catch {
        Write-Warning -Message "LogPath not found in Registry. Fall back to local log path."
        IF (Test-AdminRights) { return (Join-Path "$env:windir\System32\LogFiles" $SubFolder) }
        return (Join-Path (Join-Path $HOME "LogFiles") $SubFolder)
    }
}

function Start-Log {
    <#
    .SYNOPSIS
        Initializes the log file used by Write-Log.
    .DESCRIPTION
        Initializes the log file used by Write-Log. Without -FilePath the log file name is
        built from the script name, the current date and the computer name and placed in the
        folder returned by Get-DefaultLogPath.
    .PARAMETER FilePath
        Full path of the log file. Autodetected when not provided.
    .PARAMETER ScriptName
        Name of the calling script, used for the autodetected log file name.
    .PARAMETER SubFolder
        Sub folder used for the autodetected log path.
    .PARAMETER DeleteExistingFile
        Deletes an already existing log file instead of appending to it.
    .EXAMPLE
        Start-Log -FilePath "C:\Windows\Logs\MyScript\MyScript.log" -DeleteExistingFile
    .EXAMPLE
        $log = Start-Log -ScriptName "Repair-DFSR" -PassThru
    .NOTES
        Original Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT license.
        Additional Copyright for changes (c) 2022-2026 Fabian Niesen. All rights reserved. Licensed under the MIT license.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [string]$FilePath,
        [string]$ScriptName,
        [string]$SubFolder = "SecureAD",
        [Parameter(HelpMessage = 'Deletes existing file if used with the -DeleteExistingFile switch')]
        [switch]$DeleteExistingFile,
        [switch]$PassThru
    )
    IF ([string]::IsNullOrWhiteSpace($FilePath)) {
        $logPath = Get-DefaultLogPath -SubFolder $SubFolder
        IF ([string]::IsNullOrWhiteSpace($ScriptName)) { $ScriptName = "PowerShell" }
        $logName = $ScriptName + "_" + (Get-Date -UFormat "%Y%m%d") + "_" + $env:COMPUTERNAME
        $FilePath = Join-Path $logPath "$logName.log"
        Write-Verbose "No logfile provided - Use $FilePath"
    }
    Try {
        If ($DeleteExistingFile -and (Test-Path $FilePath)) { Remove-Item $FilePath -Force }
        If (!(Test-Path $FilePath)) { New-Item $FilePath -Type File -Force | Out-Null }
        $script:LogFilePath = $FilePath
    }
    Catch {
        Write-Error $_.Exception.Message
        return
    }
    IF ($PassThru) {
        [PSCustomObject]@{
            LogFile = $FilePath
            LogPath = Split-Path -Parent $FilePath
            LogName = [IO.Path]::GetFileNameWithoutExtension($FilePath)
        }
    }
}

function Get-LogFilePath {
    <#
    .SYNOPSIS
        Returns the log file currently used by Write-Log.
    .DESCRIPTION
        Returns the log file currently used by Write-Log or $null when Start-Log was not called yet.
    .EXAMPLE
        Get-LogFilePath
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()
    $script:LogFilePath
}

function Write-Log {
    <#
    .SYNOPSIS
        Writes a CMTrace compatible log entry and echoes it to the console.
    .DESCRIPTION
        Writes a CMTrace compatible log entry and echoes it to the console. Messages with a
        LogLevel above 1 are written as warning. Start-Log is called with autodetection when
        the log file was not initialized before.
    .PARAMETER Message
        Message to log.
    .PARAMETER LogLevel
        1 = Information, 2 = Warning, 3 = Error.
    .EXAMPLE
        Write-Log -Message "Something went wrong" -LogLevel 3
    .NOTES
        Original Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT license.
        Additional Copyright for changes (c) 2022-2026 Fabian Niesen. All rights reserved. Licensed under the MIT license.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,

        [Parameter()]
        [ValidateSet(1, 2, 3)]
        [int]$LogLevel = 1
    )
    IF (-not $script:LogFilePath) {
        Write-Warning "Start-Log was missing - starting now with autodetection"
        Start-Log
    }
    If ($LogLevel -eq 1) { Write-Host $Message } else { Write-Warning $Message }
    $TimeGenerated = "$(Get-Date -Format HH:mm:ss).$((Get-Date).Millisecond)+000"
    $Line = '<![LOG[{0}]LOG]!><time="{1}" date="{2}" component="{3}" context="" type="{4}" thread="" file="">'
    $ExecName = TRY { ($MyInvocation.ScriptName | Split-Path -Leaf -ErrorAction Stop) } CATCH { "NoScript" }
    $LineFormat = $Message, $TimeGenerated, (Get-Date -Format MM-dd-yyyy), "$($ExecName):$($MyInvocation.ScriptLineNumber)", $LogLevel
    ($Line -f $LineFormat) | Out-File -FilePath $script:LogFilePath -Append
}

function Start-Wait {
    <#
    .SYNOPSIS
        Waits the given amount of seconds and shows a progress bar.
    .DESCRIPTION
        Waits the given amount of seconds and shows a progress bar. When a log file was
        initialized with Start-Log the comment is written to the log as well.
    .PARAMETER Seconds
        Number of seconds to wait.
    .PARAMETER Comment
        Text shown in the progress bar.
    .PARAMETER Id
        Progress bar Id.
    .PARAMETER ParentId
        Progress bar parent Id.
    .EXAMPLE
        Start-Wait -Seconds 5 -Comment "Waiting for AD"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][Alias('SleepTime')][int]$Seconds,
        [Alias('Activity')][string]$Comment = "Something magic is happend in the background",
        [int]$Id = 25,
        [int]$ParentId
    )
    Write-Verbose -Message "$($MyInvocation.InvocationName) function..."
    IF ($script:LogFilePath) { Write-Log -Message $Comment }
    For ($i = 1; $i -le $Seconds; $i++) {
        $progress = @{
            Activity        = "Please Wait - $Comment - $i of $Seconds seconds"
            Status          = "Seconds Remaining: $($Seconds - $i)"
            PercentComplete = ($i / $Seconds) * 100
            Id              = $Id
        }
        IF ($PSBoundParameters.ContainsKey('ParentId')) { $progress.ParentId = $ParentId }
        Write-Progress @progress
        Start-Sleep -Seconds 1
    }
    Write-Progress -Activity $Comment -Status "Done waiting..." -Completed -Id $Id
}

function New-CheckResult {
    <#
    .SYNOPSIS
        Creates a standardized check result object.
    .DESCRIPTION
        Creates a standardized check result object used by the health check scripts.
    .PARAMETER Name
        Name of the check.
    .PARAMETER Status
        Status of the check (OK, Warning, Failed).
    .PARAMETER Message
        Detailed message about the check result.
    .EXAMPLE
        New-CheckResult -Name 'WSUS Service' -Status 'OK' -Message "Service is running"
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][ValidateSet('OK', 'Warning', 'Failed')][string]$Status,
        [string]$Message
    )
    [PSCustomObject]@{
        Check   = $Name
        Status  = $Status
        Message = $Message
        Time    = (Get-Date)
    }
}

function Get-HtmlReportStyle {
    <#
    .SYNOPSIS
        Returns the HTML style block used for the mail reports.
    .DESCRIPTION
        Returns the HTML style block used as -Head for ConvertTo-Html in the report scripts.
    .EXAMPLE
        $results | ConvertTo-Html -Head (Get-HtmlReportStyle)
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()
    "<Style>BODY{font-size:12px;font-family:verdana,sans-serif;color:navy;font-weight:normal;}" +
    "TABLE{border-width:1px;cellpadding=10;border-style:solid;border-color:navy;border-collapse:collapse;}" +
    "TH{font-size:12px;border-width:1px;padding:10px;border-style:solid;border-color:navy;}" +
    "TD{font-size:10px;border-width:1px;padding:10px;border-style:solid;border-color:navy;}</Style>"
}

function Send-EmailStatus {
    <#
    .SYNOPSIS
        Sends a status mail over SMTP.
    .DESCRIPTION
        Sends a status mail over SMTP. Supports STARTTLS and SMTP authentication.
    .PARAMETER From
        Sender address.
    .PARAMETER To
        Recipient address.
    .PARAMETER Subject
        Mail subject.
    .PARAMETER SmtpServer
        SMTP server used for delivery.
    .PARAMETER Body
        Mail body.
    .PARAMETER BodyAsHtml
        Sends the body as HTML.
    .PARAMETER SmtpPort
        SMTP port, default 25.
    .PARAMETER UseTls
        Enables SSL/TLS for the SMTP connection.
    .PARAMETER Credential
        Credential used for SMTP authentication.
    .EXAMPLE
        Send-EmailStatus -From wsus@domain.local -To admin@domain.local -Subject "Report" -SmtpServer mail.domain.local -Body $html -BodyAsHtml
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$From,
        [Parameter(Mandatory = $true)][string]$To,
        [Parameter(Mandatory = $true)][string]$Subject,
        [Parameter(Mandatory = $true)][string]$SmtpServer,
        [string]$Body,
        [switch]$BodyAsHtml,
        [int]$SmtpPort = 25,
        [switch]$UseTls,
        [System.Management.Automation.PSCredential]$Credential
    )
    Try {
        $SmtpMessage = New-Object System.Net.Mail.MailMessage $From, $To, $Subject, $Body
        $SmtpMessage.IsBodyHTML = [bool]$BodyAsHtml
        $SmtpClient = New-Object System.Net.Mail.SmtpClient($SmtpServer, $SmtpPort)
        IF ($UseTls) { $SmtpClient.EnableSsl = $true }
        IF ($Credential) { $SmtpClient.Credentials = $Credential.GetNetworkCredential() }
        $SmtpClient.Send($SmtpMessage)
        Write-Verbose "Email sent successfully to $To"
        $SmtpMessage.Dispose()
        $SmtpClient.Dispose()
    }
    Catch {
        Write-Warning "Failed to send email: $($_.Exception.Message)"
    }
}

function New-SmtpCredential {
    <#
    .SYNOPSIS
        Builds a PSCredential for SMTP authentication.
    .DESCRIPTION
        Builds a PSCredential from a user name and a secure string password. If no password is
        passed, it is prompted for interactively.
    .PARAMETER UserName
        SMTP user name.
    .PARAMETER Password
        SMTP password as secure string. Prompted for when omitted.
    .EXAMPLE
        Send-EmailStatus @mailParam -Credential (New-SmtpCredential -UserName $SmtpUser -Password $SmtpPw)
    #>
    [CmdletBinding()]
    [OutputType([System.Management.Automation.PSCredential])]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingUsernameAndPasswordParams', '', Justification = 'Converts the SMTP parameters of the existing scripts into a PSCredential')]
    param(
        [Parameter(Mandatory = $true)][string]$UserName,
        [System.Security.SecureString]$Password
    )
    If (-not $Password) { $Password = Read-Host -Prompt "Password for SMTP user $UserName" -AsSecureString }
    New-Object System.Management.Automation.PSCredential($UserName, $Password)
}

Export-ModuleMember -Function Test-AdminRights, Get-DefaultLogPath, Start-Log, Get-LogFilePath, Write-Log,
Start-Wait, New-CheckResult, Get-HtmlReportStyle, Send-EmailStatus, New-SmtpCredential
