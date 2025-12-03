#requires -version 5.1

<#
.SYNOPSIS
        Comprehensive WSUS health checks with detailed diagnostic reporting.

.DESCRIPTION
        Performs comprehensive health checks on Windows Server Update Services (WSUS) to validate 
        service availability, database connectivity, disk space, synchronization status, and event logs.
        Each check returns a consistent status object (OK, Warning, Failed) for easy integration 
        with monitoring systems.

        Checks performed:
        1. WSUS Service Status (WsusService) & WSUS Connection URL Validation
        2. IIS AppPool Status (WsusPool)
        3. SSL Certificate Check (when HTTPS is enabled)
        4. WSUS API Connectivity (Microsoft.UpdateServices.Administration)
        5. Database/API Query Validation (GetComputerTargetGroups)
        6. WSUS Content Directory Disk Space
        7. System Drive Disk Space
        8. Last Successful Synchronization Status
        9. Catalog and Content Synchronization Errors
        10. WSUS Self-Update Status
        11. Email Notification Failures (last 7 days)
        12. Update Installation Failures (last 7 days)
        13. Inventory Failures (last 7 days)
        14. Recent Event Log Errors (last 24 hours)

.PARAMETER WSUSServer
        WSUS server FQDN or hostname. Default: local computer FQDN

.PARAMETER UseSSL
        Enable HTTPS/SSL connections to WSUS server

.PARAMETER WSUSPort
        WSUS port number. Default: 8530 (HTTP) or 8531 (HTTPS)

.PARAMETER CSVExportPath
        Create CSV report in the specified path. Filename is set to "Get-WsusHealth.csv"

.EXAMPLE
        .\Get-WsusHealth.ps1
        Runs health checks on the local WSUS server

.EXAMPLE
        .\Get-WsusHealth.ps1 -Server "wsus.example.com" -UseSSL
        Runs health checks on remote WSUS server with HTTPS

.NOTES
        Author     :    Fabian Niesen
        Filename   :    Get-WsusHealth.ps1
        Requires   :    PowerShell 5.1+, Windows Server 2012 R2+, WSUS installed
        Updated    :    03.12.2025
        LastModBy  :    Fabian Niesen
        License    :    Except for the LDAP Test Code, witch is licensed by Evotec under MIT License 
                        (Code for LDAP Test from https://evotec.xyz/testing-ldap-and-ldaps-connectivity-with-powershell/ under MIT license),
                        The MIT License (MIT)
                        Copyright (c) 2022-2025 Fabian Niesen
                        Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation 
                        files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, 
                        merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is 
                        furnished to do so, subject to the following conditions:
                        The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
                        The Software is provided "as is", without warranty of any kind, express or implied, including but not limited to the warranties 
                        of merchantability, fitness for a particular purpose and noninfringement. In no event shall the authors or copyright holders be 
                        liable for any claim, damages or other liability, whether in an action of contract, tort or otherwise, arising from, out of or in 
                        connection with the software or the use or other dealings in the Software.
        Disclaimer :    This script is provided "as is" without warranty. Use at your own risk.
                        The author assumes no responsibility for any damage or data loss caused by this script.
                        Test thoroughly in a controlled environment before deploying to production.
        GitHub     :    https://github.com/InfrastructureHeroes/Scipts
        Version    :    1.3 FN 03.12.2025 Change to MIT License, housekeeping Header
        History    : 	1.2 FN 01.12.2025 BugFixes
                        1.1 FN 01.12.2025 BugFixes
                        1.0 FN 30.11.2025 Initial version.
.LINK
        https://github.com/InfrastructureHeroes/Scipts
        https://www.infrastrukturhelden.de/microsoft-infrastruktur/wsus/wsus-fehleranalyse-und-health-checks-praxisleitfaden-mit-powershell/

#>
[CmdletBinding()]
param(
        [string]$WSUSServer = $($env:COMPUTERNAME + "." + $env:USERDNSDOMAIN),
        [switch]$UseSSL,
        [int]$WSUSPort = 8530,
        [string]$SmtpServer,
        [string]$SmtpFrom,
        [string]$SmtpTo,
        [string]$SmtpSubject = "WSUS Health Report",
        [switch]$SmtpTLS,
        [switch]$SmtpAuth,
        [string]$SmtpUser = "",
        [string]$SmtpPw = "",
        [int]$SmtpPort = 25,
        [switch]$EmailLog,
        [switch]$TestMail,
        [string]$CSVExportPath
)

#region Helper Functions

function New-CheckResult {
        <#
        .SYNOPSIS
                Creates a standardized check result object
        .PARAMETER Name
                Name of the check
        .PARAMETER Status
                Status of the check (OK, Warning, Failed)
        .PARAMETER Message
                Detailed message about the check result
        #>
        param($Name, $Status, $Message)
        [PSCustomObject]@{
                Check   = $Name
                Status  = $Status
                Message = $Message
                Time    = (Get-Date)
        }
}

# Mail function
Function SendEmailStatus {
        param(
                [string]$From,
                [string]$To,
                [string]$Subject,
                [string]$SmtpServer,
                [bool]$BodyAsHtml,
                [string]$Body,
                [int]$SmtpPort
        )
        try {
                $SmtpMessage = New-Object System.Net.Mail.MailMessage $From, $To, $Subject, $Body
                $SmtpMessage.IsBodyHTML = $BodyAsHtml
                $SmtpClient = New-Object System.Net.Mail.SmtpClient($SmtpServer, $SmtpPort)
                if ($SmtpTLS) { $SmtpClient.EnableSsl = $true }
                if ($SmtpAuth) { $SmtpClient.Credentials = New-Object System.Net.NetworkCredential($SmtpUser, $SmtpPw) }
                $SmtpClient.Send($SmtpMessage)
                Write-Output "Email sent successfully."
                $SmtpMessage.Dispose()
                Remove-Variable SmtpClient
                Remove-Variable SmtpMessage
        }
        catch {
                Write-Warning "Failed to send email: $($_.Exception.Message)"
        }
}
$scriptversion = "1.3"
# HTML Style for email
$Style = "<Style>BODY{font-size:12px;font-family:verdana,sans-serif;color:navy;font-weight:normal;}" + "TABLE{border-width:1px;cellpadding=10;border-style:solid;border-color:navy;border-collapse:collapse;}" + "TH{font-size:12px;border-width:1px;padding:10px;border-style:solid;border-color:navy;}" + "TD{font-size:10px;border-width:1px;padding:10px;border-style:solid;border-color:navy;}</Style>"
$SmtpSubject = $SmtpSubject + " - WSUS Server: $WSUSServer"
# Test mail if requested
if ($TestMail) {
        $TestBody = "<h1>Test email from WSUS Health Check on $env:COMPUTERNAME</h1><BR>Send over: $SmtpServer"
        SendEmailStatus -From $SmtpFrom -To $SmtpTo -Subject "Test: $SmtpSubject" -SmtpServer $SmtpServer -BodyAsHtml $true -Body $TestBody -SmtpPort $SmtpPort
}

#endregion

$results = @()

#region 1) WSUS Service
try {
        $svc = Get-Service -Name 'WsusService' -ComputerName $WSUSServer -ErrorAction Stop
        if ($svc.Status -eq 'Running') {
                $results += New-CheckResult -Name 'WSUS Service' -Status 'OK' -Message "Service 'WsusService' is Running."
        } else {
                $results += New-CheckResult -Name 'WSUS Service' -Status 'Failed' -Message "Service 'WsusService' is $($svc.Status)."
        }
} catch {
        $results += New-CheckResult -Name 'WSUS Service' -Status 'Failed' -Message $_.Exception.Message
}

try {
        If ($UseSSL -and $WSUSPort -eq 8530) { $WSUSPort = 8531 }
        $protocol = if ($UseSSL) { 'https' } else { 'http' }
        $wsusUrl = $protocol + "://" + $WSUSServer + ":" + $WSUSPort + "/ApiRemoting30"
        $results += New-CheckResult -Name 'WSUS Connection URL' -Status 'OK' -Message "Using $wsusUrl"
} catch {
        $results += New-CheckResult -Name 'WSUS Connection URL' -Status 'Failed' -Message $_.Exception.Message
}
#endregion
#region 2) IIS App Pool (WsusPool)
try {
        Import-Module WebAdministration -ErrorAction Stop | Out-Null
        $appPoolState = Get-WebAppPoolState -Name 'WsusPool' -ErrorAction Stop
        if ($appPoolState.Value -eq 'Started') {
                $results += New-CheckResult -Name 'IIS AppPool (WsusPool)' -Status 'OK' -Message "WsusPool is Started."
        } else {
                $results += New-CheckResult -Name 'IIS AppPool (WsusPool)' -Status 'Failed' -Message "WsusPool is $($appPoolState.Value)."
        }
} catch {
        $results += New-CheckResult -Name 'IIS AppPool (WsusPool)' -Status 'Failed' -Message $_.Exception.Message
}
#endregion
#region 3 SSL Certificate Check (only if UseSSL is enabled)
if ($UseSSL) {
        try {
                Import-Module WebAdministration -ErrorAction Stop | Out-Null
                $binding = Get-WebBinding -Name 'WSUS Administration' -Protocol 'https' -ErrorAction Stop
                
                if ($binding) {
                        $certThumbprint = $binding.certificateHash
                        $cert = Get-Item -Path "Cert:\LocalMachine\My\$certThumbprint" -ErrorAction Stop
                        
                        $expiryDate = $cert.NotAfter
                        $daysUntilExpiry = ($expiryDate - (Get-Date)).Days
                        
                        if ($daysUntilExpiry -gt 90) {
                                $status = 'OK'
                                $msg = "SSL Certificate: $($cert.Subject) | Expires: $($expiryDate.ToString('yyyy-MM-dd')) | Days remaining: $daysUntilExpiry"
                        } elseif ($daysUntilExpiry -gt 0) {
                                $status = 'Warning'
                                $msg = "SSL Certificate: $($cert.Subject) | Expires: $($expiryDate.ToString('yyyy-MM-dd')) | Days remaining: $daysUntilExpiry (Renew soon!)"
                        } else {
                                $status = 'Failed'
                                $msg = "SSL Certificate: $($cert.Subject) | Expires: $($expiryDate.ToString('yyyy-MM-dd')) | EXPIRED!"
                        }
                        
                        $results += New-CheckResult -Name 'SSL Certificate (WSUS)' -Status $status -Message $msg
                } else {
                        $results += New-CheckResult -Name 'SSL Certificate (WSUS)' -Status 'Failed' -Message "No HTTPS binding found for WSUS Administration site."
                }
        } catch {
                $results += New-CheckResult -Name 'SSL Certificate (WSUS)' -Status 'Failed' -Message $_.Exception.Message
        }
}
#endregion
#region 4) WSUS API connectivity (AdminProxy)
$wsus = $null
try {
        [void][Reflection.Assembly]::LoadWithPartialName('Microsoft.UpdateServices.Administration')
        If ($UseSSL) { $wsus = [Microsoft.UpdateServices.Administration.AdminProxy]::GetUpdateServer($WSUSServer, $true, $WSUSPort) } Else {$wsus = [Microsoft.UpdateServices.Administration.AdminProxy]::GetUpdateServer($WSUSServer, $false, $WSUSPort)}
        if ($wsus -ne $null) {
                $results += New-CheckResult -Name 'WSUS API' -Status 'OK' -Message "Connected to WSUS API on '$WSUSServer'."
        } else {
                $results += New-CheckResult -Name 'WSUS API' -Status 'Failed' -Message "AdminProxy returned null."
        }
} catch {
        $results += New-CheckResult -Name 'WSUS API' -Status 'Failed' -Message $_.Exception.Message
}
#endregion
#region 5) Basic DB/API query (GetComputerTargetGroups) - ensures server side queries are functional
try {
        if ($wsus -eq $null) { throw "WSUS API object not available to run queries." }
        $groups = $wsus.GetComputerTargetGroups()  # simple call to validate server-side operations
        if ($groups -ne $null) {
                $cnt = ($groups | Measure-Object).Count
                $results += New-CheckResult -Name 'WSUS DB/API Query' -Status 'OK' -Message "Retrieved $cnt computer target groups."
        } else {
                $results += New-CheckResult -Name 'WSUS DB/API Query' -Status 'Failed' -Message "Query returned null."
        }
} catch {
        $results += New-CheckResult -Name 'WSUS DB/API Query' -Status 'Failed' -Message $_.Exception.Message
}
#endregion
#region 6) WSUS Directory Disk Space Check
try {
        # Get WSUS content directory from WSUS API configuration
        $wsusContentPath = $null
        
        if ($wsus -ne $null) {
                # Get content directory from WSUS API if available
                $wsusContentPath = $wsus.GetConfiguration().LocalContentCachePath
        }
        
        # Fallback: Try to get from registry
        if (-not $wsusContentPath) {
                $wsusPath = Get-ItemProperty -Path 'HKLM:\Software\Microsoft\Update Services\Server\Setup' -Name ContentDir -ErrorAction SilentlyContinue
                if ($wsusPath.ContentDir) {
                        $wsusContentPath = $wsusPath.ContentDir
                }
        }
        
        # Final fallback: Use default directory
        if (-not $wsusContentPath) {
                $wsusContentPath = "C:\Program Files\Update Services\WsusContent"
        }
        
        if (Test-Path $wsusContentPath) {
                $drive = Split-Path -Path $wsusContentPath -Qualifier
                $diskSpace = Get-Volume -DriveLetter $drive.TrimEnd(':') -ErrorAction Stop
                
                $freeGB = [math]::Round($diskSpace.SizeRemaining / 1GB, 2)
                $totalGB = [math]::Round($diskSpace.Size / 1GB, 2)
                $percentFree = [math]::Round(($diskSpace.SizeRemaining / $diskSpace.Size) * 100, 2)
                
                if ($freeGB -gt 50) {
                        $status = 'OK'
                        $msg = "WSUS Path: $wsusContentPath | Free: $freeGB GB / $totalGB GB ($percentFree%)"
                } elseif ($freeGB -gt 10) {
                        $status = 'Warning'
                        $msg = "WSUS Path: $wsusContentPath | Free: $freeGB GB / $totalGB GB ($percentFree%) - Low disk space!"
                } else {
                        $status = 'Failed'
                        $msg = "WSUS Path: $wsusContentPath | Free: $freeGB GB / $totalGB GB ($percentFree%) - Critical disk space!"
                }
                
                $results += New-CheckResult -Name 'WSUS Disk Space' -Status $status -Message $msg
        } else {
                $results += New-CheckResult -Name 'WSUS Disk Space' -Status 'Failed' -Message "WSUS content directory not found: $wsusContentPath"
        }
} catch {
        $results += New-CheckResult -Name 'WSUS Disk Space' -Status 'Failed' -Message $_.Exception.Message
}
#endregion
#region 7) System Drive Disk Space Check
try {
        $systemDrive = $env:SystemDrive
        $diskSpace = Get-Volume -DriveLetter $systemDrive.TrimEnd(':') -ErrorAction Stop
        
        $freeGB = [math]::Round($diskSpace.SizeRemaining / 1GB, 2)
        $totalGB = [math]::Round($diskSpace.Size / 1GB, 2)
        $percentFree = [math]::Round(($diskSpace.SizeRemaining / $diskSpace.Size) * 100, 2)
        
        if ($freeGB -gt 50) {
                $status = 'OK'
                $msg = "System Drive: $systemDrive | Free: $freeGB GB / $totalGB GB ($percentFree%)"
        } elseif ($freeGB -gt 10) {
                $status = 'Warning'
                $msg = "System Drive: $systemDrive | Free: $freeGB GB / $totalGB GB ($percentFree%) - Low disk space!"
        } else {
                $status = 'Failed'
                $msg = "System Drive: $systemDrive | Free: $freeGB GB / $totalGB GB ($percentFree%) - Critical disk space!"
        }
        
        $results += New-CheckResult -Name 'System Drive Disk Space' -Status $status -Message $msg
} catch {
        $results += New-CheckResult -Name 'System Drive Disk Space' -Status 'Failed' -Message $_.Exception.Message
}
#endregion
#region 8) Last Successful Synchronization Check
try {
        if ($wsus -eq $null) { throw "WSUS API object not available to check synchronization." }
        
        $subscription = $wsus.GetSubscription()
        $lastSyncTime = $subscription.LastSynchronizationTime
        $daysSinceSync = (New-TimeSpan -Start $lastSyncTime -End (Get-Date)).Days
        
        if ($daysSinceSync -lt 3) {
                $status = 'OK'
                $msg = "Last successful sync: $($lastSyncTime.ToString('yyyy-MM-dd HH:mm:ss')) ($daysSinceSync days ago)"
        } elseif ($daysSinceSync -lt 8) {
                $status = 'Warning'
                $msg = "Last successful sync: $($lastSyncTime.ToString('yyyy-MM-dd HH:mm:ss')) ($daysSinceSync days ago) - No recent sync!"
        } else {
                $status = 'Failed'
                $msg = "Last successful sync: $($lastSyncTime.ToString('yyyy-MM-dd HH:mm:ss')) ($daysSinceSync days ago) - Critical: No sync for 8+ days!"
        }
        
        $results += New-CheckResult -Name 'Last Synchronization' -Status $status -Message $msg
} catch {
        $results += New-CheckResult -Name 'Last Synchronization' -Status 'Failed' -Message $_.Exception.Message
}
#endregion
#region 9) Catalog and Content Synchronization Errors Check
try {
        if ($wsus -eq $null) { throw "WSUS API object not available to check sync errors." }
        
        $subscription = $wsus.GetSubscription()
        $lastSyncResult = $subscription.GetSynchronizationStatus()
        
        $catalogErrors = @()
        $contentErrors = @()
        $status = 'OK'
        $msg = ""
        
        # Check for catalog synchronization errors
        if ($lastSyncResult.CategoriesSyncError) {
                $catalogErrors += "Categories: $($lastSyncResult.CategoriesSyncError)"
        }
        if ($lastSyncResult.ComputerTargetGroupsSyncError) {
                $catalogErrors += "ComputerTargetGroups: $($lastSyncResult.ComputerTargetGroupsSyncError)"
        }
        if ($lastSyncResult.UpdatesSyncError) {
                $catalogErrors += "Updates: $($lastSyncResult.UpdatesSyncError)"
        }
        
        # Check for content synchronization errors
        if ($lastSyncResult.ContentSyncError) {
                $contentErrors += "Content: $($lastSyncResult.ContentSyncError)"
        }
        
        if ($catalogErrors.Count -gt 0 -or $contentErrors.Count -gt 0) {
                $status = 'Warning'
                $errorList = @()
                
                if ($catalogErrors.Count -gt 0) {
                        $errorList += "Catalog Errors: " + ($catalogErrors -join "; ")
                }
                if ($contentErrors.Count -gt 0) {
                        $errorList += "Content Errors: " + ($contentErrors -join "; ")
                }
                
                $msg = $errorList -join " | "
        } else {
                $msg = "No catalog or content synchronization errors detected."
        }
        
        $results += New-CheckResult -Name 'Sync Errors (Catalog & Content)' -Status $status -Message $msg
} catch {
        $results += New-CheckResult -Name 'Sync Errors (Catalog & Content)' -Status 'Failed' -Message $_.Exception.Message
}
#endregion
#region 10) Check Self Update
try {
        if ($wsus -eq $null) { throw "WSUS API object not available for self-update check." }
        
        $selfUpdatePath = "C:\Program Files\Update Services\SelfUpdate"
        
        if (Test-Path $selfUpdatePath) {
                $selfUpdateFiles = Get-ChildItem -Path $selfUpdatePath -ErrorAction SilentlyContinue | Measure-Object
                if ($selfUpdateFiles.Count -gt 0) {
                        $status = 'OK'
                        $msg = "WSUS Self-Update directory exists with $($selfUpdateFiles.Count) file(s). Updates are available for WSUS itself."
                } else {
                        $status = 'OK'
                        $msg = "WSUS Self-Update directory is empty. WSUS is up to date."
                }
        } else {
                $status = 'Warning'
                $msg = "WSUS Self-Update directory not found at: $selfUpdatePath"
        }
        
        $results += New-CheckResult -Name 'Check Self Update' -Status $status -Message $msg
} catch {
        $results += New-CheckResult -Name 'Check Self Update' -Status 'Failed' -Message $_.Exception.Message
}
#endregion
#region 11) Check For Email Notification Failures
try {
        if ($wsus -eq $null) { throw "WSUS API object not available for email check." }
        
        $startTime = (Get-Date).AddDays(-7)
        $emailErrors = Get-WinEvent -FilterHashtable @{LogName='Application'; StartTime=$startTime} -ErrorAction Stop | Where-Object { $_.ProviderName -match 'WSUS|Windows Server Update Services' -and $_.Message -match 'email|mail|notification' }
        
        if ($emailErrors.Count -eq 0) {
                $status = 'OK'
                $msg = "No email notification failures detected in the last 7 days."
        } else {
                $status = 'Warning'
                $msg = "Found $($emailErrors.Count) email notification issue(s) in the last 7 days."
        }
        
        $results += New-CheckResult -Name 'Email Notification Failures' -Status $status -Message $msg
} catch {
        $results += New-CheckResult -Name 'Email Notification Failures' -Status 'Failed' -Message $_.Exception.Message
}
#endregion
#region 12) Check For Update Install Failures
try {
        if ($wsus -eq $null) { throw "WSUS API object not available for update failures check." }
        
        $startTime = (Get-Date).AddDays(-7)
        $installErrors = Get-WinEvent -FilterHashtable @{LogName='System'; StartTime=$startTime} -ErrorAction Stop | Where-Object { $_.ProviderName -match 'WsusService|Windows Server Update Services' -and $_.Message -match 'fail|error|install' }
        
        if ($installErrors.Count -eq 0) {
                $status = 'OK'
                $msg = "No update installation failures detected in the last 7 days."
        } else {
                $status = 'Warning'
                $msg = "Found $($installErrors.Count) update installation failure(s) in the last 7 days."
        }
        
        $results += New-CheckResult -Name 'Update Install Failures' -Status $status -Message $msg
} catch {
        $results += New-CheckResult -Name 'Update Install Failures' -Status 'Failed' -Message $_.Exception.Message
}
#endregion
#region 13) Check For Inventory Failures
try {
        if ($wsus -eq $null) { throw "WSUS API object not available for inventory check." }
        
        $startTime = (Get-Date).AddDays(-7)
        $inventoryErrors = Get-WinEvent -FilterHashtable @{LogName='Application'; StartTime=$startTime} -ErrorAction Stop | Where-Object { $_.ProviderName -match 'WSUS|Windows Server Update Services' -and $_.Message -match 'inventory|synchroniz' }
        
        if ($inventoryErrors.Count -eq 0) {
                $status = 'OK'
                $msg = "No inventory failures detected in the last 7 days."
        } else {
                $status = 'Warning'
                $msg = "Found $($inventoryErrors.Count) inventory issue(s) in the last 7 days."
        }
        
        $results += New-CheckResult -Name 'Inventory Failures' -Status $status -Message $msg
} catch {
        $results += New-CheckResult -Name 'Inventory Failures' -Status 'Failed' -Message $_.Exception.Message
}
#endregion
#region 14) Recent relevant Event Log errors (last 24 hours)
try {
        $startTime = (Get-Date).AddHours(-24)
        $sysErrors = Get-WinEvent -FilterHashtable @{LogName='System'; StartTime=$startTime} -ErrorAction Stop | Where-Object { $_.ProviderName -match 'WsusService|W3SVC|MSSQL|Windows Server Update Services|Microsoft-Windows-Web-Services' -and $_.Level -lt 3 }
        $appErrors = Get-WinEvent -FilterHashtable @{LogName='Application'; StartTime=$startTime} -ErrorAction Stop | Where-Object { $_.ProviderName -match 'Windows Server Update Services|WSUS' -and $_.Level -lt 3 }
        $combined = @($sysErrors + $appErrors) | Sort-Object TimeCreated -Descending
        if ($combined.Count -eq 0) {
                $results += New-CheckResult -Name 'Recent EventLog Errors' -Status 'OK' -Message 'No relevant errors found in the last 24 hours.'
        } else {
                $top = $combined | Select-Object -First 1
                $msg = "Recent error: [$($top.TimeCreated)] $($top.ProviderName) - $($top.Id) : $($top.Message -replace '\r\n',' ')"
                $results += New-CheckResult -Name 'Recent EventLog Errors' -Status 'Warning' -Message $msg
        }
} catch {
        $results += New-CheckResult -Name 'Recent EventLog Errors' -Status 'Failed' -Message $_.Exception.Message
}
#endregion
#region Output summary
$results | Format-Table -AutoSize

IF ($CSVExportPath) {
        $CSVFile = $CSVExportPath + "\Get-WsusHealth.csv"
        $results | Export-Csv -Path $CSVFile -NoTypeInformation -Encoding UTF8 -Delimiter ";" 
}

# Send email if requested
if ($EmailLog -and $SmtpServer) {
        $Body = "<h1>WSUS Health Report from $env:COMPUTERNAME</h1>"
        $Body += $results | ConvertTo-Html -Head $Style | Out-String
        SendEmailStatus -From $SmtpFrom -To $SmtpTo -Subject $SmtpSubject -SmtpServer $SmtpServer -BodyAsHtml $true -Body $Body -SmtpPort $SmtpPort
}

# set exit code: non-zero if any Failed
if ($results | Where-Object { $_.Status -match 'Failed' }) {
        exit 2
} elseif ($results | Where-Object { $_.Status -match 'Warning' }) {
        exit 1
} else {
        exit 0
}
#endregion