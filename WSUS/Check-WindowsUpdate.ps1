<#
.SYNOPSIS
    This script forces a Group Policy update, checks Windows Update registry settings, initiates a Windows Update scan and report, and retrieves the Windows Update log and recent hotfixes.

.DESCRIPTION
    The script performs the following actions:
    1. Forces a Group Policy update.
    2. Retrieves Windows Update registry settings.
    3. Initiates a Windows Update scan and report.
    4. Waits for a specified time to allow the scan and report to complete.
    5. Retrieves the Windows Update log.
    6. Retrieves and sorts the list of installed hotfixes.
    7. Retrieves and sorts recent Windows Update events from the System event log.

.PARAMETER Wait
    The time in seconds to wait for the Windows Update scan and report to complete. Default is 120 seconds.

.PARAMETER ShutdownEvents
    The number of recent shutdown events to retrieve from the System event log. Default is 5.

.PARAMETER UpdateEventLogEvents
    The number of recent Windows Update events to retrieve from the System event log. Default is 10.

.PARAMETER UpdateLogLength
    The number of lines to retrieve from the end of the Windows Update log. Default is 40.

.NOTES
    Author     :    Fabian Niesen (InfrastructureHeroes.org / Infrastrukturhelden.de)
    Filename   :    Check-WindowsUpdate.ps1
    Requires   :    PowerShell Version 5.1

    Version    :    0.1
    History    : 	
                    0.1 FN 16.01.2025 Initial version.

.LINK
    https://github.com/InfrastructureHeroes/Scipts/blob/master/WSUS/Check-WindowsUpdate.ps1

.EXAMPLE
    .\Check-WindowsUpdate.ps1
    This example runs the script to perform the Windows Update checks and logging.

#>
[cmdletbinding()]
param (
    [int]$Wait = 120,
    [int]$ShutdownEvents = 5,
    [int]$UpdateEventLogEvents = 10,
    [int]$UpdateLogLength = 40
)
& cmd.exe /c gpupdate.exe /force
Get-Item HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate
Get-Item HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU
Write-Output "Start scan and reporting for Windows Update. Wait before generating log."
& cmd.exe /c wuauclt.exe /detectnow /reportnow
& cmd.exe /c UsoClient.exe /startscan

for ($i = 0; $i -lt $wait; $i++) {
    Write-Progress -Activity "Please wait" -Status "Time left: $(($wait - $i)) seconds" -PercentComplete (($i / $wait) * 100)
    Start-Sleep -Seconds 1
}
Write-Progress -Activity "Please wait" -Status "Completed" -Completed
$WULJob = Start-Job -ScriptBlock {Get-WindowsUpdateLog -LogPath $($ENV:USERPROFILE + "\WindowsUpdate.log")}
$WULJob | Wait-Job | Remove-Job
Write-Output " "
Write-Output "Windows Update log: (Last $UpdateLogLength lines)"
Write-Output "==================================="
Get-Content -Tail $UpdateLogLength -Path $($ENV:USERPROFILE + "\WindowsUpdate.log")
Write-Output " "
Write-Output "Installed hotfixes:"
Write-Output "==================================="
Get-HotFix | Select-Object -Property "InstalledOn", "Description", "HotFixID", "InstalledBy" | Sort-Object -Property "InstalledOn" -Descending | Format-Table -AutoSize
Write-Output " "
Write-Output "Windows Update EventLog ($UpdateEventLogEvents entries):"
Write-Output "==================================="
Get-EventLog -LogName System -Source "Microsoft-Windows-WindowsUpdateClient" | Select-Object -Property "TimeGenerated", "Message" -first $UpdateEventLogEvents | Format-Table -AutoSize
Write-Output " "
Write-Output "Last $ShutdownEvents shutdown events:"
Write-Output "==================================="
Get-EventLog -LogName  System | Where-Object {$_.EventID -eq 1074} | Select-Object -First $ShutdownEvents | Format-List -Property TimeGenerated, UserName, Message
