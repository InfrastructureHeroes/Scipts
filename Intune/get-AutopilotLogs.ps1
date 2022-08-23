#Requires -RunAsAdministrator
<#
.SYNOPSIS
Gather Informations & Logs for Autopilot Pre-Provisioning process.
	
.DESCRIPTION
Gather Informations & Logs for Autopilot Pre-Provisioning process. It creates a folder in the locaion where it was started from, usually a USB Thumdrive.

.EXAMPLE 
C:\PS> get-AutopilotLogs.ps1

.NOTES
Author     : Fabian Niesen (www.fabian-niesen.de)
Filename   : get-AutopilotLogs.ps1
Requires   : PowerShell Version 4.0
Version    : 1.0.0
History    : 1.0.0   FN  21.08.2022  initial version

.LINK
https://github.com/InfrastructureHeroes/Scipts/
#>
$ErrorActionPreference = "SilentlyContinue"
$script:BuildVer = "1.0.0"
$script:ProgramFiles = $env:ProgramFiles
$script:ParentFolder = $PSScriptRoot | Split-Path -Parent
$script:ScriptName = $myInvocation.MyCommand.Name
$script:ScriptName = $scriptName.Substring(0, $scriptName.Length - 4)
$serial = $(Get-WmiObject Win32_bios).Serialnumber
$Device = Get-CimInstance -ClassName Win32_ComputerSystem
$LogName = $serial + "_" + (Get-Date -UFormat "%Y%m%d-%H%M")
$Logpath = $PSScriptRoot + "\" + $LogName
$LogFile = $Logpath +"\" + $script:ScriptName + ".txt"
$ntpserver = "ptbtime1.ptb.de,ptbtime2.ptb.de,time.windows.com,time.nist.gov"
####################################################
#region Logfiles
<#
.COPYRIGHT
Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT license.
See LICENSE in the project https://github.com/gregnottage/IntuneScripts for license information.

Removed EventLog Handling by Fabian Niesen
#>
Function Start-Log {
    param (
        [string]$FilePath,

        [Parameter(HelpMessage = 'Deletes existing file if used with the -DeleteExistingFile switch')]
        [switch]$DeleteExistingFile
    )
	
    Try {
        If (!(Test-Path $FilePath)) {
            ## Create the log file
            New-Item $FilePath -Type File -Force | Out-Null
        }
            
        If ($DeleteExistingFile) {
            Remove-Item $FilePath -Force
        }
			
        ## Set the global variable to be used as the FilePath for all subsequent Write-Log
        ## calls in this session
        $script:ScriptLogFilePath = $FilePath
    }
    Catch {
        Write-Error $_.Exception.Message
    }
}

####################################################

Function Write-Log {
    #Write-Log -Message 'warning' -LogLevel 2
    #Write-Log -Message 'Error' -LogLevel 3
    param (
        [Parameter(Mandatory = $true)]
        [string]$Message,
			
        [Parameter()]
        [ValidateSet(1, 2, 3)]
        [int]$LogLevel = 1,

        [Parameter(HelpMessage = 'Outputs message to Event Log,when used with -WriteEventLog')]
        [switch]$WriteEventLog
    )
    Write-Host $Message
    $TimeGenerated = "$(Get-Date -Format HH:mm:ss).$((Get-Date).Millisecond)+000"
    $Line = '<![LOG[{0}]LOG]!><time="{1}" date="{2}" component="{3}" context="" type="{4}" thread="" file="">'
    $LineFormat = $Message, $TimeGenerated, (Get-Date -Format MM-dd-yyyy), "$($MyInvocation.ScriptName | Split-Path -Leaf):$($MyInvocation.ScriptLineNumber)", $LogLevel
    $Line = $Line -f $LineFormat
    Add-Content -Value $Line -Path $ScriptLogFilePath
}
#endregion Logfiles
####################################################

### Check for Admin rights
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))  
{  
  $arguments = "& '" +$myinvocation.mycommand.definition + "'"
  Start-Process powershell -Verb runAs -ArgumentList $arguments
  Break
}
###
If (-not (Test-Path $Logpath)) 
{ 
  New-Item -Path $Logpath -ItemType Directory -Force | Out-Null
}
Start-Log -FilePath $LogFile -DeleteExistingFile 
Write-Log -Message "All files will be stored here: $Logpath"
Write-Log -Message "Start get-AutopilotLogs Version $script:BuildVer"
Write-Log -Message "Device Serial          : $serial"
Write-Log -Message "Devicename             : $($Device.Name)"
Write-Log -Message "Device Manufacturer    : $($Device.Manufacturer)"
Write-Log -Message "Device Model           : $($Device.Model)"
Write-Log -Message "Device ChassisSKUNumber: $($Device.ChassisSKUNumber)"
Write-Log -Message "Device PowerSupplyState: $($Device.PowerSupplyState)"

If (Test-Path "C:\Windows\system32\w32tm.exe" ) { $w32tm = "C:\Windows\system32\w32tm.exe"} Else { $w32tm = "w32tm.exe" }
Start-Process -FilePath $w32tm -ArgumentList " /monitor /computers:$ntpserver " -NoNewWindow -Wait -RedirectStandardOutput $($Logpath+"\ntp-raw.txt")
$TimeDiff = Get-Content $($Logpath+"\ntp-raw.txt") | ForEach-Object { $_.trim() } | Where-Object { $_ -ne ""} 
$TimeDiff = $TimeDiff.Where({ $_ -like "*$($ntpserver.split(",")[0])*"},'SkipUntil') | Select-Object -First 20
$TimeTab = @(
    [PSCustomObject]@{Server = $($TimeDiff[0].split("[")[0]);  Offset = $($TimeDiff[2].Split(":")[1].trim().split(" ")[0]);  RefID = $($TimeDiff[3].Split(" ")[1]+$TimeDiff[3].Split(" ")[2]) ;   Stratum = $($TimeDiff[4].Split(" ")[1])}
    [PSCustomObject]@{Server = $($TimeDiff[5].split("[")[0]);  Offset = $($TimeDiff[7].Split(":")[1].trim().split(" ")[0]);  RefID = $($TimeDiff[8].Split(" ")[1]+$TimeDiff[8].Split(" ")[2]) ;   Stratum = $($TimeDiff[9].Split(" ")[1])}
    [PSCustomObject]@{Server = $($TimeDiff[10].split("[")[0]); Offset = $($TimeDiff[12].Split(":")[1].trim().split(" ")[0]); RefID = $($TimeDiff[13].Split(" ")[1]+$TimeDiff[13].Split(" ")[2]) ; Stratum = $($TimeDiff[14].Split(" ")[1])}
    [PSCustomObject]@{Server = $($TimeDiff[15].split("[")[0]); Offset = $($TimeDiff[17].Split(":")[1].trim().split(" ")[0]); RefID = $($TimeDiff[18].Split(" ")[1]+$TimeDiff[18].Split(" ")[2]) ; Stratum = $($TimeDiff[19].Split(" ")[1])}
)
$TimeData = $($TimeTab | ConvertTo-Csv -NoTypeInformation )
$TimeTab | export-csv -Path $($Logpath+"\ntp.txt") -force -NoTypeInformation
Write-Log -Message "Time informations `n$TimeData"


# Copy PowerShell Framework for Intune
Write-Log -Message "Checking for Logfiles from PowerShell Framework for Intune based upon https://github.com/gregnottage/IntuneScripts"
IF (Test-Path -Path "$($env:LOCALAPPDATA)\Microsoft\IntuneApps") 
{ 
    Write-Log -Message "Found Logs in $($env:LOCALAPPDATA)\Microsoft\IntuneApps"
    Copy-Item -Path "$($env:LOCALAPPDATA)\Microsoft\IntuneApps" -Destination $Logpath -Recurse -Force
}
IF (Test-Path -Path "$($env:ProgramData)\Microsoft\IntuneApps") 
{ 
    Write-Log -Message "Found Logs in $($env:ProgramData)\Microsoft\IntuneApps"
    Copy-Item -Path "$($env:ProgramData)\Microsoft\IntuneApps" -Destination $Logpath -Recurse -Force
}

# Copy AppDeploymentToolkit Logs
Write-Log -Message "Checking for Logfiles from PSAppDeploymentToolkit"
IF (Test-Path -Path "$envWinDir\Logs\Software") 
{ 
    Write-Log -Message "Found Logs in $envWinDir\Logs\Software"
    Copy-Item -Path "$envWinDir\Logs\Software" -Destination $Logpath -Recurse -Force
}

# MDMDiagnostics
[string]$DiagArea = $(Get-ChildItem HKLM:\SOFTWARE\Microsoft\MdmDiagnostics\Area).PSChildName
$DiagArea = $DiagArea.replace(' ',';')
Write-Log -Message "Start MDMDiagnostics - $DiagArea"
Start-Process -FilePath "C:\windows\system32\MdmDiagnosticsTool.exe" -ArgumentList "-area $DiagArea -cab $logpath\$serial.cab" -NoNewWindow -Wait -PassThru 

# Gater additional Informations
Write-Log -Message "Get installed Software"
get-wmiobject Win32_Product | Sort-Object -Property Name, IdentifyingNumber | Export-Csv -Path $($Logpath+"\Win32_Product.csv") -force -NoTypeInformation
Write-log -Message "Get-DeliveryOptimizationStatus"
Get-DeliveryOptimizationStatus | Export-Csv -Path $($Logpath+"\DO-Status.csv") -force -NoTypeInformation

Write-Log -Message "Export System Eventlog"
$evtldate = [math]::Round((New-TimeSpan -Start $($(Get-Date).AddDays(-10)) -End (Get-Date)).TotalMilliseconds )
#Start-Process -FilePath wevtutil -ArgumentList " epl Application test.evtx /q:$("*[System[TimeCreated[timediff(@SystemTime) <= $evtldate]]]")" -NoNewWindow -Wait -PassThru 
wevtutil  epl System $logpath\system.evtx /q:$("*[System[TimeCreated[timediff(@SystemTime) <= $evtldate]]]")
Write-Log -Message "Export Application Eventlog"
wevtutil  epl Application $logpath\Application.evtx /q:$("*[System[TimeCreated[timediff(@SystemTime) <= $evtldate]]]")
Write-Log -Message "Export Service list"
Get-WmiObject -Class Win32_Service  | Export-csv -Path $($Logpath+"\Services.csv") -force -NoTypeInformation
Write-Log -Message "Get installed Software Uninstall information"
Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Sort-Object InstallDate | Export-csv -Path $($Logpath+"\Uninstall.csv") -force -NoTypeInformation
Write-Log -Message "Get Driver versions"
Get-WmiObject Win32_PnPSignedDriver| Select-Object devicename, driverversion, driverdate | Sort-Object devicename | Export-csv -Path $($Logpath+"\Driver.csv") -force -NoTypeInformation
Write-Log -Message "Get installe AppX Packages"
Get-AppxPackage -AllUsers  | Export-csv -Path $($Logpath+"\AppX.csv") -force -NoTypeInformation
Write-Log -Message "Get Packages"
Get-Package | Sort-Object ProviderName | Export-csv -Path $($Logpath+"\Packages.csv") -force -NoTypeInformation
Write-Log -Message "Get Windows Packages"
Get-WindowsPackage -Online  | Export-csv -Path $($Logpath+"\WinPackages.csv") -force -NoTypeInformation
Write-Log -Message "Get Provisioning Packages"
Get-ProvisioningPackage -AllInstalledPackages | Export-csv -Path $($Logpath+"\ProvisioningPackage.csv") -force -NoTypeInformation
Write-Log -Message "get-AutopilotLogs is completed"