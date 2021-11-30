<#
.SYNOPSIS
Set Registry key to stay at a specific Windows 10 Release
	
.DESCRIPTION
Set Registry key to set a max Windows 10 Release version for Windows update automatic feature upgrade. This script does not force a downgrade.
Use it on your own risk.

.EXAMPLE 
C:\PS> set-WinRelease.ps1

.EXAMPLE 
C:\PS> set-WinRelease.ps1 -ver 1909

.PARAMETER 	ver 
Set Windows Release to this version 

.NOTES
Author     : Fabian Niesen (www.infrastrukturhelden.de)
Filename   : set-WinRelease
Requires   : PowerShell Version 3.0
Version    : 1.0
History    : 1.0.0   FN  30.11.2021  initial version

.LINK

#>

Param(
[Parameter(Mandatory=$true)][ValidateSet("1909","2004","20H2","21H1","21H2")] [string]$ver
)

$ErrorActionPreference = "Stop"
$RegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Update"
$RegName = "TargetReleaseVersion"
$RegValue = "1"
$ProductName = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name ProductName).ProductName
If ( $ProductName -Like "Windows 10 Pro") { $Edition = "Pro"}
elseif ( $ProductName -like "Windows 10 Enterprise") { $Edition = "Ent"}
else { $Edition = "Other" }

Try { $Version = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name ReleaseID -ErrorAction Stop).ReleaseID }
Catch { $Version = "N/A" }
Write-Output "Found $ProductName"
if ($ver -eq $null) { Write-Output "No Windows Release selected, please start again with the release of choice." ; Break }
If (-NOT (Test-Path $RegPath)) { New-Item -Path $RegPath -Force | Out-Null }
New-ItemProperty -Path $RegPath -Name $RegName -Value $RegValue -PropertyType DWORD -Force
$RegName = "TargetReleaseVersionInfo"
$date = Get-Date 
Switch ( $ver )
{
"21H2" 
    { 
        New-ItemProperty -Path $RegPath -Name $RegName -Value "21H2" -PropertyType String -Force 
        If ( $Edition -like "Pro") { $sdate = get-date -Year "2023" -Month "06" -Day "13" ; If ($date -gt $sdate) { Write-Warning "$ProductName $Version is not longer supported anymore!!"} ELSE { $left = $($sdate - $date).Days ; Write-Output "You have $left days support left till EOL for $ProductName $ver" } }        
        ElseIf ( $Edition -like "Ent") { $sdate = get-date -Year "2024" -Month "06" -Day "11" ; If ($(get-date) -gt $sdate) { Write-Warning "$ProductName $Version is not longer supported anymore!!"} ELSE { $left = $($sdate - $date).Days ; Write-Output "You have $left days support left till EOL for $ProductName $ver" } }
    }
"21H1" 
    { 
        New-ItemProperty -Path $RegPath -Name $RegName -Value "21H1" -PropertyType String -Force 
        $sdate = get-date -Year "2022" -Month "12" -Day "13"
        If ($( get-date) -gt $sdate) { Write-Warning "$ProductName $Version is not longer supported anymore!!"} ELSE { $left = $($sdate - $date).Days ; Write-Output "You have $left days support left till EOL for $ProductName $ver" }
    }
"20H2" 
    { 
        New-ItemProperty -Path $RegPath -Name $RegName -Value "20H2" -PropertyType String -Force 
        If ( $Edition -like "Pro") {$sdate = get-date -Year "2022" -Month "05" -Day "10" ; If ($( get-date) -gt $sdate) { Write-Warning "$ProductName $Version is not longer supported anymore!!"} ELSE { $left = $($sdate - $date).Days ; Write-Output "You have $left days support left till EOL for $ProductName $ver" } }        
        ElseIf ( $Edition -like "Ent") { $sdate = get-date -Year "2023" -Month "05" -Day "09" ; If ($(get-date) -gt $sdate) { Write-Warning "$ProductName $Version is not longer supported anymore!!"} ELSE { $left = $($sdate - $date).Days ; Write-Output "You have $left days support left till EOL for $ProductName $ver" } }
    }
"2004" 
    { 
        New-ItemProperty -Path $RegPath -Name $RegName -Value "2004" -PropertyType String -Force 
        $sdate = get-date -Year "2021" -Month "12" -Day "14"
        If ($( get-date) -gt $sdate) { Write-Warning "$ProductName $Version is not longer supported anymore!!"} ELSE { $left = $($sdate - $date).Days ; Write-Output "You have $left days support left till EOL for $ProductName $ver" }
    }
"1909" 
    { 
        New-ItemProperty -Path $RegPath -Name $RegName -Value "1909" -PropertyType String -Force 
        If ( $Edition -like "Pro") { $sdate = get-date -Year "2021" -Month "05" -Day "10" ; If ($( get-date) -gt $sdate) { Write-Warning "$ProductName $Version is not longer supported anymore!!"} ELSE { $left = $($sdate - $date).Days ; Write-Output "You have $left days support left till EOL for $ProductName $ver" }}        
        ElseIf ( $Edition -like "Ent") { $sdate = get-date -Year "2022" -Month "05" -Day "11" ; If ($(get-date) -gt $sdate) { Write-Warning "$ProductName $Version is not longer supported anymore!!"} ELSE { $left = $($sdate - $date).Days ; Write-Output "You have $left days support left till EOL for $ProductName $ver" }}
    }
Default { Write-Warning "No valid Value entered. Please use 21H2, 21H1, 2004 or 1909" }
}
