<#
.SYNOPSIS
Checks all Domain Controller for Event ID 5827-5829 in the System Eventlog
	
.DESCRIPTION
Checks all Domain Controller for Event ID 5827-5829 in the System Eventlog. This are the Event for connections witch will be blockt startin 9 Feb. 2021 due CVE-2020-1472.

.EXAMPLE 
C:\PS> get-CVE20201472Events.ps1

.NOTES
Author     : Fabian Niesen (www.fabian-niesen.de)
Filename   : get-CVE20201472Events.ps1
Requires   : PowerShell Version 3.0
Version    : 1.0
History    : 1.0   FN  17.01.2021  initial version
             

.LINK
https://www.infrastrukturhelden.de/?p=14850
#>

Param()

$ErrorActionPreference = "Stop"

try { Import-Module activedirectory } catch { Write-Warning "ActiveDirectory Module ist missing. Please install first"; break }
$DCs =  Get-ADDomainController -Filter  { OperatingSystemVersion -like "*" }
Write-Output "Found $($DCs.count) Domain Controllers in Active Directory"
Write-Progress -activity "Query Eventlogs" -Status "starting" -PercentComplete "0" -Id 1
[int]$i = "0"
ForEach ($DC in $DCs)
{
$i++
Write-Progress -activity "Query Eventlogs" -Status "$($DC.HostName)" -PercentComplete ((($i / $DCs.count)*100)-5) -Id 1
Write-Output $DC.HostName
Get-EventLog -ComputerName $DC.HostName -LogName "System" | Where-Object { $_.EventID  -eq 5829 -or $_.EventID  -eq 5827 -or $_.EventID  -eq 5828 } | select -First 10
}