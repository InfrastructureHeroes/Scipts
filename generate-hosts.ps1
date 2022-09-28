<#
.SYNOPSIS
    Generates a hosts file based on Active Directory
.DESCRIPTION
    Generates a hosts file based on Active Directory
.EXAMPLE 
C:\PS> Generate-Hosts.ps1

.EXAMPLE
C:\PS> Generate-Hosts.ps1 -export C:\Temp\hosts

.PARAMETER 	export
File path to export the final hosts file

.NOTES
Author     : Fabian Niesen (www.fabian-niesen.de)
Filename   : Generate-Hosts.ps1
Requires   : PowerShell Version 3.0
Version    : 1.0
History    : 1.0   FN  28.09.2022  first official

.LINK
https://github.com/InfrastructureHeroes/Scipts
#>

Param(
    $export = ".\hosts"
)
import-module activedirectory
IF ( Test-Path $export ) { Remove-Item $export -Force -Confirm:$false | out-null }
$Computers = Get-ADComputer  -filter "Enabled -eq 'true'" -Properties IPv4Address | Where-Object { $null -ne $_.IPv4Address }
ForEach ($Computer in $Computers)
{
    "$($Computer.IPv4Address)   $($Computer.Name)   $($Computer.DNSHostName)" | Out-File -FilePath $export -Append -Force
}
Get-Content $export 