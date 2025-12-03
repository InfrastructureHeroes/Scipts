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
Author     :    Fabian Niesen (www.fabian-niesen.de)
Filename   :    Generate-Hosts.ps1
Requires   :    PowerShell Version 3.0
Version    :    1.1
History    :    1.1  FN  03.12.2025 Change License to MIT, housekeeping Header
                1.0  FN  28.09.2022  first official
License    :    The MIT License (MIT)
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

.LINK
https://github.com/InfrastructureHeroes/Scipts
#>

Param(
    $export = ".\hosts"
)
$scriptversion = "1.1"
Write-Output "Generate-Hosts.ps1 Version $scriptversion " 
import-module activedirectory
IF ( Test-Path $export ) { Remove-Item $export -Force -Confirm:$false | out-null }
$Computers = Get-ADComputer  -filter "Enabled -eq 'true'" -Properties IPv4Address | Where-Object { $null -ne $_.IPv4Address }
ForEach ($Computer in $Computers)
{
    "$($Computer.IPv4Address)   $($Computer.Name)   $($Computer.DNSHostName)" | Out-File -FilePath $export -Append -Force
}
Get-Content $export 