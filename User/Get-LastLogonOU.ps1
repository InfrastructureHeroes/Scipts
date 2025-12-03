<#
	.SYNOPSIS
		Scan OU for all users an provide LastLogon for AD and Exchange
	.DESCRIPTION
		Scan OU for all users an provide LastLogon for AD and Exchange
	.EXAMPLE  
        Get-LastlogonOU.ps1 -OU "OU=Users,DC=Domain,DC=tld" -Export "C:\Export.csv"
	.INPUTS
		OU: Target OU for scanning
        Export: Exportpath for CSV File
	.OUTPUTS
		Keine.
	.NOTES
		Author     : 	Fabian Niesen
		Requires   : 	PowerShell Version 2.0
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
		Version    : 	0.2 FN 03.12.2025 Changed License to MIT, housekeeping Header
		History    : 	0.1   FN  11.10.2016  initial version
                    
    .LINK
        
#>

[CmdletBinding()]

Param(
	[Parameter(Mandatory=$false, Position=1, ValueFromPipeline=$False)]
	[String]$OU="OU=Benutzer-Extern,OU=Bonn,DC=steep,DC=loc",
    [Parameter(Mandatory=$false, Position=1, ValueFromPipeline=$False)]
	[String]$Export="c:\export.csv"
)
$schriptversion = "0.2"
Write-Output "Get-LastLogonOU.ps1 Version $scriptversion "
$ErrorActionPreference = "SilentlyContinue"
import-module activedirectory
$CSV = @()
Write-Verbose "Ersteller Userliste"
Get-ADUser -SearchBase $OU -filter * -ResultSetSize 5000 -Properties SamAccountName,displayName,lastLogonTimestamp | Sort-Object lastLogonTimestamp |Select-Object SamAccountName,DisplayName,Enabled,@{Name="lastLogonAD"; Expression={[DateTime]::FromFileTime($_.lastLogonTimestamp).ToString('dd.MM.yyyy hh:mm')}} | export-csv $Export -Delimiter ";" -NoTypeInformation -Encoding UTF8
Write-Verbose "Importiere Userliste"
$CSV = Import-CSV -Path $Export -Delimiter ";" 
$CSV | Add-Member -MemberType NoteProperty -Name 'ExchangeLastLogon' -Value $null
Write-Verbose "Starte Exchange Abfrage"
ForEach ($Entry in $CSV)
{
  $SamAccountName = $Entry.SamAccountName
  Write-Verbose "SamAccountName: $SamAccountName " 
  Try
  {
    $Entry.ExchangeLastLogon = $(Get-MailboxStatistics $SamAccountName -ErrorAction Stop).LastLogonTime 
  }
  catch 
  {
    $Entry.ExchangeLastLogon = "no Mailbox"
  }
}
$CSV | Export-Csv $Export -NoTypeInformation -Delimiter ";" -Encoding UTF8