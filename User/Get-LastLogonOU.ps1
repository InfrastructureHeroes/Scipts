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
		Author     : Fabian Niesen
		Requires   : PowerShell Version 2.0
		
		Version    : 0.1
		History    : 0.1   FN  11.10.2016  initial version
                    
    .LINK
        
#>

[CmdletBinding()]

Param(
	[Parameter(Mandatory=$false, Position=1, ValueFromPipeline=$False)]
	[String]$OU="OU=Benutzer-Extern,OU=Bonn,DC=steep,DC=loc",
    [Parameter(Mandatory=$false, Position=1, ValueFromPipeline=$False)]
	[String]$Export="c:\export.csv"
)
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