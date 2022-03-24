#requires -version 2.0
#requires -modules activedirectory


<#
	.SYNOPSIS
		Locate user Lockouts in Active Directory
	.DESCRIPTION
		Query all DC and Locate user Lockouts in Active Directory within the last 24h. As default the result is shown as Grid-View, but CSV Export is possible.
        A lunchtime project...
	.EXAMPLE  
        .\LocateADLockout-v2.ps1 -filter "bn" -CSVOUT $true -Gridview $false -CSVpath 
	.INPUTS
        -filter only DC's with this pattern in the Hostname
        -Gridview Output as GridView
        -CSVOUT Export as CSV
        -CSVpath Exportpath for CSV
	.OUTPUTS
		Keine.
	.NOTES
		Author     : Fabian Niesen
		Filename   : Locate-ADLockout.ps1
		Requires   : PowerShell Version 2.0
		
		Version    : 1.0
		History    : 1.0
                    
    .LINK
        https://www.infrastrukturhelden.de
#>

Param(
	[Parameter(Mandatory=$false, ValueFromPipeline=$True)]
	[String]$filter ="*",
	[Parameter(Mandatory=$false, ValueFromPipeline=$True)]
	[String]$Gridview =$true,    
	[Parameter(Mandatory=$false, ValueFromPipeline=$True)]
	[String]$CSVOUT = $false,
	[Parameter(Mandatory=$false, ValueFromPipeline=$True)]
	[String]$CSVpath = "changeme"
)

$LogOuts = @()


#@{label=''}, @{label=''},@{label=''}, @{label=''}, @{label=''}
$DCs =  Get-ADDomainController -Filter  { HostName -like "$filter" }
ForEach ($DC in $DCs)
{
Write-Output "Starte Remote PowerShell Session und Suche nach EventID 4625  zu:" $DC.HostName
$temp = Invoke-Command -ComputerName $DC.HostName -ScriptBlock { Get-EventLog -LogName "Security" -After (Get-Date).AddDays(-1) | Where-Object { $_.EventID -match '4625'} }
ForEach ($t in $temp)
  {
  IF ($t.ReplacementStrings[7] -like "0xc0000234") { $Staus = "Kontosperrung"} ELSEIF ($t.ReplacementStrings[7] -like "0xc000006d") { $Staus = "Anmelden"}
  $Log = New-Object -TypeName psobject
  $Log | Add-Member -MemberType NoteProperty -Name EventID -Value $t.EventID
  $Log | Add-Member -MemberType NoteProperty -Name TimeGenerated -Value $t.TimeGenerated
  $Log | Add-Member -MemberType NoteProperty -Name DC -Value $t.ReplacementStrings[4]
  $Log | Add-Member -MemberType NoteProperty -Name Benutzer -Value $($t.ReplacementStrings[6] +"\" +$t.ReplacementStrings[5])
  $Log | Add-Member -MemberType NoteProperty -Name Quelle -Value $Staus 
  $Log | Add-Member -MemberType NoteProperty -Name LoginID -Value $Null
  $Log | Add-Member -MemberType NoteProperty -Name IP -Value $t.ReplacementStrings[19]
  $Log | Add-Member -MemberType NoteProperty -Name EventServer -Value $DC.HostName
    $LogOuts += $Log
  }

  Write-Output "Starte Remote PowerShell Session und Suche nach EventID 4776 zu: "$DC.HostName
  $temp = Invoke-Command -ComputerName $DC.HostName -ScriptBlock { Get-EventLog -LogName "Security" -After (Get-Date).AddDays(-1) | Where-Object { $_.EventID -match '4776'} }
ForEach ($t in $temp)
  {
  $Log = New-Object -TypeName psobject
  $Log | Add-Member -MemberType NoteProperty -Name EventID -Value $t.EventID
  $Log | Add-Member -MemberType NoteProperty -Name TimeGenerated -Value $t.TimeGenerated
  $Log | Add-Member -MemberType NoteProperty -Name DC -Value $t.ReplacementStrings[2]
  $Log | Add-Member -MemberType NoteProperty -Name Benutzer -Value $t.ReplacementStrings[1]
  $Log | Add-Member -MemberType NoteProperty -Name EventServer -Value $DC.HostName
  $LogOuts += $Log
  }

}

IF ($Gridview -eq $true) { $LogOuts | Out-GridView -Title "EventID's 4625 and 4776 on all/filterd DCs" }
IF ($CSVOUT -eq $true) 
  {
    IF ($CSVpath -like "changeme")
      {
        Write-Verbose "No Path found"
        $CSVpath = Read-Host -Prompt "Bitte geben Sie einen Dateinamen inklusive Pfad an"
      }
    $LogOuts | Export-Csv -Path $CSVpath -Delimiter ";" -NoTypeInformation
  }


