<#
.SYNOPSIS
Execute Invoke-GPupdate for all computers in an OU.
	
.DESCRIPTION
Execute Invoke-GPupdate for all computers in an OU with parameters. To speed up the process in larger domains will be  a Test-Connection performed before the Invoke-GPupdate.

.EXAMPLE 
C:\PS> invoke-GPupdateDomain.ps1

.EXAMPLE 
C:\PS> invoke-GPupdateDomain.ps1 -SearchBase "OU=Devices,DC=Your,DC=Domain"

.EXAMPLE 
C:\PS> invoke-GPupdateDomain.ps1 -Force

.EXAMPLE 
C:\PS> invoke-GPupdateDomain.ps1 -AsJob

.EXAMPLE 
C:\PS> invoke-GPupdateDomain.ps1 -Computer

.PARAMETER 	SearchBase 
DN for the AD structure to search for Computers

.PARAMETER 	ResultPageSize
Limits the ammout of searched Computer to 1000 in default. Use this parameter to increase if nessessary

.PARAMETER 	force
Perform a invoke-gpupdate -Force

.PARAMETER 	asjob
Perform a invoke-gpupdate -asjob

.PARAMETER 	user
Perform a invoke-gpupdate -target user

.PARAMETER 	computer
Perform a invoke-gpupdate -target computer

.NOTES
Author     : Fabian Niesen (www.fabian-niesen.de)
Filename   : invoke-GPupdateDomain.ps1
Requires   : PowerShell Version 3.0
Version    : 1.0
History    : 1.0.0   FN  10/12/2018  initial version

.LINK
https://www.infrastrukturhelden.de
#>
Param(
	[Parameter(Mandatory=$false, Position=0, ValueFromPipeline=$False)]
	[String]$Searchbase="",
    [Parameter(Mandatory=$false, Position=1, ValueFromPipeline=$False)]
    [int]$ResultPageSize="1000",
    [switch]$force,
    [switch]$asjob,
    [switch]$User,
    [switch]$Computer
)
$ErrorActionPreference = "Stop"
[int]$Suc = 0
$Command = "Invoke-GPupdate "
IF ($force -eq $true) { $Command += "-Force "; Write-Output "Enable Force Mode"}
IF ($asjob -eq $true) { $Command += "-AsJob "; Write-Output "Enable AsJob"}
IF ($User -eq $true -and $Computer -eq $true) {Write-Verbose "There is no need for User and Computer"}
ElseIF ($User -eq $true) { $Command += "-Target User "; Write-Output "Only invoke User Policy"}
ElseIF ($Computer -eq $true) { $Command += "-Target Computer "; Write-Output "Only invoke Computer Policy"}
ELse {Write-Verbose "Run with no Target Scope for GPupdate"}
Write-Verbose "Invoke Command will be: $Command"
Write-Verbose "=== Import AD Module ==="
try
{
  Import-Module activedirectory
}
catch
{
  Write-Warning "ActiveDirectory Module ist missing. Please install first"
  #"GroupPolicy Module ist missing. Please install first" | Out-file $ErrorLog -Append
  break
}

IF ( $Searchbase -eq "") { Write-Verbose "Query Domain DN for Searchbase"; $Searchbase = $(Get-ADDomain).DistinguishedName } 
Write-Verbose "Searchbase: $Searchbase"

$Computers = $(Get-ADComputer -SearchBase $Searchbase -filter {(Enabled -eq $True)} -ResultPageSize $ResultPageSize ).Name
$CompCount = $($Computers.count)
Write-Output "Found $CompCount Computer at $Searchbase"
Write-Progress -activity "Trigger GPupdate" -Status "starting" -PercentComplete "0" -Id 1
[int]$i = "0"
FOREACH ( $Comp in $Computers)
{
  $i++
  $Try = $true
  Write-Progress -activity "Trigger GPupdate" -Status "Active on $Compr" -PercentComplete (($i / $CompCount)*100) -Id 1
  Write-Verbose "Test-Connection $Comp"
  Try { Test-Connection $Comp -Count 1 -Delay 1 |Out-Null } catch { Write-Warning "Computer $Comp is not reachable."; $Try = $false }
  IF ($Try -eq $true) 
  { 
    Write-Verbose "Invoke-GPUpdate on $Comp"
    $TryGP = $true
    Try { $($Command+$Comp) | Out-Null } catch { Write-Warning "Invoke-GPupdate war not successful on $Comp"; $TryGP = $false }
    IF ($TryGP -eq $true) {Write-Host -ForegroundColor Green "Invoke-GPupdate on $Comp was successful" ; $Suc++}
    
  }
}
Write-Verbose "Done"
IF ($asjob -eq $true) {Write-Output "Script was Started in Job mode. There might be still running Jobs" ; Get-Job | FT -AutoSize}
Write-Output "$Suc of $CompCount Computers triggered for GPupdate successful"