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
Author     :  Fabian Niesen (infrastrukturhelden.de)
Filename   :  invoke-GPupdateDomain.ps1
Requires   :  PowerShell Version 3.0
License    :  The MIT License (MIT)
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
Disclaimer :  This script is provided "as is" without warranty. Use at your own risk.
              The author assumes no responsibility for any damage or data loss caused by this script.
              Test thoroughly in a controlled environment before deploying to production.
Version    :  1.1
History    :  1.1   FN  03.12.2025 Changed License to MIT, housekeeping Header
              1.0   FN  10/12/2018  initial version

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
$scriptversion = "1.1"
Write-Output "invoke-GPupdateDomain.ps1 Version $scriptversion "
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