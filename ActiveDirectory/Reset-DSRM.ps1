#requires -version 3.0
#requires -modules activedirectory
#Requires -RunAsAdministrator
<#
	.SYNOPSIS
		Reset the Directory Services Restore Mode (DSRM) password on a Domain Controller in an Active Directory Domain.
	.DESCRIPTION
		Reset the Directory Services Restore Mode (DSRM) password on a Domain Controller in an Active Directory Domain.
	.EXAMPLE  
        Reset-DSRM.ps1
	.INPUTS
		Keine.
	.OUTPUTS
		Keine.
    .PARAMETER 
	.NOTES
		Author     : Fabian Niesen
		Filename   : 
		Requires   : PowerShell Version 3.0
		
		Version    : 0.1
		History    : 0.2   FN  31.08.2022  Add some autodetection, Change Logging
                     0.1   FN  26.11.2015  initial version
                    

    .LINK
https://github.com/InfrastructureHeroes/Scipts/

    .COPYRIGHT
Copyright (c) Fabian Niesen if not stated otherwise. All rights reserved. Licensed under the MIT license.
        
#>
[CmdletBinding(DefaultParameterSetName = 'AllDC')]
Param(
    [Parameter(Mandatory=$true,
    ParameterSetName = 'AllDC',
    HelpMessage = 'Reset DSRM on all DCs in Domain')]
    [switch]$AllDC,
    [Parameter(Mandatory=$true,
    ParameterSetName = 'OnlyOne',
    HelpMessage = 'Reset DSRM on a single DC')]
    [switch]$Server,
    [Parameter(Mandatory=$false,
    HelpMessage = 'RandomPassword?')]
    [switch]$RandomPW,
	[Parameter(Mandatory=$false,
    HelpMessage = 'Username for Sync Account')]
    [string]$Username,
    [Parameter(Mandatory=$false,
    HelpMessage = 'Password')]
    [string]$PW,
    [Parameter(Mandatory=$false,
    ParameterSetName = 'OnlyOne',
    HelpMessage = 'Servername')]
    [string]$ServerName,
    [string]$logPath = "C:\Windows\System32\LogFiles\"
)
$ErrorActionPreference =  "Stop"
IF (RandomPW) {
	$TokenSet = @{
		U = [Char[]]'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
		L = [Char[]]'abcdefghijklmnopqrstuvwxyz'
		N = [Char[]]'0123456789'
		S = [Char[]]'(~!@#$%^&*_-+=\(){}[]:;<>,.?/)'
	}
	$Upper = Get-Random -Count 10 -InputObject $TokenSet.U
	$Lower = Get-Random -Count 10 -InputObject $TokenSet.L
	$Number = Get-Random -Count 7 -InputObject $TokenSet.N
	$Special = Get-Random -Count 7 -InputObject $TokenSet.S    
	$StringSet = $Upper + $Lower + $Number + $Special
	
	[String]$PW = (Get-Random -Count 30 -InputObject $StringSet) -join ''
}
Write-Host "Please note this Password someware Safe: $PW"
Write-Warning "Be Aware, you need to enter the Password during the execution twice. This can not be automated. Sorry."
#TODO Check User and Create is

#TODO Set Password


If ( $OnlyOne ) {
	Try {Test-Connection $ServerName}
	catch { Throw "Server $ServerName not reachable!"}
	$ntdsutil = ntdsutil "set dsrm password" "reset password on server NULL" q q
} elseif ( $AllDC) {
	Write-Host "Not Implemented now"
	<# Action when this condition is true #>
} else {
	Throw "Please check Script Parameters with get-Help .\Reset-DSRM.PS1"
}