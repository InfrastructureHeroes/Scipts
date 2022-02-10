#requires -version 2.0
#requires -modules activedirectory

<#
	.SYNOPSIS
		Move FSMO roles to a new DC
	.DESCRIPTION
		This script moves FSMO roles to a new single DC. 
        For more information check https://docs.microsoft.com/en-us/troubleshoot/windows-server/identity/fsmo-placement-and-optimization-on-ad-dcs
	.EXAMPLE  
        move-FSMO.ps1 -Server DC -Forest -Domain
	.NOTES
		Author     : Fabian Niesen
		Filename   : move-FSMO.ps1
		Requires   : PowerShell Version 2.0
		
		Version    : 0.1
		History    : 0.1   FN  10.02.2022  initial version
                    
    .LINK
        https://gallery.technet.microsoft.com/Gesamtstruktur-Informations-63719eec
#>
[CmdLetBinding()]
param(
    [Parameter(Mandatory = $false, Position = 1, ValueFromPipelineByPropertyName = $true,
        ValueFromPipeline = $True,
        HelpMessage = 'Specify Target Server'
    )][Alias("Target")]
    [string]$Server,
    [switch]$Forest,
    [switch]$Domain,
    [switch]$All,
    [switch]$whatIf
)
Function list-FSMO {
# List actual owner
$forestdata = Get-ADForest
$domaindata = Get-ADDomain
$FSMO = @(@{DomainNamingMaster = $forestdata.DomainNamingMaster; SchemaMaster = $forestdata.SchemaMaster; InfrastructureMaster = $domaindata.InfrastructureMaster; PDCEmulator = $domaindata.PDCEmulator ; RIDMaster = $domaindata.RIDMaster})
$FSMO | ft 
} 

If (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
{   
$arguments = "& '" + $myinvocation.mycommand.definition + "'"
Start-Process powershell -Verb runAs -ArgumentList $arguments
Break
}

list-FSMO
If ($all) 
{  
    $Forest = $true
    $Domain = $true
}
If ($whatIf)
{ 
    If ($Forest) { Write-Output "This would be executed: Move-ADDirectoryServerOperationMasterRole -Identity $Server -OperationMasterRole DomainNamingMaster,SchemaMaster"  }
    If ($Domain) { Write-Output "This would be executed: Move-ADDirectoryServerOperationMasterRole -Identity $Server -OperationMasterRole RIDMaster,InfrastructureMaster,PDCEmulator"  }

}
ELSE 
{
    If ($Forest) { Move-ADDirectoryServerOperationMasterRole -Identity $Server -OperationMasterRole DomainNamingMaster,SchemaMaster -Confirm:$false }
    If ($Domain) { Move-ADDirectoryServerOperationMasterRole -Identity $Server -OperationMasterRole RIDMaster,InfrastructureMaster,PDCEmulator -Confirm:$false }
}
list-FSMO
