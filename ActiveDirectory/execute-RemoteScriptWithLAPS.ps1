#requires -version 4.0
#requires -modules activedirectory
#Requires -RunAsAdministrator
<#
.SYNOPSIS
Execute a remote script with Local Admin account and Microsoft LAPS
	
.DESCRIPTION
Execute a remote script with Local Admin account and Microsoft LAPS

.EXAMPLE 
C:\PS> execute-RemoteScriptWirhLAPS.ps1

.EXAMPLE 
C:\PS> execute-RemoteScriptWirhLAPS.ps1

.PARAMETER computer 
Computer to be used as remote target

.PARAMETER ScriptBlock
ScriptBlock to be executed remotely

.PARAMETER admin
Name of the Administrative account handled with LAPS

.NOTES
Author     :    Fabian Niesen (www.infrastrukturhelden.de)
Filename   :    execute-RemoteScriptWirhLAPS
Requires   :    PowerShell Version 4.0
Version    :    1.1
History    :    1.1     FN  08.09.2022  updated version, translated to english
                1.0.0   FN  04.06.2019  initial version

.LINK
https://www.infrastrukturhelden.de/microsoft-infrastruktur/active-directory/powershell-skripte-mit-local-administrator-password-solution-laps-nutzen-und-auditieren/
#>

Param(
[Parameter(Mandatory=$true)][string]$computer, #Computer to which the connection is established
[string]$ScriptBlock, 
[string]$admin = "Administrator"
)
#Imports the required module 
Import-Module AdmPwd.PS 
#User account that is protected with LAPS
$username = "$computer\$admin" 
#The readout works only from a shell with administrative rights and an authorized user!
$password = (Get-AdmPwdPassword -ComputerName $computer).Password 
IF ( $($password).count -gt 0 ) {
    Write-Output "Password was found" 
    $cred = new-object -typename System.Management.Automation.PSCredential -argumentlist $username,$($password | ConvertTo-SecureString -asPlainText -Force)
    #Create the credentials
    $FQDN= $computer + "."+ $(Get-ADDomain).DNSRoot
    #To avoid a certificate error the FQDN must be used to establish the connection
    IF ($ScriptBlock -ne "")
    {
        Invoke-Command -ComputerName $FQDN -ScriptBlock { $ScriptBlock } -credential $cred -UseSSL
    }
    Else 
    { 
        Write-Output "No ScriptBlock specified, start demo mode"
        Invoke-Command -ComputerName $FQDN -ScriptBlock { Get-ChildItem C:\ } -credential $cred -UseSSL
    }
    Write-Output "Reset Password timer"
    Reset-AdmPwdPassword -ComputerName $computer
    #Reset the LAPS password
    Write-Output "Give AD replication a few seconds"
    Start-Sleep -Seconds 30
    #A little patience for local AD replication
    Write-Output "Invoke GPupdate on $computer, this may need some minutes to take effect"
    Invoke-GPUpdate -Computer $computer -Target Computer -Force 
    #Run GPUdate to set a new password. This will take a few minutes.
}
else {
    Write-Warning "No LAPS Password found"
}