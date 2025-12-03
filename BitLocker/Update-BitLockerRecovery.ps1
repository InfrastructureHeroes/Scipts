
<#PSScriptInfo

.VERSION 1.0.1

.GUID 3c0736ab-4777-4b58-ae0f-80b4e89b64a2

.AUTHOR Fabian Niesen

.COMPANYNAME InfrastrukturHelden.de | Fabian Niesen Online Services

.COPYRIGHT 

.TAGS BitLocker PowerShell Update ActiveDirectory RecoveryKeys

.LICENSEURI 

.PROJECTURI https://www.infrastrukturhelden.de/microsoft-infrastruktur/active-directory/bitlocker-wiederherstellungs-keys-nachtraglich-im-ad-sichern/

.ICONURI 

.EXTERNALMODULEDEPENDENCIES 

.REQUIREDSCRIPTS 

.EXTERNALSCRIPTDEPENDENCIES 

.RELEASENOTES


#> 



<#
.SYNOPSIS
Upload BitLocker recovery information to Active Directory, if they not already exist.
	
.DESCRIPTION
Upload BitLocker recovery information to Active Directory, if they not already exist.
WARNING: While the manage-bde Output is localized, this will only work on English and German Windows 10 devices.

.EXAMPLE 
C:\PS> Update-BitLockerRecovery.ps1

.EXAMPLE 
C:\PS> Update-BitLockerRecovery.ps1 -locale "de-DE"

.PARAMETER locale 
Language code of the OS, if not set the script will use "GET-WinSystemLocale" for autodetection

.PARAMETER procstate
String to determin the protection state based on the localized output of "manage-bde -status"

.PARAMETER procstatepat
Pattern to determin the if the protection state based on the localized output of "manage-bde -status" is enabled

.PARAMETER adcheck
Check Active Directory and shows the key. Require Active Directory PowerShell module installed and Domain Admin permissions

.NOTES
Author     :  Fabian Niesen (infrastrukturhelden.de)
Filename   :  Update-BitLockerRecovery.ps1
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
Version    :  1.2
History    :  1.2 FN 03.12.2025 Changed License to MIT, housekeeping Header
              1.1 FN 09.12.2021 Change Locale setting after feedback from Jonas. Thanks
              1.0 FN 01/22/2021  initial version

.LINK
https://www.infrastrukturhelden.de/microsoft-infrastruktur/active-directory/bitlocker-wiederherstellungs-keys-nachtraglich-im-ad-sichern/
#>
Param(
	[Parameter(Mandatory=$false, Position=0, ValueFromPipeline=$False)]
	[String]$procstate="",
    [Parameter(Mandatory=$false, Position=1, ValueFromPipeline=$False)]
    [String]$procstatepat="",
    [Parameter(Mandatory=$false, Position=2, ValueFromPipeline=$false)]
    [string]$locale = $((Get-UICulture).Name),
    [switch]$adcheck
)
$scriptversion = "1.2"
Write-Output "Update-BitLockerRecovery.ps1 Version $scriptversion "
$ErrorActionPreference = "Stop"
If (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
{   
$arguments = "& '" + $myinvocation.mycommand.definition + "'"
Start-Process powershell -Verb runAs -ArgumentList $arguments
Break
}
switch($locale){
"de-DE" {$procstate = "Schutzstatus" ; $procstatepat = "*Der Schutz ist aktiviert*" ; Write-Verbose "Locale set to de-DE"}
"en-EN" {$procstate = "Protection" ; $procstatepat = "*Protection On*" ; Write-Verbose "Locale set to en-EN"}
Default {IF ($procstate -eq "" -or $procstatepat-eq "") { Write-Error -Message "Locale not prefinied in script! Please use parameter procstate and procstatepat. Please execute >Get-Help .\Update-BitLockerRecovery.ps1 -Detailed<" -Category NotImplemented }}
}

Try { New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft -Name FVE } Catch {Write-Warning "Registry path already exists"}
Set-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\FVE -Name OSRecovery -Value 1 -Type DWord -Force; 
Set-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\FVE -Name OSManageDRA -Value 1 -Type DWord -Force; 
Set-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\FVE -Name OSRequireActiveDirectoryBackup -Value 0 -Type DWord -Force; 
Set-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\FVE -Name OSActiveDirectoryInfoToStore -Value 1 -Type DWord -Force; 
Set-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\FVE -Name OSActiveDirectoryBackup -Value 1 -Type DWord -Force; 
Set-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\FVE -Name OSHideRecoveryPage -Value 0 -Type DWord -Force
Get-PSDrive -PSProvider FileSystem | Where-Object { !($_.DisplayRoot -ilike "\\*") } | ForEach-Object {
    $root = $_.Root # Fetch the drive letter or mount point
    if ($root -ilike "*\") { $root = $root.substring(0, $root.length - 1) } # Remove trailing backslash
    [string] $status = (manage-bde -status $root) | Select-String -Pattern $procstate
    Write-verbose "Status: $status"
    if ($status -ilike $procstatepat) {
        [string] $id = (manage-bde -protectors -get $root -Type recoverypassword) | Select-String -Pattern ID
        $id = $id.Replace("ID: ", "").Trim()
        Write-verbose "ID: $id"
        manage-bde -protectors -adbackup $root -id $id
        Start-Sleep -Seconds 10
    }
}
Remove-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\FVE -Name OSRecovery -Force; 
Remove-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\FVE -Name OSManageDRA -Force; 
Remove-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\FVE -Name OSRequireActiveDirectoryBackup -Force; 
Remove-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\FVE -Name OSActiveDirectoryInfoToStore -Force; 
Remove-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\FVE -Name OSActiveDirectoryBackup -Force; 
Remove-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\FVE -Name OSHideRecoveryPage -Force
Write-Verbose "Setting back GPO Settings"
GPupdate.exe /Target:Computer /Force
  if ($adcheck -eq $false ) {
  try
  {
    Import-Module ActiveDirectory 
    }
  catch
  {
    Write-Warning "ActiveDirectory Module ist missing. Please install for local check"
    break
  }
  Write-Output "Wait 30 sec to process and AD sync"
  Start-Sleep -Seconds 30
  $recoveryPass = Get-ADObject -Filter {objectclass -eq 'msFVE-RecoveryInformation'} -SearchBase $($env:COMPUTERNAME).DistinguishedName -Properties 'msFVE-RecoveryPassword' | Where-Object {$_.DistinguishedName -like "*$id*"}
  Write-Output "Stored Recovery Password in AD: $recoveryPass "
}

