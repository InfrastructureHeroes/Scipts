<#
.SYNOPSIS
Code sample to create a new AD User with Office 365 integration.
	
.DESCRIPTION
Code sample to create a new AD User with Office 365 integration. This needs to be customized to the target environment.

.NOTES
Author     :    Fabian Niesen (infrastrukturhelden.de)
Filename   :    create-user.ps1
Requires   :    PowerShell Version 3.0

Version    :    0.4
History    :    0.4 FN  Improved error handling: no silently swallowed errors, mail errors are reported, wait loop for AAD sync has a timeout
                0.3 FN  03.12.2025 Changed License to MIT, housekeeping Header
                0.2 FN  27.08.2022  Add SmtpPort due #4, fixed some encoding and Typos - Not testest, since my test env is down - Any problems, open an issue at https://github.com/InfrastructureHeroes/Scipts
                0.1 FN  22.01.2019  initial draft
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
https://www.infrastrukturhelden.de/microsoft-infrastruktur/active-directory/benutzer-einfachen-anlegen-mit-powershell/
https://github.com/InfrastructureHeroes/Scipts/blob/master/User/create-user.ps1
#>

[cmdletbinding()] 
Param(
[string] $OU="OU=Benutzer,DC=ADG,DC=local",
[string] $Vorname="",
[string] $Nachname="",
[System.Security.SecureString] $Password,
[string] $Username=$Vorname+"."+$Nachname ,
[string] $Email="demo.held@niesenf.onmicrosoft.com",
[string] $UPN="demo.held@adg.local",
[switch] $PWwechsel,
[switch] $Aktiviert,
[DateTime] $Ablaufdatum, #-AccountExpirationDate #! Umsetzen
[switch] $O365,
[string] $ADCServer="",
[String] $O365Loc="",
[String] $O365Lic="SPE_E5", #Office365 E3 Development = DEVELOPERPACK, Microsoft365 E5 = SPE_E5, WDATP = WIN_DEF_ATP
[string] $DC="",
[string] $Abt="",
[string] $SmtpServer,
[string] $From,
[string] $To,
[switch] $TLS,
[switch] $SmtpAuth,
[System.Security.SecureString] $smtppw,
[string] $smtpuser = "",
[int] $SmtpPort =""
)
$scriptversion = "0.4"
Write-Output "create-user.ps1 Version $scriptversion "
$ErrorActionPreference = "Stop"
# Maximum time to wait for the new user to appear in Azure AD after the sync cycle
[int]$AADSyncTimeoutSeconds = 900
[String] $WelcomeSub = "Willkommen bei Infrastrukturhelden.de"
[String] $WelcomeBody = "Hallo $Vorname" + ',<br>hier schreiben wir dir noch eine nette Begrüssung<br>Besuche uns auf <a href="https://www.infrastrukturhelden.de">Infrastrukturhelden.de</a>'

Function SendEmailStatus($From, $To, $Subject, $SmtpServer, $BodyAsHtml, $Body)
  { 
    $SmtpMessage = New-Object System.Net.Mail.MailMessage $From, $To, $Subject, $Body
    $SmtpMessage.IsBodyHTML = $BodyAsHtml
    $SmtpClient = New-Object System.Net.Mail.SmtpClient $SmtpServer 
    IF ($TLS) { $SmtpClient.EnableSsl = $true }
    IF ($SmtpAuth) {
      IF (-not $smtppw) { $smtppw = Read-Host -Prompt "Password for SMTP user $smtpuser" -AsSecureString }
      $SmtpClient.Credentials = New-Object System.Net.NetworkCredential($smtpuser, $smtppw)
    }
    IF ($SmtpPort) { $SmtpClient.Port = $SmtpPort }
    try { $SmtpClient.Send($SmtpMessage) }
    catch { Write-Warning "Could not send mail to $To`: $($_.Exception.Message) | $($_.Exception.GetBaseException().Message)" }
    finally
    {
      $SmtpMessage.Dispose()
      Remove-Variable SmtpClient
      Remove-Variable SmtpMessage
    }
  }
If (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole( [Security.Principal.WindowsBuiltInRole]  "Administrator"))
{
    $newProcess = new-object System.Diagnostics.ProcessStartInfo "PowerShell";
    $newProcess.Arguments = $myInvocation.MyCommand.Definition;
    $newProcess.Verb = "runas";
    Throw "This script needs to run with administrative permissions. Please start PowerShell as administrator."
} 
if(@(get-module | where-object {$_.Name -eq "ActiveDirectory"} ).count -eq 0) {import-module ActiveDirectory}
Import-Module ActiveDirectory
IF ($DC -eq "") { $DC = $(Get-ADDomainController).HostName ; Write-Verbose "Kein DC angegeben, nutze $DC"  }
IF ( $O365 )
{
  IF ( -not (Get-Command Connect-AzureAD -ErrorAction SilentlyContinue))
  {
    Write-Verbose "Installiere AzureAD Modul"
    Install-Module -Name AzureAD -Force
  }
  Connect-AzureAD
}
IF (-not $Password) { $Password = Read-Host -Prompt "Initial password for $Username" -AsSecureString }
#Zeichenlimit für SAM Account
Write-Verbose "Lege Benutzer an"
New-ADUser -Name $Username -GivenName $Vorname -Surname $Nachname -Path $OU -AccountPassword $Password -DisplayName $($Vorname+" "+$Nachname) -EmailAddress $Email -UserPrincipalName $UPN -OtherAttributes @{proxyAddresses=$("SMPT:"+$Email)} -Server $DC
Start-Sleep -Seconds 10
IF ( $PWwechsel ) { Set-ADUser -Identity $Username -ChangePasswordAtLogon $true -Server $DC } ELSE { Set-ADUser -Identity $Username -ChangePasswordAtLogon $false -Server $DC } 
IF ( $Aktiviert ) { Set-ADUser -Identity $Username -Enabled $true -Server $DC ; Write-Verbose "Aktiviere $Username" }
IF ( $Abt -eq "" ) { Write-verbose "Keine Abteilung ausgewählt" } Else { Add-ADGroupMember -Identity $Abt -Members $Username }
IF ( $O365 ) {
  Write-Verbose "Starte AAD Sync"
  Invoke-Command -ComputerName $ADCServer -ScriptBlock { Start-ADSyncSyncCycle -PolicyType Delta }
  $waited = 0
  $aadUser = $null
  while (-not $aadUser)
  {
    try { $aadUser = Get-AzureADUser -ObjectId $Email }
    catch { Write-Verbose "User $Email not available in Azure AD yet: $($_.Exception.Message)" }
    if (-not $aadUser)
    {
      IF ($waited -ge $AADSyncTimeoutSeconds) { Throw "User $Email did not appear in Azure AD within $AADSyncTimeoutSeconds seconds. Please check the AAD Connect sync on $ADCServer." }
      Start-Sleep -Seconds 10
      $waited += 10
      Write-Verbose "Wait for user appear online"
    }
  }
  #Lizenzzuweisen
  Set-AzureADUser -ObjectId $Email -UsageLocation "DE"
  $license = New-Object -TypeName Microsoft.Open.AzureAD.Model.AssignedLicense
  $licenses = New-Object -TypeName Microsoft.Open.AzureAD.Model.AssignedLicenses
  $license.SkuId = (Get-AzureADSubscribedSku | Where-Object -Property SkuPartNumber -Value $O365Lic -EQ).SkuID
  $licenses.AddLicenses = $license
  Set-AzureADUserLicense -ObjectId $Email -AssignedLicenses $licenses
  Write-Verbose "Assigned Licenses: $($(Get-AzureADUserLicenseDetail -ObjectId $Email ).SkuPartNumber)"
}
# Willkommensemail
SendEmailStatus -From $From -To $Email -Subject $WelcomeSub -SmtpServer $SmtpServer -BodyAsHtml $True -Body $WelcomeBody