<#
.SYNOPSIS
Code sample to create a new AD User with Office 365 integration.
	
.DESCRIPTION
Code sample to create a new AD User with Office 365 integration. This needs to be customized to the target environment.

.NOTES
Author     : Fabian Niesen (www.fabian-niesen.de)
Filename   : create-user.ps1
Requires   : PowerShell Version 3.0
Version    : 0.1
History    : 0.1     FN  22/01/19  initial draft
             
.LINK
https://www.infrastrukturhelden.de/microsoft-infrastruktur/active-directory/benutzer-einfachen-anlegen-mit-powershell.html
#>
[cmdletbinding()] 
 Param(
[string] $OU="OU=Benutzer,DC=ADG,DC=local",
[string] $Vorname="",
[string] $Nachname="",
[string] $Password="Pa$$w0rd!1",
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
[string] $smtppw = "",
[string] $smtpuser = ""
 )
[String] $WelcomeSub = "Willkommen bei Infrastrukturhelden.de"
[String] $WelcomeBody = "Hallo $Vorname,<br>hier schreiben wir dir noch eine nette Begrüssung<br>Besuche uns auf <a href="https://www.infrastrukturhelden.de">Infrastrukturhelden.de</a>"

Function SendEmailStatus($From, $To, $Subject, $SmtpServer, $BodyAsHtml, $Body)
     {   $SmtpMessage = New-Object System.Net.Mail.MailMessage $From, $To, $Subject, $Body
         $SmtpMessage.IsBodyHTML = $BodyAsHtml
         $SmtpClient = New-Object System.Net.Mail.SmtpClient $SmtpServer 
         IF ($TLS) { $SmtpClient.EnableSsl = $true }
         IF ($SmtpAuth) { $SmtpClient.Credentials = New-Object System.Net.NetworkCredential($smtpuser, $smtppw) }
         $SmtpClient.Send($SmtpMessage)
If($? -eq $False){Write-Warning "$($Error[0] .Exception.Message) | $($Error[0] .Exception.GetBaseException().Message)"}
         $SmtpMessage.Dispose()
         Remove-Variable SmtpClient
         Remove-Variable SmtpMessage
     }
If (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity] ::GetCurrent()).IsInRole( [Security.Principal.WindowsBuiltInRole]  "Administrator"))
 {
    $newProcess = new-object System.Diagnostics.ProcessStartInfo "PowerShell";
    $newProcess.Arguments = $myInvocation.MyCommand.Definition;
    $newProcess.Verb = "runas";
    break    
 } 
 if(@(get-module | where-object {$_.Name -eq "ActiveDirectory"} ).count -eq 0) {import-module ActiveDirectory}
 Import-Module ActiveDirectory
 IF ($DC -eq "") { $DC = $(Get-ADDomainController).HostName ; Write-Verbose "Kein DC angegeben, nutze $DC"  }
 IF ( $O365 ) { Try { Connect-AzureAD } catch { Write-Verbose "Installiere AzureAD Modul" ; Install-Module -Name AzureAD -Force ; Connect-AzureAD } }
 $SecPass = $Password | ConvertTo-SecureString -AsPlainText -Force
 !Zeichenlimit für SAM Account
 Write-Verbose "Lege Benutzer an"
 New-ADUser -Name $Username -GivenName $Vorname -Surname $Nachname -Path $OU -AccountPassword $SecPass -DisplayName $($Vorname+" "+$Nachname) -EmailAddress $Email -UserPrincipalName $UPN -OtherAttributes @{proxyAddresses=$("SMPT:"+$Email)} -Server $DC
 Start-Sleep -Seconds 10
 IF ( $PWwechsel ) { Set-ADUser -Identity $Username -ChangePasswordAtLogon $true -Server $DC } ELSE { Set-ADUser -Identity $Username -ChangePasswordAtLogon $false -Server $DC } 
 IF ( $Aktiviert ) { Set-ADUser -Identity $Username -Enabled $true -Server $DC ; Write-Verbose "Aktiviere $Username" }
 IF ( $Abt -eq "" ) { Write-verbose "Keine Abteilung ausgewählt" } Else { Add-ADGroupMember -Identity $Abt -Members $Username }
 IF ( $O365 ) {
   Write-Verbose "Starte AAD Sync"
   Invoke-Command -ComputerName $ADCServer -ScriptBlock { Start-ADSyncSyncCycle -PolicyType Delta }
   while ( $(try {Get-AzureADUser -ObjectId $Email} catch {}).count -lt 1) { start-sleep -Seconds 10 ; Write-Verbose "Wait for user appear online"}
   #Lizenzzuweisen
   Set-AzureADUser -ObjectId $Email -UsageLocation "DE"
   $license = New-Object -TypeName Microsoft.Open.AzureAD.Model.AssignedLicense
   $licenses = New-Object -TypeName Microsoft.Open.AzureAD.Model.AssignedLicenses
   $license.SkuId = (Get-AzureADSubscribedSku | Where-Object -Property SkuPartNumber -Value $O365Lic -EQ).SkuID
   $licenses.AddLicenses = $license
   Set-AzureADUserLicense -ObjectId $Email -AssignedLicenses $licenses
   Write-Verbose "Assigned Licenses: $($(Get-AzureADUserLicenseDetail -ObjectId $Email ).SkuPartNumber)"
 }
 ! Willkommensemail
 SendEmailStatus -From $From -To $Email -Subject $WelcomeSub -SmtpServer $SmtpServer -BodyAsHtml $True -Body $WelcomeBody