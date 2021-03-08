# Infrastrukturhelden.de - English version below
Powershell Skriptsammlung von Fabian Niesen [InfrastrukturHelden.de](https://www.infrastrukturhelden.de). Für alle Scripte gilt:
**Verwendung auf eigene Gefahr und ohne Gewährleistungsansprüche!**
Die Skripte die über einen Header mit Versionierung verfügen, sind meistens ausgereifter. Andere sind teilweise auch nur praktische Codeschnipsel, die ich so besser im Zugriff habe.

## Skripte in der Übersicht

### BitLocker
* List-BitLockerrecoveryKeys.ps1 - *Listet alle BitLocker Wiederherstellungsschlüssel im AD auf*
* Update-BitLockerRecovery.ps1 - *Upload BitLocker recovery information to Active Directory, if they not already exist.*
* Start-Bitlocker.ps1 - *Startet die BitLocker Verschlüsselung mit einer definierten PIN*

### Exchange

### GPO - Gruppenrichtlinien
* get-GPOBackup.ps1 - *Creates backup of the GPO with according html Reports. The script creates a subfolder based upon an actual timestamp. - V1.58*
* invoke-GPupdateDomain.ps1 - *Führt remote ein GPUPDATE für einzelne Computer, OUs oder die ganze Domäne aus*

### User - Benutzermanagement
* create-user.ps1 - *Legt einen neuen Benutzer an. Inklusive Microsoft365 Lizenzzuweisung und einer Begrüßungsmail. Passender Artikel: [Benutzer einfachen anlegen mit PowerShell](https://www.infrastrukturhelden.de/microsoft-infrastruktur/active-directory/benutzer-einfachen-anlegen-mit-powershell/)*
* Get-LastLogonOU.ps1 - *eigt das letzte LogOn für alle Nutzer in einer OU an. Sowohl AD als auch Exchange.*

### WSUS -  Windows Server Update Service
* decline-WSUSUpdatesTypes.ps1 - *Decline several Update Types in Windows Server Update Services (WSUS)*
* Reset-WSUSClient.cmd - *Setzt diverse Einstellungen auf dem Client zurück. Löst die meisten aller Client Probleme*
* start-WsusServerSync.ps1 - *Startet eine WSUS Syncronisierung über alle Server und schickt eine Email als Abschluss.*

### Sonstige
* get-adinfo.ps1 - *Erstellt einen AD Report mit Nützlichen Funktionen wie Liste der DCs und die Versionen des Schemas und eventueller Erweiterungen.*

#English version
Powershell script collection by Fabian Niesen [InfrastrukturHelden.de](https://www.infrastrukturhelden.de). The following applies to all scripts:
**Use at your own risk and without any guarantee!**
The scripts that have a header with versioning are usually more mature. Others are sometimes just practical code snippets that I can access better this way.

## Scripts in the overview

### BitLocker
* List-BitLockerrecoveryKeys.ps1 - *Lists all BitLocker recovery keys in AD*.
* Update-BitLockerRecovery.ps1 - *Upload BitLocker recovery information to Active Directory, if they do not already exist.*
* Start-Bitlocker.ps1 - *Starts BitLocker encryption with a defined PIN*.

### Exchange

### GPO - Group Policy
* get-GPOBackup.ps1 - *Creates backup of the GPO with according html reports. The script creates a subfolder based upon an actual timestamp. - V1.58*
* invoke-GPupdateDomain.ps1 - *Remotely executes a GPUPDATE for individual computers, OUs or the entire domain.*

### User - User management
* create-user.ps1 - *Creates a new user. Includes Microsoft365 licence assignment and a welcome email. Related Article: [Creating Users Easily with PowerShell](https://www.infrastrukturhelden.de/microsoft-infrastruktur/active-directory/benutzer-einfachen-anlegen-mit-powershell/)*
* Get-LastLogonOU.ps1 - *displays the last logon for all users in an OU. Both AD and Exchange.*

### WSUS - Windows Server Update Service
* decline-WSUSUpdatesTypes.ps1 - *Decline several Update Types in Windows Server Update Services (WSUS)*.
* Reset-WSUSClient.cmd - *Resets several settings on the client. Solves most of the client problems*.
* start-WsusServerSync.ps1 - *Starts a WSUS sync across all servers and sends an email as a completion.*

### Other
* get-adinfo.ps1 - *Creates an AD report with useful functions like list of DCs and the versions of the schema and any extensions.*