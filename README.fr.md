# Infrastrukturhelden Script Collection

Scripts PowerShell et utilitaires d'infrastructure de Fabian Niesen.

- Versions linguistiques : [English](README.md) | [Deutsch](README.de.md) | [Español](README.es.md) | [Français](README.fr.md)

> **Note de traduction**
> Les fichiers README non anglais ont été créés avec l'aide de l'IA pour faciliter l'utilisation. En cas d'ambiguïté, `README.md` fait foi.

- Blog allemand : [https://www.infrastrukturhelden.de](https://www.infrastrukturhelden.de)
- Blog anglais : [https://www.infrastructureheroes.org/](https://www.infrastructureheroes.org/)

> **Avertissement**
> Ce dépôt et tous les scripts inclus sont fournis « en l'état », sans garantie ni condition d'aucune sorte, expresse ou implicite, y compris notamment la qualité marchande, l'adéquation à un usage particulier et l'absence de contrefaçon.
> Vous êtes seul responsable de l'examen, des tests et de la validation de chaque script avant toute utilisation. L'auteur et les contributeurs ne pourront être tenus responsables de tout dommage direct, indirect, accessoire, consécutif ou spécial résultant de l'utilisation ou du mauvais usage de ces scripts.

## Aperçu du dépôt

Ce dépôt contient des scripts d'administration pour :

- Opérations Active Directory et identité
- Chiffrement BitLocker et des postes
- Stratégie de groupe (GPO)
- Opérations WSUS et contrôles de santé
- Création de packages Intune et dépannage
- Configuration des outils Azure
- Diagnostic réseau et configuration client
- Tâches de maintenance Exchange
- Automatisation du cycle de vie des utilisateurs
- Durcissement et nettoyage de Windows
- Listes d'autorisation Linux/Squid pour proxys d'entreprise

## Table des matières

- [Aperçu du dépôt](#aperçu-du-dépôt)
- [Inventaire des scripts (analysé depuis le dépôt)](#inventaire-des-scripts-analysé-depuis-le-dépôt)
  - [Scripts racine](#scripts-racine)
  - [ActiveDirectory](#activedirectory)
  - [Azure](#azure)
  - [BitLocker](#bitlocker)
  - [Exchange](#exchange)
  - [GPO](#gpo)
  - [Intune](#intune)
  - [Linux-Files](#linux-files)
  - [Network](#network)
  - [User](#user)
  - [Windows](#windows)
  - [WSUS](#wsus)
- [Fichiers supplémentaires](#fichiers-supplémentaires)
- [Notes](#notes)


## Inventaire des scripts (analysé depuis le dépôt)

Les descriptions sont basées sur `.SYNOPSIS` / `.DESCRIPTION` lorsqu'elles existent ; sinon, elles sont déduites du nom et du contenu des scripts.

> **Notes version/licence**
> - **Version** : déterminée dans cet ordre : variable `$ScriptVersion` dans le script, puis `$script:BuildVer`, puis `Version    :` dans l'en-tête, sinon `n/a`.
> - **Licence** : lue sur la ligne `License    :` de la section `.NOTES` ; si absente, `Not specified`.

### Scripts racine

| Fichier | Objet | Version | Licence |
|---|---|---|---|
| `Set-WinRelease.ps1` | Set registry keys to keep Windows 10 on a specific release. | 1.1 | The MIT License (MIT) |
| `Get-WindowsSid.ps1` | Collect Windows SIDs from online AD computers via Sysinternals PSGetSid. | 1.2 | The MIT License (MIT) |
| `install-greenshot.ps1` | Install the ZIP version of Greenshot and create Start Menu entries. | 1.1 | The MIT License (MIT) |
| `Set-Network.ps1` | Apply common network settings (DNS domain, NetBIOS, IPv6). | 1.2 | The MIT License (MIT) |
| `New-DokuwikiAnimal.ps1` | Create a DokuWiki "animal" structure with matching AD groups and shares. | 0.1 | The MIT License (MIT) |
| `send-files.ps1` | Send files from a directory via email. | 1.3 | The MIT License (MIT) |
| `generate-hosts.ps1` | Generate a hosts file based on Active Directory. | 1.1 | The MIT License (MIT) |

### ActiveDirectory

| Fichier | Objet | Version | Licence |
|---|---|---|---|
| `ActiveDirectory/Configure-AD.ps1` | Configure an AD domain (e.g., recycle bin, gMSA prep, central store, password policies, OU structure). | 0.2 | Not specified |
| `ActiveDirectory/Get-ADPermissionsReport.ps1` | Export CSV report of Active Directory permissions. | 0.2 | Not specified |
| `ActiveDirectory/Get-LAPSAuditReport.ps1` | Query security events for Microsoft LAPS-related audit activity. | n/a | Not specified |
| `ActiveDirectory/Get-LocalNTLMlogs.ps1` | Analyze local `Microsoft-Windows-NTLM/Operational` events with classification. | 1.0 | GNU General Public License v3 (GPLv3) |
| `ActiveDirectory/Get-NTLMLogons.ps1` | Analyze security logs for NTLM logons and authentication usage. | 1.3 | GNU General Public License v3 (GPLv3) |
| `ActiveDirectory/Get-PKICertlist.ps1` | Enumerate certificates/templates from AD CS / PKI context. | n/a | Not specified |
| `ActiveDirectory/Locate-46xx.ps1` | Locate AD lockout-related events (46xx security events). | 1.0 | Not specified |
| `ActiveDirectory/Locate-ADLockout.ps1` | Locate user lockout sources in Active Directory. | 1.0 | Not specified |
| `ActiveDirectory/Repair-DFSR.ps1` | Repair DFS-R replication (including SYSVOL) on domain controllers. | 0.1 | Not specified |
| `ActiveDirectory/Reset-DSRM.ps1` | Reset DSRM password on a domain controller. | 0.3 | GNU General Public License v3 (GPLv3) |
| `ActiveDirectory/execute-RemoteScriptWithLAPS.ps1` | Run remote scripts with local admin credentials managed by Microsoft LAPS. | 1.1 | Not specified |
| `ActiveDirectory/get-CVE20201472Events.ps1` | Check domain controllers for Netlogon CVE-2020-1472-related event IDs (5827-5829). | 1.0 | Not specified |
| `ActiveDirectory/get-adinfo.ps1` | Collect core AD forest/domain information and report details. | 0.5 | Not specified |
| `ActiveDirectory/install-AD.ps1` | Install and bootstrap a new Active Directory domain. | 0.1 | Not specified |
| `ActiveDirectory/install-DC.ps1` | Install/promote an additional domain controller. | 0.1 | Not specified |
| `ActiveDirectory/move-FSMO.ps1` | Move FSMO roles to a new domain controller. | 0.1 | Not specified |
| `ActiveDirectory/set-BSI-TR-02102-2.ps1` | Configure Windows cryptographic settings according to BSI TR-02102-2 (TLS/cipher hardening). | 0.2 | GNU General Public License v3 (GPLv3) |

### Azure

| Fichier | Objet | Version | Licence |
|---|---|---|---|
| `Azure/Install-AzCopy.ps1` | Download and install the latest AzCopy for the current user. | 1.0 | Not specified |
| `Azure/Install-AzModule.ps1` | Install/update Azure PowerShell modules (`Az`). | n/a | Not specified |

### BitLocker

| Fichier | Objet | Version | Licence |
|---|---|---|---|
| `BitLocker/List-BitLockerrecoveryKeys.ps1` | List BitLocker recovery keys stored in Active Directory. | n/a | Not specified |
| `BitLocker/Start-Bitlocker.ps1` | Start BitLocker encryption with predefined settings (including PIN workflows). | n/a | Not specified |
| `BitLocker/Update-BitLockerRecovery.ps1` | Upload missing BitLocker recovery information to Active Directory. | 1.2 | The MIT License (MIT) |

### Exchange

| Fichier | Objet | Version | Licence |
|---|---|---|---|
| `Exchange/Set-MaintananceMode.ps1` | Put an Exchange 2013 DAG node into maintenance mode. | 0.2 | Not specified |
| `Exchange/Set-Ex2013Vdir.ps1` | Configure Exchange 2013 virtual directories/URLs. | 0.1 | Not specified |

### GPO

| Fichier | Objet | Version | Licence |
|---|---|---|---|
| `GPO/Check-LocalGroupPolicy.ps1` | Detect and fix local Group Policy processing issues based on event logs. | 0.4 | The MIT License (MIT) |
| `GPO/get-GPOBackup.ps1` | Create timestamped GPO backups including HTML reports. | 1.8 | The MIT License (MIT) |
| `GPO/get-GPOreport.ps1` | Export/report GPO links and metadata for documentation. | n/a | Not specified |
| `GPO/invoke-GPupdateDomain.ps1` | Trigger remote GPUpdate for computers in an OU (or wider scope). | 1.1 | The MIT License (MIT) |

### Intune

| Fichier | Objet | Version | Licence |
|---|---|---|---|
| `Intune/create-package.ps1` | Build `.intunewin` packages from source folders. | 1.0 | Not specified |
| `Intune/get-AutopilotLogs.ps1` | Collect logs and diagnostics for Autopilot pre-provisioning. | 1.0.2 | Not specified |

### Linux-Files

| Fichier | Objet | Version | Licence |
|---|---|---|---|
| `Linux-Files/allow_windowsupdate.squid` | Squid ACL allowlist for Windows Update endpoints. | n/a | Not specified |
| `Linux-Files/allow_psgallery.squid` | Squid ACL allowlist for PowerShell Gallery / NuGet endpoints. | n/a | Not specified |
| `Linux-Files/allow_github.squid` | Squid ACL allowlist for GitHub endpoints. | n/a | Not specified |
| `Linux-Files/allow_vscode.squid` | Squid ACL allowlist for Visual Studio Code endpoints. | n/a | Not specified |

### Network

| Fichier | Objet | Version | Licence |
|---|---|---|---|
| `Network/Check-Network.ps1` | Validate client network connectivity and configuration. | 0.6 | Except for the LDAP Test Code, witch is licensed by Evotec under MIT License |
| `Network/disable-NetBios.ps1` | Disable NetBIOS over TCP/IP on active adapters. | n/a | Not specified |

### User

| Fichier | Objet | Version | Licence |
|---|---|---|---|
| `User/create-user.ps1` | Create AD users (including Microsoft 365 onboarding patterns). | 0.3 | The MIT License (MIT) |
| `User/Get-LastLogonOU.ps1` | Report last logon values for users in an OU (AD + Exchange context). | 0.2 FN 03.12.2025 Changed License to MIT, housekeeping Header | The MIT License (MIT) |

### Windows

| Fichier | Objet | Version | Licence |
|---|---|---|---|
| `Windows/set-cert4rdp.ps1` | Bind/set the RDP certificate from a specific issuing CA. | 0.2 | The MIT License (MIT) |
| `Windows/Remove-AzureArc.ps1` | Remove Azure Arc agent/components and reboot automatically if required. | 1.1 | The MIT License (MIT) |

### WSUS

| Fichier | Objet | Version | Licence |
|---|---|---|---|
| `WSUS/decline-WSUSUpdatesTypes.ps1` | Decline selected update classifications/products in WSUS. | 1.8 | The MIT License (MIT) |
| `WSUS/Reset-WSUSClient.cmd` | Reset WSUS client configuration and detection state. | n/a | Not specified |
| `WSUS/start-WsusServerSync.ps1` | Start WSUS synchronization (supports recursive upstream/downstream and email logging). | n/a | Not specified |
| `WSUS/Get-WsusHealth.ps1` | Run comprehensive WSUS health checks and generate diagnostic output. | 1.3 | Except for the LDAP Test Code, witch is licensed by Evotec under MIT License |

## Fichiers supplémentaires

- `Intune/Readme.md` – Notes spécifiques Intune (en allemand).
- `Dokumente/Zertifizierungsstellen mit Windows Server 2012R2.pdf` – PKI/CA documentation PDF.

## Notes

- Certains scripts sont matures et versionnés.
- D'autres sont des aides opérationnelles rapides pour l'administration quotidienne.
- Validez toujours les scripts dans un environnement de test avant usage en production.
