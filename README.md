# Infrastrukturhelden Script Collection

PowerShell and infrastructure helper scripts by Fabian Niesen.

- Language versions: [English](README.md) | [Deutsch](README.de.md) | [Español](README.es.md) | [Français](README.fr.md)

> **Translation notice**
> The non-English README files were created with AI assistance to make usage easier. In case of ambiguity, use `README.md` as the authoritative version.

- German blog: [https://www.infrastrukturhelden.de](https://www.infrastrukturhelden.de)
- English blog: [https://www.infrastructureheroes.org/](https://www.infrastructureheroes.org/)

> **Disclaimer**
> This repository and all included scripts are provided "as is", without warranties or conditions of any kind, express or implied, including but not limited to merchantability, fitness for a particular purpose, and non-infringement.
> You are solely responsible for reviewing, testing, and validating every script before use in any environment. The author and contributors are not liable for any direct, indirect, incidental, consequential, or special damages resulting from the use or misuse of these scripts.

## Repository Overview

This repository contains administration scripts for:

- Active Directory and identity operations
- BitLocker and endpoint encryption
- Group Policy (GPO)
- WSUS operations and health checks
- Intune packaging and troubleshooting
- Azure tooling setup
- Network diagnostics and client configuration
- Exchange maintenance tasks
- User lifecycle automation
- Windows hardening and cleanup
- Linux/Squid allowlists used in enterprise proxy setups

## Table of Contents

- [Repository Overview](#repository-overview)
- [Script Inventory (scanned from the repository)](#script-inventory-scanned-from-the-repository)
  - [Root scripts](#root-scripts)
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
- [Additional files](#additional-files)
- [Notes](#notes)


## Script Inventory (scanned from the repository)

The descriptions are based on `.SYNOPSIS` / `.DESCRIPTION` where available; otherwise they are inferred from script names/content.

> **Version/License notes**
> - **Version**: determined in this order: `$ScriptVersion` variable in the script, then `$script:BuildVer`, then `Version    :` in header notes, otherwise `n/a`.
> - **License**: read from the header `.NOTES` section line `License    :`; if not present, `Not specified`.

### Root scripts

| File | Purpose | Version | License |
|---|---|---|---|
| `Set-WinRelease.ps1` | Set registry keys to keep Windows 10 on a specific release. | 1.1 | The MIT License (MIT) |
| `Get-WindowsSid.ps1` | Collect Windows SIDs from online AD computers via Sysinternals PSGetSid. | 1.2 | The MIT License (MIT) |
| `install-greenshot.ps1` | Install the ZIP version of Greenshot and create Start Menu entries. | 1.1 | The MIT License (MIT) |
| `Set-Network.ps1` | Apply common network settings (DNS domain, NetBIOS, IPv6). | 1.2 | The MIT License (MIT) |
| `New-DokuwikiAnimal.ps1` | Create a DokuWiki "animal" structure with matching AD groups and shares. | 0.1 | The MIT License (MIT) |
| `send-files.ps1` | Send files from a directory via email. | 1.3 | The MIT License (MIT) |
| `generate-hosts.ps1` | Generate a hosts file based on Active Directory. | 1.1 | The MIT License (MIT) |

### ActiveDirectory

**Directory Documentation:** [English](ActiveDirectory/README.md) | [Deutsch](ActiveDirectory/README.de.md)

| File | Purpose | Version | License |
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

**Directory Documentation:** [English](Azure/README.md) | [Deutsch](Azure/README.de.md)

| File | Purpose | Version | License |
|---|---|---|---|
| `Azure/Install-AzCopy.ps1` | Download and install the latest AzCopy for the current user. | 1.0 | Not specified |
| `Azure/Install-AzModule.ps1` | Install/update Azure PowerShell modules (`Az`). | n/a | Not specified |

### BitLocker

**Directory Documentation:** [English](BitLocker/README.md) | [Deutsch](BitLocker/README.de.md)

| File | Purpose | Version | License |
|---|---|---|---|
| `BitLocker/List-BitLockerrecoveryKeys.ps1` | List BitLocker recovery keys stored in Active Directory. | n/a | Not specified |
| `BitLocker/Start-Bitlocker.ps1` | Start BitLocker encryption with predefined settings (including PIN workflows). | n/a | Not specified |
| `BitLocker/Update-BitLockerRecovery.ps1` | Upload missing BitLocker recovery information to Active Directory. | 1.2 | The MIT License (MIT) |

### Exchange

**Directory Documentation:** [English](Exchange/README.md) | [Deutsch](Exchange/README.de.md)

| File | Purpose | Version | License |
|---|---|---|---|
| `Exchange/Set-MaintananceMode.ps1` | Put an Exchange 2013 DAG node into maintenance mode. | 0.2 | Not specified |
| `Exchange/Set-Ex2013Vdir.ps1` | Configure Exchange 2013 virtual directories/URLs. | 0.1 | Not specified |

### GPO

**Directory Documentation:** [English](GPO/README.md) | [Deutsch](GPO/README.de.md)

| File | Purpose | Version | License |
|---|---|---|---|
| `GPO/Check-LocalGroupPolicy.ps1` | Detect and fix local Group Policy processing issues based on event logs. | 0.4 | The MIT License (MIT) |
| `GPO/get-GPOBackup.ps1` | Create timestamped GPO backups including HTML reports. | 1.8 | The MIT License (MIT) |
| `GPO/get-GPOreport.ps1` | Export/report GPO links and metadata for documentation. | n/a | Not specified |
| `GPO/invoke-GPupdateDomain.ps1` | Trigger remote GPUpdate for computers in an OU (or wider scope). | 1.1 | The MIT License (MIT) |

### Intune

**Directory Documentation:** [English](Intune/README.md) | [Deutsch](Intune/README.de.md)

| File | Purpose | Version | License |
|---|---|---|---|
| `Intune/create-package.ps1` | Build `.intunewin` packages from source folders. | 1.0 | Not specified |
| `Intune/get-AutopilotLogs.ps1` | Collect logs and diagnostics for Autopilot pre-provisioning. | 1.0.2 | Not specified |

### Linux-Files

| File | Purpose | Version | License |
|---|---|---|---|
| `Linux-Files/allow_windowsupdate.squid` | Squid ACL allowlist for Windows Update endpoints. | n/a | Not specified |
| `Linux-Files/allow_psgallery.squid` | Squid ACL allowlist for PowerShell Gallery / NuGet endpoints. | n/a | Not specified |
| `Linux-Files/allow_github.squid` | Squid ACL allowlist for GitHub endpoints. | n/a | Not specified |
| `Linux-Files/allow_vscode.squid` | Squid ACL allowlist for Visual Studio Code endpoints. | n/a | Not specified |

### Network

**Directory Documentation:** [English](Network/README.md) | [Deutsch](Network/README.de.md)

| File | Purpose | Version | License |
|---|---|---|---|
| `Network/Check-Network.ps1` | Validate client network connectivity and configuration. | 0.6 | Except for the LDAP Test Code, witch is licensed by Evotec under MIT License |
| `Network/disable-NetBios.ps1` | Disable NetBIOS over TCP/IP on active adapters. | n/a | Not specified |

### User

**Directory Documentation:** [English](User/README.md) | [Deutsch](User/README.de.md)

| File | Purpose | Version | License |
|---|---|---|---|
| `User/create-user.ps1` | Create AD users (including Microsoft 365 onboarding patterns). | 0.3 | The MIT License (MIT) |
| `User/Get-LastLogonOU.ps1` | Report last logon values for users in an OU (AD + Exchange context). | 0.2 FN 03.12.2025 Changed License to MIT, housekeeping Header | The MIT License (MIT) |

### Windows

**Directory Documentation:** [English](Windows/README.md) | [Deutsch](Windows/README.de.md)

| File | Purpose | Version | License |
|---|---|---|---|
| `Windows/set-cert4rdp.ps1` | Bind/set the RDP certificate from a specific issuing CA. | 0.2 | The MIT License (MIT) |
| `Windows/Remove-AzureArc.ps1` | Remove Azure Arc agent/components and reboot automatically if required. | 1.1 | The MIT License (MIT) |

### WSUS

**Directory Documentation:** [English](WSUS/README.md) | [Deutsch](WSUS/README.de.md)

| File | Purpose | Version | License |
|---|---|---|---|
| `WSUS/decline-WSUSUpdatesTypes.ps1` | Decline selected update classifications/products in WSUS. | 1.8 | The MIT License (MIT) |
| `WSUS/Reset-WSUSClient.cmd` | Reset WSUS client configuration and detection state. | n/a | Not specified |
| `WSUS/start-WsusServerSync.ps1` | Start WSUS synchronization (supports recursive upstream/downstream and email logging). | n/a | Not specified |
| `WSUS/Get-WsusHealth.ps1` | Run comprehensive WSUS health checks and generate diagnostic output. | 1.3 | Except for the LDAP Test Code, witch is licensed by Evotec under MIT License |

## Additional files

- `Intune/README.md` – Intune directory documentation (English and German).
- `GPO/Templates/README.md` – GPO templates documentation (English, German, Spanish, French).
- `GPO/Client_Side_Extension-GUID_List.md` – Group Policy Client-Side Extension GUID reference.
- `Dokumente/Zertifizierungsstellen mit Windows Server 2012R2.pdf` – PKI/CA documentation PDF.

## Notes

- Some scripts are mature and versioned.
- Others are quick operational helpers collected for day-to-day administration.
- Always validate scripts in a test environment before production use.
