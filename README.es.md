# Infrastrukturhelden Script Collection

Scripts de PowerShell y utilidades de infraestructura de Fabian Niesen.

- Versiones de idioma: [English](README.md) | [Deutsch](README.de.md) | [Español](README.es.md) | [Français](README.fr.md)

> **Aviso de traducción**
> Los README en idiomas distintos del inglés se crearon con ayuda de IA para facilitar el uso. En caso de duda, `README.md` es la versión de referencia.

- Blog en alemán: [https://www.infrastrukturhelden.de](https://www.infrastrukturhelden.de)
- Blog en inglés: [https://www.infrastructureheroes.org/](https://www.infrastructureheroes.org/)

> **Descargo de responsabilidad**
> Este repositorio y todos los scripts incluidos se proporcionan "tal cual", sin garantías ni condiciones de ningún tipo, expresas o implícitas, incluidas, entre otras, comerciabilidad, idoneidad para un fin concreto y no infracción.
> Usted es el único responsable de revisar, probar y validar cada script antes de usarlo en cualquier entorno. El autor y los colaboradores no son responsables de daños directos, indirectos, incidentales, consecuentes o especiales derivados del uso o mal uso de estos scripts.

## Resumen del repositorio

Este repositorio contiene scripts de administración para:

- Operaciones de Active Directory e identidad
- Cifrado de BitLocker y endpoints
- Directiva de grupo (GPO)
- Operaciones de WSUS y comprobaciones de estado
- Empaquetado y solución de problemas de Intune
- Configuración de herramientas de Azure
- Diagnóstico de red y configuración de clientes
- Tareas de mantenimiento de Exchange
- Automatización del ciclo de vida de usuarios
- Endurecimiento y limpieza de Windows
- Listas de permitidos Linux/Squid para entornos proxy empresariales

## Tabla de contenidos

- [Resumen del repositorio](#resumen-del-repositorio)
- [Inventario de scripts (analizado desde el repositorio)](#inventario-de-scripts-analizado-desde-el-repositorio)
  - [Scripts principales](#scripts-principales)
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
- [Archivos adicionales](#archivos-adicionales)
- [Notas](#notas)


## Inventario de scripts (analizado desde el repositorio)

Las descripciones se basan en `.SYNOPSIS` / `.DESCRIPTION` cuando existen; en caso contrario, se infieren del nombre y contenido del script.

> **Notas de versión/licencia**
> - **Versión**: se determina en este orden: variable `$ScriptVersion` en el script, luego `$script:BuildVer`, después `Version    :` en la cabecera, si no `n/a`.
> - **Licencia**: se obtiene de la línea `License    :` dentro de `.NOTES`; si no existe, `Not specified`.

### Scripts principales

| Archivo | Propósito | Versión | Licencia |
|---|---|---|---|
| `Set-WinRelease.ps1` | Set registry keys to keep Windows 10 on a specific release. | 1.1 | The MIT License (MIT) |
| `Get-WindowsSid.ps1` | Collect Windows SIDs from online AD computers via Sysinternals PSGetSid. | 1.2 | The MIT License (MIT) |
| `install-greenshot.ps1` | Install the ZIP version of Greenshot and create Start Menu entries. | 1.1 | The MIT License (MIT) |
| `Set-Network.ps1` | Apply common network settings (DNS domain, NetBIOS, IPv6). | 1.2 | The MIT License (MIT) |
| `New-DokuwikiAnimal.ps1` | Create a DokuWiki "animal" structure with matching AD groups and shares. | 0.1 | The MIT License (MIT) |
| `send-files.ps1` | Send files from a directory via email. | 1.3 | The MIT License (MIT) |
| `generate-hosts.ps1` | Generate a hosts file based on Active Directory. | 1.1 | The MIT License (MIT) |

### ActiveDirectory

| Archivo | Propósito | Versión | Licencia |
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

| Archivo | Propósito | Versión | Licencia |
|---|---|---|---|
| `Azure/Install-AzCopy.ps1` | Download and install the latest AzCopy for the current user. | 1.0 | Not specified |
| `Azure/Install-AzModule.ps1` | Install/update Azure PowerShell modules (`Az`). | n/a | Not specified |

### BitLocker

| Archivo | Propósito | Versión | Licencia |
|---|---|---|---|
| `BitLocker/List-BitLockerrecoveryKeys.ps1` | List BitLocker recovery keys stored in Active Directory. | n/a | Not specified |
| `BitLocker/Start-Bitlocker.ps1` | Start BitLocker encryption with predefined settings (including PIN workflows). | n/a | Not specified |
| `BitLocker/Update-BitLockerRecovery.ps1` | Upload missing BitLocker recovery information to Active Directory. | 1.2 | The MIT License (MIT) |

### Exchange

| Archivo | Propósito | Versión | Licencia |
|---|---|---|---|
| `Exchange/Set-MaintananceMode.ps1` | Put an Exchange 2013 DAG node into maintenance mode. | 0.2 | Not specified |
| `Exchange/Set-Ex2013Vdir.ps1` | Configure Exchange 2013 virtual directories/URLs. | 0.1 | Not specified |

### GPO

| Archivo | Propósito | Versión | Licencia |
|---|---|---|---|
| `GPO/Check-LocalGroupPolicy.ps1` | Detect and fix local Group Policy processing issues based on event logs. | 0.4 | The MIT License (MIT) |
| `GPO/get-GPOBackup.ps1` | Create timestamped GPO backups including HTML reports. | 1.8 | The MIT License (MIT) |
| `GPO/get-GPOreport.ps1` | Export/report GPO links and metadata for documentation. | n/a | Not specified |
| `GPO/invoke-GPupdateDomain.ps1` | Trigger remote GPUpdate for computers in an OU (or wider scope). | 1.1 | The MIT License (MIT) |

### Intune

| Archivo | Propósito | Versión | Licencia |
|---|---|---|---|
| `Intune/create-package.ps1` | Build `.intunewin` packages from source folders. | 1.0 | Not specified |
| `Intune/get-AutopilotLogs.ps1` | Collect logs and diagnostics for Autopilot pre-provisioning. | 1.0.2 | Not specified |

### Linux-Files

| Archivo | Propósito | Versión | Licencia |
|---|---|---|---|
| `Linux-Files/allow_windowsupdate.squid` | Squid ACL allowlist for Windows Update endpoints. | n/a | Not specified |
| `Linux-Files/allow_psgallery.squid` | Squid ACL allowlist for PowerShell Gallery / NuGet endpoints. | n/a | Not specified |
| `Linux-Files/allow_github.squid` | Squid ACL allowlist for GitHub endpoints. | n/a | Not specified |
| `Linux-Files/allow_vscode.squid` | Squid ACL allowlist for Visual Studio Code endpoints. | n/a | Not specified |

### Network

| Archivo | Propósito | Versión | Licencia |
|---|---|---|---|
| `Network/Check-Network.ps1` | Validate client network connectivity and configuration. | 0.6 | Except for the LDAP Test Code, witch is licensed by Evotec under MIT License |
| `Network/disable-NetBios.ps1` | Disable NetBIOS over TCP/IP on active adapters. | n/a | Not specified |

### User

| Archivo | Propósito | Versión | Licencia |
|---|---|---|---|
| `User/create-user.ps1` | Create AD users (including Microsoft 365 onboarding patterns). | 0.3 | The MIT License (MIT) |
| `User/Get-LastLogonOU.ps1` | Report last logon values for users in an OU (AD + Exchange context). | 0.2 FN 03.12.2025 Changed License to MIT, housekeeping Header | The MIT License (MIT) |

### Windows

| Archivo | Propósito | Versión | Licencia |
|---|---|---|---|
| `Windows/set-cert4rdp.ps1` | Bind/set the RDP certificate from a specific issuing CA. | 0.2 | The MIT License (MIT) |
| `Windows/Remove-AzureArc.ps1` | Remove Azure Arc agent/components and reboot automatically if required. | 1.1 | The MIT License (MIT) |

### WSUS

| Archivo | Propósito | Versión | Licencia |
|---|---|---|---|
| `WSUS/decline-WSUSUpdatesTypes.ps1` | Decline selected update classifications/products in WSUS. | 1.8 | The MIT License (MIT) |
| `WSUS/Reset-WSUSClient.cmd` | Reset WSUS client configuration and detection state. | n/a | Not specified |
| `WSUS/start-WsusServerSync.ps1` | Start WSUS synchronization (supports recursive upstream/downstream and email logging). | n/a | Not specified |
| `WSUS/Get-WsusHealth.ps1` | Run comprehensive WSUS health checks and generate diagnostic output. | 1.3 | Except for the LDAP Test Code, witch is licensed by Evotec under MIT License |

## Archivos adicionales

- `Intune/Readme.md` – Notas específicas de Intune (en alemán).
- `Dokumente/Zertifizierungsstellen mit Windows Server 2012R2.pdf` – PKI/CA documentation PDF.

## Notas

- Algunos scripts son maduros y están versionados.
- Otros son utilidades operativas rápidas para la administración diaria.
- Valida siempre los scripts en un entorno de pruebas antes de usarlos en producción.
