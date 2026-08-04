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
- [Inventario de scripts](#inventario-de-scripts)
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
- [Plantillas de GPO](#plantillas-de-gpo)
- [Archivos adicionales](#archivos-adicionales)
- [Notas](#notas)


## Inventario de scripts

Las tablas siguientes las genera [`Tools/Update-Readme.ps1`](./Tools/Update-Readme.ps1). Los textos de propósito se mantienen en [`Tools/readme-inventory.json`](./Tools/readme-inventory.json); la versión, la licencia y los enlaces a artículos se leen de las cabeceras de los scripts. No edites las tablas a mano.

> **Notas de versión/licencia**
> - **Versión**: se determina en este orden: variable `$ScriptVersion` en el script, luego `$script:BuildVer`, después la primera palabra de `Version    :` en la cabecera, si no `n/d`.
> - **Licencia**: se obtiene de la línea `License    :` de la cabecera; en su defecto, de una declaración de licencia explícita en la cabecera. Si no hay ninguna, `No especificada`.
> - **Artículo**: proviene de la sección `.LINK` de la cabecera (`EN` = infrastructureheroes.org, `DE` = infrastrukturhelden.de).

<!-- BEGIN GENERATED: inventory -->
### Scripts principales

| Archivo | Propósito | Versión | Licencia | Artículo |
|---|---|---|---|---|
| `Set-WinRelease.ps1` | Establecer claves del registro para mantener Windows en una versión concreta (versión de destino de las actualizaciones de características). | 1.1 | Licencia MIT (MIT) | &ndash; |
| `Get-WindowsSid.ps1` | Recopilar los SID de Windows de los equipos de AD accesibles mediante Sysinternals PSGetSid. | 1.2 | Licencia MIT (MIT) | [EN](https://www.infrastructureheroes.org/microsoft-infrastructure/microsoft-windows/the-windows-sid-and-an-old-problem/) / [DE](https://www.infrastrukturhelden.de/microsoft-infrastruktur/microsoft-windows/die-windows-sid-und-ein-altes-problem/) |
| `install-greenshot.ps1` | Instalar la versión ZIP de Greenshot y crear entradas en el menú Inicio. | 1.1 | Licencia MIT (MIT) | &ndash; |
| `Set-Network.ps1` | Aplicar configuraciones de red habituales (dominio DNS, NetBIOS, IPv6). | 1.2 | Licencia MIT (MIT) | &ndash; |
| `New-DokuwikiAnimal.ps1` | Crear una estructura "animal" de DokuWiki con los grupos de AD y los recursos compartidos correspondientes. | 0.1 | Licencia MIT (MIT) | &ndash; |
| `send-files.ps1` | Enviar por correo electrónico los archivos de un directorio. | 1.3 | Licencia MIT (MIT) | [DE](https://www.infrastrukturhelden.de/?p=13527) |
| `generate-hosts.ps1` | Generar un archivo hosts a partir de Active Directory. | 1.1 | Licencia MIT (MIT) | &ndash; |

### ActiveDirectory

| Archivo | Propósito | Versión | Licencia | Artículo |
|---|---|---|---|---|
| `ActiveDirectory/Configure-AD.ps1` | Configurar un dominio de AD (papelera de reciclaje, preparación de gMSA, almacén central, directivas de contraseñas, estructura de OU). | 0.2 | Licencia MIT (MIT) | &ndash; |
| `ActiveDirectory/Get-ADPermissionsReport.ps1` | Exportar un informe CSV de los permisos de Active Directory. | 0.2 | No especificada | &ndash; |
| `ActiveDirectory/Get-DFSRBacklog.ps1` | Comprobar el backlog de DFSR y generar informes de replicación (exportación CSV y comparación de hashes opcionales). | 0.5 | GNU General Public License v3 (GPLv3) | &ndash; |
| `ActiveDirectory/Get-LAPSAuditReport.ps1` | Consultar los eventos de seguridad relacionados con la auditoría de Microsoft LAPS. | n/d | No especificada | &ndash; |
| `ActiveDirectory/Get-LocalNTLMlogs.ps1` | Analizar y clasificar los eventos locales `Microsoft-Windows-NTLM/Operational`. | 1.0 | GNU General Public License v3 (GPLv3) | &ndash; |
| `ActiveDirectory/Get-NTLMLogons.ps1` | Analizar los registros de seguridad en busca de inicios de sesión NTLM y uso de autenticación. | 1.3 | GNU General Public License v3 (GPLv3) | &ndash; |
| `ActiveDirectory/Get-PKICertlist.ps1` | Enumerar certificados y plantillas del contexto de AD CS / PKI. | n/d | No especificada | &ndash; |
| `ActiveDirectory/Locate-46xx.ps1` | Localizar los eventos de bloqueo de AD (eventos de seguridad 46xx). | 1.0 | No especificada | &ndash; |
| `ActiveDirectory/Locate-ADLockout.ps1` | Localizar el origen de los bloqueos de usuario en Active Directory. | 1.0 | No especificada | &ndash; |
| `ActiveDirectory/Repair-DFSR.ps1` | Reparar la replicación DFS-R (incluido SYSVOL) en controladores de dominio. | 0.1 | No especificada | &ndash; |
| `ActiveDirectory/Reset-DSRM.ps1` | Restablecer la contraseña de DSRM en un controlador de dominio. | 0.3 | GNU General Public License v3 (GPLv3) | &ndash; |
| `ActiveDirectory/execute-RemoteScriptWithLAPS.ps1` | Ejecutar scripts remotos con credenciales de administrador local gestionadas por Microsoft LAPS. | 1.1 | No especificada | [DE](https://www.infrastrukturhelden.de/microsoft-infrastruktur/active-directory/powershell-skripte-mit-local-administrator-password-solution-laps-nutzen-und-auditieren/) |
| `ActiveDirectory/get-CVE20201472Events.ps1` | Comprobar en los controladores de dominio los eventos de Netlogon relacionados con CVE-2020-1472 (5827-5829). | 1.0 | No especificada | [DE](https://www.infrastrukturhelden.de/?p=14850) |
| `ActiveDirectory/get-adinfo.ps1` | Recopilar la información principal del bosque y del dominio de AD y generar el informe. | 0.7 | GNU General Public License v3 (GPLv3) | &ndash; |
| `ActiveDirectory/install-AD.ps1` | Instalar e inicializar un nuevo dominio de Active Directory. | 0.1 | No especificada | &ndash; |
| `ActiveDirectory/install-DC.ps1` | Instalar o promover un controlador de dominio adicional. | 0.1 | No especificada | &ndash; |
| `ActiveDirectory/move-FSMO.ps1` | Transferir los roles FSMO a un nuevo controlador de dominio. | 0.1 | No especificada | &ndash; |
| `ActiveDirectory/set-BSI-TR-02102-2.ps1` | Configurar los ajustes criptográficos de Windows según BSI TR-02102-2 (endurecimiento de TLS y cifrados). | 0.3 | GNU General Public License v3 (GPLv3) | &ndash; |

### Azure

| Archivo | Propósito | Versión | Licencia | Artículo |
|---|---|---|---|---|
| `Azure/Install-AzCopy.ps1` | Descargar e instalar la última versión de AzCopy para el usuario actual. | 1.0 | No especificada | &ndash; |
| `Azure/Install-AzModule.ps1` | Instalar o actualizar los módulos de Azure PowerShell (`Az`). | n/d | No especificada | &ndash; |

### BitLocker

| Archivo | Propósito | Versión | Licencia | Artículo |
|---|---|---|---|---|
| `BitLocker/List-BitLockerrecoveryKeys.ps1` | Listar las claves de recuperación de BitLocker almacenadas en Active Directory. | n/d | No especificada | &ndash; |
| `BitLocker/Start-Bitlocker.ps1` | Iniciar el cifrado de BitLocker con una configuración predefinida (incluidos los flujos con PIN). | n/d | No especificada | &ndash; |
| `BitLocker/Update-BitLockerRecovery.ps1` | Cargar en Active Directory la información de recuperación de BitLocker que falte. | 1.2 | No especificada | [DE](https://www.infrastrukturhelden.de/microsoft-infrastruktur/active-directory/bitlocker-wiederherstellungs-keys-nachtraglich-im-ad-sichern/) |

### Exchange

| Archivo | Propósito | Versión | Licencia | Artículo |
|---|---|---|---|---|
| `Exchange/Set-MaintananceMode.ps1` | Poner un nodo DAG de Exchange 2013 en modo de mantenimiento. | 0.2 | No especificada | &ndash; |
| `Exchange/Set-Ex2013Vdir.ps1` | Configurar los directorios virtuales y las URL de Exchange 2013. | 0.1 | No especificada | &ndash; |

### GPO

| Archivo | Propósito | Versión | Licencia | Artículo |
|---|---|---|---|---|
| `GPO/Check-LocalGroupPolicy.ps1` | Detectar y corregir problemas de procesamiento de directivas de grupo locales a partir de los registros de eventos. | 0.4 | Licencia MIT (MIT) | &ndash; |
| `GPO/get-GPOBackup.ps1` | Crear copias de seguridad de GPO con marca de tiempo, incluidos informes HTML. | 1.8 | Licencia MIT (MIT) | [DE](https://www.infrastrukturhelden.de/microsoft-infrastruktur/active-directory/gruppenrichtlinien-richtig-sichern-und-dokumentieren.html) |
| `GPO/get-GPOreport.ps1` | Exportar e informar los vínculos y metadatos de las GPO para la documentación. | n/d | No especificada | &ndash; |
| `GPO/invoke-GPupdateDomain.ps1` | Lanzar GPUpdate de forma remota para los equipos de una OU (o de un ámbito mayor). | 1.1 | Licencia MIT (MIT) | &ndash; |

### Intune

| Archivo | Propósito | Versión | Licencia | Artículo |
|---|---|---|---|---|
| `Intune/create-package.ps1` | Generar paquetes `.intunewin` a partir de carpetas de origen. | 1.0 | No especificada | &ndash; |
| `Intune/get-AutopilotLogs.ps1` | Recopilar registros y diagnósticos del aprovisionamiento previo de Autopilot. | 1.0.2 | Licencia MIT (MIT) | &ndash; |

### Linux-Files

| Archivo | Propósito | Versión | Licencia | Artículo |
|---|---|---|---|---|
| `Linux-Files/allow_windowsupdate.squid` | Lista de permitidos (ACL de Squid) para los endpoints de Windows Update. | n/d | No especificada | &ndash; |
| `Linux-Files/allow_psgallery.squid` | Lista de permitidos (ACL de Squid) para los endpoints de PowerShell Gallery / NuGet. | n/d | No especificada | &ndash; |
| `Linux-Files/allow_github.squid` | Lista de permitidos (ACL de Squid) para los endpoints de GitHub. | n/d | No especificada | &ndash; |
| `Linux-Files/allow_vscode.squid` | Lista de permitidos (ACL de Squid) para los endpoints de Visual Studio Code. | n/d | No especificada | &ndash; |

### Network

| Archivo | Propósito | Versión | Licencia | Artículo |
|---|---|---|---|---|
| `Network/Check-Network.ps1` | Validar la conectividad y la configuración de red de un cliente. | 0.6 | MIT (código de prueba LDAP: MIT &copy; Evotec) | &ndash; |
| `Network/disable-NetBios.ps1` | Desactivar NetBIOS sobre TCP/IP en los adaptadores activos. | n/d | No especificada | &ndash; |

### User

| Archivo | Propósito | Versión | Licencia | Artículo |
|---|---|---|---|---|
| `User/create-user.ps1` | Crear usuarios de AD (incluida la incorporación a Microsoft 365). | 0.3 | Licencia MIT (MIT) | [DE](https://www.infrastrukturhelden.de/microsoft-infrastruktur/active-directory/benutzer-einfachen-anlegen-mit-powershell/) |
| `User/Get-LastLogonOU.ps1` | Informar del último inicio de sesión de los usuarios de una OU (contexto de AD y Exchange). | 0.2 | Licencia MIT (MIT) | &ndash; |

### Windows

| Archivo | Propósito | Versión | Licencia | Artículo |
|---|---|---|---|---|
| `Windows/set-cert4rdp.ps1` | Asignar el certificado de RDP emitido por una CA concreta. | 0.2 | Licencia MIT (MIT) | &ndash; |
| `Windows/Remove-AzureArc.ps1` | Eliminar el agente y los componentes de Azure Arc y reiniciar automáticamente si es necesario. | 1.1 | Licencia MIT (MIT) | &ndash; |

### WSUS

| Archivo | Propósito | Versión | Licencia | Artículo |
|---|---|---|---|---|
| `WSUS/decline-WSUSUpdatesTypes.ps1` | Rechazar clasificaciones o productos de actualización seleccionados en WSUS. | 1.8 | Licencia MIT (MIT) | [DE](https://www.infrastrukturhelden.de/microsoft-infrastruktur/wsus/windows-server-update-services-bereinigen.html) |
| `WSUS/Reset-WSUSClient.cmd` | Restablecer la configuración del cliente WSUS y su estado de detección. | n/d | No especificada | &ndash; |
| `WSUS/start-WsusServerSync.ps1` | Iniciar la sincronización de WSUS (admite servidores ascendentes/descendentes recursivos y registro por correo). | n/d | No especificada | &ndash; |
| `WSUS/Get-WsusHealth.ps1` | Ejecutar comprobaciones completas de salud de WSUS y generar la salida de diagnóstico. | 1.3 | MIT (código de prueba LDAP: MIT &copy; Evotec) | [DE](https://www.infrastrukturhelden.de/microsoft-infrastruktur/wsus/wsus-fehleranalyse-und-health-checks-praxisleitfaden-mit-powershell/) |
<!-- END GENERATED: inventory -->

## Plantillas de GPO

Objetos de directiva de grupo de ejemplo publicados junto con los artículos. Cada plantilla incluye una descripción en Markdown y una copia de seguridad de GPO importable (ZIP). Detalles y licencia: [`GPO/Templates/readme.md`](./GPO/Templates/readme.md).

<!-- BEGIN GENERATED: gpo-templates -->
| Plantilla | Propósito | Copia de seguridad de GPO |
|---|---|---|
| [`GPO/Templates/Win11-24H2-IT-Grundschutz-Darksite.md`](./GPO/Templates/Win11-24H2-IT-Grundschutz-Darksite.md) | Windows 11 24H2 &ndash; protección básica de TI (darksite / comunicación limitada con la nube). | [ZIP](./GPO/Templates/Win11-24H2-IT-Grundschutz-Darksite.zip) |
| [`GPO/Templates/Win11-Disable-Copilot.md`](./GPO/Templates/Win11-Disable-Copilot.md) | Windows 11 &ndash; desactivar Microsoft Copilot y las funciones de IA. | [ZIP](./GPO/Templates/Win11-Disable-Copilot.zip) |
| [`GPO/Templates/MSOffice-Deactivate-Copilot.md`](./GPO/Templates/MSOffice-Deactivate-Copilot.md) | Microsoft Office &ndash; desactivar Copilot y las funciones de IA. | [ZIP](./GPO/Templates/MSOffice-Deactivate-Copilot.zip) |
| [`GPO/Templates/VisualStudio-Deactivate-Copilot.md`](./GPO/Templates/VisualStudio-Deactivate-Copilot.md) | Visual Studio &ndash; desactivar Copilot y las funciones de IA. | [ZIP](./GPO/Templates/VisualStudio-Deactivate-Copilot.zip) |
<!-- END GENERATED: gpo-templates -->

## Archivos adicionales

- `Intune/Readme.md` – Notas específicas de Intune (en alemán).
- `Dokumente/Zertifizierungsstellen mit Windows Server 2012R2.pdf` – documentación de entidades de certificación (PKI/CA) en PDF.
- `GPO/Templates/readme.md` – índice y condiciones de licencia de las plantillas de GPO.

## Notas

- Algunos scripts son maduros y están versionados.
- Otros son utilidades operativas rápidas para la administración diaria.
- Valida siempre los scripts en un entorno de pruebas antes de usarlos en producción.
- ¿Buscas los [diagramas de ciclo de vida](https://github.com/FabianNiesen/InfrastrukturHelden-LifeCycle-diagrams)? Están en un repositorio aparte.

[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/Z8Z8FB6VH)
