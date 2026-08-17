# Infrastrukturhelden Script Collection

PowerShell- und Infrastruktur-Hilfsskripte von Fabian Niesen.

- Sprachversionen: [English](README.md) | [Deutsch](README.de.md) | [Español](README.es.md) | [Français](README.fr.md)

> **Hinweis zur Übersetzung**
> Die nicht-englischen README-Dateien wurden mit KI-Unterstützung erstellt, um die Nutzung zu erleichtern. Bei Unklarheiten gilt `README.md` als maßgebliche Version.

- Deutscher Blog: [https://www.infrastrukturhelden.de](https://www.infrastrukturhelden.de)
- Englischer Blog: [https://www.infrastructureheroes.org/](https://www.infrastructureheroes.org/)

> **Haftungsausschluss**
> Dieses Repository und alle enthaltenen Skripte werden „wie besehen“ bereitgestellt – ohne ausdrückliche oder stillschweigende Gewährleistungen, einschließlich (aber nicht beschränkt auf) Marktgängigkeit, Eignung für einen bestimmten Zweck und Nichtverletzung von Rechten.
> Sie sind allein dafür verantwortlich, jedes Skript vor der Nutzung zu prüfen, zu testen und zu validieren. Der Autor und Mitwirkende haften nicht für direkte, indirekte, zufällige, Folge- oder besondere Schäden, die aus der Nutzung oder Fehlanwendung dieser Skripte entstehen.

## Repository-Überblick

Dieses Repository enthält Administrationsskripte für:

- Active Directory- und Identitätsoperationen
- BitLocker- und Endpunktverschlüsselung
- Gruppenrichtlinien (GPO)
- WSUS-Betrieb und Integritätsprüfungen
- Intune-Paketierung und Fehleranalyse
- Azure-Tooling-Setup
- Netzwerkdiagnose und Clientkonfiguration
- Exchange-Wartungsaufgaben
- Benutzerlebenszyklus-Automatisierung
- Windows-Härtung und Bereinigung
- Linux/Squid-Allowlists für Enterprise-Proxy-Umgebungen

## Inhaltsverzeichnis

- [Repository-Überblick](#repository-überblick)
- [Skriptübersicht](#skriptübersicht)
    - [Hauptskripte](#hauptskripte)
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
- [GPO-Templates](#gpo-templates)
- [Zusätzliche Dateien](#zusätzliche-dateien)
- [Hinweise](#hinweise)


## Skriptübersicht

Die folgenden Tabellen werden von [`Tools/Update-Readme.ps1`](./Tools/Update-Readme.ps1) erzeugt. Die Zwecktexte werden in [`Tools/readme-inventory.json`](./Tools/readme-inventory.json) gepflegt; Version, Lizenz und Artikellinks stammen aus den Skript-Headern. Die Tabellen bitte nicht manuell bearbeiten.

> **Hinweise zu Version/Lizenz**
> - **Version**: wird in dieser Reihenfolge bestimmt: Variable `$ScriptVersion` im Skript, dann `$script:BuildVer`, dann das erste Wort aus `Version    :` im Header, sonst `k. A.`.
> - **Lizenz**: wird aus der Header-Zeile `License    :` gelesen; ersatzweise aus einer eindeutigen Lizenzangabe im Header. Fehlt beides, `Nicht angegeben`.
> - **Artikel**: stammt aus dem `.LINK`-Abschnitt des Skript-Headers (`DE` = infrastrukturhelden.de, `EN` = infrastructureheroes.org).

<!-- BEGIN GENERATED: inventory -->
### Hauptskripte

| Datei | Zweck | Version | Lizenz | Artikel |
|---|---|---|---|---|
| `Set-WinRelease.ps1` | Registry-Schlüssel setzen, um Windows auf einem bestimmten Release zu halten (Ziel-Version für Funktionsupdates). | 1.1 | MIT-Lizenz (MIT) | &ndash; |
| `Get-WindowsSid.ps1` | Windows-SIDs von erreichbaren AD-Computern mit Sysinternals PSGetSid sammeln. | 1.2 | MIT-Lizenz (MIT) | [EN](https://www.infrastructureheroes.org/microsoft-infrastructure/microsoft-windows/the-windows-sid-and-an-old-problem/) / [DE](https://www.infrastrukturhelden.de/microsoft-infrastruktur/microsoft-windows/die-windows-sid-und-ein-altes-problem/) |
| `install-greenshot.ps1` | Die ZIP-Variante von Greenshot installieren und Startmenü-Einträge anlegen. | 1.1 | MIT-Lizenz (MIT) | &ndash; |
| `Set-Network.ps1` | Gängige Netzwerkeinstellungen setzen (DNS-Domäne, NetBIOS, IPv6). | 1.2 | MIT-Lizenz (MIT) | &ndash; |
| `New-DokuwikiAnimal.ps1` | Eine DokuWiki-"Animal"-Struktur samt passender AD-Gruppen und Freigaben erstellen. | 0.1 | MIT-Lizenz (MIT) | &ndash; |
| `send-files.ps1` | Dateien aus einem Verzeichnis per E-Mail versenden. | 1.3 | MIT-Lizenz (MIT) | [DE](https://www.infrastrukturhelden.de/?p=13527) |
| `generate-hosts.ps1` | Eine hosts-Datei auf Basis von Active Directory erzeugen. | 1.1 | MIT-Lizenz (MIT) | &ndash; |

### ActiveDirectory

| Datei | Zweck | Version | Lizenz | Artikel |
|---|---|---|---|---|
| `ActiveDirectory/Configure-AD.ps1` | Eine AD-Domäne konfigurieren (u. a. Papierkorb, gMSA-Vorbereitung, Central Store, Kennwortrichtlinien, OU-Struktur). | 0.2 | MIT-Lizenz (MIT) | &ndash; |
| `ActiveDirectory/Get-ADPermissionsReport.ps1` | CSV-Bericht der Active-Directory-Berechtigungen exportieren. | 0.2 | Nicht angegeben | &ndash; |
| `ActiveDirectory/Get-DFSRBacklog.ps1` | DFSR-Backlog prüfen und Replikationsberichte erzeugen (optional CSV-Export und Hash-Vergleich). | 0.5 | GNU General Public License v3 (GPLv3) | &ndash; |
| `ActiveDirectory/Get-LAPSAuditReport.ps1` | Sicherheitsereignisse zu Microsoft-LAPS-Auditaktivitäten auswerten. | k. A. | Nicht angegeben | &ndash; |
| `ActiveDirectory/Get-LocalNTLMlogs.ps1` | Lokale `Microsoft-Windows-NTLM/Operational`-Ereignisse analysieren und klassifizieren. | 1.0 | GNU General Public License v3 (GPLv3) | &ndash; |
| `ActiveDirectory/Get-NTLMLogons.ps1` | Sicherheitsprotokolle auf NTLM-Anmeldungen und Authentifizierungsnutzung auswerten. | 1.3 | GNU General Public License v3 (GPLv3) | &ndash; |
| `ActiveDirectory/Get-PKICertlist.ps1` | Zertifikate und Vorlagen aus dem AD CS-/PKI-Kontext auflisten. | k. A. | Nicht angegeben | &ndash; |
| `ActiveDirectory/Locate-46xx.ps1` | AD-Sperrungsereignisse (46xx-Sicherheitsereignisse) aufspüren. | 1.0 | Nicht angegeben | &ndash; |
| `ActiveDirectory/Locate-ADLockout.ps1` | Quellen von Benutzersperrungen in Active Directory finden. | 1.0 | Nicht angegeben | &ndash; |
| `ActiveDirectory/Repair-DFSR.ps1` | DFS-R-Replikation (inkl. SYSVOL) auf Domänencontrollern reparieren. | 0.1 | Nicht angegeben | &ndash; |
| `ActiveDirectory/Reset-DSRM.ps1` | DSRM-Kennwort auf einem Domänencontroller zurücksetzen. | 0.3 | GNU General Public License v3 (GPLv3) | &ndash; |
| `ActiveDirectory/execute-RemoteScriptWithLAPS.ps1` | Remote-Skripte mit lokalen Administratorkonten ausführen, die von Microsoft LAPS verwaltet werden. | 1.1 | Nicht angegeben | [DE](https://www.infrastrukturhelden.de/microsoft-infrastruktur/active-directory/powershell-skripte-mit-local-administrator-password-solution-laps-nutzen-und-auditieren/) |
| `ActiveDirectory/get-CVE20201472Events.ps1` | Domänencontroller auf Netlogon-Ereignisse zu CVE-2020-1472 (IDs 5827-5829) prüfen. | 1.0 | Nicht angegeben | [DE](https://www.infrastrukturhelden.de/?p=14850) |
| `ActiveDirectory/get-adinfo.ps1` | Zentrale Informationen zu AD-Forest und -Domäne sammeln und berichten. | 0.7 | GNU General Public License v3 (GPLv3) | &ndash; |
| `ActiveDirectory/install-AD.ps1` | Eine neue Active-Directory-Domäne installieren und initial einrichten. | 0.1 | Nicht angegeben | &ndash; |
| `ActiveDirectory/install-DC.ps1` | Einen zusätzlichen Domänencontroller installieren bzw. heraufstufen. | 0.1 | Nicht angegeben | &ndash; |
| `ActiveDirectory/move-FSMO.ps1` | FSMO-Rollen auf einen neuen Domänencontroller übertragen. | 0.1 | Nicht angegeben | &ndash; |
| `ActiveDirectory/set-BSI-TR-02102-2.ps1` | Kryptografische Windows-Einstellungen gemäß BSI TR-02102-2 konfigurieren (TLS-/Cipher-Härtung). | 0.3 | GNU General Public License v3 (GPLv3) | &ndash; |

### Azure

| Datei | Zweck | Version | Lizenz | Artikel |
|---|---|---|---|---|
| `Azure/Install-AzCopy.ps1` | Aktuelles AzCopy für den aktuellen Benutzer herunterladen und installieren. | 1.0 | Nicht angegeben | &ndash; |
| `Azure/Install-AzModule.ps1` | Azure-PowerShell-Module (`Az`) installieren bzw. aktualisieren. | k. A. | Nicht angegeben | &ndash; |

### BitLocker

| Datei | Zweck | Version | Lizenz | Artikel |
|---|---|---|---|---|
| `BitLocker/List-BitLockerrecoveryKeys.ps1` | In Active Directory gespeicherte BitLocker-Wiederherstellungsschlüssel auflisten. | k. A. | Nicht angegeben | &ndash; |
| `BitLocker/Start-Bitlocker.ps1` | BitLocker-Verschlüsselung mit vordefinierten Einstellungen starten (inkl. PIN-Abläufen). | k. A. | Nicht angegeben | &ndash; |
| `BitLocker/Update-BitLockerRecovery.ps1` | Fehlende BitLocker-Wiederherstellungsinformationen nach Active Directory hochladen. | 1.2 | Nicht angegeben | [DE](https://www.infrastrukturhelden.de/microsoft-infrastruktur/active-directory/bitlocker-wiederherstellungs-keys-nachtraglich-im-ad-sichern/) |

### Exchange

| Datei | Zweck | Version | Lizenz | Artikel |
|---|---|---|---|---|
| `Exchange/Set-MaintananceMode.ps1` | Einen Exchange-2013-DAG-Knoten in den Wartungsmodus versetzen. | 0.2 | Nicht angegeben | &ndash; |
| `Exchange/Set-Ex2013Vdir.ps1` | Virtuelle Verzeichnisse und URLs von Exchange 2013 konfigurieren. | 0.1 | Nicht angegeben | &ndash; |

### GPO

| Datei | Zweck | Version | Lizenz | Artikel |
|---|---|---|---|---|
| `GPO/Check-LocalGroupPolicy.ps1` | Probleme bei der Verarbeitung lokaler Gruppenrichtlinien anhand der Ereignisprotokolle erkennen und beheben. | 0.4 | MIT-Lizenz (MIT) | &ndash; |
| `GPO/get-GPOBackup.ps1` | GPO-Backups mit Zeitstempel inklusive HTML-Berichten erstellen. | 1.8 | MIT-Lizenz (MIT) | [DE](https://www.infrastrukturhelden.de/microsoft-infrastruktur/active-directory/gruppenrichtlinien-richtig-sichern-und-dokumentieren.html) |
| `GPO/get-GPOreport.ps1` | GPO-Verknüpfungen und Metadaten für die Dokumentation exportieren bzw. berichten. | k. A. | Nicht angegeben | &ndash; |
| `GPO/invoke-GPupdateDomain.ps1` | Remote-GPUpdate für Computer in einer OU (oder einem größeren Bereich) auslösen. | 1.1 | MIT-Lizenz (MIT) | &ndash; |

### Intune

| Datei | Zweck | Version | Lizenz | Artikel |
|---|---|---|---|---|
| `Intune/create-package.ps1` | `.intunewin`-Pakete aus Quellordnern erzeugen. | 1.0 | Nicht angegeben | &ndash; |
| `Intune/get-AutopilotLogs.ps1` | Protokolle und Diagnosedaten für das Autopilot-Pre-Provisioning sammeln. | 1.0.2 | MIT-Lizenz (MIT) | &ndash; |

### Linux-Files

| Datei | Zweck | Version | Lizenz | Artikel |
|---|---|---|---|---|
| `Linux-Files/allow_windowsupdate.squid` | Squid-ACL-Positivliste für Windows-Update-Endpunkte. | k. A. | Nicht angegeben | &ndash; |
| `Linux-Files/allow_psgallery.squid` | Squid-ACL-Positivliste für PowerShell-Gallery-/NuGet-Endpunkte. | k. A. | Nicht angegeben | &ndash; |
| `Linux-Files/allow_github.squid` | Squid-ACL-Positivliste für GitHub-Endpunkte. | k. A. | Nicht angegeben | &ndash; |
| `Linux-Files/allow_vscode.squid` | Squid-ACL-Positivliste für Visual-Studio-Code-Endpunkte. | k. A. | Nicht angegeben | &ndash; |

### Network

| Datei | Zweck | Version | Lizenz | Artikel |
|---|---|---|---|---|
| `Network/Check-Network.ps1` | Netzwerkverbindung und -konfiguration eines Clients prüfen. | 0.6 | MIT (LDAP-Testcode: MIT &copy; Evotec) | &ndash; |
| `Network/disable-NetBios.ps1` | NetBIOS über TCP/IP auf aktiven Adaptern deaktivieren. | k. A. | Nicht angegeben | &ndash; |

### User

| Datei | Zweck | Version | Lizenz | Artikel |
|---|---|---|---|---|
| `User/create-user.ps1` | AD-Benutzer anlegen (inklusive Microsoft-365-Onboarding). | 0.3 | MIT-Lizenz (MIT) | [DE](https://www.infrastrukturhelden.de/microsoft-infrastruktur/active-directory/benutzer-einfachen-anlegen-mit-powershell/) |
| `User/Get-LastLogonOU.ps1` | Letzte Anmeldung aller Benutzer einer OU auswerten (AD und Exchange). | 0.2 | MIT-Lizenz (MIT) | &ndash; |

### Windows

| Datei | Zweck | Version | Lizenz | Artikel |
|---|---|---|---|---|
| `Windows/set-cert4rdp.ps1` | Das RDP-Zertifikat einer bestimmten ausstellenden CA zuweisen. | 0.2 | MIT-Lizenz (MIT) | &ndash; |
| `Windows/Remove-AzureArc.ps1` | Azure-Arc-Agent und -Komponenten entfernen und bei Bedarf automatisch neu starten. | 1.1 | MIT-Lizenz (MIT) | &ndash; |

### WSUS

| Datei | Zweck | Version | Lizenz | Artikel |
|---|---|---|---|---|
| `WSUS/decline-WSUSUpdatesTypes.ps1` | Ausgewählte Updateklassifizierungen bzw. Produkte in WSUS ablehnen. | 1.8 | MIT-Lizenz (MIT) | [DE](https://www.infrastrukturhelden.de/microsoft-infrastruktur/wsus/windows-server-update-services-bereinigen.html) |
| `WSUS/Reset-WSUSClient.cmd` | WSUS-Client-Konfiguration und Erkennungsstatus zurücksetzen. | k. A. | Nicht angegeben | &ndash; |
| `WSUS/start-WsusServerSync.ps1` | WSUS-Synchronisierung starten (unterstützt rekursive Upstream-/Downstream-Server und E-Mail-Protokollierung). | k. A. | Nicht angegeben | &ndash; |
| `WSUS/Get-WsusHealth.ps1` | Umfassende WSUS-Health-Checks ausführen und Diagnoseausgaben erzeugen. | 1.3 | MIT (LDAP-Testcode: MIT &copy; Evotec) | [DE](https://www.infrastrukturhelden.de/microsoft-infrastruktur/wsus/wsus-fehleranalyse-und-health-checks-praxisleitfaden-mit-powershell/) |
<!-- END GENERATED: inventory -->

## GPO-Templates

Beispiel-Gruppenrichtlinien zu den Artikeln. Zu jedem Template gehören eine Markdown-Beschreibung und ein importierbares GPO-Backup (ZIP). Details und Lizenzbedingungen: [`GPO/Templates/readme.md`](./GPO/Templates/readme.md).

<!-- BEGIN GENERATED: gpo-templates -->
| Template | Zweck | GPO-Backup |
|---|---|---|
| [`GPO/Templates/Win11-24H2-IT-Grundschutz-Darksite.md`](./GPO/Templates/Win11-24H2-IT-Grundschutz-Darksite.md) | Windows 11 24H2 &ndash; IT-Grundschutz (Darksite / eingeschränkte Cloud-Kommunikation). | [ZIP](./GPO/Templates/Win11-24H2-IT-Grundschutz-Darksite.zip) |
| [`GPO/Templates/Win11-Disable-Copilot.md`](./GPO/Templates/Win11-Disable-Copilot.md) | Windows 11 &ndash; Microsoft Copilot und KI-Funktionen deaktivieren. | [ZIP](./GPO/Templates/Win11-Disable-Copilot.zip) |
| [`GPO/Templates/MSOffice-Deactivate-Copilot.md`](./GPO/Templates/MSOffice-Deactivate-Copilot.md) | Microsoft Office &ndash; Copilot und KI-Funktionen deaktivieren. | [ZIP](./GPO/Templates/MSOffice-Deactivate-Copilot.zip) |
| [`GPO/Templates/VisualStudio-Deactivate-Copilot.md`](./GPO/Templates/VisualStudio-Deactivate-Copilot.md) | Visual Studio &ndash; Copilot und KI-Funktionen deaktivieren. | [ZIP](./GPO/Templates/VisualStudio-Deactivate-Copilot.zip) |
<!-- END GENERATED: gpo-templates -->

## Zusätzliche Dateien

- `Intune/Readme.md` – Intune-spezifische Hinweise (auf Deutsch).
- `Dokumente/Zertifizierungsstellen mit Windows Server 2012R2.pdf` – Dokumentation zu Zertifizierungsstellen (PKI/CA) als PDF.
- `GPO/Templates/readme.md` – Übersicht und Lizenzbedingungen der GPO-Templates.

## Hinweise

- Einige Skripte sind ausgereift und versioniert.
- Andere sind schnelle operative Helfer für den Administrationsalltag.
- Skripte vor dem produktiven Einsatz immer in einer Testumgebung prüfen.
- Auf der Suche nach den [Life-Cycle-Diagrammen](https://github.com/FabianNiesen/InfrastrukturHelden-LifeCycle-diagrams)? Die liegen in einem separaten Repository.

[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/Z8Z8FB6VH)
