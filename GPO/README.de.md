# Group Policy (GPO) Skripte

**Sprachversionen:** [English](README.md) | [Deutsch](README.de.md)

## Beschreibung

Dieses Verzeichnis enthält PowerShell-Skripte für die Verwaltung von Gruppenrichtlinienobjekten (GPO), einschließlich Backup-Automatisierung, Berichterstellung, Fehlerbehebung bei lokalen GPOs und Remote-GPUpdate-Operationen. Enthält auch GPO-Vorlagen für Security-Härtung und Copilot-Deaktivierung.

## Description

This directory contains PowerShell scripts for Group Policy Object (GPO) management, including backup automation, reporting, local GPO troubleshooting, and remote GPUpdate operations. Also includes GPO templates for security hardening and Copilot deactivation.

## Voraussetzungen

### Erforderliche Module
- GroupPolicy (für GPO-Backup- und Berichtsskripte)

### Erforderliche Berechtigungen
- Domänenadministrator oder gleichwertig für GPO-Backup und Berichterstellung
- Lokaler Administrator für Fehlerbehebung bei lokalen GPOs
- Remote-Administrationsberechtigungen für GPUpdate-Operationen

### Umgebungsvoraussetzungen
- Windows Server 2012 R2 oder höher
- Active Directory-Domänenumgebung
- WinRM aktiviert für Remote-GPUpdate-Operationen
- PowerShell 5.1

## Skripte

| Skript | Zweck | Version | Lizenz |
|--------|-------|---------|--------|
| [Check-LocalGroupPolicy.ps1](Check-LocalGroupPolicy.ps1) | Erkennen und Beheben von Problemen bei der lokalen Gruppenrichtlinienverarbeitung basierend auf Ereignisprotokollen. | 0.4 | MIT |
| [get-GPOBackup.ps1](get-GPOBackup.ps1) | Erstellen von zeitgestempelten GPO-Backups einschließlich HTML-Berichten. | 1.8 | MIT |
| [get-GPOreport.ps1](get-GPOreport.ps1) | Export/Bericht von GPO-Links und Metadaten für Dokumentation. | n/a | Nicht angegeben |
| [invoke-GPupdateDomain.ps1](invoke-GPupdateDomain.ps1) | Auslösen von Remote-GPUpdate für Computer in einer OU (oder größerem Bereich). | 1.1 | MIT |

## GPO-Vorlagen

Das Unterverzeichnis `Templates/` enthält GPO-Konfigurationsvorlagen für:

- **Windows 11 24H2 – IT-Grundschutz (Darksite)**: Eingeschränkte Cloud-Kommunikation und BSI IT-Grundschutz-Konformität
- **Windows 11 – Copilot deaktivieren**: Deaktivieren von Microsoft Copilot
- **Microsoft Office – Copilot deaktivieren**: Deaktivieren von Copilot in Office-Anwendungen
- **Visual Studio – Copilot deaktivieren**: Deaktivieren von Copilot in Visual Studio

Siehe [Templates/README.md](Templates/README.md) für detaillierte Vorlagendokumentation.

## Referenzdokumentation

- **Client-Side Extension GUID-Liste**: [Client_Side_Extension-GUID_List.md](Client_Side_Extension-GUID_List.md) - Umfassende Liste der GPO Client-Side Extension GUIDs für Fehlerbehebung und Diagnose

## Häufige Anwendungsfälle

- **GPO-Backup-Automatisierung**: Planen Sie regelmäßige GPO-Backups mit HTML-Berichten und Versionsverfolgung
- **GPO-Dokumentation**: Exportieren Sie GPO-Links, Einstellungen und Metadaten für Compliance-Dokumentation
- **Fehlerbehebung bei lokalen GPOs**: Erkennen und Beheben Sie fehlerhafte lokale GPOs, die die Richtlinienverarbeitung verhindern
- **Remote-Richtlinienupdates**: Erzwingen Sie GPUpdate auf mehreren Computern über OUs hinweg
- **Security-Härtung**: Wenden Sie BSI IT-Grundschutz-konforme GPO-Konfigurationen an
- **Copilot-Management**: Deaktivieren Sie Copilot unter Windows 11, Office und Visual Studio

## Fehlerbehebung

### Häufige Probleme

**Problem**: GPO-Backup-Skript schlägt mit "Zugriff verweigert" fehl
- **Lösung**: Stellen Sie sicher, dass Sie über Domänenadministrator-Rechte und Schreibzugriff auf den Backup-Pfad verfügen

**Problem**: GPUpdate schlägt auf Remote-Computern fehl
- **Lösung**: Überprüfen Sie, ob WinRM auf Zielcomputern aktiviert ist: `Enable-PSRemoting -Force`

**Problem**: Lokales GPO-Skript meldet "Keine Probleme gefunden", aber Richtlinien werden nicht angewendet
- **Lösung**: Überprüfen Sie auf andere GPO-Verarbeitungsprobleme in den Anwendungs- und Systemereignisprotokollen

**Problem**: GPO-Vorlagen werden nicht korrekt importiert
- **Lösung**: Stellen Sie sicher, dass Sie über GPO-Bearbeitungsberechtigungen verfügen und der GPO Central Store ordnungsgemäß konfiguriert ist

## Autor

Fabian Niesen

## Lizenz

Skripte haben verschiedene Lizenzen wie in der Tabelle oben angegeben. Die meisten sind MIT-lizenziert. GPO-Vorlagen sind unter GPLv3 lizenziert. Überprüfen Sie immer den Skript-Header für spezifische Lizenzinformationen.
