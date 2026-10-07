# Microsoft Intune Skripte

**Sprachversionen:** [English](README.md) | [Deutsch](README.de.md)

## Beschreibung

Dieses Verzeichnis enthält PowerShell-Skripte für die Microsoft Intune-Verwaltung, einschließlich Autopilot-Fehlerbehebung und Erstellung von Win32-App-Paketen.

## Description

This directory contains PowerShell scripts for Microsoft Intune administration, including Autopilot troubleshooting and Win32 app package creation.

## Voraussetzungen

### Erforderliche Module
- Intune PowerShell-Module (optional, hängt von der Skriptverwendung ab)

### Erforderliche Berechtigungen
- Intune-Administrator-Berechtigungen für Paketbereitstellung
- Lokaler Administrator für Protokollsammlung

### Umgebungsvoraussetzungen
- Windows 10 oder höher
- PowerShell 5.1
- Intune Win32-App-Packaging-Tool (IntuneWinAppUtil.exe) für Paketerstellung

## Skripte

| Skript | Zweck | Version | Lizenz |
|--------|-------|---------|--------|
| [create-package.ps1](create-package.ps1) | Erstellen von `.intunewin`-Paketen aus Quellordnern. | 1.0 | Nicht angegeben |
| [get-AutopilotLogs.ps1](get-AutopilotLogs.ps1) | Sammeln von Protokollen und Diagnosen für Autopilot-Pre-Provisioning. | 1.0.2 | Nicht angegeben |

## Häufige Anwendungsfälle

- **Autopilot-Fehlerbehebung**: Sammeln von Diagnoseprotokollen, wenn das Autopilot-Pre-Provisioning fehlschlägt
- **App-Paketierung**: Erstellen von Win32-App-Paketen (.intunewin) für Intune-Bereitstellung
- **Protokollanalyse**: Sammeln von Systemprotokollen für Autopilot-Registrierungsprobleme

## Fehlerbehebung

### Häufige Probleme

**Problem**: Paketerstellung schlägt mit "IntuneWinAppUtil.exe nicht gefunden" fehl
- **Lösung**: Laden Sie das Intune Win32-App-Packaging-Tool von Microsoft herunter und platzieren Sie es im Skriptverzeichnis oder im PATH

**Problem**: Autopilot-Protokoll-Skript gibt keine Daten zurück
- **Lösung**: Stellen Sie sicher, dass das Skript auf einem Gerät ausgeführt wird, das versucht hat, sich bei Autopilot zu registrieren

**Problem**: Paketgröße überschreitet Intune-Grenzen
- **Lösung**: Komprimieren Sie Quelldateien oder teilen Sie sie in mehrere Pakete auf

## Zusätzliche Ressourcen

Für eine umfassendere Intune-App-Management-Lösung siehe: https://github.com/InfrastructureHeroes/Intune-Apps

## Autor

Fabian Niesen

## Lizenz

Skripte haben verschiedene Lizenzen wie in der Tabelle oben angegeben. Überprüfen Sie immer den Skript-Header für spezifische Lizenzinformationen.
