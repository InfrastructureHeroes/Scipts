# Azure Skripte

**Sprachversionen:** [English](README.md) | [Deutsch](README.de.md)

## Beschreibung

Dieses Verzeichnis enthält PowerShell-Skripte für die Einrichtung und Verwaltung von Azure-Tools, einschließlich AzCopy-Installation und Azure PowerShell-Modul-Management.

## Description

This directory contains PowerShell scripts for Azure tooling setup and management, including AzCopy installation and Azure PowerShell module management.

## Voraussetzungen

### Erforderliche Module
- Keine (Skripte installieren erforderliche Tools)

### Erforderliche Berechtigungen
- Lokaler Administrator für systemweite Installationen
- Internetzugang für den Download von Azure-Tools

### Umgebungsvoraussetzungen
- Windows 10 oder höher
- PowerShell 5.1
- Internetkonnektivität für den Download von Tools von Microsoft

## Skripte

| Skript | Zweck | Version | Lizenz |
|--------|-------|---------|--------|
| [Install-AzCopy.ps1](Install-AzCopy.ps1) | Herunterladen und Installieren der neuesten AzCopy für den aktuellen Benutzer. | 1.0 | Nicht angegeben |
| [Install-AzModule.ps1](Install-AzModule.ps1) | Installieren/Aktualisieren von Azure PowerShell-Modulen (`Az`). | n/a | Nicht angegeben |

## Häufige Anwendungsfälle

- **AzCopy-Installation**: Schnelles Installieren des neuesten AzCopy-Tools für Azure-Speicheroperationen
- **Azure PowerShell-Setup**: Installieren oder Aktualisieren von Azure PowerShell-Modulen für Azure-Verwaltung
- **Tool-Management**: Halten von Azure-Tools auf dem neuesten Stand

## Fehlerbehebung

### Häufige Probleme

**Problem**: AzCopy-Download schlägt mit "Zugriff verweigert" fehl
- **Lösung**: Stellen Sie sicher, dass Sie Schreibberechtigungen für den Zielordner und Internetzugang zu aka.ms haben

**Problem**: AzModule-Installation schlägt mit "Repository nicht gefunden" fehl
- **Lösung**: Stellen Sie sicher, dass der PowerShell Gallery zugänglich ist und nicht durch Netzwerkrichtlinien blockiert wird

**Problem**: Pfad wird nach Installation nicht aktualisiert
- **Lösung**: Starten Sie PowerShell neu oder melden Sie sich ab/an, damit die Änderungen der Umgebungsvariablen wirksam werden

## Autor

Fabian Niesen

## Lizenz

Skripte haben verschiedene Lizenzen wie in der Tabelle oben angegeben. Überprüfen Sie immer den Skript-Header für spezifische Lizenzinformationen.
