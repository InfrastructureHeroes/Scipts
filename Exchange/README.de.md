# Exchange Skripte

**Sprachversionen:** [English](README.md) | [Deutsch](README.de.md)

## Beschreibung

Dieses Verzeichnis enthält PowerShell-Skripte für die Microsoft Exchange Server-Verwaltung, einschließlich Wartungsmodus-Management für Database Availability Groups (DAG) und Konfiguration virtueller Verzeichnisse.

## Description

This directory contains PowerShell scripts for Microsoft Exchange Server administration, including maintenance mode management for Database Availability Groups (DAG) and virtual directory configuration.

## Voraussetzungen

### Erforderliche Module
- Exchange Management PowerShell-Module (Exchange 2013 oder höher)

### Erforderliche Berechtigungen
- Exchange-Organisationsadministrator
- Lokaler Administrator auf Exchange-Servern

### Umgebungsvoraussetzungen
- Exchange Server 2013 oder höher
- PowerShell 5.1
- Exchange Management Shell oder Remote-PowerShell-Sitzung

## Skripte

| Skript | Zweck | Version | Lizenz |
|--------|-------|---------|--------|
| [Set-MaintananceMode.ps1](Set-MaintananceMode.ps1) | Setzen eines Exchange 2013 DAG-Knotens in den Wartungsmodus. | 0.2 | Nicht angegeben |
| [Set-Ex2013Vdir.ps1](Set-Ex2013Vdir.ps1) | Konfigurieren von Exchange 2013 virtuellen Verzeichnissen/URLs. | 0.1 | Nicht angegeben |

## Häufige Anwendungsfälle

- **DAG-Wartung**: Setzen von Exchange DAG-Knotens in den Wartungsmodus für Patching oder Upgrades
- **Konfiguration virtueller Verzeichnisse**: Konfigurieren von Exchange 2013 virtuellen Verzeichnissen für OWA, ECP, Autodiscover, etc.
- **Server-Wartung**: Sicheres Verschieben aktiver Datenbanken vor Wartungsfenstern

## Fehlerbehebung

### Häufige Probleme

**Problem**: Wartungsmodus-Skript schlägt mit "DAG nicht gefunden" fehl
- **Lösung**: Stellen Sie sicher, dass die Exchange Management Shell geladen ist und Sie über die entsprechenden Berechtigungen verfügen

**Problem**: Konfiguration virtueller Verzeichnisse wird nicht wirksam
- **Lösung**: Starten Sie IIS-Dienste nach Konfigurationsänderungen neu: `iisreset`

**Problem**: Datenbankverschiebung schlägt während des Wartungsmodus fehl
- **Lösung**: Überprüfen Sie, ob der Zielserver über ausreichende Ressourcen verfügt und nicht bereits im Wartungsmodus ist

## Wichtige Hinweise

- Diese Skripte sind für Exchange 2013 konzipiert. Für neuere Exchange-Versionen (2016, 2019, 2023) überprüfen Sie vor der Verwendung die Kompatibilität
- Testen Sie Wartungsmodus-Verfahren immer zuerst in einer Nicht-Produktionsumgebung
- Stellen Sie sicher, dass vor Wartungsoperationen ein ordnungsgemäßes Backup erstellt wurde

## Autor

Fabian Niesen

## Lizenz

Skripte haben verschiedene Lizenzen wie in der Tabelle oben angegeben. Überprüfen Sie immer den Skript-Header für spezifische Lizenzinformationen.
