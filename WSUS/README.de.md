# WSUS Skripte

**Sprachversionen:** [English](README.md) | [Deutsch](README.de.md)

## Beschreibung

Dieses Verzeichnis enthält PowerShell-Skripte für die Verwaltung von Windows Server Update Services (WSUS), einschließlich Integritätsprüfungen, Update-Management, Synchronisationsautomatisierung und Client-Fehlerbehebung.

## Description

This directory contains PowerShell scripts for Windows Server Update Services (WSUS) administration, including health checks, update management, synchronization automation, and client troubleshooting.

## Voraussetzungen

### Erforderliche Module
- UpdateServices (für WSUS-Integritätsprüfungen und -Management)

### Erforderliche Berechtigungen
- WSUS-Administrator-Berechtigungen
- Lokaler Administrator auf WSUS-Server
- SMTP-Server-Zugriff für E-Mail-Benachrichtigungen (falls konfiguriert)

### Umgebungsvoraussetzungen
- Windows Server 2012 R2 oder höher mit installierter WSUS-Rolle
- WSUS-Konsole oder PowerShell-Modul installiert
- PowerShell 5.1

## Skripte

| Skript | Zweck | Version | Lizenz |
|--------|-------|---------|--------|
| [Get-WsusHealth.ps1](Get-WsusHealth.ps1) | Ausführen umfassender WSUS-Integritätsprüfungen und Generierung von Diagnoseausgaben. | 1.3 | Evotec MIT License |
| [decline-WSUSUpdatesTypes.ps1](decline-WSUSUpdatesTypes.ps1) | Ablehnen ausgewählter Update-Klassifikationen/Produkte in WSUS. | 1.8 | MIT |
| [start-WsusServerSync.ps1](start-WsusServerSync.ps1) | Starten der WSUS-Synchronisation (unterstützt rekursive Upstream/Downstream- und E-Mail-Protokollierung). | n/a | Nicht angegeben |

## Zusätzliche Dateien

- **Reset-WSUSClient.cmd**: Batch-Skript zum Zurücksetzen der WSUS-Client-Konfiguration und des Erkennungsstatus

## Häufige Anwendungsfälle

- **WSUS-Integritätsüberwachung**: Durchführen umfassender Integritätsprüfungen einschließlich Dienststatus, Datenbankkonnektivität, Festplattenspeicher und Synchronisationsstatus
- **Update-Bereinigung**: Ablehnen unnötiger Update-Typen (Beta, Vorschau, Itanium, Treiber, Ersetzte) zur Reduzierung der Datenbankgröße
- **Synchronisationsautomatisierung**: Auslösen der WSUS-Synchronisation mit E-Mail-Benachrichtigungen für Upstream/Downstream-Server
- **Client-Fehlerbehebung**: Zurücksetzen der WSUS-Client-Konfiguration, wenn Clients Updates nicht erhalten
- **Datenbank-Wartung**: Regelmäßige Bereinigung abgelehnter und ersetzter Updates zur Verbesserung der WSUS-Leistung

## Fehlerbehebung

### Häufige Probleme

**Problem**: WSUS-Integritätsprüfung schlägt mit "Verbindung zur WSUS-API nicht möglich" fehl
- **Lösung**: Überprüfen Sie, ob die WSUS-Dienste ausgeführt werden und die WSUS-Verwaltungskonsole eine Verbindung herstellen kann

**Problem**: Update-Ablehnungs-Skript findet keine Updates
- **Lösung**: Stellen Sie sicher, dass der WSUS-Server kürzlich mit Microsoft Update synchronisiert wurde

**Problem**: Synchronisationsskript schlägt mit Authentifizierungsfehler fehl
- **Lösung**: Überprüfen Sie, ob der WSUS-Server ordnungsgemäße Anmeldeinformationen für die Upstream-Synchronisation konfiguriert hat

**Problem**: Client-Reset-Skript löst Update-Probleme nicht
- **Lösung**: Überprüfen Sie, ob der Client den WSUS-Server erreichen kann und ob der Windows Update-Dienst ausgeführt wird

## Autor

Fabian Niesen

## Lizenz

Skripte haben verschiedene Lizenzen wie in der Tabelle oben angegeben. Die meisten sind MIT-lizenziert. Das Skript Get-WsusHealth.ps1 enthält von Evotec unter MIT-Lizenz lizenzierten Code. Überprüfen Sie immer den Skript-Header für spezifische Lizenzinformationen.
