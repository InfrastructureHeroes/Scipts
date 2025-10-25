# KI-Agent Anweisungen für Infra-Scripts

Dieses Repository enthält eine Sammlung von PowerShell-Skripten für die Windows-Infrastrukturverwaltung. Hier sind die wichtigsten Informationen für KI-Agenten:

## Projektstruktur

- Skripte sind nach Funktionsbereichen in Ordnern organisiert (z.B. `ActiveDirectory/`, `BitLocker/`, `WSUS/`)
- Jeder Ordner enthält spezialisierte Skripte für den jeweiligen Bereich
- Hauptverzeichnis enthält allgemeine Verwaltungsskripte

## Konventionen

### Skript-Reife
- Skripte mit Versionierung im Header sind ausgereifter und besser getestet
- Beispiel aus `GPO/get-GPOBackup.ps1`: Version wird als "V1.58" im Header angegeben

### Namenskonventionen
- Verb-Substantiv Benennungsschema (PowerShell-Standard)
- Präfixe zeigen Hauptfunktion:
  - `get-` für Abfragen
  - `set-` für Konfigurationen
  - `install-` für Installationen
  - `update-` für Aktualisierungen

### Fehlerbehandlung
- PowerShell ErrorAction und Try-Catch Blöcke werden verwendet
- Kritische Operationen haben Sicherheitsabfragen

## Hauptkomponenten

### Active Directory Management
- Primäre Skripte in `ActiveDirectory/`
- Kernfunktionen: DC-Installation, LAPS-Management, AD-Berechtigungen
- Integration mit Windows-Ereignisprotokollen

### BitLocker Verwaltung
- Zentrale Funktionen in `BitLocker/`
- Fokus auf Wiederherstellungsschlüssel-Management und AD-Integration

### Gruppenrichtlinien (GPO)
- Backup und Reporting in `GPO/`
- Domänenweite Aktualisierungen
- HTML-Berichterstellung für Dokumentation

### Benutzerverwaltung
- Integration mit Microsoft 365
- Automatisierte Benutzerbereitstellung
- Audit und Reporting-Funktionen

## Entwicklungs-Workflow

### Testing
- Skripte sollten in einer Testumgebung validiert werden
- Parameter `-WhatIf` und `-Confirm` für sensitive Operationen verwenden

### Best Practices
- Dokumentiere Änderungen im Skript-Header
- Füge Kommentare für komplexe Operationen hinzu
- Verwende standardisierte PowerShell-Parameter

## Wichtige Hinweise

- Alle Skripte sind "Verwendung auf eigene Gefahr"
- Einige Exchange-Skripte werden nicht mehr aktiv gepflegt
- Bei Microsoft 365-Integration müssen entsprechende Berechtigungen vorhanden sein

## Beispiele

### GPO-Backup erstellen:
```powershell
# Erstellt Backup und HTML-Report in timestamp-basiertem Unterordner
.\get-GPOBackup.ps1
```

### BitLocker-Wiederherstellungsschlüssel aktualisieren:
```powershell
# Lädt fehlende BitLocker-Informationen ins AD hoch
.\Update-BitLockerRecovery.ps1
```