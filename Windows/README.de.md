# Windows-Skripte

**Sprachversionen:** [English](README.md) | [Deutsch](README.de.md)

## Beschreibung

Dieses Verzeichnis enthält PowerShell-Skripte für Windows-Systemmanagement, einschließlich Entfernung des Azure Arc-Agents und RDP-Zertifikatskonfiguration.

## Description

This directory contains PowerShell scripts for Windows system management, including Azure Arc agent removal and RDP certificate configuration.

## Voraussetzungen

### Erforderliche Module
- Keine (verwendet integrierte PowerShell-Cmdlets)

### Erforderliche Berechtigungen
- Lokaler Administrator für Systemebenen-Änderungen
- Domänenadministrator für Zertifikatoperationen (bei Verwendung von AD CS)

### Umgebungsvoraussetzungen
- Windows 10 oder höher / Windows Server 2016 oder höher
- PowerShell 5.1
- Administratorrechte

## Skripte

| Skript | Zweck | Version | Lizenz |
|--------|-------|---------|--------|
| [Remove-AzureArc.ps1](Remove-AzureArc.ps1) | Entfernen des Azure Arc-Agents/Komponenten und automatischer Neustart falls erforderlich. | 1.1 | MIT |
| [set-cert4rdp.ps1](set-cert4rdp.ps1) | Binden/Setzen des RDP-Zertifikats von einer spezifischen ausstellenden CA. | 0.2 | MIT |

## Häufige Anwendungsfälle

- **Azure Arc-Entfernung**: Entfernen des Azure Arc-Agents von Windows-Servern, wenn er nicht mehr benötigt wird
- **RDP-Zertifikats-Management**: Konfigurieren von RDP für die Verwendung von Zertifikaten einer spezifischen ausstellenden CA für sichere Remotedesktopverbindungen
- **Systembereinigung**: Entfernen unerwünschter Azure-Management-Komponenten
- **Security-Härtung**: Verwenden von PKI-basierten Zertifikaten für RDP anstelle von selbstsignierten Zertifikaten

## Fehlerbehebung

### Häufige Probleme

**Problem**: Azure Arc-Entfernung schlägt mit "Dienst nicht gefunden" fehl
- **Lösung**: Überprüfen Sie, ob der Azure Arc-Agent tatsächlich auf dem System installiert ist

**Problem**: Skript meldet Neustart erforderlich, startet aber nicht neu
- **Lösung**: Das Skript erfordert möglicherweise einen manuellen Neustart, wenn der automatische Neustart durch Richtlinien deaktiviert ist

**Problem**: RDP-Zertifikat-Skript schlägt mit "CA nicht gefunden" fehl
- **Lösung**: Überprüfen Sie, ob die ausstellende CA zugänglich ist und Sie über Berechtigungen zum Anfordern von Zertifikaten verfügen

**Problem**: RDP-Zertifikat wird nach Skriptausführung nicht angewendet
- **Lösung**: Starten Sie den Remotedesktopdienste neu: `Restart-Service TermService`

## Wichtige Hinweise

- Das Skript Remove-AzureArc.ps1 startet das System automatisch neu, falls erforderlich
- Planen Sie die Azure Arc-Entfernung immer während Wartungsfenstern
- Testen Sie die RDP-Zertifikatskonfiguration zuerst in einer Nicht-Produktionsumgebung
- Stellen Sie sicher, dass vor Systemebenen-Änderungen ein ordnungsgemäßes Backup erstellt wurde

## Autor

Fabian Niesen

## Lizenz

Skripte sind unter MIT-Lizenz lizenziert. Überprüfen Sie immer den Skript-Header für spezifische Lizenzinformationen.
