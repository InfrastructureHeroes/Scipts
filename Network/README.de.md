# Netzwerk-Skripte

**Sprachversionen:** [English](README.md) | [Deutsch](README.de.md)

## Beschreibung

Dieses Verzeichnis enthält PowerShell-Skripte für Netzwerkdiagnose und Client-Konfiguration, einschließlich Konnektivitätsvalidierung, MTU-Tests, LDAP-Prüfungen und NetBIOS über TCP/IP-Management.

## Description

This directory contains PowerShell scripts for network diagnostics and client configuration, including connectivity validation, MTU testing, LDAP checks, and NetBIOS over TCP/IP management.

## Voraussetzungen

### Erforderliche Module
- Keine (verwendet integrierte PowerShell-Cmdlets)

### Erforderliche Berechtigungen
- Lokaler Administrator für Änderungen an der Netzwerkadapterkonfiguration
- Netzwerkkonnektivität für Remote-Prüfungen

### Umgebungsvoraussetzungen
- Windows 7 oder höher
- PowerShell 5.1
- Konfigurierte Netzwerkadapter

## Skripte

| Skript | Zweck | Version | Lizenz |
|--------|-------|---------|--------|
| [Check-Network.ps1](Check-Network.ps1) | Validieren der Client-Netzwerkkonnektivität und -konfiguration. | 0.6 | Evotec MIT License |
| [disable-NetBios.ps1](disable-NetBios.ps1) | Deaktivieren von NetBIOS über TCP/IP auf aktiven Adaptern. | n/a | Nicht angegeben |

## Häufige Anwendungsfälle

- **Netzwerkdiagnose**: Validieren der Netzwerkkonnektivität, MTU-Einstellungen und DNS-Konfiguration
- **LDAP-Tests**: Testen der LDAP/LDAPS-Konnektivität zu Domänencontrollern
- **Security-Härtung**: Deaktivieren von NetBIOS über TCP/IP zur Reduzierung der Angriffsfläche
- **Fehlerbehebung**: Identifizieren von Netzwerkkonfigurationsproblemen auf Client-Maschinen

## Fehlerbehebung

### Häufige Probleme

**Problem**: Netzwerkprüfung schlägt mit "Keine Netzwerkadapter gefunden" fehl
- **Lösung**: Stellen Sie sicher, dass der Computer über mindestens einen aktiven Netzwerkadapter verfügt

**Problem**: LDAP-Test schlägt mit "Verbindung nicht möglich" fehl
- **Lösung**: Überprüfen Sie, ob der Domänencontroller erreichbar ist und die Firewall LDAP/LDAPS-Traffic zulässt

**Problem**: NetBIOS-Deaktivierungsskript schlägt mit "Zugriff verweigert" fehl
- **Lösung**: Führen Sie das Skript mit Administratorrechten aus

**Problem**: MTU-Test zeigt Paketverlust
- **Lösung**: Passen Sie die MTU-Größe an oder überprüfen Sie MTU-Begrenzungen der Netzwerkausrüstung

## Sicherheitsüberlegungen

- Das Deaktivieren von NetBIOS über TCP/IP wird aus Sicherheitsgründen empfohlen, kann aber Legacy-Anwendungen beeinträchtigen
- Testen Sie Netzwerkänderungen immer in einer kontrollierten Umgebung vor der Produktionsbereitstellung
- LDAP-Tests können vertrauliche Verzeichnisinformationen offenlegen - verwenden Sie sie mit Vorsicht

## Autor

Fabian Niesen

## Lizenz

Skripte haben verschiedene Lizenzen wie in der Tabelle oben angegeben. Das Skript Check-Network.ps1 enthält von Evotec unter MIT-Lizenz lizenzierten LDAP-Testcode. Überprüfen Sie immer den Skript-Header für spezifische Lizenzinformationen.
