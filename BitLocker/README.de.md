# BitLocker Skripte

**Sprachversionen:** [English](README.md) | [Deutsch](README.de.md)

## Beschreibung

Dieses Verzeichnis enthält PowerShell-Skripte für die Verwaltung der BitLocker-Laufwerkverschlüsselung, einschließlich Backup von Wiederherstellungsschlüsseln, Einleitung der Verschlüsselung und Synchronisation von Active Directory-Wiederherstellungsinformationen.

## Description

This directory contains PowerShell scripts for BitLocker drive encryption management, including recovery key backup, encryption initiation, and Active Directory recovery information synchronization.

## Voraussetzungen

### Erforderliche Module
- BitLocker (in Windows integriert)

### Erforderliche Berechtigungen
- Lokaler Administrator auf Zielcomputern
- Domänenadministrator-Berechtigungen für AD-Wiederherstellungsschlüssel-Operationen

### Umgebungsvoraussetzungen
- Windows 7 oder höher mit BitLocker-Unterstützung
- Active Directory-Domänenumgebung (für AD-Backup)
- TPM-Chip auf Zielcomputern (für TPM-basierte Verschlüsselung)
- PowerShell 5.1

## Skripte

| Skript | Zweck | Version | Lizenz |
|--------|-------|---------|--------|
| [List-BitLockerrecoveryKeys.ps1](List-BitLockerrecoveryKeys.ps1) | Auflisten von BitLocker-Wiederherstellungsschlüsseln, die in Active Directory gespeichert sind. | n/a | Nicht angegeben |
| [Start-Bitlocker.ps1](Start-Bitlocker.ps1) | Starten der BitLocker-Verschlüsselung mit vordefinierten Einstellungen (einschließlich PIN-Workflows). | n/a | Nicht angegeben |
| [Update-BitLockerRecovery.ps1](Update-BitLockerRecovery.ps1) | Hochladen fehlender BitLocker-Wiederherstellungsinformationen in Active Directory. | 1.2 | MIT |

## Häufige Anwendungsfälle

- **Wiederherstellungsschlüssel-Management**: Auflisten und Dokumentieren von BitLocker-Wiederherstellungsschlüsseln, die in Active Directory gespeichert sind
- **Verschlüsselungs-Bereitstellung**: Aktivieren der BitLocker-Verschlüsselung mit TPM- und PIN-Schutz
- **Wiederherstellungsinformations-Backup**: Hochladen fehlender BitLocker-Wiederherstellungsinformationen in Active Directory für Compliance
- **Schlüsselwiederherstellung**: Abrufen von Wiederherstellungsschlüsseln aus Active Directory, wenn Benutzer ihre Kennwörter oder PINs vergessen haben

## Fehlerbehebung

### Häufige Probleme

**Problem**: Skript schlägt mit "TPM nicht verfügbar" fehl
- **Lösung**: Überprüfen Sie, ob der Computer über einen TPM-Chip verfügt und dieser im BIOS/UEFI aktiviert ist

**Problem**: Upload des Wiederherstellungsschlüssels in AD schlägt fehl
- **Lösung**: Stellen Sie sicher, dass der Computer domänenverbunden ist und Sie über Berechtigungen zum Schreiben auf das Computerobjekt in AD verfügen

**Problem**: Verschlüsselung schlägt mit "Unzureichender Festplattenspeicher" fehl
- **Lösung**: Stellen Sie sicher, dass mindestens 1,5 GB freier Speicherplatz auf dem Systemlaufwerk für BitLocker-Metadaten vorhanden ist

**Problem**: PIN-basierte Verschlüsselung nicht unterstützt
- **Lösung**: Überprüfen Sie, ob das System TPM 2.0 und Enhanced PINs unterstützt

## Sicherheitsüberlegungen

- Speichern Sie Wiederherstellungsschlüssel immer sicher in Active Directory
- Verwenden Sie starke PINs für TPM+PIN-Schutz
- Dokumentieren Sie Wiederherstellungsverfahren für verlorene Schlüssel/vergessene PINs
- Überwachen Sie regelmäßig den Zugriff auf Wiederherstellungsschlüssel in Active Directory
- Stellen Sie sicher, dass BitLocker-Wiederherstellungsinformationen vor Systemänderungen gesichert sind

## Autor

Fabian Niesen

## Lizenz

Skripte haben verschiedene Lizenzen wie in der Tabelle oben angegeben. Die meisten sind MIT-lizenziert. Überprüfen Sie immer den Skript-Header für spezifische Lizenzinformationen.
