# Active Directory Skripte

**Sprachversionen:** [English](README.md) | [Deutsch](README.de.md)

## Beschreibung

Dieses Verzeichnis enthält PowerShell-Skripte für die Active Directory-Verwaltung, einschließlich Domänencontroller-Management, DFS-Replikationsüberwachung, Berechtigungsberichte, Sicherheitsaudits und Benutzerlebenszyklus-Automatisierung.

## Description

This directory contains PowerShell scripts for Active Directory administration, including domain controller management, DFS replication monitoring, permission reporting, security auditing, and user lifecycle automation.

## Voraussetzungen

### Erforderliche Module
- ActiveDirectory
- DFSR (für DFS-Replikations-Skripte)

### Erforderliche Berechtigungen
- Domänenadministrator oder gleichwertig für die meisten Operationen
- Lokaler Administrator auf Zielservern für Remote-Operationen
- Enterprise-Administrator für Forest-Level-Operationen

### Umgebungsvoraussetzungen
- Windows Server 2012 R2 oder höher
- Active Directory-Domänenumgebung
- WinRM aktiviert für Remote-Operationen
- PowerShell 5.1

## Skripte

| Skript | Zweck | Version | Lizenz |
|--------|-------|---------|--------|
| [Configure-AD.ps1](Configure-AD.ps1) | Konfigurieren einer AD-Domäne (z.B. Papierkorb, gMSA-Vorbereitung, Central Store, Kennwortrichtlinien, OU-Struktur). | 0.2 | Nicht angegeben |
| [Get-ADPermissionsReport.ps1](Get-ADPermissionsReport.ps1) | CSV-Exportbericht über Active Directory-Berechtigungen. | 0.2 | Nicht angegeben |
| [Get-DFSRBacklog.ps1](Get-DFSRBacklog.ps1) | Überprüft den DFSR-Backlog und generiert Replikationsberichte für DFS-Replikationsgruppen. | 0.5 | GPLv3 |
| [Get-LAPSAuditReport.ps1](Get-LAPSAuditReport.ps1) | Abfrage von Sicherheitsereignissen für Microsoft LAPS-bezogene Audit-Aktivitäten. | n/a | Nicht angegeben |
| [Get-LocalNTLMlogs.ps1](Get-LocalNTLMlogs.ps1) | Analyse lokaler `Microsoft-Windows-NTLM/Operational`-Ereignisse mit Klassifizierung. | 1.0 | GPLv3 |
| [Get-Logons.ps1](Get-Logons.ps1) | Abfrage von Windows-Sicherheitsereignisprotokollen für erfolgreiche und fehlgeschlagene Anmeldeereignisse. | n/a | Nicht angegeben |
| [Get-NTLMLogons.ps1](Get-NTLMLogons.ps1) | Analyse von Sicherheitsprotokollen für NTLM-Anmeldungen und Authentifizierungsverwendung. | 1.3 | GPLv3 |
| [Get-PKICertlist.ps1](Get-PKICertlist.ps1) | Auflisten von Zertifikaten/Vorlagen aus AD CS / PKI-Kontext. | n/a | Nicht angegeben |
| [Locate-46xx.ps1](Locate-46xx.ps1) | Lokalisieren von AD-Sperrungsereignissen (46xx-Sicherheitsereignisse). | 1.0 | Nicht angegeben |
| [Locate-ADLockout.ps1](Locate-ADLockout.ps1) | Lokalisieren von Benutzer-Sperrungsquellen in Active Directory. | 1.0 | Nicht angegeben |
| [Repair-DFSR.ps1](Repair-DFSR.ps1) | Reparatur der DFS-R-Replikation (einschließlich SYSVOL) auf Domänencontrollern. | 0.1 | Nicht angegeben |
| [Reset-DSRM.ps1](Reset-DSRM.ps1) | Zurücksetzen des DSRM-Kennworts auf einem Domänencontroller. | 0.3 | GPLv3 |
| [execute-RemoteScriptWithLAPS.ps1](execute-RemoteScriptWithLAPS.ps1) | Ausführen von Remote-Skripten mit lokalen Administrator-Anmeldeinformationen, die von Microsoft LAPS verwaltet werden. | 1.1 | Nicht angegeben |
| [get-CVE20201472Events.ps1](get-CVE20201472Events.ps1) | Überprüfung von Domänencontrollern auf Netlogon CVE-2020-1472-bezogene Ereignis-IDs (5827-5829). | 1.0 | Nicht angegeben |
| [get-adinfo.ps1](get-adinfo.ps1) | Sammeln von Kern-AD-Forest/Domänen-Informationen und Berichtsdetails. | 0.5 | Nicht angegeben |
| [install-AD.ps1](install-AD.ps1) | Installation und Bootstrap einer neuen Active Directory-Domäne. | 0.1 | Nicht angegeben |
| [install-DC.ps1](install-DC.ps1) | Installation/Promotion eines zusätzlichen Domänencontrollers. | 0.1 | Nicht angegeben |
| [move-FSMO.ps1](move-FSMO.ps1) | Verschieben von FSMO-Rollen auf einen neuen Domänencontroller. | 0.1 | Nicht angegeben |
| [set-BSI-TR-02102-2.ps1](set-BSI-TR-02102-2.ps1) | Konfiguration von Windows-kryptografischen Einstellungen gemäß BSI TR-02102-2 (TLS/Cipher-Hardening). | 0.2 | GPLv3 |

## Häufige Anwendungsfälle

- **Domänencontroller-Management**: Installation neuer Domänen, Promotion zusätzlicher DCs, Verschieben von FSMO-Rollen
- **Replikationsüberwachung**: Überprüfung des DFSR-Backlogs, Reparatur von Replikationsproblemen, Generierung von Propagationsberichten
- **Sicherheitsaudits**: Überwachung von Anmeldeereignissen, Nachverfolgung der NTLM-Nutzung, Audit von LAPS-Aktivitäten
- **Berechtigungsanalyse**: Export und Überprüfung von AD-Berechtigungen im gesamten Verzeichnis
- **Benutzer-Fehlerbehebung**: Lokalisieren von Sperrungsquellen, Nachverfolgung von Benutzeraktivitäten
- **PKI-Management**: Auflisten von Zertifikaten und Vorlagen aus AD CS
- **Härtung**: Anwendung von BSI TR-02102-2-kryptografischen Einstellungen

## Fehlerbehebung

### Häufige Probleme

**Problem**: Skripte schlagen mit "Zugriff verweigert"-Fehlern fehl
- **Lösung**: Stellen Sie sicher, dass Sie über Domänenadministrator-Rechte verfügen und PowerShell als Administrator ausführen

**Problem**: DFSR-Skripte melden "Modul nicht gefunden"
- **Lösung**: Installieren Sie DFSR-Verwaltungstools: `Install-WindowsFeature RSAT-DFS-Mgmt-Con`

**Problem**: Remote-Operationen schlagen fehl
- **Lösung**: Überprüfen Sie, ob WinRM auf Zielservern aktiviert ist: `Enable-PSRemoting -Force`

**Problem**: Ereignisprotokollabfragen geben keine Ergebnisse zurück
- **Lösung**: Überprüfen Sie, ob der angegebene Zeitbereich korrekt ist und ob Ereignisprotokolle auf Ziel-DCs vorhanden sind

## Autor

Fabian Niesen

## Lizenz

Skripte haben verschiedene Lizenzen wie in der Tabelle oben angegeben. Die meisten sind GPLv3 oder MIT-lizenziert. Überprüfen Sie immer den Skript-Header für spezifische Lizenzinformationen.
