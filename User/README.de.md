# Benutzer-Skripte

**Sprachversionen:** [English](README.md) | [Deutsch](README.de.md)

## Beschreibung

Dieses Verzeichnis enthält PowerShell-Skripte für den Benutzerlebenszyklus-Management, einschließlich Active Directory-Benutzererstellung mit Office 365-Integration und Benutzeraktivitätsberichte.

## Description

This directory contains PowerShell scripts for user lifecycle management, including Active Directory user creation with Office 365 integration and user activity reporting.

## Voraussetzungen

### Erforderliche Module
- ActiveDirectory
- Exchange PowerShell-Module (für Exchange-Kontext in Benutzerberichten)

### Erforderliche Berechtigungen
- Domänenadministrator oder gleichwertig für Benutzererstellung
- Exchange-Administrator für Exchange-bezogene Operationen

### Umgebungsvoraussetzungen
- Windows Server 2012 R2 oder höher
- Active Directory-Domänenumgebung
- PowerShell 5.1
- Office 365-Mandant (für O365-Integrationsfunktionen)

## Skripte

| Skript | Zweck | Version | Lizenz |
|--------|-------|---------|--------|
| [create-user.ps1](create-user.ps1) | Erstellen von AD-Benutzern (einschließlich Microsoft 365-Onboarding-Mustern). | 0.3 | MIT |
| [Get-LastLogonOU.ps1](Get-LastLogonOU.ps1) | Bericht über letzte Anmeldezeiten für Benutzer in einer OU (AD + Exchange-Kontext). | 0.2 | MIT |

## Häufige Anwendungsfälle

- **Benutzerbereitstellung**: Erstellen neuer Active Directory-Benutzer mit Office 365-Integration
- **Benutzer-Onboarding**: Automatisieren der Benutzererstellung mit E-Mail, UPN und Kennwortrichtlinien
- **Aktivitätsberichte**: Nachverfolgen der letzten Anmeldezeiten für Benutzer in bestimmten OUs
- **Benutzerbereinigung**: Identifizieren inaktiver Benutzer basierend auf letzten Anmeldedaten

## Fehlerbehebung

### Häufige Probleme

**Problem**: Benutzererstellung schlägt mit "OU nicht gefunden" fehl
- **Lösung**: Überprüfen Sie, ob der OU-Pfad existiert und Sie über Berechtigungen zum Erstellen von Objekten darin verfügen

**Problem**: Office 365-Integration schlägt fehl
- **Lösung**: Stellen Sie sicher, dass die Azure AD Connect-Synchronisation konfiguriert ist und die Anmeldeinformationen gültig sind

**Problem**: Bericht über letzte Anmeldung zeigt keine Daten
- **Lösung**: Stellen Sie sicher, dass das Skript Zugriff auf alle Domänencontroller und Exchange-Server hat

**Problem**: Kennwortkomplexitätsanforderungen nicht erfüllt
- **Lösung**: Überprüfen Sie, ob das Kennwort den Domänenkennwortrichtlinienanforderungen entspricht

## Wichtige Hinweise

- Das Skript create-user.ps1 ist ein Codebeispiel, das für Ihre Zielumgebung angepasst werden muss
- Testen Sie Benutzererstellungsskripte immer zuerst in einer Nicht-Produktionsumgebung
- Stellen Sie sicher, dass ordnungsgemäße Kennwortrichtlinien bei der Benutzererstellung durchgesetzt werden
- Überprüfen und passen Sie Office 365-Integrationseinstellungen für Ihren Mandanten an

## Autor

Fabian Niesen

## Lizenz

Skripte sind unter MIT-Lizenz lizenziert. Überprüfen Sie immer den Skript-Header für spezifische Lizenzinformationen.
