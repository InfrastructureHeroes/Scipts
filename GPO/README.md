# Group Policy (GPO) Scripts

**Language versions:** [English](README.md) | [Deutsch](README.de.md)

## Description

This directory contains PowerShell scripts for Group Policy Object (GPO) management, including backup automation, reporting, local GPO troubleshooting, and remote GPUpdate operations. Also includes GPO templates for security hardening and Copilot deactivation.

## Beschreibung

Dieses Verzeichnis enthält PowerShell-Skripte für die Verwaltung von Gruppenrichtlinienobjekten (GPO), einschließlich Backup-Automatisierung, Berichterstellung, Fehlerbehebung bei lokalen GPOs und Remote-GPUpdate-Operationen. Enthält auch GPO-Vorlagen für Security-Härtung und Copilot-Deaktivierung.

## Prerequisites

### Required Modules
- GroupPolicy (for GPO backup and reporting scripts)

### Required Permissions
- Domain Administrator or equivalent for GPO backup and reporting
- Local Administrator for local GPO troubleshooting
- Remote administration permissions for GPUpdate operations

### Environment Requirements
- Windows Server 2012 R2 or later
- Active Directory domain environment
- WinRM enabled for remote GPUpdate operations
- PowerShell 5.1

## Scripts

| Script | Purpose | Version | License |
|--------|---------|---------|---------|
| [Check-LocalGroupPolicy.ps1](Check-LocalGroupPolicy.ps1) | Detect and fix local Group Policy processing issues based on event logs. | 0.4 | MIT |
| [get-GPOBackup.ps1](get-GPOBackup.ps1) | Create timestamped GPO backups including HTML reports. | 1.8 | MIT |
| [get-GPOreport.ps1](get-GPOreport.ps1) | Export/report GPO links and metadata for documentation. | n/a | Not specified |
| [invoke-GPupdateDomain.ps1](invoke-GPupdateDomain.ps1) | Trigger remote GPUpdate for computers in an OU (or wider scope). | 1.1 | MIT |

## GPO Templates

The `Templates/` subdirectory contains GPO configuration templates for:

- **Windows 11 24H2 – IT-Grundschutz (Darksite)**: Restricted cloud communication and BSI IT-Grundschutz compliance
- **Windows 11 – Disable Copilot**: Deactivate Microsoft Copilot
- **Microsoft Office – Disable Copilot**: Deactivate Copilot in Office applications
- **Visual Studio – Disable Copilot**: Deactivate Copilot in Visual Studio

See [Templates/README.md](Templates/README.md) for detailed template documentation.

## Reference Documentation

- **Client-Side Extension GUID List**: [Client_Side_Extension-GUID_List.md](Client_Side_Extension-GUID_List.md) - Comprehensive list of GPO Client-Side Extension GUIDs for troubleshooting and diagnostics

## Common Use Cases

- **GPO Backup Automation**: Schedule regular GPO backups with HTML reports and version tracking
- **GPO Documentation**: Export GPO links, settings, and metadata for compliance documentation
- **Local GPO Troubleshooting**: Detect and fix malformed local GPOs that prevent policy processing
- **Remote Policy Updates**: Force GPUpdate on multiple computers across OUs
- **Security Hardening**: Apply BSI IT-Grundschutz compliant GPO configurations
- **Copilot Management**: Deactivate Copilot across Windows 11, Office, and Visual Studio

## Troubleshooting

### Common Issues

**Issue**: GPO backup script fails with "Access Denied"
- **Solution**: Ensure you have Domain Administrator privileges and write access to the backup path

**Issue**: GPUpdate fails on remote computers
- **Solution**: Verify WinRM is enabled on target computers: `Enable-PSRemoting -Force`

**Issue**: Local GPO script reports "No issues found" but policies aren't applying
- **Solution**: Check for other GPO processing issues in the Application and System event logs

**Issue**: GPO templates don't import correctly
- **Solution**: Ensure you have GPO editing permissions and the GPO Central Store is properly configured

## Author

Fabian Niesen

## License

Scripts have varying licenses as indicated in the table above. Most are MIT licensed. GPO templates are licensed under GPLv3. Always review the script header for specific license information.
