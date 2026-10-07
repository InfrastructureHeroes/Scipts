# Windows Scripts

**Language versions:** [English](README.md) | [Deutsch](README.de.md)

## Description

This directory contains PowerShell scripts for Windows system management, including Azure Arc agent removal and RDP certificate configuration.

## Beschreibung

Dieses Verzeichnis enthält PowerShell-Skripte für Windows-Systemmanagement, einschließlich Entfernung des Azure Arc-Agents und RDP-Zertifikatskonfiguration.

## Prerequisites

### Required Modules
- None (uses built-in PowerShell cmdlets)

### Required Permissions
- Local Administrator for system-level changes
- Domain Administrator for certificate operations (if using AD CS)

### Environment Requirements
- Windows 10 or later / Windows Server 2016 or later
- PowerShell 5.1
- Administrative privileges

## Scripts

| Script | Purpose | Version | License |
|--------|---------|---------|---------|
| [Remove-AzureArc.ps1](Remove-AzureArc.ps1) | Remove Azure Arc agent/components and reboot automatically if required. | 1.1 | MIT |
| [set-cert4rdp.ps1](set-cert4rdp.ps1) | Bind/set the RDP certificate from a specific issuing CA. | 0.2 | MIT |

## Common Use Cases

- **Azure Arc Removal**: Remove Azure Arc agent from Windows servers when no longer needed
- **RDP Certificate Management**: Configure RDP to use certificates from a specific issuing CA for secure remote desktop connections
- **System Cleanup**: Remove unwanted Azure management components
- **Security Hardening**: Use PKI-based certificates for RDP instead of self-signed certificates

## Troubleshooting

### Common Issues

**Issue**: Azure Arc removal fails with "Service not found"
- **Solution**: Verify Azure Arc agent is actually installed on the system

**Issue**: Script reports reboot required but doesn't reboot
- **Solution**: The script may require manual reboot if automatic reboot is disabled by policy

**Issue**: RDP certificate script fails with "CA not found"
- **Solution**: Verify the issuing CA is accessible and you have permissions to request certificates

**Issue**: RDP certificate not applied after script execution
- **Solution**: Restart the Remote Desktop Services service: `Restart-Service TermService`

## Important Notes

- The Remove-AzureArc.ps1 script will automatically reboot the system if required
- Always schedule Azure Arc removal during maintenance windows
- Test RDP certificate configuration in a non-production environment first
- Ensure proper backup before making system-level changes

## Author

Fabian Niesen

## License

Scripts are licensed under MIT License. Always review the script header for specific license information.
