# Network Scripts

**Language versions:** [English](README.md) | [Deutsch](README.de.md)

## Description

This directory contains PowerShell scripts for network diagnostics and client configuration, including connectivity validation, MTU testing, LDAP checks, and NetBIOS over TCP/IP management.

## Beschreibung

Dieses Verzeichnis enthält PowerShell-Skripte für Netzwerkdiagnose und Client-Konfiguration, einschließlich Konnektivitätsvalidierung, MTU-Tests, LDAP-Prüfungen und NetBIOS über TCP/IP-Management.

## Prerequisites

### Required Modules
- None (uses built-in PowerShell cmdlets)

### Required Permissions
- Local Administrator for network adapter configuration changes
- Network connectivity for remote checks

### Environment Requirements
- Windows 7 or later
- PowerShell 5.1
- Network adapter(s) configured

## Scripts

| Script | Purpose | Version | License |
|--------|---------|---------|---------|
| [Check-Network.ps1](Check-Network.ps1) | Validate client network connectivity and configuration. | 0.6 | Evotec MIT License |
| [disable-NetBios.ps1](disable-NetBios.ps1) | Disable NetBIOS over TCP/IP on active adapters. | n/a | Not specified |

## Common Use Cases

- **Network Diagnostics**: Validate network connectivity, MTU settings, and DNS configuration
- **LDAP Testing**: Test LDAP/LDAPS connectivity to domain controllers
- **Security Hardening**: Disable NetBIOS over TCP/IP to reduce attack surface
- **Troubleshooting**: Identify network configuration issues on client machines

## Troubleshooting

### Common Issues

**Issue**: Network check fails with "No network adapters found"
- **Solution**: Ensure the computer has at least one active network adapter

**Issue**: LDAP test fails with "Unable to connect"
- **Solution**: Verify domain controller is reachable and firewall allows LDAP/LDAPS traffic

**Issue**: NetBIOS disable script fails with "Access Denied"
- **Solution**: Run the script with Administrator privileges

**Issue**: MTU test shows packet loss
- **Solution**: Adjust MTU size or check for network equipment MTU limitations

## Security Considerations

- Disabling NetBIOS over TCP/IP is recommended for security but may break legacy applications
- Always test network changes in a controlled environment before production deployment
- LDAP testing may expose sensitive directory information - use with caution

## Author

Fabian Niesen

## License

Scripts have varying licenses as indicated in the table above. The Check-Network.ps1 script includes LDAP test code licensed by Evotec under MIT License. Always review the script header for specific license information.
