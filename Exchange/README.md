# Exchange Scripts

**Language versions:** [English](README.md) | [Deutsch](README.de.md)

## Description

This directory contains PowerShell scripts for Microsoft Exchange Server administration, including maintenance mode management for Database Availability Groups (DAG) and virtual directory configuration.

## Beschreibung

Dieses Verzeichnis enthält PowerShell-Skripte für die Microsoft Exchange Server-Verwaltung, einschließlich Wartungsmodus-Management für Database Availability Groups (DAG) und Konfiguration virtueller Verzeichnisse.

## Prerequisites

### Required Modules
- Exchange Management PowerShell modules (Exchange 2013 or later)

### Required Permissions
- Exchange Organization Administrator
- Local Administrator on Exchange servers

### Environment Requirements
- Exchange Server 2013 or later
- PowerShell 5.1
- Exchange Management Shell or remote PowerShell session

## Scripts

| Script | Purpose | Version | License |
|--------|---------|---------|---------|
| [Set-MaintananceMode.ps1](Set-MaintananceMode.ps1) | Put an Exchange 2013 DAG node into maintenance mode. | 0.2 | Not specified |
| [Set-Ex2013Vdir.ps1](Set-Ex2013Vdir.ps1) | Configure Exchange 2013 virtual directories/URLs. | 0.1 | Not specified |

## Common Use Cases

- **DAG Maintenance**: Put Exchange DAG nodes into maintenance mode for patching or upgrades
- **Virtual Directory Configuration**: Configure Exchange 2013 virtual directories for OWA, ECP, Autodiscover, etc.
- **Server Maintenance**: Safely move active databases before maintenance windows

## Troubleshooting

### Common Issues

**Issue**: Maintenance mode script fails with "DAG not found"
- **Solution**: Ensure the Exchange Management Shell is loaded and you have proper permissions

**Issue**: Virtual directory configuration doesn't take effect
- **Solution**: Restart IIS services after configuration changes: `iisreset`

**Issue**: Database move fails during maintenance mode
- **Solution**: Verify target server has sufficient resources and is not already in maintenance mode

## Important Notes

- These scripts are designed for Exchange 2013. For newer Exchange versions (2016, 2019, 2023), verify compatibility before use
- Always test maintenance mode procedures in a non-production environment first
- Ensure proper backup before performing maintenance operations

## Author

Fabian Niesen

## License

Scripts have varying licenses as indicated in the table above. Always review the script header for specific license information.
