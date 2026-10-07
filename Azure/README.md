# Azure Scripts

**Language versions:** [English](README.md) | [Deutsch](README.de.md)

## Description

This directory contains PowerShell scripts for Azure tooling setup and management, including AzCopy installation and Azure PowerShell module management.

## Beschreibung

Dieses Verzeichnis enthält PowerShell-Skripte für die Einrichtung und Verwaltung von Azure-Tools, einschließlich AzCopy-Installation und Azure PowerShell-Modul-Management.

## Prerequisites

### Required Modules
- None (scripts install required tools)

### Required Permissions
- Local Administrator for system-wide installations
- Internet access for downloading Azure tools

### Environment Requirements
- Windows 10 or later
- PowerShell 5.1
- Internet connectivity for downloading tools from Microsoft

## Scripts

| Script | Purpose | Version | License |
|--------|---------|---------|---------|
| [Install-AzCopy.ps1](Install-AzCopy.ps1) | Download and install the latest AzCopy for the current user. | 1.0 | Not specified |
| [Install-AzModule.ps1](Install-AzModule.ps1) | Install/update Azure PowerShell modules (`Az`). | n/a | Not specified |

## Common Use Cases

- **AzCopy Installation**: Quickly install the latest AzCopy tool for Azure storage operations
- **Azure PowerShell Setup**: Install or update Azure PowerShell modules for Azure administration
- **Tool Management**: Keep Azure tools up-to-date with the latest versions

## Troubleshooting

### Common Issues

**Issue**: AzCopy download fails with "Access Denied"
- **Solution**: Ensure you have write permissions to the target folder and internet access to aka.ms

**Issue**: AzModule installation fails with "Repository not found"
- **Solution**: Ensure PowerShell Gallery is accessible and not blocked by network policies

**Issue**: Path not updated after installation
- **Solution**: Restart PowerShell or log off/on for environment variable changes to take effect

## Author

Fabian Niesen

## License

Scripts have varying licenses as indicated in the table above. Always review the script header for specific license information.
