# Microsoft Intune Scripts

**Language versions:** [English](README.md) | [Deutsch](README.de.md)

## Description

This directory contains PowerShell scripts for Microsoft Intune administration, including Autopilot troubleshooting and Win32 app package creation.

## Beschreibung

Dieses Verzeichnis enthält PowerShell-Skripte für die Microsoft Intune-Verwaltung, einschließlich Autopilot-Fehlerbehebung und Erstellung von Win32-App-Paketen.

## Prerequisites

### Required Modules
- Intune PowerShell modules (optional, depends on script usage)

### Required Permissions
- Intune Administrator permissions for package deployment
- Local Administrator for log collection

### Environment Requirements
- Windows 10 or later
- PowerShell 5.1
- Intune Win32 app packaging tool (IntuneWinAppUtil.exe) for package creation

## Scripts

| Script | Purpose | Version | License |
|--------|---------|---------|---------|
| [create-package.ps1](create-package.ps1) | Build `.intunewin` packages from source folders. | 1.0 | Not specified |
| [get-AutopilotLogs.ps1](get-AutopilotLogs.ps1) | Collect logs and diagnostics for Autopilot pre-provisioning. | 1.0.2 | Not specified |

## Common Use Cases

- **Autopilot Troubleshooting**: Collect diagnostic logs when Autopilot pre-provisioning fails
- **App Packaging**: Create Win32 app packages (.intunewin) for Intune deployment
- **Log Analysis**: Gather system logs for Autopilot enrollment issues

## Troubleshooting

### Common Issues

**Issue**: Package creation fails with "IntuneWinAppUtil.exe not found"
- **Solution**: Download the Intune Win32 app packaging tool from Microsoft and place it in the script directory or PATH

**Issue**: Autopilot logs script returns no data
- **Solution**: Ensure the script is run on a device that has attempted Autopilot enrollment

**Issue**: Package size exceeds Intune limits
- **Solution**: Compress source files or split into multiple packages

## Additional Resources

For a more complete Intune app management solution, see: https://github.com/InfrastructureHeroes/Intune-Apps

## Author

Fabian Niesen

## License

Scripts have varying licenses as indicated in the table above. Always review the script header for specific license information.
