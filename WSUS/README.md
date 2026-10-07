# WSUS Scripts

**Language versions:** [English](README.md) | [Deutsch](README.de.md)

## Description

This directory contains PowerShell scripts for Windows Server Update Services (WSUS) administration, including health checks, update management, synchronization automation, and client troubleshooting.

## Beschreibung

Dieses Verzeichnis enthält PowerShell-Skripte für die Verwaltung von Windows Server Update Services (WSUS), einschließlich Integritätsprüfungen, Update-Management, Synchronisationsautomatisierung und Client-Fehlerbehebung.

## Prerequisites

### Required Modules
- UpdateServices (for WSUS health checks and management)

### Required Permissions
- WSUS Administrator permissions
- Local Administrator on WSUS server
- SMTP server access for email notifications (if configured)

### Environment Requirements
- Windows Server 2012 R2 or later with WSUS role installed
- WSUS console or PowerShell module installed
- PowerShell 5.1

## Scripts

| Script | Purpose | Version | License |
|--------|---------|---------|---------|
| [Get-WsusHealth.ps1](Get-WsusHealth.ps1) | Run comprehensive WSUS health checks and generate diagnostic output. | 1.3 | Evotec MIT License |
| [decline-WSUSUpdatesTypes.ps1](decline-WSUSUpdatesTypes.ps1) | Decline selected update classifications/products in WSUS. | 1.8 | MIT |
| [start-WsusServerSync.ps1](start-WsusServerSync.ps1) | Start WSUS synchronization (supports recursive upstream/downstream and email logging). | n/a | Not specified |

## Additional Files

- **Reset-WSUSClient.cmd**: Batch script to reset WSUS client configuration and detection state

## Common Use Cases

- **WSUS Health Monitoring**: Perform comprehensive health checks including service status, database connectivity, disk space, and synchronization status
- **Update Cleanup**: Decline unnecessary update types (Beta, Preview, Itanium, Drivers, Superseded) to reduce database size
- **Synchronization Automation**: Trigger WSUS synchronization with email notifications for upstream/downstream servers
- **Client Troubleshooting**: Reset WSUS client configuration when clients fail to update
- **Database Maintenance**: Regular cleanup of declined and superseded updates to improve WSUS performance

## Troubleshooting

### Common Issues

**Issue**: WSUS health check fails with "Unable to connect to WSUS API"
- **Solution**: Verify WSUS services are running and the WSUS Administration console can connect

**Issue**: Update decline script doesn't find updates
- **Solution**: Ensure the WSUS server has synchronized with Microsoft Update recently

**Issue**: Synchronization script fails with authentication error
- **Solution**: Verify the WSUS server has proper credentials configured for upstream synchronization

**Issue**: Client reset script doesn't resolve update issues
- **Solution**: Check if the client can reach the WSUS server and that Windows Update service is running

## Author

Fabian Niesen

## License

Scripts have varying licenses as indicated in the table above. Most are MIT licensed. The Get-WsusHealth.ps1 script includes code licensed by Evotec under MIT License. Always review the script header for specific license information.
