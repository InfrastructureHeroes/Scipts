# Active Directory Scripts

**Language versions:** [English](README.md) | [Deutsch](README.de.md)

## Description

This directory contains PowerShell scripts for Active Directory administration, including domain controller management, DFS replication monitoring, permission reporting, security auditing, and user lifecycle automation.

## Beschreibung

Dieses Verzeichnis enthält PowerShell-Skripte für die Active Directory-Verwaltung, einschließlich Domänencontroller-Management, DFS-Replikationsüberwachung, Berechtigungsberichte, Sicherheitsaudits und Benutzerlebenszyklus-Automatisierung.

## Prerequisites

### Required Modules
- ActiveDirectory
- DFSR (for DFS replication scripts)

### Required Permissions
- Domain Administrator or equivalent for most operations
- Local Administrator on target servers for remote operations
- Enterprise Administrator for forest-level operations

### Environment Requirements
- Windows Server 2012 R2 or later
- Active Directory domain environment
- WinRM enabled for remote operations
- PowerShell 5.1

## Scripts

| Script | Purpose | Version | License |
|--------|---------|---------|---------|
| [Configure-AD.ps1](Configure-AD.ps1) | Configure an AD domain (e.g., recycle bin, gMSA prep, central store, password policies, OU structure). | 0.2 | Not specified |
| [Get-ADPermissionsReport.ps1](Get-ADPermissionsReport.ps1) | Export CSV report of Active Directory permissions. | 0.2 | Not specified |
| [Get-DFSRBacklog.ps1](Get-DFSRBacklog.ps1) | Checks the DFSR backlog and generates replication reports for DFS Replication groups. | 0.5 | GPLv3 |
| [Get-LAPSAuditReport.ps1](Get-LAPSAuditReport.ps1) | Query security events for Microsoft LAPS-related audit activity. | n/a | Not specified |
| [Get-LocalNTLMlogs.ps1](Get-LocalNTLMlogs.ps1) | Analyze local `Microsoft-Windows-NTLM/Operational` events with classification. | 1.0 | GPLv3 |
| [Get-Logons.ps1](Get-Logons.ps1) | Query Windows Security event logs for successful and failed logon events. | n/a | Not specified |
| [Get-NTLMLogons.ps1](Get-NTLMLogons.ps1) | Analyze security logs for NTLM logons and authentication usage. | 1.3 | GPLv3 |
| [Get-PKICertlist.ps1](Get-PKICertlist.ps1) | Enumerate certificates/templates from AD CS / PKI context. | n/a | Not specified |
| [Locate-46xx.ps1](Locate-46xx.ps1) | Locate AD lockout-related events (46xx security events). | 1.0 | Not specified |
| [Locate-ADLockout.ps1](Locate-ADLockout.ps1) | Locate user lockout sources in Active Directory. | 1.0 | Not specified |
| [Repair-DFSR.ps1](Repair-DFSR.ps1) | Repair DFS-R replication (including SYSVOL) on domain controllers. | 0.1 | Not specified |
| [Reset-DSRM.ps1](Reset-DSRM.ps1) | Reset DSRM password on a domain controller. | 0.3 | GPLv3 |
| [execute-RemoteScriptWithLAPS.ps1](execute-RemoteScriptWithLAPS.ps1) | Run remote scripts with local admin credentials managed by Microsoft LAPS. | 1.1 | Not specified |
| [get-CVE20201472Events.ps1](get-CVE20201472Events.ps1) | Check domain controllers for Netlogon CVE-2020-1472-related event IDs (5827-5829). | 1.0 | Not specified |
| [get-adinfo.ps1](get-adinfo.ps1) | Collect core AD forest/domain information and report details. | 0.5 | Not specified |
| [install-AD.ps1](install-AD.ps1) | Install and bootstrap a new Active Directory domain. | 0.1 | Not specified |
| [install-DC.ps1](install-DC.ps1) | Install/promote an additional domain controller. | 0.1 | Not specified |
| [move-FSMO.ps1](move-FSMO.ps1) | Move FSMO roles to a new domain controller. | 0.1 | Not specified |
| [set-BSI-TR-02102-2.ps1](set-BSI-TR-02102-2.ps1) | Configure Windows cryptographic settings according to BSI TR-02102-2 (TLS/cipher hardening). | 0.2 | GPLv3 |

## Common Use Cases

- **Domain Controller Management**: Install new domains, promote additional DCs, move FSMO roles
- **Replication Monitoring**: Check DFSR backlog, repair replication issues, generate propagation reports
- **Security Auditing**: Monitor logon events, track NTLM usage, audit LAPS activity
- **Permission Analysis**: Export and review AD permissions across the directory
- **User Troubleshooting**: Locate lockout sources, track user activity
- **PKI Management**: Enumerate certificates and templates from AD CS
- **Hardening**: Apply BSI TR-02102-2 cryptographic settings

## Troubleshooting

### Common Issues

**Issue**: Scripts fail with "Access Denied" errors
- **Solution**: Ensure you have Domain Administrator privileges and are running PowerShell as Administrator

**Issue**: DFSR scripts report "Module not found"
- **Solution**: Install DFSR management tools: `Install-WindowsFeature RSAT-DFS-Mgmt-Con`

**Issue**: Remote operations fail
- **Solution**: Verify WinRM is enabled on target servers: `Enable-PSRemoting -Force`

**Issue**: Event log queries return no results
- **Solution**: Check if the specified time range is correct and verify event logs exist on target DCs

## Author

Fabian Niesen

## License

Scripts have varying licenses as indicated in the table above. Most are GPLv3 or MIT licensed. Always review the script header for specific license information.
