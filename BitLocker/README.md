# BitLocker Scripts

**Language versions:** [English](README.md) | [Deutsch](README.de.md)

## Description

This directory contains PowerShell scripts for BitLocker drive encryption management, including recovery key backup, encryption initiation, and Active Directory recovery information synchronization.

## Beschreibung

Dieses Verzeichnis enthält PowerShell-Skripte für die Verwaltung der BitLocker-Laufwerkverschlüsselung, einschließlich Backup von Wiederherstellungsschlüsseln, Einleitung der Verschlüsselung und Synchronisation von Active Directory-Wiederherstellungsinformationen.

## Prerequisites

### Required Modules
- BitLocker (built-in on Windows)

### Required Permissions
- Local Administrator on target computers
- Domain Administrator permissions for AD recovery key operations

### Environment Requirements
- Windows 7 or later with BitLocker support
- Active Directory domain environment (for AD backup)
- TPM chip on target computers (for TPM-based encryption)
- PowerShell 5.1

## Scripts

| Script | Purpose | Version | License |
|--------|---------|---------|---------|
| [List-BitLockerrecoveryKeys.ps1](List-BitLockerrecoveryKeys.ps1) | List BitLocker recovery keys stored in Active Directory. | n/a | Not specified |
| [Start-Bitlocker.ps1](Start-Bitlocker.ps1) | Start BitLocker encryption with predefined settings (including PIN workflows). | n/a | Not specified |
| [Update-BitLockerRecovery.ps1](Update-BitLockerRecovery.ps1) | Upload missing BitLocker recovery information to Active Directory. | 1.2 | MIT |

## Common Use Cases

- **Recovery Key Management**: List and document BitLocker recovery keys stored in Active Directory
- **Encryption Deployment**: Enable BitLocker encryption with TPM and PIN protection
- **Recovery Information Backup**: Upload missing BitLocker recovery information to Active Directory for compliance
- **Key Recovery**: Retrieve recovery keys from Active Directory when users forget their passwords or PINs

## Troubleshooting

### Common Issues

**Issue**: Script fails with "TPM not available"
- **Solution**: Verify the computer has a TPM chip and it's enabled in BIOS/UEFI

**Issue**: Recovery key upload to AD fails
- **Solution**: Ensure the computer is domain-joined and you have permissions to write to the computer object in AD

**Issue**: Encryption fails with "Insufficient disk space"
- **Solution**: Ensure there is at least 1.5 GB of free space on the system drive for BitLocker metadata

**Issue**: PIN-based encryption not supported
- **Solution**: Verify the system supports TPM 2.0 and Enhanced PINs

## Security Considerations

- Always store recovery keys securely in Active Directory
- Use strong PINs for TPM+PIN protection
- Document recovery procedures for lost keys/forgotten PINs
- Regularly audit recovery key access in Active Directory
- Ensure BitLocker recovery information is backed up before any system changes

## Author

Fabian Niesen

## License

Scripts have varying licenses as indicated in the table above. Most are MIT licensed. Always review the script header for specific license information.
