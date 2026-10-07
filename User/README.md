# User Scripts

**Language versions:** [English](README.md) | [Deutsch](README.de.md)

## Description

This directory contains PowerShell scripts for user lifecycle management, including Active Directory user creation with Office 365 integration and user activity reporting.

## Beschreibung

Dieses Verzeichnis enthält PowerShell-Skripte für den Benutzerlebenszyklus-Management, einschließlich Active Directory-Benutzererstellung mit Office 365-Integration und Benutzeraktivitätsberichte.

## Prerequisites

### Required Modules
- ActiveDirectory
- Exchange PowerShell modules (for Exchange context in user reporting)

### Required Permissions
- Domain Administrator or equivalent for user creation
- Exchange Administrator for Exchange-related operations

### Environment Requirements
- Windows Server 2012 R2 or later
- Active Directory domain environment
- PowerShell 5.1
- Office 365 tenant (for O365 integration features)

## Scripts

| Script | Purpose | Version | License |
|--------|---------|---------|---------|
| [create-user.ps1](create-user.ps1) | Create AD users (including Microsoft 365 onboarding patterns). | 0.3 | MIT |
| [Get-LastLogonOU.ps1](Get-LastLogonOU.ps1) | Report last logon values for users in an OU (AD + Exchange context). | 0.2 | MIT |

## Common Use Cases

- **User Provisioning**: Create new Active Directory users with Office 365 integration
- **User Onboarding**: Automate user creation with email, UPN, and password policies
- **Activity Reporting**: Track last logon times for users in specific OUs
- **User Cleanup**: Identify inactive users based on last logon data

## Troubleshooting

### Common Issues

**Issue**: User creation fails with "OU not found"
- **Solution**: Verify the OU path exists and you have permissions to create objects in it

**Issue**: Office 365 integration fails
- **Solution**: Ensure the Azure AD Connect synchronization is configured and credentials are valid

**Issue**: Last logon report shows no data
- **Solution**: Ensure the script has access to all domain controllers and Exchange servers

**Issue**: Password complexity requirements not met
- **Solution**: Verify the password meets domain password policy requirements

## Important Notes

- The create-user.ps1 script is a code sample that needs customization for your target environment
- Always test user creation scripts in a non-production environment first
- Ensure proper password policies are enforced when creating users
- Review and customize Office 365 integration settings for your tenant

## Author

Fabian Niesen

## License

Scripts are licensed under MIT License. Always review the script header for specific license information.
