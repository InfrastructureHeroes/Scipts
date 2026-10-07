# Agent Development Standard

> ## Documentation Notice
>
> This documentation is provided **"as-is"** and does not claim to be complete, exhaustive, or free of errors.
>
> The documentation contained within this repository has been created partially or fully with the assistance of Artificial Intelligence (AI).
>
> Documentation may not have undergone a complete human review.
>
> Human validation is typically performed on a sampling basis and should not be considered a full technical, operational, security, or editorial review.
>
> Users remain responsible for validating all procedures, configurations, recommendations, examples, and technical guidance before use.
>
> The implementation, source code, scripts, and configuration files remain the authoritative source of truth.

> **Status:** Active
> **Version:** 1.0
> **Author:** Fabian Niesen, assisted by AI (Cascade/SWE-1.6)
> **Last Updated:** 2026-10-06

---

## Table of Contents

- [Introduction](#introduction)
- [Scope and Target Audience](#scope-and-target-audience)
- [Development Principles](#development-principles)
- [PowerShell Version Requirements](#powershell-version-requirements)
- [Microsoft Documentation Verification](#microsoft-documentation-verification)
- [Script Documentation Requirements](#script-documentation-requirements)
- [README.md Maintenance Requirements](#readmemd-maintenance-requirements)
- [Error Handling Standards](#error-handling-standards)
- [String Concatenation Standards](#string-concatenation-standards)
- [Logging Standards](#logging-standards)
- [Validation Requirements](#validation-requirements)
- [Mandatory Coding Rules](#mandatory-coding-rules)
- [PowerShell Best Practices](#powershell-best-practices)
- [Security Standards](#security-standards)
- [Code Review Standards](#code-review-standards)
- [Examples](#examples)
- [Documentation Templates](#documentation-templates)
- [Exceptions Process](#exceptions-process)

---

## Introduction

This document defines the development standards and guidelines for all PowerShell scripts created for the Scripts repository. These standards ensure consistency, maintainability, reliability, and long-term supportability across all code.

These standards apply to:
- All new scripts added to the repository
- All modifications to existing scripts
- Both AI-generated and human-written code
- All script categories (Active Directory, Network, BitLocker, GPO, WSUS, etc.)

---

## Scope and Target Audience

### Target Audience
- AI coding assistants (Devin, Cascade, etc.)
- Human developers and administrators
- Code reviewers
- Contributors to the Scripts repository

### Scope
This standard applies to all PowerShell scripts in the Scripts repository.

### Repository Context
The Scripts repository contains administration scripts for:
- Active Directory and identity operations
- BitLocker and endpoint encryption
- Group Policy (GPO)
- WSUS operations and health checks
- Intune packaging and troubleshooting
- Azure tooling setup
- Network diagnostics and client configuration
- Exchange maintenance tasks
- User lifecycle automation
- Windows hardening and cleanup

For a complete inventory, see [README.md](README.md).

---

## Development Principles

### Code Quality Objectives
- **Readability**: Code should be self-documenting and easy to understand
- **Maintainability**: Code should be easy to modify and extend
- **Reliability**: Code should handle errors gracefully and validate inputs
- **Consistency**: Code should follow consistent patterns across the repository

### Consistency Requirements
- Use consistent naming conventions across all scripts
- Follow consistent error handling patterns
- Use consistent logging formats
- Maintain consistent documentation structure

### Long-term Supportability Goals
- Write code that is easy to debug
- Include comprehensive error handling
- Document complex logic
- Avoid dependencies on deprecated features
- Plan for future Windows Server versions

### Testing and Validation Requirements
- Test scripts in a non-production environment first
- Validate all inputs and parameters
- Verify configuration changes after execution
- Test with different Windows Server versions (2016, 2019, 2022, 2025)

### Documentation Requirements
- Every script must have a corresponding .md documentation file
- Documentation must be kept in sync with script changes
- README.md must be updated when scripts are added or modified
- All documentation must be in English

---

## PowerShell Version Requirements

### Mandatory: PowerShell 5.1 Only

All scripts must target PowerShell 5.1 as the baseline version. This ensures compatibility with:
- Windows Server 2016
- Windows Server 2019
- Windows Server 2022
- Windows Server 2025

### Requirements

1. **Mandatory #requires statement**
   Every script must start with:
   ```powershell
   #requires -version 5.1
   ```

2. **No PowerShell Core (6.x/7.x) features**
   - Do not use features introduced in PowerShell Core
   - Do not use PowerShell 7+ specific syntax
   - Avoid cross-platform considerations (Windows-only is acceptable)

3. **Avoid advanced .NET features not available in PS 5.1**
   - Do not use classes (PowerShell 5.0+ feature, avoid for maximum compatibility)
   - Avoid advanced .NET generics
   - Use traditional PowerShell objects instead

4. **Use traditional PowerShell syntax**
   - Do not use null-coalescing operators: `??`, `??=`
   - Do not use pipeline chain operators: `&&`, `||`
   - Use traditional if/else statements
   - Use traditional error handling patterns

5. **Module compatibility**
   - Verify all modules are available in Windows Server 2016+
   - Use Windows Server built-in modules when possible
   - Document any external module requirements

6. **Testing requirements**
   - Test all code on Windows Server 2022/2025 with PowerShell 5.1
   - Document any version-specific requirements
   - Provide fallback mechanisms for older Windows versions if needed

### Example

**Correct:**
```powershell
#requires -version 5.1
#requires -modules ActiveDirectory

param(
    [string]$ComputerName
)

# Traditional PowerShell syntax
if ($ComputerName) {
    Write-Output "Processing computer: " + $ComputerName
}
```

**Incorrect:**
```powershell
# No #requires statement
# Using PowerShell 7+ syntax
$ComputerName ??= "localhost"
```

---

## Microsoft Documentation Verification

### Mandatory: Verify All PowerShell Commands Against Microsoft Documentation

All cmdlets, parameters, and syntax used in scripts must be verified against official Microsoft PowerShell 5.1 documentation.

### Verification Process

1. **Verify cmdlet existence in PowerShell 5.1**
   - Check Microsoft documentation for cmdlet availability
   - Verify cmdlet is not deprecated or removed
   - Confirm cmdlet is available in Windows Server 2016+

2. **Verify parameter names and syntax**
   - Check parameter names match official documentation
   - Verify parameter types and validation
   - Confirm parameter behavior matches documentation

3. **Check for deprecated features**
   - Review Microsoft deprecation notices
   - Avoid using deprecated parameters or cmdlets
   - Use recommended alternatives

4. **Validate module availability**
   - Verify module is available in Windows Server 2016/2019/2022/2025
   - Check if module requires additional installation
   - Document module installation requirements

5. **Reference Microsoft documentation**
   - Add comment references to Microsoft documentation URLs
   - Document the verification date
   - Note any version-specific behavior

### Required Documentation in Scripts

For each cmdlet used, add a comment with the Microsoft documentation reference:

```powershell
# Get-ADUser: https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-aduser
# Verified: 2026-10-06
Get-ADUser -Identity $UserName
```

### Example Verification Workflow

1. Identify cmdlet: `Get-DfsrBacklog`
2. Search Microsoft documentation: "Get-DfsrBacklog PowerShell 5.1"
3. Verify availability: Confirmed in DFSR module (Windows Server 2012+)
4. Check parameters: `-DestinationComputerName`, `-SourceComputerName`, etc.
5. Add documentation reference comment to script
6. Document any prerequisites (DFS-R management tools)

### Maintaining Verified Cmdlet List

Maintain a list of commonly used cmdlets with their Microsoft documentation URLs in this Agent.md document:

| Cmdlet | Module | Microsoft Documentation | Verified Date |
|--------|--------|------------------------|---------------|
| Get-ADUser | ActiveDirectory | https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-aduser | 2026-10-06 |
| Get-WmiObject | - | https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-wmiobject | 2026-10-06 |
| Test-Connection | - | https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/test-connection | 2026-10-06 |

---

## Script Documentation Requirements

### Mandatory: Create .md Documentation File for Every Script

Every PowerShell script in the repository must have a corresponding Markdown documentation file.

### File Naming Convention

- Documentation file must be in the same directory as the script
- Documentation file must have the same base name as the script
- Example: `Get-DFSRBacklog.ps1` → `Get-DFSRBacklog.md`

### Required Documentation Sections

Every script documentation file must include the following sections:

#### 1. Title and Description
```markdown
# Get-DFSRBacklog

Checks the DFSR backlog and generates replication reports for DFS Replication groups.
```

#### 2. Purpose and Use Cases
```markdown
## Purpose

This script analyzes the DFS Replication status on the local server and within the Active Directory environment.

## Use Cases

- Monitor DFSR replication health
- Identify replication backlogs
- Generate propagation test reports
- Compare file hashes between replication partners
```

#### 3. Parameters
```markdown
## Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| CompareHashes | Switch | $false | Compares file hashes between replication partners |
| ReplicationGroupList | String[] | "" | Limits analysis to specified DFS Replication groups |
| LogPath | String | "C:\Temp\DFSRMonitor" | Path for log files and reports |
| CSVFilename | String | "DFSR-Backlog.csv" | Filename for CSV backlog export |
```

#### 4. Examples
```markdown
## Examples

### Example 1: Basic backlog analysis
```powershell
.\Get-DFSRBacklog.ps1 -LogPath "C:\Temp\DFSRMonitor" -Verbose
```

### Example 2: Analyze specific replication groups
```powershell
.\Get-DFSRBacklog.ps1 -ReplicationGroupList "Domain System Volume","Data Replication" -LogPath "C:\Temp\DFSRMonitor"
```

### Example 3: Compare file hashes
```powershell
.\Get-DFSRBacklog.ps1 -CompareHashes -LogPath "C:\Temp\DFSRMonitor"
```
```

#### 5. Prerequisites
```markdown
## Prerequisites

### Required Modules
- ActiveDirectory
- DFSR

### Required Permissions
- Domain Administrator or equivalent
- Local Administrator on target servers

### Environment Requirements
- Windows Server 2012 R2 or later
- DFSR role installed
- WinRM enabled for remote operations
```

#### 6. Output Format
```markdown
## Output Format

The script generates:
- Console output with backlog counts
- CSV export of backlog details
- HTML propagation test reports
- Optional hash comparison output
```

#### 7. Error Handling Behavior
```markdown
## Error Handling

The script:
- Logs all errors to the specified log path
- Continues processing non-critical errors
- Terminates on critical failures
- Provides detailed error messages for troubleshooting
```

#### 8. Dependencies
```markdown
## Dependencies

- Windows Server 2012 R2 or later
- DFSR management tools
- Active Directory PowerShell module
- WinRM for remote operations
```

#### 9. Version History
```markdown
## Version History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 0.5 | 2026-03-28 | Fabian Niesen | First public version |
```

#### 10. Author and License
```markdown
## Author

Fabian Niesen

## License

GNU General Public License v3 (GPLv3)
```

#### 11. Microsoft Documentation Links
```markdown
## Microsoft Documentation Links

- Get-DfsReplicationGroup: https://learn.microsoft.com/en-us/powershell/module/dfsr/get-dfsreplicationgroup
- Get-DfsrBacklog: https://learn.microsoft.com/en-us/powershell/module/dfsr/get-dfsrbacklog
- Start-DfsrPropagationTest: https://learn.microsoft.com/en-us/powershell/module/dfsr/start-dfsrpropagationtest
```

### Documentation Requirements

- Documentation must be in English
- Documentation must be kept in sync with script changes
- Update documentation when script parameters change
- Update documentation when new features are added
- Update version history with each change

### Documentation Template

See the [Documentation Templates](#documentation-templates) section for a complete template.

---

## README.md Maintenance Requirements

### Mandatory: Maintain README.md with All Scripts and Links to Documentation

The repository README.md must list all scripts with links to both the script file and its documentation.

### README.md Structure

Organize scripts by category/directory. Each script entry must include:

| Field | Requirement |
|-------|-------------|
| Script Name | Clickable link to the script file |
| Documentation Link | Clickable link to the script's .md documentation file |
| Description | Brief description of script purpose |
| Version | Version number from script |
| License | License information from script |

### Example README.md Entry

```markdown
### ActiveDirectory

| Script | Documentation | Purpose | Version | License |
|--------|--------------|---------|---------|---------|
| [Get-DFSRBacklog.ps1](ActiveDirectory/Get-DFSRBacklog.ps1) | [Get-DFSRBacklog.md](ActiveDirectory/Get-DFSRBacklog.md) | Checks DFSR backlog and generates replication reports | 0.5 | GPLv3 |
| [Get-ADPermissionsReport.ps1](ActiveDirectory/Get-ADPermissionsReport.ps1) | [Get-ADPermissionsReport.md](ActiveDirectory/Get-ADPermissionsReport.md) | Export CSV report of Active Directory permissions | 0.2 | Not specified |
```

### Synchronization Requirements

1. **When adding a new script:**
   - Add entry to README.md in appropriate category
   - Include script link, documentation link, description, version, license
   - Update script count if applicable

2. **When removing a script:**
   - Remove entry from README.md
   - Update script count if applicable

3. **When updating a script:**
   - Update version in README.md if version changed
   - Update description if purpose changed
   - Update license if license changed

4. **When adding documentation:**
   - Add documentation link to README.md entry
   - Verify link is correct

### Format Guidelines

- Use Markdown tables for script listings
- Organize by directory/category
- Use consistent formatting across all entries
- Keep descriptions brief (1-2 sentences)
- Use relative paths for links

### Example README.md Structure

See the [Examples](#examples) section for a complete README.md example.

---

## Error Handling Standards

### Mandatory Try-Catch for All State-Changing Operations

All operations that modify system state must be wrapped in try-catch blocks.

### Operations Requiring Error Handling

The following operations MUST have error handling:

- **Active Directory operations**: Creating/deleting users, groups, computers, OUs
- **DNS operations**: Creating/deleting DNS records, zones
- **File system operations**: Creating/deleting files, directories
- **Registry operations**: Reading/writing registry keys
- **Service operations**: Starting/stopping/restarting services
- **Network operations**: Configuring network adapters, firewall rules
- **WMI/CIM operations**: Querying or modifying WMI/CIM objects
- **Configuration changes**: Any modification to system configuration

### Catch Block Requirements

Every catch block must:

1. **Log the error** with a meaningful message
2. **Log the exception details** (`$_.Exception.Message`)
3. **Log the operation being executed**
4. **Log the affected object/parameters**
5. **Re-throw or gracefully terminate** based on severity

### Empty Catch Block Prohibition

Empty catch blocks are **FORBIDDEN**:

**Incorrect:**
```powershell
try {
    New-ADUser -Name $UserName
}
catch {
    # Empty catch block - FORBIDDEN
}
```

**Correct:**
```powershell
try {
    New-ADUser -Name $UserName -ErrorAction Stop
    Write-Output "Successfully created user: " + $UserName
}
catch {
    Write-Error "Failed to create user '" + $UserName + "': " + $_.Exception.Message
    throw
}
```

### Silent Failure Prohibition

Silent failures are **FORBIDDEN**. All errors must be logged.

**Incorrect:**
```powershell
try {
    New-ADUser -Name $UserName
}
catch {
    # Silent failure - FORBIDDEN
}
```

**Correct:**
```powershell
try {
    New-ADUser -Name $UserName -ErrorAction Stop
    Write-Output "Successfully created user: " + $UserName
}
catch {
    Write-Error "Failed to create user '" + $UserName + "': " + $_.Exception.Message
    throw
}
```

### ErrorAction Stop Usage

Use `-ErrorAction Stop` for state-changing operations to ensure errors are caught:

```powershell
try {
    New-ADGroup -Name $GroupName -ErrorAction Stop
}
catch {
    Write-Error "Failed to create group: " + $_.Exception.Message
    throw
}
```

### Cleanup Logic for Partial Failures

When operations fail mid-process, clean up partial changes:

```powershell
$createdObjects = @()

try {
    foreach ($item in $items) {
        $obj = New-ADObject -Type $item.Type -Name $item.Name -ErrorAction Stop
        $createdObjects += $obj
    }
}
catch {
    Write-Error "Failed during object creation: " + $_.Exception.Message
    
    # Cleanup created objects
    foreach ($obj in $createdObjects) {
        try {
            Remove-ADObject -Identity $obj.DistinguishedName -Confirm:$false
        }
        catch {
            Write-Warning "Failed to cleanup object '" + $obj.DistinguishedName + "': " + $_.Exception.Message
        }
    }
    throw
}
```

### Examples

See the [Examples](#examples) section for more error handling examples.

---

## String Concatenation Standards

### Problem Statement

PowerShell variable interpolation can create ambiguity when variables are followed by special characters like `:`, `.`, `_`, `\`, `/`. This can lead to:
- Parsing issues
- Unexpected output
- Readability problems
- Difficult troubleshooting

### Mandatory Concatenation Pattern

**Do NOT use variable interpolation with special characters:**

**Incorrect:**
```powershell
"$Variable: Text"
"Server $ServerName:"
"$Object.Property"
```

**Preferred Pattern: Use Concatenation**

**Correct:**
```powershell
'Text ' + $Variable
'Server ' + $ServerName + ' failed.'
'OU Path: ' + $OUPath
'Creating computer object ' + $ComputerName
'Unable to configure server ' + $ServerName + '.'
```

### Subexpression Standard

When interpolation is unavoidable, use `$()`:

**Correct:**
```powershell
"The server is $($ServerName)."
"The distinguished name is $($Object.DistinguishedName)."
"Current value: $($Result.Value)"
```

**Incorrect:**
```powershell
"$Object.Property"
"$ServerName:"
"$Result.Property"
```

### Special Character Handling

Any variable followed by these characters must be wrapped in `$()`:
- Colon (`:`)
- Dot (`.`)
- Brackets (`[`, `]`)
- Underscore (`_`)
- Backslash (`\`)
- Forward slash (`/`)

### Examples

**Incorrect:**
```powershell
Write-Output "Server $ServerName: Failed"
Write-Output "Path: $Path\file.txt"
Write-Output "User: $User.Name"
```

**Correct:**
```powershell
Write-Output "Server " + $ServerName + ": Failed"
Write-Output "Path: " + $Path + "\file.txt"
Write-Output "User: " + $User.Name
```

Or with subexpression:
```powershell
Write-Output "Server $($ServerName): Failed"
Write-Output "Path: $($Path)\file.txt"
Write-Output "User: $($User.Name)"
```

### String Handling Best Practices

1. **Prefer concatenation** for complex strings with multiple variables
2. **Use `$()`** when interpolation is clearer
3. **Avoid interpolation** when variables are followed by special characters
4. **Prioritize readability** over compact syntax
5. **Use single quotes** for literal strings
6. **Use double quotes** only when interpolation is needed

---

## Logging Standards

### Logging Requirements

1. **Log before changes** - Log what operation is about to be performed
2. **Log after changes** - Log the result of the operation
3. **Log inside catch blocks** - Log all errors with details
4. **Log validation results** - Log the outcome of validation checks

### Output Cmdlet Guidelines

**Use appropriate output cmdlets:**

| Cmdlet | Use Case |
|--------|----------|
| Write-Output | Standard output, information messages |
| Write-Verbose | Detailed diagnostic information (requires -Verbose) |
| Write-Warning | Warning messages that don't stop execution |
| Write-Error | Error messages that indicate failure |
| Write-Debug | Debugging information (requires -Debug) |

**Do NOT use Write-Host in production code** (use Write-Output instead).

### Transcript Logging

For long-running operations, use transcript logging:

```powershell
$LogName = (Get-Date -UFormat "%Y%m%d-%H%M") + "-" + $ScriptName + "_" + $ENV:COMPUTERNAME + ".log"
Start-Transcript -Path "$logpath\$LogName" -Append

# Script logic here

Stop-Transcript
```

### Log Message Format

Log messages should be:
- Clear and descriptive
- Include relevant context (object names, parameters)
- Use consistent format
- Include error details in error messages

**Good:**
```powershell
Write-Output "Failed to create user '" + $UserName + "' in OU '" + $OUPath + "': " + $_.Exception.Message
```

**Poor:**
```powershell
Write-Output "Error creating user"
```

### Log Level Guidelines

- **Information**: Normal operations, successful completions
- **Warning**: Non-critical issues, potential problems
- **Error**: Failures that prevent operation completion

### Examples

**Correct logging pattern:**
```powershell
# Log before operation
Write-Output "Creating user account: " + $UserName

try {
    New-ADUser -Name $UserName -ErrorAction Stop
    # Log after operation
    Write-Output "Successfully created user: " + $UserName
}
catch {
    # Log error with details
    Write-Error "Failed to create user '" + $UserName + "': " + $_.Exception.Message
    throw
}
```

---

## Validation Requirements

### Mandatory Validation After Configuration Changes

After every configuration change, validate that:
- Desired state was reached
- Command succeeded
- Configuration is compliant

### Validation Examples

Validate the following operations:

| Operation | Validation Method |
|-----------|-------------------|
| User created | Get-ADUser to verify user exists |
| Group created | Get-ADGroup to verify group exists |
| DNS record created | Get-DnsServerResourceRecord to verify record exists |
| Service started | Get-Service to verify service is running |
| Registry key set | Get-ItemProperty to verify registry value |
| File operation completed | Test-Path to verify file exists |

### Validation Failure Treatment

Validation failures must be treated as errors:
- Log the validation failure
- Include details about what was expected vs. what was found
- Re-throw or terminate based on severity

### Examples

**Correct validation pattern:**
```powershell
try {
    New-ADUser -Name $UserName -ErrorAction Stop
    Write-Output "Successfully created user: " + $UserName
}
catch {
    Write-Error "Failed to create user '" + $UserName + "': " + $_.Exception.Message
    throw
}

# Validate user was created
try {
    $user = Get-ADUser -Identity $UserName -ErrorAction Stop
    Write-Output "Validation successful: User '" + $UserName + "' exists"
}
catch {
    Write-Error "Validation failed: User '" + $UserName + "' was not created"
    throw
}
```

---

## Mandatory Coding Rules

### 1. No Write-Host in Production Code

**Incorrect:**
```powershell
Write-Host "Processing user: $UserName"
```

**Correct:**
```powershell
Write-Output "Processing user: " + $UserName
```

### 2. Use Appropriate Output Cmdlets

- Use `Write-Output` for standard output
- Use `Write-Verbose` for detailed information
- Use `Write-Warning` for warnings
- Use `Write-Error` for errors

### 3. No Empty Catch Blocks

**Incorrect:**
```powershell
try {
    New-ADUser -Name $UserName
}
catch {
    # Empty - FORBIDDEN
}
```

**Correct:**
```powershell
try {
    New-ADUser -Name $UserName -ErrorAction Stop
}
catch {
    Write-Error "Failed to create user: " + $_.Exception.Message
    throw
}
```

### 4. No Silent Error Suppression

**Incorrect:**
```powershell
New-ADUser -Name $UserName -ErrorAction SilentlyContinue
```

**Correct:**
```powershell
try {
    New-ADUser -Name $UserName -ErrorAction Stop
}
catch {
    Write-Error "Failed to create user: " + $_.Exception.Message
    throw
}
```

### 5. No Hardcoded Values if Parameters Exist

**Incorrect:**
```powershell
$OUPath = "OU=Users,DC=domain,DC=com"
```

**Correct:**
```powershell
param(
    [string]$OUPath
)
```

### 6. No Duplicated Logic

Extract duplicated logic to functions:

**Incorrect:**
```powershell
# Repeated in multiple places
if ($UserName.Length -lt 3) {
    Write-Error "Username too short"
}
```

**Correct:**
```powershell
function Test-UserNameLength {
    param([string]$UserName)
    if ($UserName.Length -lt 3) {
        Write-Error "Username too short"
        return $false
    }
    return $true
}

# Use function
if (-not (Test-UserNameLength -UserName $UserName)) {
    throw "Invalid username"
}
```

### 7. Reuse Helper Functions

Use existing helper functions instead of reimplementing.

### 8. Validate All Inputs

```powershell
param(
    [Parameter(Mandatory = $true)]
    [ValidateLength(3, 20)]
    [string]$UserName
)
```

### 9. Validate All Configuration Values

```powershell
if (-not (Test-Path $ConfigPath)) {
    Write-Error "Configuration file not found: " + $ConfigPath
    throw
}
```

### 10. Validate All External Dependencies

```powershell
if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Error "ActiveDirectory module not available"
    throw
}
```

### 11. Validate All Prerequisites

```powershell
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "Script must be run as Administrator"
    throw
}
```

### 12. All Functions Must Contain Comment-Based Help

```powershell
<#
.SYNOPSIS
    Creates a new user account.

.DESCRIPTION
    Creates a new Active Directory user account with specified parameters.

.PARAMETER UserName
    The username for the new account.

.EXAMPLE
    New-UserAccount -UserName "jdoe"

.LINK
    https://github.com/[username]/[repository]/blob/main/[path]/[ScriptName].ps1

.NOTES
    Author     :    [Author Name]
    Filename   :    [ScriptName].ps1
    Requires   :    PowerShell Version 5.1

    Version    :    1.0
    History    :
                    1.0 YYYYMMDD [Author] Initial Version
#>
function New-UserAccount {
    param([string]$UserName)
    # Function logic
}
```

### 13. All Public Functions Must Include Examples

See the comment-based help example above.

### 14. Use #requires Statements for Module Dependencies

```powershell
#requires -modules ActiveDirectory
#requires -version 5.1
```

### 15. #requires -version 5.1 is Mandatory

Every script must start with:
```powershell
#requires -version 5.1
```

---

## PowerShell Best Practices

### PowerShell 5.1 Compatibility

- Use traditional syntax
- Avoid new operators
- Test on Windows Server 2016+

### Parameter Validation

Use parameter validation attributes:

```powershell
param(
    [Parameter(Mandatory = $true)]
    [ValidateLength(3, 20)]
    [ValidatePattern('^[a-zA-Z0-9]+$')]
    [string]$UserName,
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("Enabled", "Disabled")]
    [string]$Status = "Enabled",
    
    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 100)]
    [int]$RetryCount = 3,
    
    [Parameter(Mandatory = $false)]
    [ValidateScript({ Test-Path $_ })]
    [string]$ConfigPath
)
```

### CmdletBinding() Usage

Always use `[CmdletBinding()]` for advanced functions:

```powershell
[CmdletBinding()]
param(
    [string]$UserName
)
```

### Parameter Set Definitions

Use parameter sets for mutually exclusive parameters:

```powershell
[CmdletBinding(DefaultParameterSetName = "Standard")]
param(
    [Parameter(ParameterSetName = "Standard")]
    [string]$UserName,
    
    [Parameter(ParameterSetName = "CSV")]
    [string]$CSVPath
)
```

### Code Structure Guidelines

Use regions to organize code:

```powershell
#region Parameters
param(...)
#endregion Parameters

#region Initialization
# Initialization code
#endregion Initialization

#region Main Logic
# Main script logic
#endregion Main Logic
```

### Progress Bar Requirements

For operations taking more than 2 seconds, use progress bars:

```powershell
$totalItems = $items.Count
$currentItem = 0

foreach ($item in $items) {
    $currentItem++
    $percentComplete = ($currentItem / $totalItems) * 100
    
    Write-Progress -Activity "Processing items" `
                  -Status "Processing item $currentItem of $totalItems" `
                  -PercentComplete $percentComplete `
                  -CurrentOperation "Processing: $($item.Name)"
    
    # Process item
}

Write-Progress -Activity "Processing items" -Completed
```

### Script Versioning

Include version information in comment-based help:

```powershell
.NOTES
    Version    : 1.0
    History    : 1.0 2026-10-06 Initial version
```

### Comment Standards

- All comments must be in English
- Explain **why**, not just **what**
- Comment complex logic
- Comment workarounds
- Keep comments current

**Good:**
```powershell
# Use -ErrorAction Stop to ensure errors are caught in try-catch
New-ADUser -Name $UserName -ErrorAction Stop
```

**Poor:**
```powershell
# Create user
New-ADUser -Name $UserName
```

### ErrorActionPreference Handling

Set `$ErrorActionPreference` at script start:

```powershell
$ErrorActionPreference = "Stop"
```

### WhatIf and Confirm Support

For destructive operations, add WhatIf and Confirm support:

```powershell
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$UserName
)

if ($PSCmdlet.ShouldProcess($UserName, "Create user")) {
    New-ADUser -Name $UserName
}
```

### Microsoft Documentation Verification in Comments

Add documentation references for cmdlets:

```powershell
# Get-ADUser: https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-aduser
# Verified: 2026-10-06
Get-ADUser -Identity $UserName
```

---

## Security Standards

### Password Handling

**Never log passwords:**

**Incorrect:**
```powershell
Write-Output "Password: $Password"
```

**Correct:**
```powershell
Write-Output "Password set successfully"
```

### Credential Handling

Use PSCredential objects:

```powershell
$Credential = Get-Credential
```

Never store passwords in plain text.

### Sensitive Data Logging Restrictions

- Do not log sensitive data (passwords, keys, tokens)
- Do not log PII unless necessary for troubleshooting
- Mask sensitive data in logs

### Audit Trail Requirements

For critical operations, maintain an audit trail:
- Log who performed the operation
- Log when the operation was performed
- Log what was changed
- Log the result

### Execution Policy Considerations

Scripts should work with common execution policies:
- RemoteSigned
- AllSigned
- Unrestricted (not recommended for production)

Document any execution policy requirements.

### Script Signing Recommendations

For production environments, consider script signing:
- Sign scripts with a code-signing certificate
- Verify signature before execution
- Document signing requirements

---

## Code Review Standards

### Review Checklist for New Scripts

Before merging a new script, verify:

- [ ] Script has `#requires -version 5.1`
- [ ] Script has corresponding .md documentation file
- [ ] All cmdlets verified against Microsoft documentation
- [ ] All state-changing operations have try-catch blocks
- [ ] No empty catch blocks
- [ ] No silent error suppression
- [ ] No Write-Host in production code
- [ ] String concatenation follows standards
- [ ] All inputs are validated
- [ ] All functions have comment-based help
- [ ] Examples provided in documentation
- [ ] README.md updated with script entry
- [ ] Documentation links in README.md are correct
- [ ] Script tested on Windows Server 2016/2019/2022/2025
- [ ] PowerShell 5.1 compatibility verified

### Approval Requirements

- Scripts must be reviewed by at least one other person
- AI-generated scripts must be reviewed by a human
- Security-sensitive scripts require additional review

### Testing Requirements

- Test in non-production environment first
- Test with different Windows Server versions
- Test error scenarios
- Test validation logic

### Documentation Requirements

- Documentation file created and complete
- README.md updated
- Microsoft documentation links verified
- Examples tested and verified

### Microsoft Documentation Verification Requirements

- All cmdlets verified against PowerShell 5.1 documentation
- Documentation references added to script comments
- Deprecated features avoided
- Module availability verified

### README.md Update Requirements

- Script entry added to appropriate category
- Script link is correct
- Documentation link is correct
- Description is accurate
- Version is correct
- License is correct

---

## Examples

### Error Handling Examples

**Correct:**
```powershell
try {
    New-ADUser -Name $UserName -Path $OUPath -ErrorAction Stop
    Write-Output "Successfully created user: " + $UserName
}
catch {
    Write-Error "Failed to create user '" + $UserName + "' in OU '" + $OUPath + "': " + $_.Exception.Message
    throw
}
```

**Incorrect:**
```powershell
try {
    New-ADUser -Name $UserName
}
catch {
    # Empty catch block - FORBIDDEN
}
```

### String Concatenation Examples

**Correct:**
```powershell
Write-Output "Server " + $ServerName + ": Failed"
Write-Output "Path: " + $Path + "\file.txt"
```

**Incorrect:**
```powershell
Write-Output "Server $ServerName: Failed"
Write-Output "Path: $Path\file.txt"
```

### Logging Examples

**Correct:**
```powershell
Write-Output "Creating user account: " + $UserName
try {
    New-ADUser -Name $UserName -ErrorAction Stop
    Write-Output "Successfully created user: " + $UserName
}
catch {
    Write-Error "Failed to create user '" + $UserName + "': " + $_.Exception.Message
    throw
}
```

### Validation Examples

**Correct:**
```powershell
try {
    New-ADUser -Name $UserName -ErrorAction Stop
}
catch {
    Write-Error "Failed to create user: " + $_.Exception.Message
    throw
}

# Validate
try {
    $user = Get-ADUser -Identity $UserName -ErrorAction Stop
    Write-Output "Validation successful: User exists"
}
catch {
    Write-Error "Validation failed: User was not created"
    throw
}
```

### Documentation File Example

See the [Documentation Templates](#documentation-templates) section.

### README.md Entry Example

```markdown
### ActiveDirectory

| Script | Documentation | Purpose | Version | License |
|--------|--------------|---------|---------|---------|
| [Get-DFSRBacklog.ps1](ActiveDirectory/Get-DFSRBacklog.ps1) | [Get-DFSRBacklog.md](ActiveDirectory/Get-DFSRBacklog.md) | Checks DFSR backlog and generates replication reports | 0.5 | GPLv3 |
```

---

## Documentation Templates

### Script Documentation Template

```markdown
# [Script Name]

[Brief description of script purpose]

## Purpose

[Detailed description of what the script does]

## Use Cases

- [Use case 1]
- [Use case 2]
- [Use case 3]

## Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| [ParameterName] | [Type] | [Default] | [Description] |

## Examples

### Example 1: [Description]
```powershell
.\[ScriptName].ps1 -[Parameter] [Value]
```

### Example 2: [Description]
```powershell
.\[ScriptName].ps1 -[Parameter] [Value] -[Parameter] [Value]
```

## Prerequisites

### Required Modules
- [Module 1]
- [Module 2]

### Required Permissions
- [Permission 1]
- [Permission 2]

### Environment Requirements
- [Requirement 1]
- [Requirement 2]

## Output Format

[Description of what the script outputs]

## Error Handling

[Description of error handling behavior]

## Dependencies

- [Dependency 1]
- [Dependency 2]

## Version History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| [Version] | [Date] | [Author] | [Changes] |

## Author

[Author Name]

## License

[License information]

## Microsoft Documentation Links

- [Cmdlet 1]: [URL]
- [Cmdlet 2]: [URL]

## GitHub Repository Link

- [Script File]: https://github.com/[username]/[repository]/blob/main/[path]/[ScriptName].ps1
```

---

## Exceptions Process

### Documenting Exceptions

If a script must deviate from these standards, document the exception:

1. **Create an exception entry** in the script documentation
2. **Explain why the exception is necessary**
3. **Get approval** from repository maintainer
4. **Document the approval** in the script header

### Exception Documentation Format

```powershell
<#
.EXCEPTION
    This script uses Write-Host for user interaction because it requires
    real-time feedback during long-running operations.
    Approved by: [Name]
    Date: [Date]
    Reason: [Reason]
#>
```

### Approval Process

1. Submit exception request with justification
2. Review by repository maintainer
3. Approval or rejection
4. Document approved exceptions

### Exception Review

Exceptions should be reviewed periodically to determine if:
- The exception is still necessary
- The standard can be updated to accommodate the use case
- The script can be refactored to comply with the standard

---

## Conclusion

These development standards ensure that all scripts in the Scripts repository are:
- Compatible with PowerShell 5.1
- Well-documented
- Reliable and maintainable
- Following best practices
- Verified against Microsoft documentation

Adherence to these standards improves code quality, reduces errors, and makes the repository easier to use and maintain.

For questions or suggestions for improving these standards, please contact the repository maintainer.
