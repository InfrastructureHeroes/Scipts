<#
.SYNOPSIS
Creates backup of Group Policy Objects with HTML reports and optional PowerShell export scripts.

.DESCRIPTION
PowerShell script to periodically back up Group Policy Objects and document version changes using HTML reports. 
Ideal as a scheduled task to perform regular backups of GPOs. Each backup creates a new subfolder with a timestamp.
The script does not require Administrative privileges. If the script runs with Administrative privileges, it will write status information to the event log.
The script is compatible with PowerShell 5.1 and follows PowerShell best practices.

.PARAMETER BackupPath
Path to backup directory. Default is "C:\Temp\GPOBackup".

.PARAMETER KeepDate
Amount of days to keep old backup versions. Default is 93 days. Valid range: 1-365 days.

.PARAMETER characters
Characters to be replaced in GPO names with an underscore "_". Default is '. $%&!?#*:;\><|/"'.

.PARAMETER PolicyDefinitions
Switch to enable backup of PolicyDefinition files (Central Store).

.PARAMETER PowerShellExport
Switch to enable creation of PowerShell import scripts for registry-based GPO settings.

.PARAMETER testerror
Switch to force an Error for testing purposes.

.PARAMETER testwarning
Switch to force a Warning for testing purposes.

.PARAMETER testerrorwarning
Switch to force an Error with Warning for testing purposes.

.EXAMPLE
C:\PS> .\get-GPOBackup.ps1
Run with default settings (backup to C:\Temp\GPOBackup, keep 93 days).

.EXAMPLE
C:\PS> .\get-GPOBackup.ps1 -BackupPath C:\GPOBACKUP -KeepDate 90
Backup to C:\GPOBACKUP and keep backups for 90 days.

.EXAMPLE
C:\PS> .\get-GPOBackup.ps1 -BackupPath C:\GPOBACKUP -KeepDate 90 -PolicyDefinitions -PowerShellExport
Backup with PolicyDefinitions and PowerShell export scripts enabled.

.EXAMPLE
C:\PS> .\get-GPOBackup.ps1 -BackupPath C:\GPOBACKUP -KeepDate 90 -Verbose
Run with verbose output for detailed troubleshooting information.

.NOTES
Author     :  Fabian Niesen (infrastrukturhelden.de)
Filename   :  get-GPOBackup.ps1
Requires   :  PowerShell Version 5.1
Version    :  1.9
License    :  The MIT License (MIT)
              Copyright (c) 2022-2025 Fabian Niesen
              Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation 
              files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, 
              merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is 
              furnished to do so, subject to the following conditions:
              The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
              The Software is provided "as is", without warranty of any kind, express or implied, including but not limited to the warranties 
              of merchantability, fitness for a particular purpose and noninfringement. In no event shall the authors or copyright holders be 
              liable for any claim, damages or other liability, whether in an action of contract, tort or otherwise, arising from, out of or in 
              connection with the software or the use or other dealings in the Software.
Disclaimer :  This script is provided "as is" without warranty. Use at your own risk.
              The author assumes no responsibility for any damage or data loss caused by this script.
              Test thoroughly in a controlled environment before deploying to production.
History    : 1.0.0   FN  27/07/14  initial version
            1.1.0   FN  25/08/14  Change script to handle new GUID on GPO backup
            1.1.1   FN  03/09/14  Fix Targetpath for secured enviorment
            1.2     FN  20/01/15  move download to TechNet, translation to english, 
                                  implement Eventlog if Run as Admin
            1.3     FN  09/02/15  Change Name to get-GPOBackup, Change Path to parameter 
                                  instead Config, Implementing KeepDate, Implementing Error-Logging
            1.4     FN  25/02/15  Tracking runtime, fixes in documentation
            1.55    FN  11/08/17  Add some Debug Options. Filtering GPO Names for unwanted Characters
            1.56    FN  04/03/18  Fix Eventlog handling. Add additional Eventlog posibilities, 
                                  for this I change and add EventIDs. Some fixes with the get-Help output
            1.57    FN  06/02/19  Added "/" to Escape Chars
            1.58    FN  12/03/19  Added Central Store Backup
            1.59    FN  11/08/21  Added '"' to Escape Chars
            1.60    FN  13.10.22  Added PowerShell Creation for easier GPO export and import - only works with GPO Settings stored in Regestry Keys under HKEY_LOCAL_MACHINE and HKEY_CURRENT_USER Everthing under Software and System!
            1.61    FN  26.01.23  Small Improvements for Module loading
            1.7     FN  25.10.2025 Change License to GPLv3, except for 3rdparty code (e.g Function Get-GPPolicyKey)
            1.8     FN  03.12.2025 Changed License to MIT, housekeeping Header
            1.9     FN  14.08.2026 Optimized for PowerShell 5.1 compatibility, improved error handling, structured logging, AI Based optimization => Warning: This change the output format of the script and the logfiles. You may need to adjust your monitoring solution if you do not use Eventlog based monitoring.

.LINK
https://www.infrastrukturhelden.de/microsoft-infrastruktur/active-directory/gruppenrichtlinien-richtig-sichern-und-dokumentieren/
https://github.com/InfrastructureHeroes/Scipts/blob/master/GPO/get-GPOBackup.ps1
#>

param(
  [Parameter(Mandatory = $false, Position = 0, ValueFromPipeline = $False)]
  [ValidateScript({
      if (-not (Test-Path $_ -IsValid)) {
        throw "Invalid path format: $_"
      }
      $true
    })]
  [String]$BackupPath = "C:\Temp\GPOBackup",
  
  [Parameter(Mandatory = $false, Position = 1, ValueFromPipeline = $False)]
  [ValidateRange(1, 365)]
  [Int]$KeepDate = 93,
  
  [Parameter(Mandatory = $false, Position = 2, ValueFromPipeline = $false)]
  [string]$characters = '. $%&!?#*:;\><|/"',
  
  [switch]$PolicyDefinitions,
  [switch]$PowerShellExport,
  [switch]$testerror,
  [switch]$testwarning,
  [switch]$testerrorwarning
)
#region Functions 
########################
# Function found at: https://sdmsoftware.com/group-policy-videos/find-all-registry-settings-managed-in-a-gpo/
function Get-GPPolicyKey {
  param(
    [string]$gpoName,
    [string]$key
  )
  $ErrorActionPreference = "Stop"
  Write-Verbose "GPO: $gpoName - Key: $key"
  $hive = Get-GPRegistryValue -Name $gpoName -Key $key -ErrorAction Stop
  foreach ($item in $hive) {
    Write-Verbose "Item: $($item.FullKeyPath)"
    if ($item.ValueName -ne $null) { [array]$result += $item }
    else { Get-GPPolicyKey -Key $item.FullKeyPath -gpoName $gpoName }
  }
  return $result
}

function Write-Log {
  <#
  .SYNOPSIS
    Writes log messages to appropriate log files based on log level.

  .DESCRIPTION
    This function writes timestamped log messages to different log files based on the specified log level.
    Log levels: 0 = Information, 1 = Warning, 2 = Error.

  .PARAMETER Message
    The message to write to the log.

  .PARAMETER LogLevel
    The log level (0 = Information, 1 = Warning, 2 = Error). Default is 0.

  .EXAMPLE
    Write-Log -Message "Backup completed successfully" -LogLevel 0

  .EXAMPLE
    Write-Log -Message "Failed to backup GPO" -LogLevel 2
  #>
  param(
    [Parameter(Mandatory = $true)]
    [string]$Message,
    
    [Parameter(Mandatory = $false)]
    [ValidateSet(0, 1, 2, 3)]
    [int]$LogLevel = 0
  )
  
  $logFile = switch ($LogLevel) {
    0 { $script:InfoLog }
    1 { $script:InfoLog }
    2 { $script:WarningLog }
    3 { $script:ErrorLog }
  }
  
  # Remove manually-embedded bracketed severity prefixes to prevent duplicate labels.
  $cleanedMessage = $Message -replace '^\s*(?i)\[(info|warning|error)\]\s*'

  switch ($LogLevel) {
    0 { [String]$prefix = 'Info:' }
    1 { [String]$prefix = 'Info:' }
    2 { [String]$prefix = 'Warning:' }
    3 { [String]$prefix = 'Error:' }
  }

  $foregroundColor = switch ($LogLevel) {
    0 { 'White' }
    1 { 'White' }
    2 { 'Yellow' }
    3 { 'Red' }
  }

  Write-Host "$prefix $cleanedMessage" -ForegroundColor $foregroundColor

  [String]$TimeGenerated = "$(Get-Date -Format HH:mm:ss).$((Get-Date).Millisecond)+000"
  [String]$Line = '<![LOG[{0}]LOG]!><time="{1}" date="{2}" component="{3}" context="" type="{4}" thread="" file="">'
  $Execname = try { ($MyInvocation.ScriptName | Split-Path -Leaf -ErrorAction stop) } catch { "NoScript" }
  # CMTrace/SCCM type values do not define 0; treat 0 as informational (1) in the file.
  $fileLogLevel = if ($LogLevel -eq 0) { 1 } else { $LogLevel }
  $LineFormat = $cleanedMessage, $TimeGenerated, (Get-Date -Format MM-dd-yyyy), "$($Execname):$($MyInvocation.ScriptLineNumber)", $fileLogLevel
  $Line = $Line -f $LineFormat
  $Line | Out-File -FilePath $logFile -Append -Encoding UTF8
}

#endregion Functions 

# Save junction points
$scriptversion = "1.9"
Write-Output "Get-GPOBackup.ps1 Version $scriptversion "
$ErrorActionPreference = "Stop"
$GPOBackupList = [System.Collections.ArrayList]::new()
$regex = "[$([regex]::Escape($characters))]"
$before = Get-Date

# Ensure backup path ends with backslash
if (-not $BackupPath.EndsWith("\")) { 
  $BackupPath = $BackupPath + "\" 
}

# Create backup directory if it doesn't exist
if (!(Test-Path $BackupPath)) { 
  try {
    New-Item -Path $BackupPath -ItemType directory -ErrorAction Stop | Out-Null
    Write-Verbose "Created backup directory: $BackupPath"
  }
  catch {
    Write-Error "Failed to create backup directory '$BackupPath': $_"
    throw
  }
}

$date = Get-Date -Format yyyyMMdd-HHmm
$ErrorLog = Join-Path $BackupPath "${date}-error.log"
$InfoLog = Join-Path $BackupPath "${date}-info.log"
$WarningLog = Join-Path $BackupPath "${date}-warning.log"
$Report = Join-Path $BackupPath "${date}-Report.csv"

Write-Verbose "Checking required Windows features"
$requiredFeatures = @('GPMC', 'RSAT-AD-PowerShell')
foreach ($feature in $requiredFeatures) {
  $featureState = Get-WindowsFeature -Name $feature -ErrorAction Stop
  if ($featureState.InstallState -ne 'Installed') {
    Write-Warning "Missing Windows Feature $feature - attempting installation"
    try {
      Install-WindowsFeature -Name $feature -ErrorAction Stop
      Write-Verbose "Successfully installed feature: $feature"
    }
    catch {
      Write-Error "Failed to install $feature : $_"
      throw
    }
  }
  else {
    Write-Verbose "Feature $feature is already installed"
  }
}

Write-Verbose "Check if backup path is default"
if ($BackupPath -eq "c:\temp\GPOBackup\") {
  Write-Log -Message "BackupPath not set, use default (C:\TEMP\GPOBackup)" -LogLevel 2
  $Wait = $True
}

if ($KeepDate -eq 93) {
  Write-Log -Message "KeepDate not set, use default (93 days)" -LogLevel 2
  $Wait = $True
}

if ($Wait -eq $True) { Start-Sleep -s 10 }
Write-Verbose "Start housekeeping, deleting old backups"

try {
  Write-Host "Start deleting Backups older than $KeepDate days" 
  Get-ChildItem $BackupPath -ErrorAction Stop | Where-Object { $_.PSIsContainer -and $_.LastWriteTime -le (Get-Date).AddDays(-$KeepDate) } | ForEach-Object { 
    try {
      Remove-Item $_.Fullname -Recurse -Force -ErrorAction Stop
      Write-Verbose "Deleted old backup: $($_.FullName)"
    }
    catch {
      Write-Log -Message "Failed to delete old backup '$($_.FullName)': $_" -LogLevel 2
    }
  }
  Write-Log -Message "Successfully completed housekeeping of old backups" -LogLevel 0
}
catch {
  Write-Log -Message "Deletion of old backups failed: $_" -LogLevel 3
}

$BackupPath = Join-Path $BackupPath $date
if (!(Test-Path $BackupPath)) { 
  try {
    New-Item -Path $BackupPath -ItemType directory -ErrorAction Stop | Out-Null
    Write-Verbose "Created backup directory: $BackupPath"
  }
  catch {
    Write-Log -Message "Failed to create backup directory '$BackupPath': $_" -LogLevel 3
    throw
  }
}
else { 
  Write-Log -Message "Backup already exist. Script started twice or you use a time machine!" -LogLevel 3
  break
}

### Processing PolicyDefinitions
if ($PolicyDefinitions -eq $true) {
  Write-Verbose "Start policyDefinition Backup"
  try {
    $DomDNS = $(Get-ADDomain -ErrorAction Stop).DNSroot
    $PolDef = $null
    
    if (Test-Path "C:\Windows\SYSVOL\domain\Policies\PolicyDefinitions") { 
      Write-Verbose "Found Local SYSVOL Central Store" 
      $PolDef = "C:\Windows\SYSVOL\domain\Policies\PolicyDefinitions" 
    }
    elseif (Test-Path "\\$DomDNS\SYSVOL\$DomDNS\Policies\PolicyDefinitions") { 
      $PolDef = "\\$DomDNS\SYSVOL\$DomDNS\Policies\PolicyDefinitions" 
    }
    else { 
      Write-Log -Message "No Central Store Found. Central Store is needed for this feature, otherwise it is useless. Please Check" -LogLevel 3
      break 
    }
    
    Write-Verbose "Found Central Store: $PolDef"
    Add-Type -assembly "system.io.compression.filesystem"
    $PDZip = Join-Path $BackupPath "PolicyDefinition.zip"
    
    if (Test-Path $PDZip) { 
      Write-Log -Message "PolicyDefinition backup target already exists: $PDZip" -LogLevel 2
    } 
    else {
      try {
        [io.compression.zipfile]::CreateFromDirectory($PolDef, $PDZip)
        Write-Log -Message "Successfully backed up PolicyDefinitions to: $PDZip" -LogLevel 0
      }
      catch {
        Write-Log -Message "Failed to create PolicyDefinition backup: $_" -LogLevel 3
      }
    }
  }
  catch {
    Write-Log -Message "PolicyDefinitions backup failed: $_" -LogLevel 3
  }
}

### Processing GPO
Write-Verbose "Query GPOs"
try {
  $GPOS = Get-GPO -All -ErrorAction Stop
  Write-Verbose "Found $($GPOS.Count) GPOs to process"
}
catch {
  Write-Log -Message "Failed to retrieve GPOs: $_" -LogLevel 3
  throw
}

Write-Verbose "Start processing GPO"
Write-Progress -Activity "Processing GPO" -Status "starting" -PercentComplete "0" -Id 1
[int]$i = 0
$totalGPOs = $GPOS.Count

foreach ($GPO in $GPOS) {
  $i++
  $percentComplete = ($i / $totalGPOs) * 100
  Write-Progress -Activity "Processing GPO" -Status "$($GPO.DisplayName) ($i of $totalGPOs)" -PercentComplete $percentComplete -Id 1
  
  $GPOname = $($GPO.DisplayName).Trim()
  $GPOname = $GPOname -replace $regex, "_"
  
  if (!($($GPO.DisplayName) -eq $GPOname)) { 
    Write-Log -Message "Filtered GPO Name >$($GPO.DisplayName)< to: >$GPOname<" -LogLevel 0
  }
  
  $backupDirectory = Join-Path $BackupPath $GPOname
  
  try {
    New-Item -Path $backupDirectory -ItemType directory -ErrorAction Stop | Out-Null
    Write-Verbose "Created backup directory: $backupDirectory"
  }
  catch {
    Write-Log -Message "Failed to create backup directory '$backupDirectory': $_" -LogLevel 3
    continue
  }
  
  Write-Verbose "Starting backup $($GPO.DisplayName)"
  try {
    $gpoBackupResult = Backup-GPO -Name $($GPO.DisplayName) -Path $backupDirectory -ErrorAction Stop
    
    $GPitem = [PSCustomObject]@{
      DisplayName     = $gpoBackupResult.DisplayName
      GpoId           = $gpoBackupResult.GpoId
      Id              = $gpoBackupResult.Id
      BackupDirectory = $gpoBackupResult.BackupDirectory
      CreationTime    = $gpoBackupResult.CreationTime
      DomainName      = $gpoBackupResult.DomainName
      Comment         = $gpoBackupResult.Comment
    }
    
    [void]$GPOBackupList.Add($GPitem)
    Write-Log -Message "Successfully backed up GPO: $($GPO.DisplayName)" -LogLevel 0
  }
  catch {
    Write-Log -Message "$($GPO.DisplayName) backup failed: $_" -LogLevel 3
  }
  
  Write-Verbose "Starting HTML report $($GPO.DisplayName)"
  try {
    $htmlReportPath = Join-Path $backupDirectory "${GPOname}.html"
    Get-GPOReport -Name $($GPO.DisplayName) -ReportType HTML -Path $htmlReportPath -ErrorAction Stop
    Write-Log -Message "Successfully created HTML report for: $($GPO.DisplayName)" -LogLevel 0
  }
  catch {
    Write-Log -Message "$($GPO.DisplayName) HTML report failed: $_" -LogLevel 2
  }
  
  if ($PowerShellExport) {
    Write-Verbose "Start PowerShell script creation"
    $exportcsv = Join-Path $backupDirectory "${GPOname}-PS.csv"
    $exportps = Join-Path $backupDirectory "${GPOname}.ps1"
    Write-Verbose "ExportCSV: $exportcsv - ExportPS: $exportps"
    
    $settings = @()
    $registryKeys = @(
      "HKEY_LOCAL_MACHINE\Software",
      "HKEY_LOCAL_MACHINE\System", 
      "HKEY_CURRENT_USER\Software",
      "HKEY_CURRENT_USER\System"
    )
    
    foreach ($key in $registryKeys) {
      try {
        $keySettings = Get-GPPolicyKey -key $key -gpoName $($GPO.DisplayName) -ErrorAction Stop
        if ($keySettings) {
          $settings += $keySettings
        }
      }
      catch {
        Write-Verbose "No Policy under $key for GPO $($GPO.DisplayName)"
      }
    }
    
    $settings = $settings.Where({ $null -ne $_ })
    
    if ($settings.Count -gt 0) {
      Write-Verbose "Export CSV with $($settings.Count) settings"
      try {
        $settings | Export-Csv -NoTypeInformation -Path $exportcsv -Force -Confirm:$false -Delimiter ";" -ErrorAction Stop
        Write-Log -Message "Successfully exported CSV for GPO: $($GPO.DisplayName)" -LogLevel 0
      }
      catch {
        Write-Log -Message "Failed to export CSV for GPO $($GPO.DisplayName): $_" -LogLevel 3
      }
      
      Write-Progress -Activity "Processing GPO $GPOname - $i of $totalGPOs" -Status "Create PowerShell import script" -PercentComplete (($i / $totalGPOs) * 100) -Id 1 -ErrorAction SilentlyContinue
      Write-Progress -Activity "Create PowerShell import script" -Status "starting" -PercentComplete "0" -Id 2 -ParentId 1
      Write-Verbose "Found $($settings.Count) registry settings"
      
      [int]$i2 = 0
      [int]$j2 = $settings.Count
      
      foreach ($setting in $settings) {
        $i2++
        Write-Progress -Activity "Create PowerShell import script - $i2 of $j2" -Status $($setting.ValueName) -PercentComplete (($i2 / $j2 * 100)) -Id 2 -ParentId 1 -ErrorAction SilentlyContinue 
        
        try {
          $psLine = "Set-GPRegistryValue -Key '$($setting.FullKeyPath)' -Name '$GPOname' -Type '$($setting.Type)' -Value '$($setting.Value)' -ValueName '$($setting.ValueName)'"
          $psLine | Out-File -FilePath $exportps -Append -ErrorAction Stop
        }
        catch {
          Write-Log -Message "Failed to write PowerShell export line: $_" -LogLevel 3
        }
      }
      
      Write-Progress -Activity "Create PowerShell import script" -Completed -Id 2
    }
    else {
      Write-Verbose "No registry settings found for GPO $($GPO.DisplayName)"
    }
  }
}

Write-Progress -Activity "Processing GPO" -Completed -Id 1

$GPOBackupList | Export-Csv $Report -NoTypeInformation -Delimiter ";"
Write-Output "Creating a report about all handled GPO. Please check $Report"
Write-Log -Message "GPO backup process completed. Processed $($GPOBackupList.Count) GPOs." -LogLevel 0

### Prepare Error Handling Output
$EHMessage = @()
$EHID = $null
$EHCategory = "Information"

if ((Test-Path $ErrorLog) -and (Test-Path $WarningLog)) {
  $EHID = "301"
  $EHCategory = "Error"
  $EHMessage += "Backup completed with Errors and Warnings. Targetpath: $BackupPath"
  $EHMessage += "--- ERRORLOG $ErrorLog ---"
  $EHMessage += Get-Content $ErrorLog -ErrorAction SilentlyContinue
  $EHMessage += "--- WARNINGLOG $WarningLog ---"
  $EHMessage += Get-Content $WarningLog -ErrorAction SilentlyContinue
}
elseif (Test-Path $ErrorLog) {
  $EHID = "300"
  $EHCategory = "Error"
  $EHMessage += "Backup completed with Errors. Targetpath: $BackupPath" 
  $EHMessage += "--- ERRORLOG $ErrorLog ---"
  $EHMessage += Get-Content $ErrorLog -ErrorAction SilentlyContinue
}
elseif (Test-Path $WarningLog) {
  $EHID = "200"
  $EHCategory = "Warning"
  $EHMessage += "Backup completed with Warnings. Targetpath: $BackupPath"
  $EHMessage += "--- WARNINGLOG $WarningLog ---"
  $EHMessage += Get-Content $WarningLog -ErrorAction SilentlyContinue
}
elseif (Test-Path $InfoLog) {
  $EHID = "101"
  $EHCategory = "Information"
  $EHMessage += "Backup completed only with Informations. Targetpath: $BackupPath"
  $EHMessage += "--- INFOLOG $InfoLog ---"
  $EHMessage += Get-Content $InfoLog -ErrorAction SilentlyContinue
}
else {
  $EHID = "100"
  $EHCategory = "Information"
  $EHMessage += "Backup completed successfully. Targetpath: $BackupPath"
}

# Handle test parameters
if ($testerrorwarning -eq $true) { 
  $EHID = "301" 
  $EHCategory = "Error" 
  $EHMessage += "Test Error with Warnings" 
}
elseif ($testerror -eq $true) { 
  $EHID = "300" 
  $EHCategory = "Error" 
  $EHMessage += "Test Error" 
}
elseif ($testwarning -eq $true) { 
  $EHID = "200" 
  $EHCategory = "Warning" 
  $EHMessage += "Test Warning" 
}

$Message = $EHMessage | Out-String


Write-Verbose "Check Admin privileges for creation of the EventLog entries"
### Check for administrative permissions (UAC) and start EventLog Handling
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")

if (-not $isAdmin) {
  Write-Warning "Not run as administrator, eventlog handling will be disabled."
  Write-Log -Message "Script not running as administrator, eventlog handling disabled" -LogLevel 2
}
else {
  $skipeventlog = $false
  try { 
    Write-Verbose "Check for Eventlog source"
    $null = Get-EventLog -LogName Application -Source "GPObackup" -ErrorAction Stop
    Write-Verbose "Eventlog source 'GPObackup' exists"
  }
  catch {  
    Write-Verbose "Eventlog Source 'GPObackup' not found. Attempting to create"
    Write-Log -Message "Eventlog Source 'GPObackup' not found. Attempting to create" -LogLevel 0
    
    try {
      New-EventLog -LogName Application -Source "GPObackup" -ErrorAction Stop
      Write-Verbose "Successfully created Eventlog source 'GPObackup'"
      Write-Log -Message "Successfully created Eventlog source 'GPObackup'" -LogLevel 0
    }
    catch { 
      Write-Warning "Creating EventLog category failed, cancel eventlog handling"
      Write-Log -Message "Creating EventLog category failed: $_" -LogLevel 3
      $skipeventlog = $true
    }
  }
  
  if (-not $skipeventlog) {
    try {
      Write-EventLog -LogName Application -Source "GPObackup" -EventId $EHID -EntryType $EHCategory -Message $Message -ErrorAction Stop
      Write-Verbose "Eventlog entry written successfully."
      Write-Log -Message "Eventlog entry written with ID $EHID and category $EHCategory" -LogLevel 0
      
      # Show eventlog entry if verbose is enabled
      if ($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent) { 
        Get-EventLog -LogName Application -Source "GPObackup" -Newest 1 -ErrorAction SilentlyContinue | Format-List 
      }
    }
    catch {
      Write-Log -Message "Failed to write to Eventlog: $_" -LogLevel 3
    }
  }
}

$after = Get-Date
$time = $after - $before

$buildTime = "Backup completed in "
if ($time.Minutes -gt 0) {
  $buildTime += "{0} minute(s) " -f $time.Minutes
}
$buildTime += "{0} second(s)" -f $time.Seconds

Write-Verbose $buildTime
Write-Log -Message $buildTime -LogLevel 0
Write-Verbose "Done. Have a nice day!"
Write-Log -Message "GPO backup process completed successfully" -LogLevel 0
