<#
.SYNOPSIS
Creates backup of the GPO with according html Reports. The script creates a subfolder based upon an actual timestamp.
	
.DESCRIPTION
PowerShell script to periodically back up the Group Policy and documentation of version using HTML reports. Ideal as a scheduled task to perform regular backups of the GPO. Each backup creates a new subfolder with a time stamp.
The script does not require Administrative privileges. If the script runs with Administrative privileges, it will write status information to the event log.
Based opon the german blog article contained in the link. Get the actual Script version from Microsoft TechNet: http://bit.ly/gpobackup
If you like this script, please rate it in the TechNet Gallery.

.EXAMPLE 
C:\PS> get-GPOBackup.ps1

.EXAMPLE 
C:\PS> get-GPOBackup.ps1 -BackupPath C:\GPOBACKUP -KeepDate 90

.EXAMPLE 
C:\PS> get-GPOBackup.ps1 -BackupPath C:\GPOBACKUP -KeepDate 90 -Verbose

.PARAMETER 	BackupPath 
Path to Backup.

.PARAMETER 	KeepDate
Amount of days to keep the old versions.

.PARAMETER 	characters
Characters to be replaced in GPO names with an "_".

.PARAMETER PolicyDefinition
Switch to enable Backup of PolicyDefinition Files

.PARAMETER 	testerror
Switch to force an Error for testing

.PARAMETER 	testwarning
Switch to force an Warrning for testing

.PARAMETER 	testerrorwarning
Switch to force an Error with Warrning for testing

.NOTES
Author     : Fabian Niesen (www.fabian-niesen.de)
Filename   : get-GPOBackup.ps1
Requires   : PowerShell Version 4.0
Version    : 1.59
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
             1.60    FN  13.10.22  Addep PowerShell Creation for easier GPO export and import - only works with GPO Settings stored in Regestry Keys under HKEY_LOCAL_MACHINE and HKEY_CURRENT_USER Everthing under Software and System!

.LINK
https://www.infrastrukturhelden.de/microsoft-infrastruktur/active-directory/gruppenrichtlinien-richtig-sichern-und-dokumentieren.html
#>

Param(
	[Parameter(Mandatory=$false, Position=0, ValueFromPipeline=$False)]
	[String]$BackupPath="C:\Temp\GPOBackup",
    [Parameter(Mandatory=$false, Position=1, ValueFromPipeline=$False)]
    [Int]$KeepDate="93",
    [Parameter(Mandatory=$false, Position=2, ValueFromPipeline=$false)]
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
function Get-GPPolicyKey
        {
            param(
                [string]$gpoName,
                [string]$key
            )
            $ErrorActionPreference = "Stop"
            Write-Verbose "GPO: $gpoName - Key: $key"
            $hive = Get-GPRegistryValue -Name $gpoName -Key $key
            ForEach ($item in $hive)
            {
                Write-Verbose "Item: $($item.FullKeyPath)"
                if ($item.ValueName -ne $null) { [array]$result += $item }
                else { Get-GPPolicyKey -Key $item.FullKeyPath -gpoName $gpoName  }
            }
            return $result
        }

#endregion Functions 

#Verknüfungsorte mit speichern

$ErrorActionPreference = "Stop"
$GPList = @()
$regex = "[$([regex]::Escape($characters))]"
#[Array]$GPList = $null

$before = Get-Date

IF ($BackupPath.EndsWith("\") -like "False") { $BackupPath =$BackupPath+"\" }
IF (!(Test-Path $BackupPath)) { new-item -Path $BackupPath -ItemType directory }

$date = get-date -format yyyyMMdd-HHmm
$ErrorLog =$BackupPath+$date+"-error.log"
$InfoLog =$BackupPath+$date+"-info.log"
$WarningLog =$BackupPath+$date+"-warning.log"
$Report = $BackupPath+$date+"-Report.csv"
Write-Verbose "Import Grouppolicy module"
try
{
  Import-Module grouppolicy 
}
catch
{
  Write-Warning "GroupPolicy Module ist missing. Please install first"
  "GroupPolicy Module ist missing. Please install first" | Out-file $ErrorLog -Append
  break
}
try
{
  Import-Module activedirectory 
}
catch
{
  Write-Warning "ActiveDirectory Module ist missing. Please install first"
  "ActiveDirectory Module ist missing. Please install first" | Out-file $ErrorLog -Append
  break
}

Write-Verbose "Check if backup path is default"
IF ($BackupPath -eq "c:\temp\GPOBackup\")
{
  Write-Warning "No BackupPath provided, use C:\TEMP\GPOBackup. To provide a Backuppath use >Get-GPOBackup -BackupPath<" 
  "BackupPath not set, use default"| Out-file $WarningLog -Append
  $Wait = $True
}


IF ($KeepDate -eq "93")
{
  Write-Warning "No KeepDate provided, delete Backups older than 93 days. To provide a an other timeperiod use >Get-GPOBackup -KeepDate<" 
  "KeepDate not set, use default"| Out-file $WarningLog -Append
  $Wait = $True
}

IF ($Wait -eq $True) { Start-Sleep -s 10 }
Write-Verbose "Start housekeeping, deleting old backups"

try
{
  Write-Host "Start deleting Backups older than $KeepDate days" 
  Get-ChildItem $BackupPath |? {$_.PSIsContainer -and $_.LastWriteTime -le (Get-Date).AddDays(-$KeepDate)} |% {Remove-Item $_.Fullname -Recurse -Force }
}
catch
{
  $Error.Item($Error.Count - 1) | Format-List * -Force | Out-file $ErrorLog -Append
  "Deletion of old backups failed" | Out-file $ErrorLog -Append
  Write-Warning "Deletion of old backups failed"
}


$BackupPath =$BackupPath+$date
IF (!(Test-Path $BackupPath)) { New-Item -Path $BackupPath -ItemType directory | out-null }
ELSE 
{ 
  "Backup already exist. Script started twice or you use a time machine!" | Out-file $ErrorLog -Append  
  Write-Warning "Backup already exist. Script started twice or you use a time machine!"
  break
}

### Processing PolicyDefinitions
If ($PolicyDefinitions -eq $true) {
  Write-Verbose "Start policyDefinition Backup"
  $DomDNS = $(Get-ADDomain).DNSroot
  IF (Test-Path "C:\Windows\SYSVOL\domain\Policies\PolicyDefinitions") { Write-Verbose "Found Local SYSVOL Central Store" ; $PolDef = "C:\Windows\SYSVOL\domain\Policies\PolicyDefinitions" }
  elseif (Test-Path "\\$DomDNS\SYSVOL\$DomDNS\Policies\PolicyDefinitions") { $PolDef = "\\$DomDNS\SYSVOL\$DomDNS\Policies\PolicyDefinitions" }
  Else {Write-Warning "No Central Store Found. Central Store is needed for this feature, otherwise it is useless. Please Check"; "No Central Store Found. Backup failed"| Out-file $ErrorLog -Append ; Break}
  Write-Verbose "Found Central Store: $PolDef"
  Add-Type -assembly "system.io.compression.filesystem"
  $PDZip = $($BackupPath+"\PolicyDefinition.zip")
  If (Test-Path "$PDZip") {Write-Warning "Something went wrong, Target already exist. Timetravel?"} 
  Else {
    [io.compression.zipfile]::CreateFromDirectory($PolDef,$PDZip) 
  }
}

### Processing GPO
Write-Verbose "Query GPOs"
$GPOS = get-GPO -all
Write-Verbose "Start processing GPO"
Write-Progress -activity "Processing GPO" -Status "starting" -PercentComplete "0" -Id 1
[int]$i = "0"
FOREACH ( $GPO in $GPOS)
{
  $i++
  Write-Progress -activity "Processing GPO" -Status "$($GPO.DisplayName)" -PercentComplete (($i / $GPOS.count)*100) -Id 1
  $GPOname = $($GPO.DisplayName).Trim()
  $GPOname = $GPOname -replace $regex,"_"
  IF (!($($GPO.DisplayName) -eq $GPOname)) 
  { 
    Write-Verbose "Filtered GPO Name >$($GPO.DisplayName)< to: >$GPOname<" 
    "Filtered GPO Name >$($GPO.DisplayName)< to: >$GPOname<" | Out-File $InfoLog -Append
  }
  $bpath = $BackupPath+"\"+$GPOname
  New-Item -Path $bpath -ItemType directory | Out-Null
  Write-Verbose "Starting backup $($GPO.DisplayName)"
  try
  {
    $gptemp = Backup-Gpo -Name $($GPO.DisplayName) -Path $bpath 
    $GPitem = New-Object -TypeName psobject
    $GPitem | Add-Member -MemberType NoteProperty -Name DisplayName -Value $gptemp.DisplayName
    $GPitem | Add-Member -MemberType NoteProperty -Name GpoId -Value $gptemp.GpoId
    $GPitem | Add-Member -MemberType NoteProperty -Name Id -Value $gptemp.Id
    $GPitem | Add-Member -MemberType NoteProperty -Name BackupDirectory -Value $gptemp.BackupDirectory
    $GPitem | Add-Member -MemberType NoteProperty -Name CreationTime -Value $gptemp.CreationTime
    $GPitem | Add-Member -MemberType NoteProperty -Name DomainName -Value $gptemp.DomainName
    $GPitem | Add-Member -MemberType NoteProperty -Name Comment -Value $gptemp.Comment
    $GPList += $GPitem
  }
  catch
  {
    $Error.Item($Error.Count - 1) | Format-List * -Force | Out-file $ErrorLog -Append
    Write-Warning "$($GPO.DisplayName) backup failed"
    "$($GPO.DisplayName) Backup failed"| Out-file $ErrorLog -Append
  }
  Write-Verbose "Starting HTML report $($GPO.DisplayName)"
  try
  {
    Get-GPOReport $($GPO.DisplayName) -ReportType HTML -Path "$bpath\$GPOname.html" 
  }
  catch
  {
    $Error.Item($Error.Count - 1) | Format-List * -Force | Out-file $ErrorLog -Append
    Write-Warning "$($GPO.DisplayName) HTML report failed"
    "$($GPO.DisplayName) HTML report failed"| Out-file $ErrorLog -Append
  }
  IF ( $PowerShellExport )
  {
    Write-Verbose "Start PowerShell script creation"
    $exportcsv = $bpath  + "\" + $GPOname + "-PS.csv"
    $exportps = $bpath + "\" + $GPOname + ".ps1"
    Write-Verbose "ExportCSV: $exportcsv - ExportPS: $exportps"
    try { $settings = Get-GPPolicyKey -key "HKEY_LOCAL_MACHINE\Software" -gpoName $($GPO.DisplayName) -ErrorAction Stop }
    catch 
    { 
      Write-Host "No Policy under HKEY_LOCAL_MACHINE\Software" 
    }
    try { $settings += Get-GPPolicyKey -key "HKEY_LOCAL_MACHINE\System" -gpoName $($GPO.DisplayName) -ErrorAction Stop }
    catch 
    { 
      Write-Host "No Policy under HKEY_LOCAL_MACHINE\System" 
    }
    try { $settings += Get-GPPolicyKey -key "HKEY_CURRENT_USER\Software" -gpoName $($GPO.DisplayName) -ErrorAction Stop }
    catch 
    { 
      Write-Host "No Policy under HKEY_CURRENT_USER\Software" 
    }
    try { $settings += Get-GPPolicyKey -key "HKEY_CURRENT_USER\System" -gpoName $($GPO.DisplayName) -ErrorAction Stop }
    catch 
    { 
      Write-Host "No Policy under HKEY_CURRENT_USER\System" 
    }
    $settings = $settings.Where({ $null -ne $_ })
    Write-Verbose "Export CSV"
    $settings | Export-Csv -NoTypeInformation -Path $exportcsv -Force -Confirm:$false -Delimiter ";"
    Write-Progress -activity "Processing GPO $GPOname - $i of $j" -Status "Create PowerShell import script" -PercentComplete (($i / $GPOS.count)*100) -Id 1 -ErrorAction SilentlyContinue
    Write-Progress -activity "Create PowerShell import script" -Status "starting" -PercentComplete "0" -Id 2 -ParentId 1
    Write-Verbose "Found $(($settings).count)"
    [int]$i2 = 0
    [int]$j2 = $($settings).count
    ForEach ($setting in $settings)
    {
        $i2++
        Write-Progress -activity "Create PowerShell import script - $i2 of $j2" -Status $($setting.ValueName) -PercentComplete (($i2 / $j2 *100)) -Id 2 -ParentId 1 -ErrorAction SilentlyContinue 
        "Set-GPRegistryValue -Key " + $($setting.FullKeyPath) + " -Name '"+ $GPOname +"' -Type "+ $($setting.Type) + " -Value "+ $($setting.Value)+ " -ValueName " + $($setting.ValueName) | out-file -FilePath $exportps -Append
    }
  }
}

$GPList | Export-Csv $Report -NoTypeInformation -Delimiter ";"
Write-Output "Creating a report about all handled GPO. Please check $Report"

###Prepare Errorhandling Output
$EHMessage = @()
IF ((Test-Path $ErrorLog) -and (Test-Path $WarningLog))
{
  IF ($EHID -eq $null) { $EHID = "301" }
  $EHCategory = "Error"
  $EHMessage += "Backup completed with Errors and Warnings. Targetpath: $BackupPath"
  $EHMessage += "--- ERRORLOG $ErrorLog ---"
  $EHMessage += Get-Content $ErrorLog
  $EHMessage += "--- WARNINGLOG $WarningLog ---"
  $EHMessage += Get-Content $WarningLog

}
ELSEIF (Test-Path $ErrorLog)
{
  IF ($EHID -eq $null) { $EHID = "300" }
  $EHCategory = "Error"
  $EHMessage += "Backup completed with Errors. Targetpath: $BackupPath" 
  $EHMessage += "--- ERRORLOG $ErrorLog ---"
  $EHMessage += Get-Content $ErrorLog
}
ELSeIF (Test-Path $WarningLog)
{
  IF ($EHID -eq $null) { $EHID = "200" }
  $EHCategory = "Warning"
  $EHMessage += "Backup completed with Warnings. Targetpath: $BackupPath"
  $EHMessage += "--- WARNINGLOG $WarningLog ---"
  $EHMessage += Get-Content $WarningLog
}
ELSEIF (Test-Path $InfoLog)
{
  IF ($EHID -eq $null) { $EHID = "101" }
  $EHCategory = "Information"
  $EHMessage += "Backup completed only with Informations. Targetpath: $BackupPath"
  $EHMessage += "--- INFOLOG $InfoLog ---"
  $EHMessage += Get-Content $InfoLog
}
ELSE
  {
  IF ($EHID -eq $null) { $EHID = "100" }
  $EHCategory = "Information"
  $EHMessage += "Backup completed. Targetpath: $BackupPath"
  }

  IF ($testerrorwarning -eq $true) { $EHID = "301" ; $EHCategory = "Error" ; $EHMessage += "Test Error with Warnings" }
  ELSEIF ($testerror -eq $true) { $EHID = "300" ; $EHCategory = "Error" ; $EHMessage += "Test Error" }
  ELSEIF ($testwarning -eq $true) { $EHID = "200" ; $EHCategory = "Warning" ; $EHMessage += "Test Warning" }
  $Message = $EHMessage | Out-String
  IF ($EHCategory -like "Error" -or  $EHCategory -like "Warning") { Write-Warning $Message }
  ELSE { Write-output $Message }


Write-Verbose "Check Admin privilages for creation of the EventLog entries"
### Proof for administrative permissions (UAC) and start EventLog Handling
If (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole( [Security.Principal.WindowsBuiltInRole] "Administrator"))
{
  Write-Warning "Not run as administrator, eventlog handling will be disabled."
} ELSE {
  $skipeventlog = $false
  Try 
  { 
    Write-verbose "Check for Eventlog source"
    ( Get-EventLog -LogName Application -Source "GPObackup").count -ge 0 | Out-Null
  }
  Catch 
  {  
    Write-Verbose "Eventlog Source >GPObackup< not found. Try to create"
    "Eventlog Source >GPObackup< not found. Try to create" | Out-File $InfoLog -Append
    Try 
    {
      New-EventLog -LogName Application -Source "GPObackup"
    }
    catch 
    { 
      write-warning "Creating EventLog category failed, cancel eventlog handling"
      "Creating EventLog category failed, cancel eventlog handling"| Out-file $ErrorLog -Append 
      $skipeventlog = $true
    }
  }
  IF ( $skipeventlog -eq $false)
  {
    write-eventlog -logname Application -source "GPObackup" -EventId $EHID -EntryType $EHCategory -Message $Message 
    Write-verbose "Eventlog entry written."
    ### Add for verbose
    IF ($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent) { Get-EventLog -LogName Application -Source "GPObackup" -Newest 1 | FL }
  }
}

$after = Get-Date

$time = $after - $before
$buildTime = "`nBuild finished in ";
if ($time.Minutes -gt 0)
{
    $buildTime += "{0} minute(s) " -f $time.Minutes;
}

$buildTime += "{0} second(s)" -f $time.Seconds;
Write-verbose $buildTime
Write-verbose "Done. Have a nice day!"
