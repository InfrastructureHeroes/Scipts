#requires -version 5.1
#requires -modules activedirectory

<#
	.SYNOPSIS
		Checks the DFSR backlog and generates replication reports for DFS Replication groups.
	.DESCRIPTION
		This script analyzes the DFS Replication status on the local server and within the Active Directory environment. It creates propagation tests and reports, determines backlog values between DFSR members, optionally exports detailed results to CSV, and can also compare file hashes between replication partners.
        
        DISCLAIMER
        This script is provided "as is" without any warranty of any kind, express or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose, and noninfringement. 
        Use of this script is at your own risk. The author assumes no responsibility for any damage or data loss caused by the use of this script.

        (c) 2026 Fabian Niesen, www.infrastrukturhelden.de - License: GNU General Public License v3 (GPLv3), see notes for details
	.EXAMPLE
        Get-DFSRBacklog.ps1 -LogPath "C:\Temp\DFSRMonitor" -Verbose
        This will execute the script and create logfiles and CSV exports in C:\Temp\DFSRMonitor. The -Verbose switch will show additional information about the DFSR replication groups and folders.
	.INPUTS
		none
	.OUTPUTS
		none
    .PARAMETER CompareHashes
        Compares file hashes between replication partners after the backlog analysis to help identify content mismatches.

    .PARAMETER ReplicationGroupList
        Limits the backlog analysis to the specified DFS Replication groups. If not specified, all available replication groups are processed.

    .PARAMETER LogPath
        Defines the path where log files, HTML reports, and CSV exports are created. Default: C:\Temp\DFSRMonitor

    .PARAMETER CSVFilename
        Defines the file name used for the CSV backlog export. The current timestamp is prefixed automatically. Default: DFSR-Backlog.csv

	.NOTES
		Author     : Fabian Niesen
		Filename   : get-DFSRBacklog.ps1
		Requires   : PowerShell Version 5.1
        License    : GNU General Public License v3 (GPLv3)
                    (c) 2026 Fabian Niesen, www.infrastrukturhelden.de
                    This script is licensed under the GNU General Public License v3 (GPLv3). 
                    You can redistribute it and/or modify it under the terms of the GPLv3 as published by the Free Software Foundation.
                    This script is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of
                    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details. 
                    See https://www.gnu.org/licenses/gpl-3.0.html for the full license text.
		
		Version    : 0.6  FN  06.10.2026 Optimized version
		History    : 0.6  FN  06.10.2026 Added parameter validation, comprehensive error handling, progress bars, performance optimizations, fixed variable naming and typos
		            0.5  FN  28.03.2026 First public version
                    
                    
    .LINK
        https://github.com/InfrastructureHeroes/Scipts/blob/master/ActiveDirectory/get-DFSRBacklog.ps1
#>

[cmdletbinding()]
param (
    [Switch]$CompareHashes,
    
    [String[]]$ReplicationGroupList = @(),
    
    [ValidateNotNullOrEmpty()]
    [ValidateScript({
            if (-not (Test-Path -Path $_ -IsValid)) {
                throw "Invalid path: ${_}"
            }
            $true
        })]
    [string]$LogPath = "C:\Temp\DFSRMonitor",
    
    [ValidateNotNullOrEmpty()]
    [ValidatePattern('^[a-zA-Z0-9_\-\.]+\.csv$')]
    [string]$CSVFilename = "DFSR-Backlog.csv"
)
try {
    $WindowsInstallationType = (Get-ComputerInfo).WindowsInstallationType
    if ($WindowsInstallationType -like "Server Core") {
        $IsServerCore = $true
    }
    else {
        $IsServerCore = $false
    }
    Write-Verbose "Detect Server Core: $IsServerCore"
}
catch {
    Write-Error "Failed to detect Windows installation type: ${_}"
    exit 1
}
$ScriptVersion = "0.6"
$ScriptName = $($myInvocation.MyCommand.Name).Replace('.ps1', '')
"Get-DFSRBacklog.ps1 by Fabian Niesen, www.infrastrukturhelden.de - License: GNU General Public License v3 (GPLv3), see notes for details" | Write-Output
"Start $ScriptName $ScriptVersion - Executed on $($Env:COMPUTERNAME) by $($Env:USERNAME) at $(Get-Date -Format 'HH:mm dd.MM.yyyy' )" | Write-Output
if ($IsServerCore -eq $true) {
    Write-Output "Core Installation Setup..."   
    try {
        $InAD = Install-WindowsFeature -Name FS-DFS-Namespace, FS-DFS-Replication -IncludeManagementTools -ErrorAction Stop
        Write-Verbose "Successfully installed DFS features for Server Core"
    }
    catch {
        Write-Error "Failed to install DFS features for Server Core: ${_}"
        exit 1
    }
    try {
        Set-SConfig -AutoLaunch $false
    }
    catch {
        Write-Warning "Failed to configure SConfig: ${_}"
    }
}
else {
    Write-Output "Desktop Experience Installation Setup..."     
    try {
        $InAD = Install-WindowsFeature -Name RSAT-DFS-Mgmt-Con -IncludeManagementTools -ErrorAction Stop
        Write-Verbose "Successfully installed RSAT DFS Management Console"
    }
    catch {
        Write-Error "Failed to install RSAT DFS Management Console: ${_}"
        exit 1
    }
}
try {
    Import-Module -Name DFSR -Verbose:$false -ErrorAction Stop
    Import-Module -Name ActiveDirectory -Verbose:$false -ErrorAction Stop
}
catch {
    Write-Error "Failed to import required modules: ${_}"
    exit 1
}

if ($LogPath.EndsWith("\") -eq $false) {
    $LogPath = $LogPath + "\"
}

try {
    if (!(Test-Path $LogPath)) {
        New-Item -Path $LogPath -ItemType directory -ErrorAction Stop | Out-Null
        Write-Verbose "Created log directory: $LogPath"
    }
}
catch {
    Write-Error "Failed to create log directory '$LogPath': ${_}"
    exit 1
}

Write-Output "Logpath is set to: $LogPath"
Write-Output "SysVol is only visable in the last test!"
Write-Output "=========================="
$date = Get-Date -Format yyyyMMdd-HHmm
$CSVExport = $LogPath + "\" + $date + $CSVFilename

try {
    $DFSRServers = Get-ADDomain | Select-Object -ExpandProperty ReplicaDirectoryServers -ErrorAction Stop
    Write-Verbose "Successfully retrieved DFSR servers from AD"
}
catch {
    Write-Error "Failed to retrieve DFSR servers from Active Directory: ${_}"
    exit 1
}
Write-Verbose "*********"
if ( $PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent) { $DFSRServers | Format-Table -AutoSize }
Write-Verbose "*********"
Write-Output "Start DFSR Propagation Test"

try {
    $AllReplicationGroups = Get-DfsReplicationGroup -IncludeSysvol -ErrorAction Stop
    $DFSRFolders = $AllReplicationGroups | Get-DfsReplicatedFolder
    
    $TotalFolders = $DFSRFolders.Count
    $CurrentFolder = 0
    
    foreach ($DFSRFolder in $DFSRFolders) {
        $CurrentFolder++
        $PercentComplete = ($CurrentFolder / $TotalFolders) * 100
        
        Write-Progress -Activity "DFS Replication Propagation Test" `
            -Status "Processing folder $CurrentFolder of $TotalFolders" `
            -PercentComplete $PercentComplete `
            -CurrentOperation "Folder: $($DFSRFolder.FolderName)"
        
        $GroupMembers = $AllReplicationGroups | Where-Object { $_.GroupName -eq $DFSRFolder.GroupName } | Get-DfsrMember
        
        foreach ($DFSRMember in $GroupMembers) {
            try {
                Start-DfsrPropagationTest -FolderName $DFSRFolder.FolderName -ReferenceComputerName $DFSRMember.ComputerName -ErrorAction Stop
                Write-Verbose "Started propagation test for $($DFSRFolder.FolderName) on $($DFSRMember.ComputerName)"
            }
            catch {
                Write-Warning "Failed to start propagation test for $($DFSRFolder.FolderName) on $($DFSRMember.ComputerName): ${_}"
            }
        }
    }
    
    Write-Progress -Activity "DFS Replication Propagation Test" -Completed
}
catch {
    Write-Error "Failed during propagation test: ${_}"
    exit 1
}
Write-Output "Wait 60 Seconds for DFS-R Replication"
Start-Sleep -Seconds 60
Write-Output "Create DFSR Propagation Test Reports"

Write-Verbose "*********"
if ($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent) { $DFSRFolders | Format-Table -AutoSize }
Write-Verbose "*********"

try {
    $TotalFolders = $DFSRFolders.Count
    $CurrentFolder = 0
    
    foreach ($DFSRFolder in $DFSRFolders) {
        $CurrentFolder++
        $PercentComplete = ($CurrentFolder / $TotalFolders) * 100
        
        Write-Progress -Id 1 -Activity "DFS Replication Report Generation" `
            -Status "Processing folder $CurrentFolder of $TotalFolders" `
            -PercentComplete $PercentComplete `
            -CurrentOperation "Folder: $($DFSRFolder.FolderName)"
        
        $GroupMembers = $AllReplicationGroups | Where-Object { $_.GroupName -eq $DFSRFolder.GroupName } | Get-DfsrMember
        $TotalMembers = $GroupMembers.Count
        $CurrentMember = 0
        
        foreach ($DFSRMember in $GroupMembers) {
            $CurrentMember++
            $MemberPercent = ($CurrentMember / $TotalMembers) * 100
            
            Write-Progress -Id 2 -ParentId 1 -Activity "Generating Reports for $($DFSRFolder.FolderName)" `
                -Status "Processing member $CurrentMember of $TotalMembers" `
                -PercentComplete $MemberPercent `
                -CurrentOperation "Member: $($DFSRMember.ComputerName)"
            
            $MemberLogPath = $LogPath + $DFSRMember.ComputerName
            
            try {
                if (!(Test-Path $MemberLogPath)) {
                    New-Item -Path $MemberLogPath -ItemType directory -ErrorAction Stop | Out-Null
                    Write-Verbose "Created directory: $MemberLogPath"
                }
                
                Write-DfsrPropagationReport -FolderName $DFSRFolder.FolderName -GroupName $DFSRFolder.GroupName -ReferenceComputerName $DFSRMember.ComputerName -Path $MemberLogPath -FileCount 5 -ErrorAction Stop
                Start-Sleep -Seconds 2
                
                $Report = (Get-ChildItem -Path $MemberLogPath -Filter *.html | Sort-Object -Descending -Property LastWriteTime)[0].FullName
                Write-Output "Check DFS-R Propagation Report: $Report"
                
                if ($IsServerCore -eq $false) {
                    try {
                        & $Report
                    }
                    catch {
                        Write-Warning "Failed to open report: ${_}"
                    }
                }
            }
            catch {
                Write-Warning "Failed to generate report for $($DFSRFolder.FolderName) on $($DFSRMember.ComputerName): ${_}"
            }
        }
        
        Write-Progress -Id 2 -Activity "Generating Reports for $($DFSRFolder.FolderName)" -Completed
    }
    
    Write-Progress -Id 1 -Activity "DFS Replication Report Generation" -Completed
}
catch {
    Write-Error "Failed during report generation: ${_}"
    exit 1
}
Write-Warning "DFSRState - this output might not be reliable! This shows only normal backlog when everything is smooth"

try {
    $TotalServers = $DFSRServers.Count
    $CurrentServer = 0
    
    foreach ($DFSRServer in $DFSRServers) {
        $CurrentServer++
        $PercentComplete = ($CurrentServer / $TotalServers) * 100
        
        Write-Progress -Activity "Checking DFSR State" `
            -Status "Processing server $CurrentServer of $TotalServers" `
            -PercentComplete $PercentComplete `
            -CurrentOperation "Server: $DFSRServer"
        
        Write-Output "Server: $DFSRServer"
        try {
            Get-DfsrState -ComputerName $DFSRServer -Verbose -ErrorAction Stop
        }
        catch {
            Write-Warning "Get-DfsrState failed for $DFSRServer - WinRM may not be available: ${_}"
        }
    }
    
    Write-Progress -Activity "Checking DFSR State" -Completed
}
catch {
    Write-Warning "Failed during DFSR state check: ${_}"
}
try {
    Write-Output "=========================="
    Write-Output "Running deep backlog analyses - Including conflict files"
    
    if (Test-Path $CSVExport -ErrorAction SilentlyContinue) {
        try {
            Clear-Content $CSVExport -ErrorAction Stop
            Write-Verbose "Cleared existing CSV export file"
        }
        catch {
            Write-Warning "Failed to clear CSV export file: ${_}"
        }
    }
    
    $RGroups = Get-WmiObject -Namespace "root\MicrosoftDFS" -Query "SELECT * FROM DfsrReplicationGroupConfig" -ErrorAction Stop
    
    # If replication groups specified, use only those
    if ($ReplicationGroupList.Count -gt 0) {
        $SelectedRGroups = @()
        foreach ($ReplicationGroup in $ReplicationGroupList) {
            $SelectedRGroups += $RGroups | Where-Object { $_.ReplicationGroupName -eq $ReplicationGroup }
        }
        if ($SelectedRGroups.Count -eq 0) {
            Write-Error "None of the group names specified were found, exiting"
            exit 1
        }
        else {
            $RGroups = $SelectedRGroups
            Write-Verbose "Using specified replication groups: $($ReplicationGroupList -join ', ')"
        }
    }
            
    $ComputerName = $env:ComputerName
    $SuccessCount = 0
    $WarningCount = 0
    $ErrorCount = 0
    
    $TotalGroups = $RGroups.Count
    $CurrentGroup = 0
    
    foreach ($Group in $RGroups) {
        $CurrentGroup++
        $GroupPercent = ($CurrentGroup / $TotalGroups) * 100
        
        Write-Progress -Id 1 -Activity "Deep Backlog Analysis" `
            -Status "Processing replication group $CurrentGroup of $TotalGroups" `
            -PercentComplete $GroupPercent `
            -CurrentOperation "Group: $($Group.ReplicationGroupName)"
        
        $RGFoldersWMIQ = "SELECT * FROM DfsrReplicatedFolderConfig WHERE ReplicationGroupGUID='" + $Group.ReplicationGroupGUID + "'"
        $RGFolders = Get-WmiObject -Namespace "root\MicrosoftDFS" -Query $RGFoldersWMIQ
        $RGConnectionsWMIQ = "SELECT * FROM DfsrConnectionConfig WHERE ReplicationGroupGUID='" + $Group.ReplicationGroupGUID + "'"
        $RGConnections = Get-WmiObject -Namespace "root\MicrosoftDFS" -Query $RGConnectionsWMIQ
        
        $TotalConnections = $RGConnections.Count
        $CurrentConnection = 0
        
        foreach ($Connection in $RGConnections) {
            $CurrentConnection++
            $ConnectionPercent = ($CurrentConnection / $TotalConnections) * 100
            
            Write-Progress -Id 2 -ParentId 1 -Activity "Analyzing Connections for $($Group.ReplicationGroupName)" `
                -Status "Processing connection $CurrentConnection of $TotalConnections" `
                -PercentComplete $ConnectionPercent `
                -CurrentOperation "Partner: $($Connection.PartnerName)"
            
            $ConnectionName = $Connection.PartnerName
            if ($Connection.Enabled -eq $true) {
                foreach ($Folder in $RGFolders) {
                    $RGName = $Group.ReplicationGroupName
                    $RFName = $Folder.ReplicatedFolderName
                    
                    if ($Connection.Inbound -eq $true) {
                        $SendingMember = $ConnectionName
                        $ReceivingMember = $ComputerName
                        $Direction = "inbound"
                    }
                    else {
                        $SendingMember = $ComputerName
                        $ReceivingMember = $ConnectionName
                        $Direction = "outbound"
                    }
                    
                    $BLArgs = @("Backlog", "/RGName:$RGName", "/RFName:$RFName", "/SendingMember:$SendingMember", "/ReceivingMember:$ReceivingMember")
                    Write-Verbose "dfsrdiag $BLArgs"
                    $Backlog = & dfsrdiag.exe @BLArgs
                    
                    $BacklogFileCount = 0
                    foreach ($item in $Backlog) {
                        if ($item -ilike "*Backlog File count*") {
                            $BacklogFileCount = [int]$Item.Split(":")[1].Trim()
                        }
                    }
                    
                    if ($BacklogFileCount -eq 0) {
                        $Color = "white"
                        $SuccessCount = $SuccessCount + 1
                    }
                    elseif ($BacklogFileCount -lt 10) {
                        $Color = "yellow"
                        $WarningCount = $WarningCount + 1
                    }
                    else {
                        $Color = "red"
                        $ErrorCount = $ErrorCount + 1
                    }
                    Write-Host "$BacklogFileCount files in backlog $SendingMember->$ReceivingMember for $RGName" -ForegroundColor $Color
                    if ($BacklogFileCount -ne 0) {
                        Write-Warning -Message "Please Check Log for File List: $CSVExport"
                        try {
                            Get-DfsrBacklog -DestinationComputerName $ReceivingMember -SourceComputerName "$SendingMember" -GroupName $RGName -FolderName $RFName -ErrorAction Stop | Export-Csv -Path $CSVExport -Append -UseCulture -NoClobber
                        }
                        catch {
                            Write-Warning "Failed to get backlog details for " + $RGName + ": " + ${_}
                        }
                    }
                    
                } # Closing iterate through all folders
            } # Closing If Connection enabled
        } # Closing iteration through all connections
        
        Write-Progress -Id 2 -Activity "Analyzing Connections for $($Group.ReplicationGroupName)" -Completed
    } # Closing iteration through all groups
    
    Write-Progress -Id 1 -Activity "Deep Backlog Analysis" -Completed
    
    Write-Host "$SuccessCount successful, $WarningCount warnings and $ErrorCount errors from $($SuccessCount + $WarningCount + $ErrorCount) replications."
    if ($ErrorCount -ne 0) {
        Write-Warning "Please wait 5 minutes and check if numbers are reducing. If not execute Repair-DFSR.ps1"
    }
}
catch {
    Write-Warning "Error during deep backlog analysis: $($_.Exception.Message)"
    Write-Warning "Detail Analysis work only on DFSR member servers"
}
if ($CompareHashes) {
    [String[]]$DFSHashFiles = @()
    Write-Output "Compare Hashes ... this may take a while ..."
    
    try {
        $DFSRMemberships = $DFSRFolder | Get-DfsrMembership
        $TotalMemberships = $DFSRMemberships.Count
        $CurrentMembership = 0
        
        foreach ($DFSRMembership in $DFSRMemberships) {
            $CurrentMembership++
            $PercentComplete = ($CurrentMembership / $TotalMemberships) * 100
            
            Write-Progress -Activity "Computing File Hashes" `
                -Status "Processing membership $CurrentMembership of $TotalMemberships" `
                -PercentComplete $PercentComplete `
                -CurrentOperation "Server: $($DFSRMembership.ComputerName)"
            
            $ContentPath = $DFSRMembership.ContentPath
            $UNCPref = "\\" + $DFSRMembership.ComputerName + "\c$\"
            Write-Verbose "UNCPath : $UNCPref"
            $ContentPath = $ContentPath.replace("C:\", $UNCPref)
            $DFSHashFile = $LogPath + $date + "-DFSHash-" + $DFSRMembership.ComputerName + ".txt"
            Write-Verbose "Hashfile : $DFSHashFile"
            
            try {
                if (Test-Path $DFSHashFile) {
                    Clear-Content $DFSHashFile -ErrorAction Stop
                }
                
                [String[]]$DFSHashes = @("Path;FileHash;Server")
                
                $Files = Get-ChildItem -Path $ContentPath -Recurse -File -ErrorAction Stop
                $TotalFiles = $Files.Count
                $CurrentFile = 0
                
                foreach ($File in $Files) {
                    $CurrentFile++
                    if ($CurrentFile % 100 -eq 0) {
                        $FilePercent = ($CurrentFile / $TotalFiles) * 100
                        Write-Progress -Id 2 -ParentId 1 -Activity "Hashing Files on $($DFSRMembership.ComputerName)" `
                            -Status "Processing file $CurrentFile of $TotalFiles" `
                            -PercentComplete $FilePercent
                    }
                    
                    try {
                        $FileHash = Get-DfsrFileHash -Path $File.FullName -ErrorAction Stop
                        $DFSHash = (($_.Path -split "\\", 4)[3]) + ";" + $FileHash.FileHash + ";" + $DFSRMembership.ComputerName
                        $DFSHashes += $DFSHash
                    }
                    catch {
                        Write-Warning "Failed to hash file $($File.FullName): ${_}"
                    }
                }
                
                $DFSHashes | Out-File $DFSHashFile -ErrorAction Stop
                $DFSHashFiles += $DFSHashFile
                Write-Progress -Id 2 -Activity "Hashing Files on $($DFSRMembership.ComputerName)" -Completed
            }
            catch {
                Write-Warning "Failed to process hashes for $($DFSRMembership.ComputerName): ${_}"
            }
        }
        
        Write-Progress -Activity "Computing File Hashes" -Completed
        
        Write-Verbose "*********"
        if ($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent) { $DFSHashFiles | Format-List }
        Write-Verbose "*********"
        
        if ($DFSHashFiles.Count -ge 2) {
            try {
                $Server1Hashes = Import-Csv -Path $DFSHashFiles[0] -Delimiter ";" -ErrorAction Stop
                $Server2Hashes = Import-Csv -Path $DFSHashFiles[1] -Delimiter ";" -ErrorAction Stop
                
                if ($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent) {
                    Write-Output "List of all scanned files and Hashes - Mismatch will be presented as Warning"
                }
                else {
                    Write-Output "Only Mismatch are presented - To show matches also run again with -Verbose"
                }
                
                Write-Output "Found $($Server1Hashes.count) entries for Server 1 and $($Server2Hashes.count) for Server 2."
                
                $TotalHashes = $Server1Hashes.Count
                $CurrentHash = 0
                
                foreach ($HashValue in $Server1Hashes) {
                    $CurrentHash++
                    if ($CurrentHash % 100 -eq 0) {
                        $HashPercent = ($CurrentHash / $TotalHashes) * 100
                        Write-Progress -Activity "Comparing File Hashes" `
                            -Status "Comparing hash $CurrentHash of $TotalHashes" `
                            -PercentComplete $HashPercent
                    }
                    
                    $NotMatched = $Server2Hashes | Where-Object { $_.Path -eq $HashValue.Path -and $_.FileHash -ne $HashValue.FileHash }
                    $Matched = $Server2Hashes | Where-Object { $_.Path -eq $HashValue.Path -and $_.FileHash -eq $HashValue.FileHash }
                    
                    if ($NotMatched) {
                        Write-Warning "$($HashValue.Path) Not Match - 1: $($HashValue.FileHash) - 2: $($NotMatched.FileHash)"
                    }
                    else {
                        Write-Verbose "$($HashValue.Path) Match - 1: $($HashValue.FileHash) - 2: $($Matched.FileHash)"
                    }
                }
                
                Write-Progress -Activity "Comparing File Hashes" -Completed
            }
            catch {
                Write-Warning "Failed to compare hashes: ${_}"
            }
        }
        else {
            Write-Warning "Need at least 2 hash files for comparison. Found: $($DFSHashFiles.Count)"
        }
        
        if ($DFSRMemberships.Count -ne 2) {
            Write-Warning "The Comparison will only happen between the first 2 Files. Please manually compare the files:"
            $DFSHashFiles | Format-List
        }
    }
    catch {
        Write-Warning "Error during hash comparison: ${_}"
    }
}
