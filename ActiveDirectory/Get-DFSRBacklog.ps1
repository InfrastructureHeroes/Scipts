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
        get-DSFRBacklog.ps1 -LogPath "C:\Temp\DFSRMonitor" -Verbose
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
		
		Version    : 0.5  FN  28.03.2026 First public version
		History    : 0.5  FN  28.03.2026 First public version
                    
                    
    .LINK
        https://github.com/InfrastructureHeroes/Scipts/blob/master/ActiveDirectory/get-DFSRBacklog.ps1
#>

[cmdletbinding()]
Param (
    [Switch]$CompareHashes,
    [String[]]$ReplicationGroupList = (""),
    $LogPath = "C:\Temp\DFSRMonitor",
    $CSVFilename = "DFSR-Backlog.csv"
)
if (((Get-ComputerInfo).WindowsInstallationType) -like "Server Core") {$CoreVersion=$true} else {$CoreVersion = $false}
Write-Verbose "Detect Server Core: $CoreVersion"
$ScriptVersion = "0.5"
$ScriptName = $($myInvocation.MyCommand.Name).Replace('.ps1', '')
"Get-DFSRBacklog.ps1 by Fabian Niesen, www.infrastrukturhelden.de - License: GNU General Public License v3 (GPLv3), see notes for details" | Write-Output
"Start $ScriptName $ScriptVersion - Executed on $($Env:COMPUTERNAME) by $($Env:USERNAME) at $(get-date -format 'HH:mm dd.MM.yyyy' )" | Write-Output
if ($CoreVersion -eq $True)
    {
    Write-Output "Core Installation Setup..."   
    Try { $InAD = Install-WindowsFeature -Name FS-DFS-Namespace,FS-DFS-Replication -IncludeManagementTools -ErrorAction Stop }
    Catch { Write-Warning "Something went wrong..." ; break }
    Set-SConfig -AutoLaunch $false
    }
else
    {
    Write-Output "Desktop Experience Installation Setup..."     
    Try { $InAD = Install-WindowsFeature -Name RSAT-DFS-Mgmt-Con  -IncludeManagementTools -ErrorAction Stop }
    Catch { Write-Warning "Something went wrong..." ; break }
    }
Import-Module -Name DFSR -Verbose:$false
Import-Module -Name ActiveDirectory -Verbose:$false
IF ($LogPath.EndsWith("\") -like "False") { $LogPath =$LogPath+"\" }
IF (!(Test-Path $LogPath)) { new-item -Path $LogPath -ItemType directory | out-null }
Write-Output "Logpath is set to: $LogPath"
Write-Output "SysVol is only visable in the last test!"
Write-Output "=========================="
$date = get-date -format yyyyMMdd-HHmm
$CSVExport = $LogPath +"\"+$date + $CSVFilename
$DFSRServers = Get-ADDomain | Select-Object -ExpandProperty ReplicaDirectoryServers
Write-Verbose "*********"
If ( $PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent) { $DFSRServers | format-Table -AutoSize }
Write-Verbose "*********"
Write-Output "Start DFSR Propagation Test"
ForEach ( $DFSRFolder in $(Get-DfsReplicationGroup -IncludeSysvol | Get-DfsReplicatedFolder))
{
    ForEach ($DFSRMember in $(Get-DfsReplicationGroup -GroupName $DFSRFolder.GroupName | Get-DfsrMember))
    {
        Start-DfsrPropagationTest -FolderName $DFSRFolder.FolderName -ReferenceComputerName $DFSRMember.ComputerName -Verbose
    }
}
Write-Output "Wait 60 Seconds for DFS-R Replication"
Start-sleep -Seconds 60
Write-Output "Create DFSR Propagation Test Reports"
$DFSRFolders = Get-DfsReplicationGroup -IncludeSysvol | Get-DfsReplicatedFolder
Write-Verbose "*********"
If ( $PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent) { $DFSRFolders | Format-Table -AutoSize }
Write-Verbose "*********"
 ForEach ( $DFSRFolder in $DFSRFolders)
{
    ForEach ($DFSRMember in $(Get-DfsReplicationGroup -GroupName $DFSRFolder.GroupName | Get-DfsrMember))
    {
        IF (!(Test-Path $($LogPath+"\"+$DFSRMember.ComputerName))) { new-item -Path $($LogPath+"\"+$DFSRMember.ComputerName) -ItemType directory | out-null }
        Write-DfsrPropagationReport -FolderName $DFSRFolder.FolderName -GroupName $DFSRFolder.GroupName -ReferenceComputerName $DFSRMember.ComputerName -Path $($LogPath+"\"+$DFSRMember.ComputerName) -FileCount 5 
        Start-Sleep -Seconds 2
        $Report = (Get-ChildItem -Path $($LogPath+"\"+$DFSRMember.ComputerName) -Filter *.html | Sort-Object -Descending -Property LastWriteTime)[0].FullName
        Write-Output "Check DFS-R Propagation Report: $Report"
        if ($CoreVersion -eq $false) {.$Report}
    }
}
Write-Warning "DFSRState -  this output might not be reliable! This shows only normal backlog when everthing is smooth"
ForEach ($DFSRServer in $DFSRServers) 
{
    Write-Output "Server: $DFSRServer"
    Try { Get-DfsrState -ComputerName $DFSRServer -Verbose -ErrorAction Stop } CATCH { Write-Output "Get-DfsrState needed WinRM" }
}
Try {
    Write-Output "=========================="
    Write-Output "Running deep backlog analyses - Including conflict files"
    IF ( Test-Path $CSVExport -ErrorAction SilentlyContinue ) { Clear-Content $CSVExport }
    $RGroups = Get-WmiObject  -Namespace "root\MicrosoftDFS" -Query "SELECT * FROM DfsrReplicationGroupConfig" -ErrorAction Stop
    #If  replication groups specified, use only those.
    if($ReplicationGroupList)
    {
        $SelectedRGroups = @()
        foreach($ReplicationGroup IN $ReplicationGroupList)
        {
            $SelectedRGroups += $rgroups | Where-Object {$_.ReplicationGroupName -eq $ReplicationGroup}
        }
        if($SelectedRGroups.count -eq 0)
        {
            Write-Error "None of the group names specified were found, exiting"
            exit
        }
        else
        {
            $RGroups = $SelectedRGroups
        }
    }
            
    $ComputerName=$env:ComputerName
    $Succ=0
    $Warn=0
    $Err=0
    
    foreach ($Group in $RGroups)
    {
        $RGFoldersWMIQ = "SELECT * FROM DfsrReplicatedFolderConfig WHERE ReplicationGroupGUID='" + $Group.ReplicationGroupGUID + "'"
        $RGFolders = Get-WmiObject -Namespace "root\MicrosoftDFS" -Query  $RGFoldersWMIQ
        $RGConnectionsWMIQ = "SELECT * FROM DfsrConnectionConfig WHERE ReplicationGroupGUID='"+ $Group.ReplicationGroupGUID + "'"
        $RGConnections = Get-WmiObject -Namespace "root\MicrosoftDFS" -Query  $RGConnectionsWMIQ
        foreach ($Connection in $RGConnections)
        {
            $ConnectionName = $Connection.PartnerName#.Trim()
            if ($Connection.Enabled -eq $True)
            {
                #if (((New-Object System.Net.NetworkInformation.ping).send("$ConnectionName")).Status -eq "Success")
                #{
                    foreach ($Folder in $RGFolders)
                    {
                        $RGName = $Group.ReplicationGroupName
                        $RFName = $Folder.ReplicatedFolderName
                    
                        if ($Connection.Inbound -eq $True)
                        {
                            $SendingMember = $ConnectionName
                            $ReceivingMember = $ComputerName
                            $Direction="inbound"
                        }
                        else
                        {
                            $SendingMember = $ComputerName
                            $ReceivingMember = $ConnectionName
                            $Direction="outbound"
                        }
                    
                        $BLCommand = "dfsrdiag Backlog /RGName:'" + $RGName + "' /RFName:'" + $RFName + "' /SendingMember:" + $SendingMember + " /ReceivingMember:" + $ReceivingMember
                        $Backlog = Invoke-Expression -Command $BLCommand
                    
                        $BackLogFilecount = 0
                        foreach ($item in $Backlog)
                        {
                            if ($item -ilike "*Backlog File count*")
                            {
                                $BacklogFileCount = [int]$Item.Split(":")[1].Trim()
                            }
                        }
                    
                        if ($BacklogFileCount -eq 0)
                        {
                            $Color="white"
                            $Succ=$Succ+1
                        }
                        elseif ($BacklogFilecount -lt 10)
                        {
                            $Color="yellow"
                            $Warn=$Warn+1
                        }
                        else
                        {
                            $Color="red"
                            $Err=$Err+1
                        }
                        Write-Host "$BacklogFileCount files in backlog $SendingMember->$ReceivingMember for $RGName" -fore $Color
                        IF ( $BacklogFileCount -ne 0)
                        {
                            Write-Warning -Message "Please Check Log for File List: $CSVExport"
                            Get-DfsrBacklog -DestinationComputerName $ReceivingMember -SourceComputerName "$SendingMember" -GroupName $RGName -FolderName $RFName | Export-Csv -Path $CSVExport -Append -UseCulture -NoClobber 
                        }
                    
                    } # Closing iterate through all folders
                #} # Closing  If replies to ping
            } # Closing  If Connection enabled
        } # Closing iteration through all connections
    } # Closing iteration through all groups
    
    
    Write-Host "$Succ successful, $Warn warnings and $Err errors from $($Succ+$Warn+$Err) replications."
    IF ( $Err -ne 0 ) { Write-Warning "Please wait 5 minutes and check if numbers are reducing. If not execute Repair-DFSR.ps1"}
} Catch { Write-Warning "Error: $($_.Exception.Message)" ; Write-Warning "Detail Analysis work only on DFSR member servers" }
IF ($CompareHashes)
{
    [String[]]$DFSHashFiles = $null
    Write-Output "Compare Hashes ... this may take a while ..."
    ForEach ($DFSRMembership in $($DFSRFolder| Get-DfsrMembership))
    {
        $ContentPath = $DFSRMembership.ContentPath
        $UNCPref = "\\" + $DFSRMembership.ComputerName + "\c$\"
        Write-Verbose "UNCPath : $UNCPref"
        $ContentPath = $ContentPath.replace("C:\",$UNCPref)
        $DFSHashFile = $LogPath+$date+"-DFSHash-"+$DFSRMembership.ComputerName+".txt" 
        Write-Verbose "Hashfile : $DFSHashFile"
        IF (Test-Path $DFSHashFile ) { Clear-Content $DFSHashFile}
        [String[]]$DFSHases = "Path;FileHash;Server"
        Get-DfsrFileHash -Path (Get-ChildItem -Path $ContentPath -Recurse -file ).fullname | ForEach-Object { 
            $DFSHash = (($_.Path  -split "\\",4)[3])+";"+$_.FileHash + ";" + $DFSRMembership.ComputerName
            $DFSHases += $DFSHash
        }  
        ##If ( $PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent) { $DFSHases   }
        $DFSHases | Out-File $DFSHashFile
        $DFSHashFiles += $DFSHashFile
    }
    Write-Verbose "*********"
    If ( $PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent) { $DFSHashFiles | format-List  }
    Write-Verbose "*********"
    $Server1Hashes = Import-Csv -Path $DFSHashFiles[0] -Delimiter ";" 
    $Server2Hashes = Import-Csv -Path $DFSHashFiles[1] -Delimiter ";" 
    If ( $PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent) { Write-Output "List of all scanned files and Hashes - Missmatch will be presented as Warning"} Else { Write-Output "Only Missmatch are presented - To show matches aslo run again with >-Verbose<"}
    Write-Output "Found $($Server1Hashes.count) entries for Server 1 and $($Server2Hashes.count) for Server 2."
    ForEach ( $HashValue in $Server1Hashes)
    {
        $NotMatched = $Server2Hashes | Where-Object { $_.Path -eq $HashValue.Path -and $_.FileHash -ne $HashValue.FileHash } 
        $Matched = $Server2Hashes | Where-Object { $_.Path -eq $HashValue.Path -and $_.FileHash -eq $HashValue.FileHash } 
        #$Hash1 = ($Server1Hashes | where { $_.Path -eq $HashValue.Path  } ).FileHash
        IF ($NotMatched ) { Write-Warning "$($HashValue.Path) Not Match - 1: $($HashValue.FileHash) - 2: $($NotMatched.FileHash)"} Else {Write-Verbose "$($HashValue.Path) Match - 1: $($HashValue.FileHash) - 2: $($Matched.FileHash)" }
        #| IF ( $_.FileHash -notlike $HashValue.FileHash ) { Write-Warning "$($_.Path) - Hash not match "} Else {Write-Output "$($_.Path) - Hash match "}
    }
    IF ( $($DFSRFolder| Get-DfsrMembership).count -ne 2 ) {
        Write-Warning "The Comparison will only happen between the first 2 Files. Please manually compare the files:"
        $DFSHashFiles | format-List
    }
}
