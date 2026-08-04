#requires -version 5.0
#Requires -Modules ActiveDirectory,dfsr
#Requires -RunAsAdministrator

<#
	.SYNOPSIS
		Repairs all DFS-R Replications configured on the Domain Controllers, including SysVol. 
	.DESCRIPTION
        Repairs all DFS-R Replications configured on the Domain Controllers, including SysVol. 
        Limitations: The script is only tested for other DFS-R replication groups, then SYSVOL, if they also located on all DC.
        FireWall Requirements: DFS Replication, DFS Namespace, WinRM, Remote EventLog, RemotePowerShell
	.EXAMPLE  
        .\Repair-DFSR.ps1 -Authoritative -refernceDC DC01
        Executes an Authorative sync from DC01

    .EXAMPLE 
        .\Repair-DFSR.ps1 -Authoritative
        Executes an Authorative sync from PDC emulator

    .EXAMPLE
        .\Repair-DFSR.ps1 
        Stops and Restart the DFSR replication

    .PARAMETER Authoritative,
        Replication will be Authorative

    .PARAMETER referenceServer
        referenceServer for replication. Required for Authorative. If not defined PDC is used, if reachable.

	.NOTES
		Author     :    Fabian Niesen
		Filename   :    Repair-DFSR.ps1
		Requires   :    PowerShell Version 5.0
		
		Version    :    0.2 FN 04.08.2026 Use shared helper functions from Modules\IH.Common
        History    :    0.1 FN 04.04.2023 Initial version.
    .LINK
        https://learn.microsoft.com/en-us/troubleshoot/windows-server/group-policy/force-authoritative-non-authoritative-synchronization
#>
Param(
    [Parameter(ParameterSetName = "TargetReplicationGroup")][string]$TargetReplicationGroup, #To be implemented
    [Parameter(ParameterSetName = "all")][Switch]$all,
    [Parameter(ParameterSetName = "list")][Switch]$list,
    [switch]$Authoritative,
    [String]$referenceServer
)
#region Functions
#Shared helper functions (Start-Log, Write-Log, Start-Wait) live in Modules\IH.Common
Import-Module (Join-Path $PSScriptRoot "..\Modules\IH.Common\IH.Common.psd1") -Force -ErrorAction Stop
####################################################
function IsNull($objectToCheck) {
    <#
    .COPYRIGHT
    Original Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT license.
#>
if ($objectToCheck -eq $null) { return $true }
if ($objectToCheck -is [String] -and $objectToCheck -eq [String]::Empty) { return $true }
if ($objectToCheck -is [DBNull] -or $objectToCheck -is [System.Management.Automation.Language.NullString]) { return $true }
return $false
}
####################################################
#endregion functions
#region init
$ScriptVersion = "0.2"
$script:ParentFolder = $PSScriptRoot | Split-Path -Parent
$global:ScriptName = $myInvocation.MyCommand.Name
$global:ScriptName = $ScriptName.Substring(0, $scriptName.Length - 4)
$global:scriptsource = $myInvocation.MyCommand.Source
$global:scriptparam = $MyInvocation.BoundParameters
Write-Verbose "RefenceDC: $referenceServer - Authoritative: $Authoritative"
$Log = Start-Log -ScriptName $ScriptName -PassThru
Write-Log -Message "Start $ScriptName $ScriptVersion - Executed on $($Env:COMPUTERNAME)"
#endregion init
Set-Location $PSScriptRoot
Start-Transcript -Path "$($Log.LogPath)\$($Log.LogName)-Transcript.log" -Append
If ($list) {
    Get-DfsReplicationGroup -IncludeSysvol
    Write-Host "Please us the Identyfier"
    Break
}
IF ($null -ne $TargetReplicationGroup){

}

$DC=(Get-ADDomainController -Filter {OperationMasterRoles -like "PDC*"}).Hostname
IF ( IsNull($referenceServer)  ) { $referenceServer = $DC } Else { $referenceServer = (Get-ADComputer -Identity $referenceServer).DNSHostName }
[String]$LDAPDOM = (Get-ADDomain).DistinguishedName
$DFSServers = Get-ADDomain | Select-Object -ExpandProperty ReplicaDirectoryServers
#region Sort Server
[String[]]$SortServer = $DFSServers | Where-Object { $_ -like "$referenceServer"}
ForEach ( $DFSServer in $($DFSServers | Where-Object { $_ -ne "$referenceServer"})) { $SortServer += $DFSServer }
$DFSServers = $SortServer
Write-Log -message "Server precedence: $($DFSServers -join(', '))"
#endregion Sort Server
Write-Log -message "Detected $($DFSServers.count) Replication Server"

ForEach ( $DFSServer in $DFSServers )
{
    Write-Debug "$DFSServer"
    $DFSServerDN = (Get-ADComputer -Identity $($DFSServer.Split(".")[0])).DistinguishedName
    IF ( $all ) { [string[]]$ReplicationGroups = Get-ChildItem "AD:\CN=DFSR-LocalSettings,$DFSServerDN" }
    IF ( $TargetReplicationGroup) { [string[]]$ReplicationGroups = "$TargetReplicationGroup"  }
    #IF ($null -ne $TargetReplicationGroup) {  }
    ForEach ( $ReplicationGroup in $ReplicationGroups)
    {
        $ReplicationGroupName =$((($ReplicationGroup -split ',')[0]).Replace('CN=',''))
        Write-Log -Message "Modify Replication Group $ReplicationGroupName"
        $DfsrSettingsObject = Get-ADObject $((Get-ChildItem "AD:\$($ReplicationGroup)").DistinguishedName) -Properties "msDFSR-Enabled","msDFSR-Options" -Server $DC
        If ( $PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent) { $DfsrSettingsObject | format-List }
        IF ( $Authoritative -and $DFSServer -like $referenceServer ) { $DfsrSettingsObject.'msDFSR-options' = 1 }
        $DfsrSettingsObject.'msDFSR-Enabled' = $False
        Set-ADObject -Instance $DfsrSettingsObject -Server $DC
        start-wait -Comment "Waiting for AD" -seconds 5
        $DfsrSettingsObject = Get-ADObject $((Get-ChildItem "AD:\$($ReplicationGroup)").DistinguishedName) -Properties "msDFSR-Enabled","msDFSR-Options" -Server $DC
        Write-Log -message "DFSR settings for $ReplicationGroupName are - msDFSR-Enabled: $($DfsrSettingsObject.'msDFSR-Enabled') msDFSR-options: $($DfsrSettingsObject.'msDFSR-options') " 
    }
    Write-Log -Message "Start remote AD replication on $DFSServer"
    Try { Invoke-Command -ComputerName $DFSServer -ScriptBlock {Start-Process repadmin -ArgumentList "/syncall /APed" -NoNewWindow -Wait} -ErrorAction Stop }
    Catch { Write-log -message "$($_.Exception.Message)" -logLevel 3 ; Continue }
    start-wait -Comment "Waiting for AD" -seconds 5
    Update-DfsrConfigurationFromAD -ComputerName $DFSServer -Verbose
    Write-Log -Message "Stop DFS-R Service on $DFSServer"
    Try { Invoke-Command -ComputerName $DFSServer -ScriptBlock { Stop-Service -Name dfsr } -ErrorAction Stop }
    Catch { Write-log -message "$($_.Exception.Message)" -logLevel 3 ; Continue }
}
Write-Log -Message "DFS-R Disabled"
Write-Host "========================================================"
Write-Log -Message "Enable DFS-R"
ForEach ( $DFSServer in $DFSServers )
{
    $DFSServerDN = (Get-ADComputer -Identity $($DFSServer.Split(".")[0])).DistinguishedName
    $ReplicationGroups = Get-ChildItem "AD:\CN=DFSR-LocalSettings,$DFSServerDN"
    Write-Debug "Round 2 - $DFSServer"
    Write-Log -Message "Start DFS-R Service on $DFSServer"
    Try { Invoke-Command -ComputerName $DFSServer -ScriptBlock { Start-Service -Name dfsr } -ErrorAction Stop }
    Catch { Write-log -message "$($_.Exception.Message)" -logLevel 3 ; Continue }
    do {
        Start-Wait -comment "Wait for DFS-R to settle" -seconds 10
        If ( $PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent) {(Get-EventLog -LogName "DFS Replication" -ComputerName $DFSServer -InstanceId 1073745938 -Newest 10 -After ((Get-Date).AddMinutes(-10)))}
    } Until ( (Get-EventLog -LogName "DFS Replication" -ComputerName $DFSServer -InstanceId 1073745938 -After ((Get-Date).AddMinutes(-10))).Count -ge 1 )
    ForEach ( $ReplicationGroup in $ReplicationGroups)
    {
        $ReplicationGroupName =$((($ReplicationGroup -split ',')[0]).Replace('CN=',''))
        Write-Log -Message "Modify Replication Group $ReplicationGroupName"
        $DfsrSettingsObject = Get-ADObject $((Get-ChildItem "AD:\$($ReplicationGroup)").DistinguishedName) -Properties "msDFSR-Enabled","msDFSR-Options" -Server $DC
        If ( $PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent) { $DfsrSettingsObject | format-List }
        $DfsrSettingsObject.'msDFSR-Enabled' = $True
        Set-ADObject -Instance $DfsrSettingsObject -Server $DC
        start-wait -Comment "Waiting for AD" -seconds 5
        $DfsrSettingsObject = Get-ADObject $((Get-ChildItem "AD:\$($ReplicationGroup)").DistinguishedName) -Properties "msDFSR-Enabled","msDFSR-Options" -Server $DC
        Write-Log -message "DFSR settings for $ReplicationGroupName are - msDFSR-Enabled: $($DfsrSettingsObject.'msDFSR-Enabled') msDFSR-options: $($DfsrSettingsObject.'msDFSR-options') " 
    }
    Write-Log -Message "Start remote AD replication on $DFSServer"
    Try { Invoke-Command -ComputerName $DFSServer -ScriptBlock {Start-Process repadmin -ArgumentList "/syncall /APed" -NoNewWindow -Wait} -ErrorAction Stop }
    Catch { Write-log -message "$($_.Exception.Message)" -logLevel 3 ; Continue }
    start-wait -Comment "Waiting for AD" -seconds 5
    Update-DfsrConfigurationFromAD -ComputerName $DFSServer -Verbose
    IF ( $DFSServer -eq $referenceServer)
    {
        do {
            Start-Wait -comment "Wait for DFS-R to settle" -seconds 10
        } Until ( (Get-EventLog -LogName "DFS Replication" -ComputerName $referenceServer -InstanceId 1073746426 -Newest 3 -After (Get-Date).AddMinutes(-10)).Count -ge 1 )
    }   
}
Write-Log -Message "DFS-R Repair Completed - Synchronisation may take a while"