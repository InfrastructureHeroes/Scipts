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
		
		Version    :    0.1 FN 04.04.2023 Initial Version
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
Function Start-Log {
    <#
        .COPYRIGHT
        Original Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT license.
        Additional Copyright for changes (c) 2022 Fabian Niesen. All rights reserved. Licensed under the MIT license.
    #>
    param (
        [string]$FilePath ,
        [string]$scriptName = "",
        [Parameter(HelpMessage = 'Deletes existing file if used with the -DeleteExistingFile switch')]
        [switch]$DeleteExistingFile
    )
    IF ($FilePath -like "") 
    { 
        Try 
        {
            $global:logPath = $(Split-Path -Parent $(Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription\" -Name "OutputDirectory" -ErrorAction Stop).OutputDirectory) + "\SecureAD"
            "Test $Transscripttarget $(Get-Date) from $env:COMPUTERNAME" | Out-File -FilePath $global:logPath\test.log -Append -ErrorAction Stop 
            Write-Output "Variable Targetfolder not provided - Used Autodetection: $logPath"
        }
        CATCH 
        {
            Write-Warning -Message "LogPath not found in Registry. Fall back to local log path."
            IF ( (([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole( [Security.Principal.WindowsBuiltInRole] "Administrator")) ) { $global:logPath = "C:\Windows\System32\LogFiles\SecureAD" } else { $global:logPath = $HOME + "\LogFiles\SecureAD" }
        }
        If (!(Test-Path $logPath)) { New-Item $logPath -Type Directory -Force | Out-Null }
        IF ( $scriptName -like "" ) 
        { 
            $global:scriptName = $myInvocation.MyCommand.Name 
            $global:scriptName = $ScriptName.Substring(0, $scriptName.Length - 4)
        }
        $global:LogName = $scriptName + "_" + (Get-Date -UFormat "%Y%m%d") +"_" + $Env:COMPUTERNAME
        $global:logFile = "$logPath\$LogName.log"
        #$global:logFile = "C:\Windows\System32\LogFiles\SecureAD\" + $(($myInvocation.MyCommand.Name).Substring(0, $($myInvocation.MyCommand.Name).Length - 4) + "_" + (Get-Date -UFormat "%Y%m%d"))+".log" 
        Write-Output "No logfile provided - Use $logFile"
        $FilePath = $logFile
    }
    Try {
        If ($DeleteExistingFile) { Remove-Item $FilePath -Force }
        If (!(Test-Path $FilePath)) { New-Item $FilePath -Type File -Force | Out-Null }
    }
    Catch {
        Write-Error $_.Exception.Message
    }
}
####################################################
Function Write-Log {
    <#
        .COPYRIGHT
        Original Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT license.
        Additional Copyright for changes (c) 2022 Fabian Niesen. All rights reserved. Licensed under the MIT license.
    #>
    #Write-Log -Message 'warning' -LogLevel 2
    #Write-Log -Message 'Error' -LogLevel 3
    param (
        [Parameter(Mandatory = $true)]
        [string]$Message,
			
        [Parameter()]
        [ValidateSet(1, 2, 3)]
        [int]$LogLevel = 1
    )
    IF ( ! ($logFile)) { Write-Warning "Start-Log was missing - starting now with Autodetection" ; Start-Log ;  }
    If ($LogLevel -eq 1) {Write-Host $Message } else { Write-Warning $Message }
    $TimeGenerated = "$(Get-Date -Format HH:mm:ss).$((Get-Date).Millisecond)+000"
    $Line = '<![LOG[{0}]LOG]!><time="{1}" date="{2}" component="{3}" context="" type="{4}" thread="" file="">'
    $Execname = TRY { ($MyInvocation.ScriptName | Split-Path -Leaf -ErrorAction stop)} catch { "NoScript" }
    $LineFormat = $Message, $TimeGenerated, (Get-Date -Format MM-dd-yyyy), "$($Execname):$($MyInvocation.ScriptLineNumber)", $LogLevel
    $Line = $Line -f $LineFormat
    $Line | Out-File  -FilePath $global:logFile -Append

}
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
Function start-wait {
    <#
        .COPYRIGHT
        Copyright (c) 2022 Fabian Niesen. All rights reserved. Licensed under the MIT license.
    #>

    param (
        [Parameter(Mandatory = $true)][int]$seconds,
        [string]$Comment ="Something magic is happend in the background"
    )
    Begin { 
        Write-Verbose -Message "$($MyInvocation.InvocationName) function..."
        Write-Log -Message $Comment
    }
    Process {
        For ($i=1; $i -le $seconds; $i++)
        {
        Write-Progress -Activity "Please Wait - $Comment - $i of $seconds seconds" -Status "$([Math]::round($i / $seconds*100 , 2))% Complete:" -PercentComplete (($i / $seconds)*100) -id 25
        Start-Sleep -Seconds 1
        }
    }
    End { Write-Verbose "Returning..." }
}
####################################################
#endregion functions
#region init
$ScriptVersion = "0.1"
$script:ParentFolder = $PSScriptRoot | Split-Path -Parent
$global:ScriptName = $myInvocation.MyCommand.Name
$global:ScriptName = $ScriptName.Substring(0, $scriptName.Length - 4)
$global:scriptsource = $myInvocation.MyCommand.Source
$global:scriptparam = $MyInvocation.BoundParameters
Write-Verbose "RefenceDC: $referenceServer - Authoritative: $Authoritative"
Start-log -ScriptName $ScriptName
Write-Log -Message "Start $ScriptName $ScriptVersion - Executed on $($Env:COMPUTERNAME)"
#endregion init
Set-Location $PSScriptRoot
Start-Transcript -Path "$logPath\$LogName-Transcript.log" -Append
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
        $DfsrSettingsObject = Get-ADObject $((Get-ChildItem "AD:\$($ReplicationGroup.DistinguishedName)").DistinguishedName) -Properties "msDFSR-Enabled","msDFSR-options" -Server $DC
        If ( $PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent) { $DfsrSettingsObject | format-List }
        IF ( $Authoritative -and $DFSServer -like $referenceServer ) { $DfsrSettingsObject.'msDFSR-options' = 1 }
        $DfsrSettingsObject.'msDFSR-Enabled' = $False
        Set-ADObject -Instance $DfsrSettingsObject -Server $DC
        start-wait -Comment "Waiting for AD" -seconds 5
        $DfsrSettingsObject = Get-ADObject $((Get-ChildItem "AD:\$($ReplicationGroup.DistinguishedName)").DistinguishedName) -Properties "msDFSR-Enabled","msDFSR-options" -Server $DC
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
        $DfsrSettingsObject = Get-ADObject $((Get-ChildItem "AD:\$($ReplicationGroup.DistinguishedName)").DistinguishedName) -Properties "msDFSR-Enabled","msDFSR-options" -Server $DC
        If ( $PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent) { $DfsrSettingsObject | format-List }
        $DfsrSettingsObject.'msDFSR-Enabled' = $True
        Set-ADObject -Instance $DfsrSettingsObject -Server $DC
        start-wait -Comment "Waiting for AD" -seconds 5
        $DfsrSettingsObject = Get-ADObject $((Get-ChildItem "AD:\$($ReplicationGroup.DistinguishedName)").DistinguishedName) -Properties "msDFSR-Enabled","msDFSR-options" -Server $DC
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