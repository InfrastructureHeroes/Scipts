#requires -version 5.1
<#
.SYNOPSIS
Analyzes the local event log "Microsoft-Windows-NTLM/Operational".

.DESCRIPTION
Reads NTLM events from the local operational log and classifies whether events represent audited or blocked NTLM activity. In addition, it outputs as many details as possible about identity, target system, workstation, logon type, process, and protocol (when available in the event).

This includes the new NTLM Audit events (4020-4023) for Windows 11 24H2 and Windows Sever 2025, announced with KB5064479. 

Explicitly handles known NTLM event IDs (e.g. 100/101/301, 4001-4025, 8001-8003) including short description and category.

For Domain Controller based NTLM analysis, use the Get-NTLMLogons.ps1 script, which queries the Security Log for relevant logon events (4624/4625) and provides an analysis of NTLM logons in the domain.

.PARAMETER Days
Number of days in the past to analyze.

.PARAMETER MaxEvents
Optional limit for the maximum number of events to process.

.PARAMETER ShowRawEventData
Outputs full EventData keys per event in addition to parsed fields.

.PARAMETER IncludeOriginalMessage
Shows the original event message only when this switch is provided.

.PARAMETER CSVExportPath
Optional file path to export results as CSV.

.EXAMPLE
.\Get-LocalNTLMlogs.ps1

.EXAMPLE
.\Get-LocalNTLMlogs.ps1 -Days 7 -MaxEvents 500 -ShowRawEventData -Message

.EXAMPLE
.\Get-LocalNTLMlogs.ps1 -CSVExport C:\Temp\ntlmlog.csv

.NOTES
Author     : Fabian Niesen (www.infrastukturhelden.de)
Filename   : Get-LocalNTLMlogs.ps1
Requires   : PowerShell Version 5.1
License    : GNU General Public License v3 (GPLv3)
            (c) 2026 Fabian Niesen, www.infrastrukturhelden.de
            This script is licensed under the GNU General Public License v3 (GPLv3). 
            You can redistribute it and/or modify it under the terms of the GPLv3 as published by the Free Software Foundation.
            This script is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of
            MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details. 
            See https://www.gnu.org/licenses/gpl-3.0.html for the full license text.
DISCLAIMER :
            This script is provided "as is" without any warranty of any kind, express or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose, and noninfringement. 
            Use of this script is at your own risk. The author assumes no responsibility for any damage or data loss caused by the use of this script.
Version    : 1.0
History    :
                1.0  Fabian Niesen  10.02.2026  initial version

.LINK
https://github.com/InfrastructureHeroes/Scipts/blob/master/ActiveDirectory/Get-LocalNTLMlogs.ps1
Blog (DE): https://www.infrastrukturhelden.de/
Blog (EN): https://www.InfrastructureHeroes.org/ 
KB5064479: https://support.microsoft.com/en-us/topic/overview-of-ntlm-auditing-enhancements-in-windows-11-version-24h2-and-windows-server-2025-b7ead732-6fc5-46a3-a943-27a4571d9e7b
Get-NTLMLogons.ps1: https://github.com/InfrastructureHeroes/Scipts/blob/master/ActiveDirectory/Get-NTLMLogons.ps1
#>

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateRange(1, 365)]
    [int]$Days = 3,

    [Parameter()]
    [ValidateRange(1, 500000)]
    [int]$MaxEvents = 10000,

    [Parameter()]
    [switch]$ShowRawEventData,

    [Parameter()]
    [Alias('Message')]
    [switch]$IncludeOriginalMessage,

    [Parameter()]
    [Alias('CSVExport')]
    [string]$CSVExportPath
)
#region Helper Functions
function Get-FirstValue {
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Map,

        [Parameter(Mandatory = $true)]
        [string[]]$Names
    )

    foreach ($name in $Names) {
        if ($Map.ContainsKey($name) -and $null -ne $Map[$name] -and "$($Map[$name])".Trim().Length -gt 0) {
            return $Map[$name]
        }
    }

    return $null
}
#endregion Helper Functions
#region init
$ScriptVersion = "1.0"
$ScriptName = $($myInvocation.MyCommand.Name).Replace('.ps1', '')
Write-Output "Start $ScriptName $ScriptVersion - Executed on $($Env:COMPUTERNAME) by $($Env:USERNAME)" 
Write-Verbose "Parameters: Days=$Days, MaxEvents=$MaxEvents, ShowRawEventData=$ShowRawEventData, IncludeOriginalMessage=$IncludeOriginalMessage, CSVExportPath=$CSVExportPath"
if (((Get-ComputerInfo).WindowsInstallationType) -like "Server Core") {$CoreVersion=$true} else {$CoreVersion = $false}
Write-Verbose "CoreVersion: $CoreVersion"
#endregion init
$logName = 'Microsoft-Windows-NTLM/Operational'
$startTime = (Get-Date).AddDays(-$Days)

# Based on the provided NTLM event ID list.
$knownEvents = @{
    100  = @{ Category = 'Blocked'; ShortText = 'Protected Users blocked NTLM authentication.' }
    101  = @{ Category = 'Blocked'; ShortText = 'Access-control restrictions block NTLM.' }
    301  = @{ Category = 'Audited'; ShortText = 'NTLM currently succeeds but would fail with policy enforcement.' }
    4001 = @{ Category = 'Blocked'; ShortText = 'NTLM client outgoing blocked.' }
    4002 = @{ Category = 'Blocked'; ShortText = 'NTLM server incoming blocked.' }
    4003 = @{ Category = 'Blocked'; ShortText = 'NTLM in domain blocked.' }
    4010 = @{ Category = 'Blocked'; ShortText = 'Minimum client security blocked.' }
    4011 = @{ Category = 'Blocked'; ShortText = 'Minimum server security blocked.' }
    4012 = @{ Category = 'Info';    ShortText = 'Fallback to domain password after secret failure.' }
    4013 = @{ Category = 'Blocked'; ShortText = 'NTLMv1 usage failed.' }
    4014 = @{ Category = 'Blocked'; ShortText = 'Credential Guard blocked CallPackage key access.' }
    4015 = @{ Category = 'Blocked'; ShortText = 'NTLM client blocked by application.' }
    4020 = @{ Category = 'Audited'; ShortText = 'Outgoing NTLM attempt (detailed audit).' }
    4021 = @{ Category = 'Blocked'; ShortText = 'Outgoing NTLM attempt (detailed block).' }
    4022 = @{ Category = 'Audited'; ShortText = 'Incoming NTLM client (detailed audit).' }
    4023 = @{ Category = 'Blocked'; ShortText = 'Incoming NTLM client (detailed block).' }
    4024 = @{ Category = 'Audited'; ShortText = 'Audit: NTLMv1-derived SSO-Credentials.' }
    4025 = @{ Category = 'Blocked'; ShortText = 'Block: NTLMv1-derived SSO-Credentials.' }
    8001 = @{ Category = 'Audited'; ShortText = 'Audit outgoing NTLM that would be blocked.' }
    8002 = @{ Category = 'Audited'; ShortText = 'Audit incoming NTLM that would be blocked.' }
    8003 = @{ Category = 'Audited'; ShortText = 'Audit domain NTLM that would be blocked.' }
}

if (-not (Get-WinEvent -ListLog $logName -ErrorAction SilentlyContinue)) {
    throw "The event log '$logName' was not found. Make sure NTLM operational logging is enabled."
}

Write-Output "Analyzing '$logName' from $($startTime.ToString('u')) ..."

$ntlmevents = Get-WinEvent -FilterHashtable @{
    LogName   = $logName
    StartTime = $startTime
} -MaxEvents $MaxEvents -ErrorAction Stop

if (-not $ntlmevents) {
    Write-Warning 'No NTLM events found in the selected time range.'
    return
}
Write-Verbose "Retrieved $($ntlmevents.Count) NTLM events for analysis."
Write-Progress -activity "Processing NTLM Events" -Status "starting" -PercentComplete "0" -Id 1
$results = foreach ($ntlmevent in $ntlmevents) {
    $i++
    Write-Progress -activity "Processing NTLM Events" -Status "$($ntlmevent.Id)" -PercentComplete (($i / $ntlmevents.Count)*100) -Id 1
    $xml = [xml]$ntlmevent.ToXml()

    $ntlmeventData = @{}
    foreach ($node in $xml.Event.EventData.Data) {
        if ($null -ne $node.Name -and $node.Name -ne '') {
            $ntlmeventData[$node.Name] = [string]$node.'#text'
        }
    }

    $known = $knownEvents[[int]$ntlmevent.Id]

    $classificationByText = switch -Regex ($ntlmevent.Message) {
        '(?i)\bblock(ed|ing)?\b|\bdeny\b|\bdenied\b|\bfailed\b' { 'Blocked'; break }
        '(?i)\baudit(ed|ing)?\b' { 'Audited'; break }
        '(?i)\bsuccess\b|\bsucceeded\b' { 'Info'; break }
        default { $null }
    }

    $action = if ($known) { $known.Category } elseif ($classificationByText) { $classificationByText } else { 'Unknown' }
    $ntlmeventDescription = if ($known) { $known.ShortText } else { $null }

    $identity = Get-FirstValue -Map $ntlmeventData -Names @(
        'UserName', 'TargetUserName', 'AccountName', 'ClientUserName',
        'SuppliedUser', 'Username', 'User'
    )

    $identityDomain = Get-FirstValue -Map $ntlmeventData -Names @(
        'DomainName', 'TargetDomainName', 'AccountDomain', 'ClientDomainName',
        'SuppliedDomain', 'Domain'
    )

    $targetServer = Get-FirstValue -Map $ntlmeventData -Names @(
        'TargetServer', 'TargetMachine', 'TargetName', 'ServerName',
        'DestinationServer', 'WorkstationName', 'DeviceName'
    )

    $targetDomain = Get-FirstValue -Map $ntlmeventData -Names @(
        'TargetDomain', 'DestinationDomain', 'Domain'
    )

    $targetResource = Get-FirstValue -Map $ntlmeventData -Names @(
        'TargetResource', 'ResourceName', 'ServiceName', 'TargetInfo',
        'TargetNetworkName', 'ServiceBinding'
    )

    $serviceBinding = Get-FirstValue -Map $ntlmeventData -Names @(
        'ServiceBinding'
    )

    if ([int]$ntlmevent.Id -eq 4020 -and $serviceBinding) {
        $targetResource = $serviceBinding
    }

    $client = Get-FirstValue -Map $ntlmeventData -Names @(
        'ClientName', 'ClientMachine', 'ClientMachineName', 'Workstation',
        'WorkstationName', 'Hostname', 'SourceHost'
    )

    $workstation = Get-FirstValue -Map $ntlmeventData -Names @(
        'Workstation', 'WorkstationName', 'ClientMachine', 'ClientMachineName',
        'Hostname', 'DeviceName'
    )

    $targetIp = Get-FirstValue -Map $ntlmeventData -Names @(
        'TargetIP', 'DestinationIpAddress'
    )

    $protocol = Get-FirstValue -Map $ntlmeventData -Names @(
        'PackageName', 'AuthenticationPackageName', 'ProtocolName',
        'NtlmVersion', 'LmPackageName', 'Mechanism', 'MechanismOID', 'MechanismOid'
    )

    $logonType = Get-FirstValue -Map $ntlmeventData -Names @(
        'LogonType', 'SignOnType'
    )

    $processName = Get-FirstValue -Map $ntlmeventData -Names @(
        'ProcessName', 'CallerProcessName', 'ApplicationName',
        'CallingProcessName', 'NameOfClientProcess', 'Process'
    )

    $ntlmUsageReason = Get-FirstValue -Map $ntlmeventData -Names @(
        'NtlmUsageReason', 'NTLMUsageReason', 'Reason'
    )

    $result = [ordered]@{
        Timestamp          = $ntlmevent.TimeCreated
        Computer             = $ntlmevent.MachineName
        EventId              = [int]$ntlmevent.Id
        Action               = $action
        EventShortText        = $ntlmeventDescription
        Identity           = $identity
        Domain              = $identityDomain
        TargetServer           = $targetServer
        TargetDomain          = $targetDomain
        TargetResource        = $targetResource
        Client               = $client
        Workstation          = $workstation
        TargetIP               = $targetIp
        Protocol            = $protocol
        LogonType             = $logonType
        Process              = $processName
        NtlmUsageReason      = $ntlmUsageReason
    }

    if ($IncludeOriginalMessage) {
        $result['EventMessage'] = ($ntlmevent.Message -replace '\s+', ' ').Trim()
    }

    if ($ShowRawEventData) {
        $result['RawEventData'] = ($ntlmeventData.GetEnumerator() | Sort-Object Name | ForEach-Object { "{0}={1}" -f $_.Name, $_.Value }) -join '; '
    }

    [PSCustomObject]$result
}
Write-Progress -activity "Processing NTLM Events" -Status "completed" -PercentComplete "100" -Id 1
Write-Output ''
Write-Output 'Summary by action:'
$results | Group-Object -Property Action | Sort-Object -Property Name | ForEach-Object {
        "  {0,-10}: {1}" -f $_.Name, $_.Count
    } | Write-Output

Write-Output ''
Write-Output 'Summary by EventId:'
$results | Group-Object -Property EventId | Sort-Object -Property Name | ForEach-Object {
        "  {0,-6}: {1}" -f $_.Name, $_.Count
    } | Write-Output

if ($CSVExportPath) {
    $results | Export-Csv -Path $CSVExportPath -NoTypeInformation -Encoding UTF8
    Write-Output "CSV exported to: $CSVExportPath"
}

Write-Output ''
Write-Output 'Details (newest first) in Out-GridView:'
If ($CoreVersion -eq $true) {
    $results | Sort-Object -Property Timestamp -Descending | Format-Table -AutoSize -Wrap 
} else {
    $results | Sort-Object -Property Timestamp -Descending | Out-GridView -Title 'NTLM Operational Analysis (newest first)'
}
