#requires -version 5.1
#requires -modules activedirectory

<#
.SYNOPSIS
    Query Windows Security event logs for successful and failed logon events.

.DESCRIPTION
    This script queries all Domain Controllers for Windows Security event IDs 4624 (successful logon)
    and 4625 (failed logon) within a specified time range. Results can be displayed in GridView
    or exported to CSV. The script includes user filtering with wildcard support and automatically
    detects Windows Server Core to disable GridView when not available.

.PARAMETER Days
    The number of days to look back in the event logs. Default is 1 (last 24 hours).
    Valid range is 1 to 365 days.

.PARAMETER User
    Optional username filter with wildcard support. Searches across TargetUserName,
    SubjectUserName, and WorkstationName fields. Example: 'jdoe*' matches 'jdoe', 'jdoe_admin', etc.

.PARAMETER GridView
    Display results in GridView. Automatically disabled on Windows Server Core.
    Default is $true.

.PARAMETER CsvExport
    Export results to CSV file. Default is $false.

.PARAMETER CsvPath
    Path for CSV export file. Directory must exist. Required if CsvExport is $true.

.EXAMPLE
    .\Get-Logons.ps1
    Query all DCs for logon events from the last 24 hours and display in GridView.

.EXAMPLE
    .\Get-Logons.ps1 -Days 7 -User 'admin*'
    Query all DCs for logon events from the last 7 days, filtering for users matching 'admin*'.

.EXAMPLE
    .\Get-Logons.ps1 -CsvExport $true -CsvPath 'C:\Logs\Logons.csv' -GridView $false
    Query all DCs for logon events and export to CSV without displaying GridView.

.LINK
    https://github.com/InfrastructureHeroes/Scipts/blob/master/ActiveDirectory/get-logons.ps1

.NOTES
    Author     : Fabian Niesen
    Filename   : Get-Logons.ps1
    Requires   : PowerShell Version 5.1

    Version    : 1.0.0
    History    :
                1.0.0 20261007 FN Initial version for SecureCloudAD3
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 365)]
    [int]$Days = 1,

    [Parameter(Mandatory = $false)]
    [string]$User,

    [Parameter(Mandatory = $false)]
    [bool]$GridView = $true,

    [Parameter(Mandatory = $false)]
    [bool]$CsvExport = $false,

    [Parameter(Mandatory = $false)]
    [ValidateScript({
            if (-not (Test-Path (Split-Path $_))) {
                throw 'Directory does not exist: ' + (Split-Path $_)
            }
            $true
        })]
    [string]$CsvPath
)

# Script version information
[string]$ScriptVersion = '1.0.0'

# Import required modules
# Import-Module ActiveDirectory

# Initialize variables
$ErrorActionPreference = 'Stop'
$LogOuts = [System.Collections.ArrayList]::new()
$TotalEventsFound = 0
$TotalEventsFiltered = 0

# Function to detect Windows Server Core
function Test-ServerCore {
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    $isServerCore = $false

    try {
        if (((Get-ComputerInfo).WindowsInstallationType) -like 'Server Core') {
            $isServerCore = $true
        }
    }
    catch {
        # Get-ComputerInfo not available, assume not Server Core
        $isServerCore = $false
    }

    Write-Verbose 'Detect Server Core: ' + $isServerCore
    return $isServerCore
}

# Main script logic with progress bars
try {
    # Detect Server Core and adjust GridView parameter
    $isCore = Test-ServerCore
    if ($isCore -and $GridView) {
        Write-Warning 'Windows Server Core detected. GridView is not available. Output will be to console only.'
        $GridView = $false
    }

    Write-Output 'Starting logon event query for the last ' + $Days + ' day(s)'

    # Check if user filter is provided
    if ($PSBoundParameters.ContainsKey('User')) {
        Write-Output 'Filtering for user: ' + $User
    }

    # Get all Domain Controllers
    Write-Output 'Retrieving Domain Controllers...'
    $DCs = Get-ADDomainController -Filter *
    $totalDCs = $DCs.Count
    $currentDC = 0

    if ($totalDCs -eq 0) {
        Write-Error 'No Domain Controllers found'
        exit 1
    }

    Write-Output 'Found ' + $totalDCs + ' Domain Controller(s)'

    # Query each DC
    foreach ($DC in $DCs) {
        $currentDC++
        $dcPercent = ($currentDC / $totalDCs) * 100

        Write-Progress -Id 1 -Activity 'Querying Domain Controllers' `
            -Status ('Processing DC ' + $currentDC + ' of ' + $totalDCs) `
            -PercentComplete $dcPercent `
            -CurrentOperation ('DC: ' + $DC.HostName)

        Write-Output 'Starting remote PowerShell session to query DC: ' + $DC.HostName

        try {
            # Query events 4624 and 4625 from Security log
            $events = Invoke-Command -ComputerName $DC.HostName -ScriptBlock {
                param($daysBack)
                try {
                    Get-WinEvent -LogName Security -FilterXPath @'
*[System[(EventID=4624 or EventID=4625) and TimeCreated[timediff(@SystemTime) <= 86400000]]]
'@.Replace('86400000', ($daysBack * 86400000).ToString()) -ErrorAction Stop
                }
                catch {
                    # No events found or access denied
                    @()
                }
            } -ArgumentList $Days -ErrorAction Stop

            $eventsFound = 0
            $eventsFiltered = 0

            foreach ($event in $events) {
                $eventsFound++

                # Extract event data with error handling
                try {
                    $eventId = $event.Id
                    $timeCreated = $event.TimeCreated
                    $targetUserName = $null
                    $targetDomainName = $null
                    $workstationName = $null
                    $ipAddress = $null
                    $logonType = $null
                    $status = $null
                    $failureReason = $null

                    # Extract properties based on event ID
                    if ($eventId -eq 4624) {
                        # Event 4624: Successful logon
                        $targetUserName = $event.Properties[5].Value
                        $targetDomainName = $event.Properties[6].Value
                        $workstationName = $event.Properties[11].Value
                        $ipAddress = $event.Properties[18].Value
                        $logonType = $event.Properties[8].Value
                    }
                    elseif ($eventId -eq 4625) {
                        # Event 4625: Failed logon
                        $targetUserName = $event.Properties[5].Value
                        $targetDomainName = $event.Properties[6].Value
                        $workstationName = $event.Properties[13].Value
                        $ipAddress = $event.Properties[19].Value
                        $logonType = $event.Properties[10].Value
                        $status = $event.Properties[7].Value
                        $failureReason = $event.Properties[8].Value
                    }

                    # Apply user filter if provided
                    $includeEvent = $true
                    if ($PSBoundParameters.ContainsKey('User')) {
                        $matchTarget = $false
                        $matchSubject = $false
                        $matchWorkstation = $false

                        if ($targetUserName -and $targetUserName -like $User) {
                            $matchTarget = $true
                        }
                        if ($event.Properties[1].Value -and $event.Properties[1].Value -like $User) {
                            $matchSubject = $true
                        }
                        if ($workstationName -and $workstationName -like $User) {
                            $matchWorkstation = $true
                        }

                        if (-not ($matchTarget -or $matchSubject -or $matchWorkstation)) {
                            $includeEvent = $false
                            $eventsFiltered++
                        }
                    }

                    if ($includeEvent) {
                        # Create custom object for output
                        $logEntry = [PSCustomObject]@{
                            EventID          = $eventId
                            TimeCreated      = $timeCreated
                            TargetUserName   = $targetUserName
                            TargetDomainName = $targetDomainName
                            WorkstationName  = $workstationName
                            IpAddress        = $ipAddress
                            LogonType        = $logonType
                            Status           = $status
                            FailureReason    = $failureReason
                            EventServer      = $DC.HostName
                        }

                        $null = $LogOuts.Add($logEntry)
                    }
                }
                catch {
                    Write-Warning 'Failed to extract event data: ' + $_.Exception.Message
                }
            }

            $TotalEventsFound += $eventsFound
            $TotalEventsFiltered += $eventsFiltered

            Write-Output 'Found ' + $eventsFound + ' event(s) on ' + $DC.HostName
            if ($PSBoundParameters.ContainsKey('User') -and $eventsFiltered -gt 0) {
                Write-Output 'Filtered ' + $eventsFiltered + ' event(s) on ' + $DC.HostName
            }
        }
        catch {
            Write-Error 'Failed to query DC ' + $DC.HostName + ': ' + $_.Exception.Message
        }
    }

    Write-Progress -Id 1 -Activity 'Querying Domain Controllers' -Completed

    Write-Output 'Total events found: ' + $TotalEventsFound
    if ($PSBoundParameters.ContainsKey('User')) {
        Write-Output 'Total events filtered: ' + $TotalEventsFiltered
        Write-Output 'Events after filtering: ' + $LogOuts.Count
    }

    # Output results
    if ($LogOuts.Count -eq 0) {
        Write-Output 'No events found matching the criteria'
    }
    else {
        if ($GridView) {
            $LogOuts | Out-GridView -Title ('Logon Events (4624/4625) - Last ' + $Days + ' Day(s)')
        }

        if ($CsvExport) {
            if (-not $CsvPath) {
                Write-Warning 'CsvPath parameter is required when CsvExport is $true'
                $CsvPath = Read-Host -Prompt 'Please enter a filename including path for CSV export'
            }

            Write-Output 'Exporting to CSV: ' + $CsvPath
            $LogOuts | Export-Csv -Path $CsvPath -Delimiter ';' -NoTypeInformation
            Write-Output 'CSV export completed'
        }

        if (-not $GridView -and -not $CsvExport) {
            # Display in console if neither GridView nor CSV export is selected
            $LogOuts | Format-Table -AutoSize
        }
    }
}
catch {
    Write-Error 'Script failed: ' + $_.Exception.Message
    exit 1
}
finally {
    # Cleanup
    Write-Progress -Id 1 -Activity 'Querying Domain Controllers' -Completed
}
