#requires -version 5.1
<#
.SYNOPSIS
Checks the security event logs for NTLM logons and analyses them.
	
.DESCRIPTION
Checks the security event logs for NTLM logons and analyses them. The participating systems and users as well as the login type are output.

DISCLAIMER
This script is provided "as is" without any warranty of any kind, express or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose, and noninfringement. 
Use of this script is at your own risk. The author assumes no responsibility for any damage or data loss caused by the use of this script.

(c) 2026 Fabian Niesen, www.infrastrukturhelden.de - License: GNU General Public License v3 (GPLv3), see notes for details

.PARAMETER AllDCs
Query on all DC instead of local system only.

.PARAMETER Days
Number of days in the past to search for Events

.PARAMETER exportCSV
Export results as CSV

.PARAMETER exportpath
Path to CSV file

.EXAMPLE 
C:\PS> get-NTLMLogons.ps1
Query local System and show results on screen

.EXAMPLE 
C:\PS> get-NTLMLogons.ps1 -AllDCs
Query all DC and show results on screen

.EXAMPLE 
C:\PS> get-NTLMLogons.ps1 -AllDCs -exportCSV -exportpath C:\Temp\NTLM.csv
Query all DC and export results to C:\Temp\NTLM.csv

.NOTES
Author     : Fabian Niesen (www.infrastukturhelden.de)
Filename   : get-NTLMLogons.ps1
Requires   : PowerShell Version 5.1
License    : GNU General Public License v3 (GPLv3)
            (c) 2026 Fabian Niesen, www.infrastrukturhelden.de
            This script is licensed under the GNU General Public License v3 (GPLv3). 
            You can redistribute it and/or modify it under the terms of the GPLv3 as published by the Free Software Foundation.
            This script is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of
            MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details. 
            See https://www.gnu.org/licenses/gpl-3.0.html for the full license text.
DISCLAIMER  :
            This script is provided "as is" without any warranty of any kind, express or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose, and noninfringement. 
            Use of this script is at your own risk. The author assumes no responsibility for any damage or data loss caused by the use of this script.

Version    : 1.1
History    : 
                1.1  Fabian Niesen  27.01.2026  Fix local DC with AllDcs switch, Catch for unreachable DCs
                1.0  Fabian Niesen  17.02.2024  initial version


.LINK
https://www.infrastrukturhelden.de/
#>

Param(
    [switch]$AllDCs,
    #[int]$Days = 3,
    [Parameter(HelpMessage = 'Export results as CSV' )][switch]$exportCSV,
    [Parameter(HelpMessage = 'Path to CSV file' )][string]$exportpath = "C:\Temp\NTLM.csv"

)
<# TODO
- Verify Logging for NTLM
- Integrate other Event IDs (NTLM Logs)
- If Exportpath exists, rename instead delete
#>
#region init
$ScriptVersion = "1.1"
$script:ParentFolder = $PSScriptRoot | Split-Path -Parent
$global:ScriptName = $myInvocation.MyCommand.Name
$global:ScriptName = $ScriptName.Substring(0, $scriptName.Length - 4)
$global:scriptsource = $myInvocation.MyCommand.Source
$global:scriptparam = $MyInvocation.BoundParameters
Write-Output -Message "Start $ScriptName $ScriptVersion - Executed on $($Env:COMPUTERNAME) by $($Env:USERNAME)" 
#endregion init

Write-Warning "You need to activate NTLM Auditing to get the Events generated! Otherwise, this will not show anything."
$start = $(Get-Date)
Write-Output "Query Events for the last day. This will take some time. Start: $start"
$xmlQuery = @'
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">
      *[System[(EventID=4624)and TimeCreated[timediff(@SystemTime) &lt;= 86400000]]] 
      and
      *[EventData[Data[@Name='AuthenticationPackageName'] and (Data='NTLM') or (Data='MICROSOFT_AUTHENTICATION_PACKAGE_V1_0')]]
	</Select>
  </Query>
</QueryList>
'@
$NTLMLogs = @()
If ( $AllDCs ) {
    Write-Output "- Execute for all DCs -"
    IF ( (Get-WindowsFeature -Name RSAT-AD-PowerShell).InstallState -like "Installed") 
        {
            [String]$DNSDomain = (Get-ADDomain).DNSRoot.toLower()
            $DCs = (Get-ADDomainController -Filter *).HostName.toLower()
        } Else {
            [String]$DNSDomain = $env:USERDNSDOMAIN
            $DCs = (((nltest /dclist:$DNSDomain).trim() | Select-String -Pattern ".$DNSDomain") | Select-Object -skip 1 )
            $DCs = (($DCs -split " ") -match ".$DNSDomain").ToLower()
        }
    Write-Output "- Found following DCs: $($DCs -join ", ") -"
    [int]$i = 0
    ForEach ( $DC in $DCs)
        {
            $i++
            Write-Progress -activity "Query DC Security Logs" -Status "This may take a while.... - $DC" -PercentComplete (($i / $DCs.count)*100) -Id 1
            Try {
                IF ( $DC -eq $env:COMPUTERNAME.toLower() ) 
                    {
                        Write-Output "- Query local DC $DC -"
                        $ID4624 += Get-WinEvent -FilterXml $xmlquery
                    } 
                Else 
                    {
                        Write-Output "- Query remote DC $DC -"
                        $ID4624 += Get-WinEvent -ComputerName $dc -FilterXml $xmlquery
                    }
            } Catch {
                Write-Warning "Could not query DC $DC : $_"
            }
        }
    Write-Progress -activity "Finish query"  -Completed 100 -Id 1
}
Else 
{
    Write-Output "- Execute in Local mode -"
    $ID4624 = Get-WinEvent -FilterXml $xmlquery
}
$NTLMLogs = $ID4624 | Where-object { $_.Message -match "NtLmSsp" }
$NTLMLogs += $ID4624 | Where-object { $_.Message -match "MICROSOFT_AUTHENTICATION_PACKAGE_V1_0" }
Write-Output "Found $($NTLMLogs.count) entries"
$NTLMData = @()

[int]$i = 0
ForEach ( $NTLMEvent in $NTLMLogs )
{
    $i++
    Write-Progress -activity "Processing NTLM Events" -PercentComplete (($i / $NTLMLogs.count)*100) -Id 2
    $data = New-Object PSObject
    $data | Add-Member -MemberType NoteProperty -Name "MachineName" -Value $NTLMEvent.MachineName
    $data | Add-Member -MemberType NoteProperty -Name "ID" -Value $NTLMEvent.Id
    $data | Add-Member -MemberType NoteProperty -Name "TimeCreated" -Value $NTLMEvent.TimeCreated
    #$data | Add-Member -MemberType NoteProperty -Name "KeywordsDisplayNames" -Value $NTLMEvent.KeywordsDisplayNames
    $data | Add-Member -MemberType NoteProperty -Name "Logon Type" -Value $NTLMEvent.Properties[8].Value
    $data | Add-Member -MemberType NoteProperty -Name "Account Name" -Value $NTLMEvent.Properties[5].Value
    $data | Add-Member -MemberType NoteProperty -Name "Workstation Name" -Value $NTLMEvent.Properties[11].Value
    $data | Add-Member -MemberType NoteProperty -Name "Source" -Value $NTLMEvent.Properties[18].Value
    $data | Add-Member -MemberType NoteProperty -Name "Logon Process" -Value $NTLMEvent.Properties[9].Value
    $data | Add-Member -MemberType NoteProperty -Name "Package Name" -Value $NTLMEvent.Properties[10].Value
    $NTLMData += $data
}
Write-Progress -activity "Finish processing NTLM Events"  -Completed 100 -Id 2
IF ($exportCSV) 
{ 
    IF ( Test-Path $exportpath ) { Remove-Item -Path $exportpath -Force -Confirm:$false }
    $NTLMData | Export-CSV -Path $exportpath -NoClobber -Force -Delimiter ";"  -NoTypeInformation
}
$NTLMData | Format-Table -AutoSize 
Write-Output "$($NTLMData.count) NTLM events found"
Write-Output "Start: $start - End: $(Get-Date)"
