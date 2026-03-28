#requires -version 5.1
#requires -modules activedirectory

<#
	.SYNOPSIS
		Get basic information upon the Active Directory Forrest
	.DESCRIPTION
		Get basic information upon the Active Directory Forrest, like the cration date of the domains, a list off all DC and a Report the Schema versions (AD, Exchange, Lync and SCCM).
        Based upon an TechNet article from "The Scripting guys". Thanks also to Shawn Johnson, Paul Wetter, SteveLarson for providing SCCM extension and more schema versions.
        http://blogs.technet.com/b/heyscriptingguy/archive/2012/01/05/how-to-find-active-directory-schema-update-history-by-using-powershell.aspx
        Require the ActiveDirectory PowerShell Module, no admin permisions needed for most functions.
        Will provide more details about replication and replication errors is executed on a Domain Controller
        
        DISCLAIMER
        This script is provided "as is" without any warranty of any kind, express or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose, and noninfringement. 
        Use of this script is at your own risk. The author assumes no responsibility for any damage or data loss caused by the use of this script.

        (c) 2015-2026 Fabian Niesen, www.infrastrukturhelden.de - Since V0.6 License: GNU General Public License v3 (GPLv3), see notes for details
	.EXAMPLE  
        get-adinfo.ps1
	.INPUTS
		Keine.
	.OUTPUTS
		Keine.
    .PARAMETER Logpath
        Path to create Logfiles and CSV Exports. Default: C:\Temp
	.NOTES
		Author     : Fabian Niesen
		Filename   : get-adinfo.ps1
		Requires   : PowerShell Version 5.1
        License    : GNU General Public License v3 (GPLv3)
                    (c) 2026 Fabian Niesen, www.infrastrukturhelden.de
                    This script is licensed under the GNU General Public License v3 (GPLv3). 
                    You can redistribute it and/or modify it under the terms of the GPLv3 as published by the Free Software Foundation.
                    This script is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of
                    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details. 
                    See https://www.gnu.org/licenses/gpl-3.0.html for the full license text.
		
		Version    : 0.7
		History    : 0.7  FN  28.03.2026 Add more features to support DC replacement article, optimization for core server
                    0.6   FN  26.03.2026 Update Schema versions, change License, add replication connections
                    0.5   FN  19.02.2021  
                    0.4   FN  15.07.2020  Update Schemas, integrate LAPS detection
                    0.3   FN  21.07.2016  Add Windows Server 2016, Exchange multiple CU and 2016, some SystemCenter and Sign Script
                    0.2   FN  10.03.2015  Add SCCM R2 CU1-4 and SCCM CU5
                    0.1   FN  18.02.2015  initial version
                    
    .LINK
        https://github.com/InfrastructureHeroes/Scipts/blob/master/ActiveDirectory/get-adinfo.ps1
#>

[cmdletbinding()]
Param(
    $logpath="C:\Temp\"
)
#region Functions
Function Get-DC {
    Begin { Write-Host "Start DC detection" }
    Process {
        Try {
            IF ( (Get-WindowsFeature -Name RSAT-AD-PowerShell).InstallState -like "Installed") 
            {
                Write-Host "Use RSAT-AD-PowerShell for DC detection"
                $DC=(Get-ADDomainController -Filter {OperationMasterRoles -like "PDC*"}).Hostname
                if ((Test-Connection $DC -Count 1) -eq $false)
                    {
                        Write-Warning "Found RSAT-AD-PowerShell - PDC not reachable - Fallback mode" 
                        $DC = (Get-ADDomainController).Hostname
                        if ((Test-Connection $DC -Count 1) -eq $false)
                        {
                            Write-Warning "DC not reachable - Abort" 
                            Break;                
                        }
                    } Else {
                        Write-Host "PDC is reachable - Using $DC"
                    }
            }
            else {
                Write-Host "RSAT-AD-PowerShell not found, fall back to NLtest - the determined DC might not be the PDC!"
                $DCs = (((nltest /dclist:$DNSDomain).trim() | Select-String -Pattern ".$DNSDomain") | Select-Object -skip 1 )
                $DCs = ($DCs -split " ") -match ".$DNSDomain"
                $DC = $DCs[0].ToString()
                Write-Host "Set DC to $DC"
            }
        }
        Catch {
            Write-Host "GET-DC - $($_.Exception.Message)" 
            $DCs = (((nltest /dclist:$DNSDomain).trim() | Select-String -Pattern ".$DNSDomain") | Select-Object -skip 1 )
            $DCs = ($DCs -split " ") -match ".$DNSDomain"
            $DC = $DCs[0].ToString()
            Write-Host "Set DC to $DC"
        }
    }
    END { return $DC }
}
#endregion Functions
$timestamp = get-date -format yyyyMMdd-HHmm 
IF ($logpath.EndsWith("\") -like "False") { $logpath =$logpath+"\" }
IF (!(Test-Path $logpath)) { new-item -Path $logpath -ItemType directory }
$ScriptVersion = "0.7"
$ScriptName = $($myInvocation.MyCommand.Name).Replace('.ps1', '')
$logfile = $logpath + $timestamp + "-" + $ScriptName + ".log"
"Get-ADInfo.ps1 by Fabian Niesen, www.infrastrukturhelden.de - Since V0.6 License: GNU General Public License v3 (GPLv3), see notes for details" | Tee-Object -FilePath $logfile | Write-Output
"Start $ScriptName $ScriptVersion - Executed on $($Env:COMPUTERNAME) by $($Env:USERNAME) at $(get-date -format 'HH:mm dd.MM.yyyy' )" | Tee-Object -FilePath $logfile -Append | Write-Output
if (((Get-ComputerInfo).WindowsInstallationType) -like "Server Core") {$CoreVersion=$true} else {$CoreVersion = $false}
"Is Windows Server Core: $CoreVersion" | Tee-Object -FilePath $logfile -Append | Write-Output
$dc = Get-DC
$ErrorActionPreference = "SilentlyContinue"
$before = Get-Date
Try
{
    Import-Module ActiveDirectory -Verbose:$false
}
catch
{
    Write-Warning "PowerShell module for Active Directory not found!"
    break
}
[String]$DNSDomain = (Get-ADDomain).DNSRoot.toLower()
#$localisDC
$ComputerSystem = Get-WmiObject Win32_ComputerSystem
$IsDomainController = ($ComputerSystem.DomainRole -ge 4)
IF ($IsDomainController) { "Localhost detected as Domain Controller" | Tee-Object -FilePath $logfile -Append | Write-Output }
# Forrest creation
" "| Tee-Object -FilePath $logfile -Append | Write-Output
"> Creation date of the domains" | Tee-Object -FilePath $logfile -Append | Write-Output
"===============================================================" | Tee-Object -FilePath $logfile -Append | Write-Output
$Doms = Get-ADObject -SearchBase (Get-ADForest).PartitionsContainer -LDAPFilter "(&(objectClass=crossRef)(systemFlags=3))" -Property dnsRoot, nETBIOSName, whenCreated |Sort-Object whenCreated #| Tee-Object -FilePath $logfile -Append | Write-Output
$Doms | Select-Object dnsRoot, NETBIOSName, whenCreated  | Tee-Object -FilePath $logfile -Append | Format-Table -AutoSize -Wrap

# Fuctional Levels
" "| Tee-Object -FilePath $logfile -Append | Write-Output
"> Funtional Level and FSMO roles" | Tee-Object -FilePath $logfile -Append | Write-Output
"===============================================================" | Tee-Object -FilePath $logfile -Append | Write-Output
Get-ADForest | Select-Object Name,ForestMode,SchemaMaster,DomainNamingMaster | Tee-Object -FilePath $logfile -Append | Format-List
$Doms.Netbiosname | Get-ADDomain | Select-Object Name,NetBiosName,DNSRoot,DomainMode,PDCEmulator,RIDMaster,InfrastructureMaster | Tee-Object -FilePath $logfile -Append | Format-List
# List DCs
" "| Tee-Object -FilePath $logfile -Append | Write-Output
"> List of all domain controllers" | Tee-Object -FilePath $logfile -Append | Write-Output
"===============================================================" | Tee-Object -FilePath $logfile -Append | Write-Output
try 
        { 
            $Forest = [system.directoryservices.activedirectory.Forest]::GetCurrentForest()     
        } 
    catch 
        { 
            "Cannot connect to current forest." 
        } 
$DCData = @()
[int]$i = 0
$dcs = $($Forest.domains).DomainControllers
ForEach ( $DC in $DCS )
{
    $i++
    Write-Progress -activity "Processing Domain Controllers: $($DC.Name)" -PercentComplete (($i / $dcs.count)*100) -Id 2
    Write-Verbose "$DC $i of $($dcs.count)"
    $data = New-Object PSObject
    $GADDC = Get-ADDomainController -Identity $DC.Name 
    $data | Add-Member -MemberType NoteProperty -Name "Name" -Value $DC.Name
    $data | Add-Member -MemberType NoteProperty -Name "OSVersion" -Value $DC.OSVersion
    $data | Add-Member -MemberType NoteProperty -Name "SiteName" -Value $DC.SiteName
    $data | Add-Member -MemberType NoteProperty -Name "InboundConnections" -Value $DC.InboundConnections 
    $data | Add-Member -MemberType NoteProperty -Name "OutboundConnections" -Value $DC.OutboundConnections 
    $data | Add-Member -MemberType NoteProperty -Name "InvocationId" -Value $GADDC.InvocationId
    $data | Add-Member -MemberType NoteProperty -Name "IPv4Address" -Value $GADDC.IPv4Address
    $data | Add-Member -MemberType NoteProperty -Name "IPv6Address" -Value $GADDC.IPv6Address
    $data | Add-Member -MemberType NoteProperty -Name "IsGlobalCatalog" -Value $GADDC.IsGlobalCatalog
    $data | Add-Member -MemberType NoteProperty -Name "IsReadOnly" -Value $GADDC.IsReadOnly
    Try {
        Get-ChildItem -Path \\$DC\sysvol\$DNSDomain\ -ErrorAction Stop | Out-Null
        $data | Add-Member -MemberType NoteProperty -Name "SysVol" -Value "Reachable"
    } Catch {$data | Add-Member -MemberType NoteProperty -Name "SysVol" -Value "ERROR"}
    Try {
        Get-ChildItem -Path \\$DC\NetLogon\ -ErrorAction Stop | Out-Null
        $data | Add-Member -MemberType NoteProperty -Name "NetLogon" -Value "Reachable"
    } Catch {$data | Add-Member -MemberType NoteProperty -Name "NetLogon" -Value "ERROR"}
    $DCData += $data
}
Write-Progress -activity "Finish processing Domain Controllers"  -Completed 100 -Id 2
$DCData | Select-Object Name,OSVersion,SiteName,@{Name='InboundConnections'; Expression={ $_.InboundConnections -join ',' }},@{Name='OutboundConnections'; Expression={ $_.OutboundConnections -join ',' }},InvocationId,IPv4Address,IPv6Address,IsGlobalCatalog,IsReadOnly,SysVol,NetLogon | ConvertTo-Csv -Delimiter ";" -NoTypeInformation | Out-File -FilePath $($logpath + $timestamp + "-" + "DC_List.csv") -Force -NoClobber 
IF ($CoreVersion) {$DCData | Format-List -Property * } else {$DCData | Out-GridView -Title "List of Domain Contollers"}
"DC List is available as CSV file at $($logpath + $timestamp + "-" + "DC_List.csv")" | Tee-Object -FilePath $logfile -Append | Write-Output
$msdcs = "_msdcs." + $DNSDomain
" "| Tee-Object -FilePath $logfile -Append | Write-Output
"> List of all domain controler for $DNSDomain in DNS"| Tee-Object -FilePath $logfile -Append | Write-Output
"===============================================================" | Tee-Object -FilePath $logfile -Append | Write-Output
Resolve-DnsName -Name _ldap._tcp.dc.$msdcs -Type SRV | Tee-Object -FilePath $logfile -Append | Write-Output
Try 
{ 
    $GDSRR = Get-DnsServerResourceRecord -ZoneName $msdcs  -RRType CNAME -ComputerName $DC -ErrorAction Stop 
    " "| Tee-Object -FilePath $logfile -Append | Write-Output
    ">> List of all CName Records for $msdcs in DNS"| Tee-Object -FilePath $logfile -Append | Write-Output
    "===============================================================" | Tee-Object -FilePath $logfile -Append | Write-Output
    If ($CoreVersion -eq $true) {$GDSRR | Format-List } ELSE { $GDSRR | Out-GridView -Title "List of all CName Records for $msdcs in DNS" }
}
catch {"Read Access to $msdcs DNS Zone on DNS Server $dc not possible - Maybe not enough permissions or DNS RSAT missing"| Tee-Object -FilePath $logfile -Append | Write-Warning}
#Region Replication connections
" "| Tee-Object -FilePath $logfile -Append | Write-Output
"> ADReplication Information" | Tee-Object -FilePath $logfile -Append | Write-Output
"===============================================================" | Tee-Object -FilePath $logfile -Append | Write-Output
$ADReplicationPartnerMetadata = Get-ADReplicationPartnerMetadata -Target * 
$ADReplicationPartnerMetadata | Write-Output -FilePath $logfile -Append
If ($CoreVersion -eq $true) {$ADReplicationPartnerMetadata | Format-List } ELSE { $ADReplicationPartnerMetadata | Out-GridView -Title "AD Replication Partner Metadata" }
IF ($IsDomainController){
    " "| Tee-Object -FilePath $logfile -Append | Write-Output
    ">> AD Replication Failures"| Tee-Object -FilePath $logfile -Append | Write-Output
    "===============================================================" | Tee-Object -FilePath $logfile -Append | Write-Output
    $ADReplicationFailure = Get-ADReplicationFailure -Target * 
    $ADReplicationFailure | Write-Output -FilePath $logfile -Append
    If ($CoreVersion -eq $true) {$ADReplicationFailure  | Format-List } ELSE { $ADReplicationFailure | Out-GridView -Title "AD Replication Failures"}
    " "| Tee-Object -FilePath $logfile -Append | Write-Output
    ">> Repadmin /showrepl"| Tee-Object -FilePath $logfile -Append | Write-Output
    "===============================================================" | Tee-Object -FilePath $logfile -Append | Write-Output
    $repadmincsv = $logpath + $timestamp + "-" + "repadmin.csv"
    "Export Replication data from >repadmin< to $repadmincsv"| Tee-Object -FilePath $logfile -Append | Write-Output
    repadmin /showrepl * /csv > $repadmincsv
    If ($CoreVersion -eq $true) {& notepad.exe $repadmincsv} ELSE {$repadmincsv | convertfrom-csv | out-gridview}
} Else { "For more replication information like Replication Failures, execute this script on a Domain Controller" | Tee-Object -FilePath $logfile -Append | Write-Output}
#Endregion Replication connections
#Region SchemaVersionen
$SchemaVersions = @()
$SchemaHashAD = @{ 
13="Windows 2000 Server"; 
30="Windows Server 2003"; 
31="Windows Server 2003 R2"; 
44="Windows Server 2008"; 
47="Windows Server 2008 R2";
51="!!! Windows Server 8 Developer Preview !!!";
52="!!! Windows Server 8 BETA !!!";
56="Windows Server 2012";
69="Windows Server 2012 R2";
72="!!! Windows Server vNext Technical Preview (Build 9841) !!!";
87="Windows Server 2016";
88="Windows Server 2019 / 2022";
91="Windows Server 2025";
}
Write-Verbose "Starting AD Schema"
$SchemaPartition = (Get-ADRootDSE).NamingContexts | Where-Object {$_ -like "*Schema*"} 
$SchemaVersionAD = (Get-ADObject $SchemaPartition -Property objectVersion).objectVersion 
write-verbose "SchemaVersionAD: $SchemaVersionAD"
$SchemaVersions += 1 | Select-Object @{name="Product";expression={"AD"}}, @{name="Schema";expression={$SchemaVersionAD}}, @{name="Version";expression={$SchemaHashAD.Item($SchemaVersionAD)}}
#------------------------------------------------------------------------------
$SchemaHashExchange = @{ 
0="No Exchange Schema extension installed";
4397="Exchange Server 2000 RTM"; 
4406="Exchange Server 2000 SP3"; 
6870="Exchange Server 2003 RTM or SP2"; 
6936="Exchange Server 2003 SP3"; 
10628="Exchange Server 2007 RTM"; 
10637="Exchange Server 2007 RTM"; 
11116="Exchange 2007 SP1"; 
14622="Exchange 2007 SP2 or Exchange 2010 RTM";
14625="Exchange 2007 SP3"; 
14726="Exchange 2010 SP1"; 
14732="Exchange 2010 SP2";
14734="Exchange 2010 SP3";
15137="Exchange 2013 RTM";
15254="Exchange 2013 CU1";
15281="Exchange 2013 CU2";
15283="Exchange 2013 CU3";
15292="Exchange 2013 SP1/CU4";
15300="Exchange 2013 CU5";
15303="Exchange 2013 CU6";
15312="Exchange 2013 CU7 - CU23";
15317="Exchange 2016 RTM / Preview";
15323="Exchange 2016 CU1";
15325="Exchange 2016 CU2";
15326="Exchange 2016 CU3 - CU5";
15330="Exchange 2016 CU6";
15332="Exchange 2016 CU7 - CU18 or Exchange 2019 Preview";
15333="Exchange 2016 CU19";
17000="Exchange 2019 RTM/CU1";
17001="Exchange 2019 CU2-CU7";
17002="Exchange 2019 CU8-CU9";
17003="Exchange 2019 CU10-CU15 / Exchange SE RTM";
}
Write-Verbose "Starting Exchange Schema"
$SchemaPathExchange = "CN=ms-Exch-Schema-Version-Pt,$SchemaPartition" 
If (Test-Path "AD:$SchemaPathExchange") { 
Write-Verbose "Exchange Schema found"
$SchemaVersionExchange = (Get-ADObject $SchemaPathExchange -Property rangeUpper).rangeUpper 
Write-Verbose "SchemaVersionExchange: $SchemaVersionExchange"
} Else { 
$SchemaVersionExchange = 0 
}
$SchemaVersions += 1 | Select-Object @{name="Product";expression={"Exchange"}}, @{name="Schema";expression={$SchemaVersionExchange}}, @{name="Version";expression={$SchemaHashExchange.Item($SchemaVersionExchange)}}
#------------------------------------------------------------------------------
$SchemaHashLync = @{ 
0="No Lync / OCS / S4B Schema extension installed";
1006="LCS 2005"; 
1007="OCS 2007 R1"; 
1008="OCS 2007 R2"; 
1100="Lync Server 2010";
1150="Lync Server 2013 / Skype 4 Business 2015" 
}
Write-Verbose "Starting Lync / Skype4Business Schema"
$SchemaPathLync = "CN=ms-RTC-SIP-SchemaVersion,$SchemaPartition" 
If (Test-Path "AD:$SchemaPathLync") { 
Write-Verbose "Lync found"
$SchemaVersionLync = (Get-ADObject $SchemaPathLync -Property rangeUpper).rangeUpper 
Write-Verbose "SchemaVersionLync: $SchemaVersionLync"
} Else { 
$SchemaVersionLync = 0 
}
$SchemaVersions += 1 | Select-Object @{name="Product";expression={"Lync"}}, @{name="Schema";expression={$SchemaVersionLync}}, @{name="Version";expression={$SchemaHashLync.Item($SchemaVersionLync)}}
$SchemaHashSCCM = @{ 
0="No SCCM Schema extension installed";
"4.00.5135.0000"="SCCM 2007 Beta 1";
"4.00.5931.0000"="SCCM 2007 RTM";
"4.00.6221.1000"="SCCM 2007 SP1/R2";
"4.00.6221.1193"="SCCM 2007 SP1 (KB977203)";
"4.00.6487.2000"="SCCM 2007 SP2";
"4.00.6487.2111"="SCCM 2007 SP2 (KB977203)";
"4.00.6487.2157"="SCCM 2007 R3";
"4.00.6487.2207"="SCCM 2007 SP2 (KB2750782)";
"5.00.7561.0000"="SCCM 2012 Beta 2";
"5.00.7678.0000"="SCCM 2012 RC1";
"5.00.7703.0000"="SCCM 2012 RC2";
"5.00.7711.0000"="SCCM 2012 RTM";
"5.00.7711.0200"="SCCM 2012 CU1";
"5.00.7711.0301"="SCCM 2012 CU2";
"5.00.7782.1000"="SCCM 2012 SP1 Beta";
"5.00.7804.1000"="SCCM 2012 SP1";
"5.00.7804.1202"="SCCM 2012 SP1 CU1";
"5.00.7804.1300"="SCCM 2012 SP1 CU2";
"5.00.7804.1400"="SCCM 2012 SP1 CU3";
"5.00.7804.1500"="SCCM 2012 SP1 CU4";
"5.00.7804.1600"="SCCM 2012 SP1 CU5";
"5.00.7958.1000"="SCCM 2012 R2";
"5.00.7958.1203"="SCCM 2012 R2 CU1";
"5.00.7958.1303"="SCCM 2012 R2 CU2";
"5.00.7958.1401"="SCCM 2012 R2 CU3";
"5.00.7958.1501"="SCCM 2012 R2 CU4";
"5.00.7958.1604"="SCCM 2012 R2 CU5";
"5.00.8239.1000"="SCCM 2012 R2 SP1";
"5.00.8239.1203"="SCCM 2012 R2 SP1 CU1";
"5.00.8239.1301"="SCCM 2012 R2 SP1 CU2";
"5.00.8239.1403"="SCCM 2012 R2 SP1 CU3";
"5.0.8325.1000"="SCCM Current Branch 1511";
"5.0.8355.1000"="SCCM Current Branch 1602";
"5.0.8239.1501"  = "SCCM 2012 R2 SP1 - CU4";
"5.00.8355.1306" = "SCCM 1602 - UR1";
"5.00.8412.1007" = "SCCM 1606";
"5.00.8412.1307" = "SCCM 1606 - UR1";
"5.0.8458.1000"  = "SCCM 1610";
"5.0.8458.1001"  = "SCCM 1610";
"5.0.8458.1002"  = "SCCM 1610";
"5.0.8458.1003"  = "SCCM 1610";
"5.0.8458.1004"  = "SCCM 1610";
"5.0.8458.1005"  = "SCCM 1610";
"5.0.8458.1006"  = "SCCM 1610 - Update 1, FW (KB3209501)";
"5.0.8458.1007"  = "SCCM 1610 - Update 1, FW (KB3209501)";
"5.0.8458.1008"  = "SCCM 1610 - Update 1, FW (KB3209501)";
"5.0.8458.1009"  = "SCCM 1610 - IU (KB3214042)";
"5.0.8458.1520"  = "SCCM 1610 - UR (KB4010155)";
"5.0.8498.1007"  = "SCCM 1702";
"5.00.8498.1711" = "SCCM 1702- UR1 (KB4019926)";
"5.00.8540.1000" = "SCCM 1706";
"5.00.8540.1005" = "SCCM 1706 - Update 1, FW (KB4039380)";
"5.00.8540.1007" = "SCCM 1706 - Update 2, FW(KB4036267)";
"5.0.8540.1611"  = "SCCM 1706 - UR1 (KB4042949)";
"5.00.8577.1000" = "SCCM 1710";
"5.0.8577.1108"  = "SCCM 1710 UR1 (KB4057517)";
"5.0.8577.1115"  = "SCCM 1710 UR2 (KB4086143)";
"5.00.8634.1007" = "SCCM 1802";
"5.0.8634.1813"  = "SCCM 1802 UR (KB4163547)";
"5.00.8692.1003" = "SCCM 1806";
"5.00.8740.1003" = "SCCM 1810";
"5.00.8790.1005" = "SCCM 1902";
"5.00.8853.1006" = "SCCM 1906";
"5.00.8913.1006" = "SCCM 1910";
"5.00.8968.1000" = "SCCM 2002";
"5.00.9012.1000" = "SCCM 2006";
"5.00.9040.1000" = "SCCM 2010";
"5.00.9040.1019" = "SCCM 2010 (KB4594177)";
"5.00.9049.1000" = "SCCM 2103";
"5.00.9058.1000" = "SCCM 2107";
"5.00.9068.1000" = "SCCM 2111";
"5.00.9078.1000" = "SCCM 2203";
"5.00.9088.1000" = "SCCM 2207";
"5.00.9096.1000" = "SCCM 2211";
"5.00.9106.1000" = "SCCM 2303";
"5.00.9122.1000" = "SCCM 2309";
"5.00.9128.1000" = "SCCM 2403";
"5.00.9132.1000" = "SCCM 2409";
"5.00.9135.1000" = "SCCM 2503";
}
Write-Verbose "Starting SCCM Schema"
$SchemaPathSCCM = "CN=System Management," + (Get-ADDomain).SystemsContainer
if (Test-Path "AD:$SchemaPathSCCM") {
Write-Verbose "Found SCCM Schema"
$SCCMData = Get-ADObject -SearchBase ("CN=System Management," + (Get-ADDomain).SystemsContainer) -LDAPFilter "(&(objectClass=mSSMSManagementPoint))" -Property mSSMSCapabilities,mSSMSMPName
Write-Verbose "SCCMData: $SCCMData"
$SCCMxml = [XML]$SCCMdata.mSSMSCapabilities
Write-Verbose "SCCMxml: $SCCMxml"
$SchemaVersionSCCM = $SCCMxml.ClientOperationalSettings.Version
Write-Verbose "SchemaVersionSCCM: $SchemaVersionSCCM"
IF ( $SchemaVersionSCCM -eq $null) { Write-Warning "Ops, SCCM Schema found but could not figure out" ; Write-Warning "You found a known bug, whitch I could not fix till know. Any Idears or suggestion will be welcome: mail@fabian-niesen.de" }
}Else{
Write-Verbose "No SCCM Schema found"
$SchemaVersionSCCM = 0
}
Write-Verbose "Add SCCM Version to Schemaextension List"
$SchemaVersions += 1 | Select-Object @{name="Product";expression={"SCCM"}}, @{name="Schema";expression={$SchemaVersionSCCM}}, @{name="Version";expression={$SchemaHashSCCM.Item($SchemaVersionSCCM)}}
" "| Tee-Object -FilePath $logfile -Append | Write-Output
"> Known current schema version of products"  | Tee-Object -FilePath $logfile -Append | Write-Output
"===============================================================" | Tee-Object -FilePath $logfile -Append | Write-Output
$SchemaVersions | Format-Table * -AutoSize  | Tee-Object -FilePath $logfile -Append | Write-Output
IF ((Get-ADObject -Filter  'Name -like "ms-Mcs-AdmPwd"' -SearchBase $Schemapath -Properties Name)) { "Schema is LAPS ready" | Tee-Object -FilePath $logfile -Append | Write-Output } Else  { "Schema is NOT LAPS ready" | Tee-Object -FilePath $logfile -Append | Write-Output }
#Endregion SchemaVersionen
"To test full network connectivity to Domain Controllers checkout Check-Network.ps1: https://github.com/InfrastructureHeroes/Scipts/blob/master/Network/Check-Network.ps1"| Tee-Object -FilePath $logfile -Append | Write-Output
$after = Get-Date
$time = $after - $before
$buildTime = "`nScript finished in ";
if ($time.Minutes -gt 0) { $buildTime += "{0} minute(s) " -f $time.Minutes; }
$buildTime += "{0} second(s)" -f $time.Seconds;
"$buildTime"
"Logfile written to: $logfile" | Write-Host