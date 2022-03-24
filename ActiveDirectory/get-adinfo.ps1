##requires -version 2.0
##requires -modules activedirectory

<#
	.SYNOPSIS
		Get basic information upon the Active Directory Forrest
	.DESCRIPTION
		Get basic information upon the Active Directory Forrest, like the cration date of the domains, a list off all DC and a Report the Schema versions (AD, Exchange, Lync and SCCM).
        Based upon an TechNet article from "The Scripting guys". Thanks also to Shawn Johnson, Paul Wetter, SteveLarson for providing SCCM extension and more schema versions.
        http://blogs.technet.com/b/heyscriptingguy/archive/2012/01/05/how-to-find-active-directory-schema-update-history-by-using-powershell.aspx
        Require the ActiveDirectory PowerShell Module, no admin permisions needed.
	.EXAMPLE  
        get-adinfo
	.INPUTS
		Keine.
	.OUTPUTS
		Keine.
	.NOTES
		Author     : Fabian Niesen
		Filename   : get-adinfo.ps1
		Requires   : PowerShell Version 2.0
		
		Version    : 0.5
		History    : 0.5   FN  19.02.2021  
                     0.4   FN  15.07.2020  Update Schemas, integrate LAPS detection
                     0.3   FN  21.07.2016  Add Windows Server 2016, Exchange multiple CU and 2016, some SystemCenter and Sign Script
                     0.2   FN  10.03.2015  Add SCCM R2 CU1-4 and SCCM CU5
                     0.1   FN  18.02.2015  initial version
                    
    .LINK
        https://gallery.technet.microsoft.com/Gesamtstruktur-Informations-63719eec
#>

[cmdletbinding()]
Param(
    $logfile="C:\Temp\log.txt"
)

<#
Param(
	[Parameter(Mandatory=$false, ValueFromPipeline=$True)]
	[switch]$Verbose = $false
)

$oldverbose = $VerbosePreference
IF ($Verbose -eq $True) 
{
  $VerbosePreference = "Continue"
}
#>
"Get-ADInfo.ps1 by Fabian Niesen" | Out-file -FilePath $logfile | Write-Output
get-date -format yyyyMMdd-HHmm | Tee-Object -FilePath $logfile -Append | Write-Output


$ErrorActionPreference = "SilentlyContinue"
$before = Get-Date
Try
{
    Import-Module ActiveDirectory
}
catch
{
    Write-Warning "PowerShell module for Active Directory not found!"
    break
}

# Forrest creation
"Creation date of the domains" | Tee-Object -FilePath $logfile -Append | Write-Output
"============================" | Tee-Object -FilePath $logfile -Append | Write-Output
$Doms = Get-ADObject -SearchBase (Get-ADForest).PartitionsContainer -LDAPFilter "(&(objectClass=crossRef)(systemFlags=3))" -Property dnsRoot, nETBIOSName, whenCreated |Sort-Object whenCreated 
$Doms | Format-Table dnsRoot, NETBIOSName, whenCreated -AutoSize

# Fuctional Levels
"Funtional Level and FSMO roles" | Tee-Object -FilePath $logfile -Append | Write-Output
"==============================" | Tee-Object -FilePath $logfile -Append | Write-Output
Get-ADForest | fl Name,ForestMode,SchemaMaster,DomainNamingMaster
$Doms.Netbiosname | Get-ADDomain | FL Name,NetBiosName,DNSRoot,DomainMode,PDCEmulator,RIDMaster,InfrastructureMaster 

# List DCs
"List of all domain controllers" | Tee-Object -FilePath $logfile -Append | Write-Output
"==============================" | Tee-Object -FilePath $logfile -Append | Write-Output
try 
        { 
            $Forest = [system.directoryservices.activedirectory.Forest]::GetCurrentForest()     
        } 
    catch 
        { 
            "Cannot connect to current forest." 
        } 
$Forest.domains | ForEach-Object {$_.DomainControllers} | FT Name,OSVersion,SiteName -AutoSize -GroupBy Domain

# User Objects normal & Password age180+



# Computer Objects  normal & Password age180+



# SchemaVersionen

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
 88="Windows Server 2019";
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
17002="Exchange 2019 CU8";
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

"Known current schema version of products"  | Tee-Object -FilePath $logfile -Append | Write-Output
"========================================" | Tee-Object -FilePath $logfile -Append | Write-Output
$SchemaVersions | Format-Table * -AutoSize  | Tee-Object -FilePath $logfile -Append | Write-Output
IF ((Get-ADObject -Filter  'Name -like "ms-Mcs-AdmPwd"' -SearchBase $Schemapath -Properties Name)) { "Schema is LAPS ready" | Tee-Object -FilePath $logfile -Append | Write-Output } Else  { "Schema is NOT LAPS ready" | Tee-Object -FilePath $logfile -Append | Write-Output }


$after = Get-Date

$time = $after - $before
$buildTime = "`nBuild finished in ";
if ($time.Minutes -gt 0)
{
    $buildTime += "{0} minute(s) " -f $time.Minutes;
}

$buildTime += "{0} second(s)" -f $time.Seconds;
"$buildTime"
$VerbosePreference = $oldverbose 
$logfile | Write-Host