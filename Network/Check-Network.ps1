<#
	.SYNOPSIS
		Check Network connection and configuration from a client.
	.DESCRIPTION
		Check Network connection and configuration from a client. Including MTU, NetBios over TCP/IP, IPv6 and LDAP Checks

    .COPYRIGHT
        Copyright (c) 2022 Fabian Niesen. All rights reserved. Licensed under the MIT license.

    .EXAMPLE  
        .\Check-Network.ps1

    .EXAMPLE
        .\Check-Network.ps1 -targetMTU 8000

    .PARAMETER targetMTU
        Target MTU in bytes. Default value is 8800 bytes.

    .PARAMETER mtuoh
        Overhead for MTU in bytes. Default size is 28 bytes.

    .PARAMETER DNSDomain
        DNS Domain for Domain Controller detection. If not defined first entry from DNS Serach Suffix List is used.

    .PARAMETER logpath
        Path for Transscript. Default Value is "C:\Windows\System32\LogFiles\"

	.NOTES
		Author     :    Fabian Niesen
		Filename   :    Check-Network.ps1
		Requires   :    PowerShell Version 4.0
		
		Version    :    0.2
		History    : 	0.2 FN 23.12.2022 Housekeeping & Cleanup
						0.1 FN 12.10.2022 Initial version.

    .LINK
        https://github.com/FabianNiesen/SecureAD
#>

param (
    [int]$targetMTU = 8800,
    [int]$mtuoh = 28,
    [string]$DNSDomain = (Get-DnsClientGlobalSetting).SuffixSearchList[0],
    [string]$logpath = "C:\Windows\System32\LogFiles"
)
Set-Location $PSScriptRoot
$ScriptName = $myInvocation.MyCommand.Name
$ScriptName = $ScriptName.Substring(0, $scriptName.Length - 4)
$LogName = (Get-Date -UFormat "%Y%m%d-%H%M") + "-" + $scriptName + "_" + $ENV:COMPUTERNAME +".log"
Start-Transcript -Path "$logpath\$LogName" -Append
IF ( $DNSDomain -like "")
    {
        Write-Warning "DNSDomain not Valid. Please use the Parameter >-DNSDomain domain.tld<"
        Break
    }
Write-Verbose "Scan for Networkinterfaces"
$networkConfig = Get-WmiObject Win32_NetworkAdapterConfiguration -filter "ipenabled = 'true'"
Write-Verbose "Get IPv6 Status (Based on Microsoft KB929852)"
Try {
$IPv6State = Get-ItemPropertyValue "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" "DisabledComponents" -ErrorAction SilentlyContinue
}
Catch { $IPv6State = -1 }
If ($IPv6State -eq 50 ) {Write-Output "IPv6 diabled on Interfaces and prefer IPv4 over IPv6 (Based on Microsoft KB929852)"} else { Write-Warning "IPv6 is not proper disabled!"}
Write-Output " "
Write-Output "DNSSearchSuffix: $((Get-DnsClientGlobalSetting).SuffixSearchList)"
Foreach ( $nc in $networkConfig )
{
    $NIPI = Get-NetIPInterface -InterfaceIndex $($nc.InterfaceIndex)  -AddressFamily IPv4
    Write-Output " "
    Write-Output "InterfaceIndex: $($nc.InterfaceIndex) - InterfaceAlias: $($NIPI.ifAlias)"
    Write-Output "Description: $($nc.Description)"
    Write-Output "DnsDomain: $($nc.DnsDomain)"
    Write-Output "DHCP is $($NIPI.Dhcp)"
    Write-Verbose "Get DNSDomain"
    Write-Verbose "Get NetBios over TCPIP"
    $NetBios = $nc.TcpipNetbiosOptions
    If ( $NetBios -eq 2) { write-output "NetBios over TCP/IP is disabled" } ELSE { Write-Warning "NetBios over TCP/IP is not disabled" }
    $IP = $nc.IPAddress[0]
    $DNSServer1 = $nc.DNSServerSearchOrder[0]
    #Testen
    IF ( $DNSServer1 -match $IP -or $DNSServer1 -match "127.*") { Write-Warning "Please Check DNS Serversetting, primary DNS is local Server" }
    $MTU = $NIPI.NlMtu
    IF ($targetMTU -eq $MTU ) { Write-Output "MTU as expected ($MTU)" } else { Write-warning "MTUSize is: $MTU expected is $targetMTU" }
}
# Test Domain access

#region EVOTec Test LDAP
#Code for this region from https://evotec.xyz/testing-ldap-and-ldaps-connectivity-with-powershell/ under MIT license
#GitHub: https://github.com/EvotecIT/ADEssentials
function Test-LDAPPorts {
    [CmdletBinding()]
    param(
        [string] $ServerName,
        [int] $Port
    )
    if ($ServerName -and $Port -ne 0) {
        try {
            $LDAP = "LDAP://" + $ServerName + ':' + $Port
            $Connection = [ADSI]($LDAP)
            $Connection.Close()
            return $true
        } catch {
            if ($_.Exception.ToString() -match "The server is not operational") {
                Write-Warning "Can't open $ServerName`:$Port."
            } elseif ($_.Exception.ToString() -match "The user name or password is incorrect") {
                Write-Warning "Current user ($Env:USERNAME) doesn't seem to have access to to LDAP on port $Server`:$Port"
            } else {
                Write-Warning -Message $_
            }
        }
        return $False
    }
}
Function Test-LDAP {
    [CmdletBinding()]
    param (
        [alias('Server', 'IpAddress')][Parameter(Mandatory = $True)][string[]]$ComputerName,
        [int] $GCPortLDAP = 3268,
        [int] $GCPortLDAPSSL = 3269,
        [int] $PortLDAP = 389,
        [int] $PortLDAPS = 636
    )
    # Checks for ServerName - Makes sure to convert IPAddress to DNS
    foreach ($Computer in $ComputerName) {
        [Array] $ADServerFQDN = (Resolve-DnsName -Name $Computer -ErrorAction SilentlyContinue)
        if ($ADServerFQDN) {
            if ($ADServerFQDN.NameHost) {
                $ServerName = $ADServerFQDN[0].NameHost
            } else {
                [Array] $ADServerFQDN = (Resolve-DnsName -Name $Computer -ErrorAction SilentlyContinue)
                $FilterName = $ADServerFQDN | Where-Object { $_.QueryType -eq 'A' }
                $ServerName = $FilterName[0].Name
            }
        } else {
            $ServerName = ''
        }
        $GlobalCatalogSSL = Test-LDAPPorts -ServerName $ServerName -Port $GCPortLDAPSSL
        $GlobalCatalogNonSSL = Test-LDAPPorts -ServerName $ServerName -Port $GCPortLDAP
        $ConnectionLDAPS = Test-LDAPPorts -ServerName $ServerName -Port $PortLDAPS
        $ConnectionLDAP = Test-LDAPPorts -ServerName $ServerName -Port $PortLDAP
        $PortsThatWork = @(
            if ($GlobalCatalogNonSSL) { $GCPortLDAP }
            if ($GlobalCatalogSSL) { $GCPortLDAPSSL }
            if ($ConnectionLDAP) { $PortLDAP }
            if ($ConnectionLDAPS) { $PortLDAPS }
        ) | Sort-Object
        [pscustomobject]@{
            Computer           = $Computer
            ComputerFQDN       = $ServerName
            GlobalCatalogLDAP  = $GlobalCatalogNonSSL
            GlobalCatalogLDAPS = $GlobalCatalogSSL
            LDAP               = $ConnectionLDAP
            LDAPS              = $ConnectionLDAPS
            AvailablePorts     = $PortsThatWork -join ','
        }
    }
}
#endregion 

$DCs2 = (((nltest /dclist:$DNSDomain).trim() | Select-String -Pattern ".$DNSDomain") | Select-Object -skip 1 )
$DCs2 = ($DCs2 -split " ") -match ".$DNSDomain"

ForEach ($DC in $DCs2)
{
    [String]$IP = (Resolve-DNSname $DC -Type A ).IPAddress
    Write-Output "Start Test for $DC - $IP"
    Write-Output "============================================"
    IF (Test-Connection -ComputerName $DC -Count 1 -ErrorAction SilentlyContinue | Out-Null )
    {
        Write-Output "$DC is reachable with ICMP"
        Try { 
            Get-ChildItem -Path \\$DC\sysvol\$DNSDomain\ -ErrorAction stop | Out-Null
            Write-Output "Sysvol on $DC accessable"
            } 
        catch
        {Write-Warning "Sysvol on $DC NOT accessable"}
        Test-LDAP $DC
        Write-Output "Testing MTU Size, asummed Overhead is $mtuoh."
        $MTUPing = ping $DC -n 1 -l 1400 -f
        IF ($MTUPing[2] -like "*fragmented*" ) { Write-Warning "$DC not reachable with MTU 1400" } ELSE { Write-Output "$DC is reachable with MTU 1400" }
        $MTUPing = ping $DC -n 1 -l $($targetMTU-$mtuoh) -f
        IF ($MTUPing[2] -like "*fragmented*" ) { Write-Warning "$DC not reachable with target MTU $targetMTU" } ELSE { Write-Output "$DC is reachable with target MTU $targetMTU" }
        $MTUPing = ping $DC -n 1 -l $($MTU-$mtuoh) -f
        IF ($MTUPing[2] -like "*fragmented*" ) { Write-Warning "$DC not reachable with local MTU $MTU" } ELSE { Write-Output "$DC is reachable with local MTU $MTU" }

    } ELSE {
        Write-Warning "$DC is not reachable with ICMP"
    }
}
Stop-Transcript 