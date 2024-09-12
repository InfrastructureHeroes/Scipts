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
        https://github.com/FabianNiesen/
#>

param (
    [int]$targetMTU = 8000,
    [int]$mtuoh = 28,
    [string]$DNSDomain = (Get-DnsClientGlobalSetting).SuffixSearchList[0],
    [string]$logpath = "C:\Windows\System32\LogFiles"
)
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
#endregion EVOTec Test LDAP
Function Test-UDP {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)][string]$target,
        [Parameter(Mandatory = $true)][int]$UDPport
    )
    try {
        $udpClient = New-Object System.Net.Sockets.UdpClient
        $udpClient.Connect($target, $UDPport)
        Write-Verbose "UDP-Port $UDPport ist auf $target verfügbar."
        $udpClient.Close()
        $Success = $true
    } catch {
        Write-Verbose "Es konnte keine Verbindung zu $target auf UDP-Port $UDPport hergestellt werden."
        $Success = $false
    }
    return $Success
}
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

Write-Output " "
Write-Output "Test DC connection"
Write-Output "============================================"
$DCs2 = (((nltest /dclist:$DNSDomain).trim() | Select-String -Pattern ".$DNSDomain") | Select-Object -skip 1 )
$DCs2 = ($DCs2 -split " ") -match ".$DNSDomain"
Write-Output "Found $DCs2"
ForEach ($DC in $DCs2)
{
    [String]$IP = (Resolve-DNSname $DC -Type A ).IPAddress
    Write-Output " "
    Write-Output "Start Test for $DC - $IP"
    Write-Output "============================================"
    IF (Test-Connection -ComputerName $DC -Count 1 -ErrorAction SilentlyContinue )
    {
        Write-Output "$DC is reachable with ICMP"
        Try { 
            Get-ChildItem -Path \\$DC\sysvol\$DNSDomain\ -ErrorAction stop | Out-Null
            Write-Output "Sysvol on $DC accessable"
            } 
        catch {Write-Warning "Sysvol on $DC NOT accessable"}
        Write-Output "Testing MTU Size, asummed Overhead is $mtuoh."
        $MTUPing = ping $DC -n 1 -l 1400 -f
        IF ($MTUPing[2] -like "*fragmented*" ) { Write-Warning "$DC not reachable with MTU 1400" } ELSE { Write-Output "$DC is reachable with MTU 1400" }
        $MTUPing = ping $DC -n 1 -l $($targetMTU-$mtuoh) -f
        IF ($MTUPing[2] -like "*fragmented*" ) { Write-Warning "$DC not reachable with target MTU $targetMTU" } ELSE { Write-Output "$DC is reachable with target MTU $targetMTU" }
        $MTUPing = ping $DC -n 1 -l $($MTU-$mtuoh) -f
        IF ($MTUPing[2] -like "*fragmented*" ) { Write-Warning "$DC not reachable with local MTU $MTU" } ELSE { Write-Output "$DC is reachable with local MTU $MTU" }

    } ELSE {
        Write-Warning "$DC is not reachable with ICMP at all"
    }

    Write-Output " "
    Write-Output "Test Common TCP ports connection"
    Write-Output "============================================"
    Write-Output "WinRM (TCP 5985)         : $((Test-NetConnection -ComputerName $DC -CommonTCPPort WINRM -ErrorAction SilentlyContinue -WarningAction SilentlyContinue ).TcpTestSucceeded)"
    Write-Output "WinRMs (TCP 5986)        : $((Test-NetConnection -ComputerName $DC -Port 5986 -ErrorAction SilentlyContinue -WarningAction SilentlyContinue ).TcpTestSucceeded)"
    Write-Output "Kerberos (TCP 88)        : $((Test-NetConnection -ComputerName $DC -Port 88 -ErrorAction SilentlyContinue -WarningAction SilentlyContinue ).TcpTestSucceeded)"
    Write-Output "KerberosPW (TCP 464)     : $((Test-NetConnection -ComputerName $DC -Port 464 -ErrorAction SilentlyContinue -WarningAction SilentlyContinue ).TcpTestSucceeded)"
    Write-Output "DNS (TCP 53)             : $((Test-NetConnection -ComputerName $DC -Port 53 -ErrorAction SilentlyContinue -WarningAction SilentlyContinue ).TcpTestSucceeded)"
    Write-Output "RPC (TCP 135)            : $((Test-NetConnection -ComputerName $DC -Port 135 -ErrorAction SilentlyContinue -WarningAction SilentlyContinue ).TcpTestSucceeded)"
    Write-Output "SMB (TCP 445)            : $((Test-NetConnection -ComputerName $DC -Port 445 -ErrorAction SilentlyContinue -WarningAction SilentlyContinue ).TcpTestSucceeded)"
    Write-Output "Legacy NetBios (TCP 139) : $((Test-NetConnection -ComputerName $DC -Port 445 -ErrorAction SilentlyContinue -WarningAction SilentlyContinue ).TcpTestSucceeded)"
    Write-Output " "
    Write-Output "Test Common UDP ports connection (True might be filltered / silently droped!)"
    Write-Output "============================================" 
    Write-Output "Kerberos (UDP 88)        : $(Test-UDP -target $DC -UDPport 88   )"
    Write-Output "DNS (UDP 53)             : $(Test-UDP -target $DC -UDPport 53  )"
    Write-Output "SMB (UDP 445)            : $(Test-UDP -target $DC -UDPport 445  )"
    Write-Output "W32Time / NTP (UDP 123)  : $(Test-UDP -target $DC -UDPport 123  )"
    Write-Output "Legacy NetBios (UDP 137) : $(Test-UDP -target $DC -UDPport 137  )"
    Write-Output "Legacy NetBios (UDP 138) : $(Test-UDP -target $DC -UDPport 138  )"

    Write-Output " "
    Write-Output "Test LDAP connection (Application Test)"
    Write-Output "============================================"
    Test-LDAP $DC

    Write-Output " "
    Write-Output "Test SMB connection (might not work for not Domainjoined Computers)"
    Write-Output "============================================"
    Write-Output "Found Directories in SysVol: $(([System.IO.Directory]::GetDirectories($("\\"+$DC+"\SysVol"))).Count)"
    Write-Output "Found Files in NetLogon: $(([System.IO.Directory]::GetFiles($("\\"+$DC+"\NetLogon"))).Count)"

}
Stop-Transcript 