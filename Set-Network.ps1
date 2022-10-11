#requires -version 4.0
#Requires -RunAsAdministrator
<#
.SYNOPSIS
Modify often needed Networkkonfiguration like set DNSDomainName, disable NetBios over TCP/IP or disable IPv6.
	
.DESCRIPTION
Modify often needed Networkkonfiguration like set DNSDomainName, disable NetBios over TCP/IP or disable IPv6 based on MS KB929852

.EXAMPLE 
C:\PS> Set-Network.ps1

.EXAMPLE 
C:\PS> Set-Network.ps1

.PARAMETER 	DNSDomain 
String of the DNSDomain. If used, the DNSDomain will changed and a DNS re-register is triggert.

.PARAMETER 	DisableNetbios
Diable NetBios over TCP/IP on all enabled network interfaces

.PARAMETER DisableIPv6Interfaces
Disable IPv6 on all interfaces and change the prefference to IPv4. Set DisabledComponents to 0x32


.COPYRIGHT
Copyright (c) 2022 Fabian Niesen. All rights reserved. Licensed under the MIT license.

.NOTES
Author     :    Fabian Niesen (mail@fabian-niesen.de)
Filename   :    Set-Network.ps1
Requires   :    PowerShell Version 4.0
Version    :    1.1
History    :    1.1 FN  11.10.2022  Add Set MTU
                1.0 FN  04.10.2022  extracted from other script for idependent use

.LINK
www.dell.com
#>

    param (
        [string]$DNSDomain,
        [switch]$DisableNetbios,
        [switch]$DisableIPv6Interfaces,
        [int]$MTU = 0
        
    )
    Write-Verbose "DNSDomain: $DNSDomain - DisableNetbios: $DisableNetbios - DisableIPv6Interfaces: $DisableIPv6Interfaces"
    Write-Verbose "Scan for Networkinterfaces"
    $networkConfig = Get-WmiObject Win32_NetworkAdapterConfiguration -filter "ipenabled = 'true'"
    Foreach ( $nc in $networkConfig )
    {
        $NIPI = Get-NetIPInterface -InterfaceIndex $($nc.InterfaceIndex)  -AddressFamily IPv4
        IF ( $DNSDomain -ne "")
        {   
            Write-Verbose "Set DNSDomain"
            $nc.SetDnsDomain($DNSDomain)
            Write-Verbose "Set Dynamic DNS Registration"
            $nc.SetDynamicDNSRegistration($true,$true)
            ipconfig /registerdns
        }
        IF ($DisableNetbios)
        {
            Write-Verbose "Disable NetBios over TCPIP"
            $nc.SetTcpipNetbios(2)
        }
        if ($DisableIPv6Interfaces)
        {
            Write-Verbose "Disable IPv6 on Interfaces and prefer IPv4 over IPv6 (Based on Microsoft KB929852)"
            reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" /v DisabledComponents /t REG_DWORD /d 0x32 /f
        }
        if ($MTU -ne 0 )
        {
            Write-Verbose "Set MTU to $MTU is activeatd"
            $localMTU = $NIPI.NlMtu
            If ( $localMTU -ne $MTU )
            {
                Set-NetIPInterface -InterfaceIndex $($nc.InterfaceIndex) -NlMtuBytes $MTU -PolicyStore ActiveStore -Confirm:$false 
                Set-NetIPInterface -InterfaceIndex $($nc.InterfaceIndex) -NlMtuBytes $MTU -PolicyStore PersistentStore -Confirm:$false
                #test einbauen
            }

        }
    }