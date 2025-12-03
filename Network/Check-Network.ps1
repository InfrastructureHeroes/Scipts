#requires -version 5.1

<#
.SYNOPSIS
    Check Network connection and configuration from a client.

.DESCRIPTION
    Check Network connection and configuration from a client. Including MTU, NetBios over TCP/IP, IPv6 and LDAP Checks
    
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
    Path for Transcript. Default Value is "C:\Windows\System32\LogFiles\"
    
.NOTES
    Author     :    Fabian Niesen
    Filename   :    Check-Network.ps1
    Requires   :    PowerShell Version 5.1
    Created    :    12.10.2022
    Updated    :    03.12.2025
    LastModBy  :    Fabian Niesen
    License    :    Except for the LDAP Test Code, witch is licensed by Evotec under MIT License 
                    (Code for LDAP Test from https://evotec.xyz/testing-ldap-and-ldaps-connectivity-with-powershell/ under MIT license),
                    The MIT License (MIT)
                    Copyright (c) 2022-2025 Fabian Niesen
                    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation 
                    files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, 
                    merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is 
                    furnished to do so, subject to the following conditions:
                    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
                    The Software is provided "as is", without warranty of any kind, express or implied, including but not limited to the warranties 
                    of merchantability, fitness for a particular purpose and noninfringement. In no event shall the authors or copyright holders be 
                    liable for any claim, damages or other liability, whether in an action of contract, tort or otherwise, arising from, out of or in 
                    connection with the software or the use or other dealings in the Software.
    Disclaimer :    This script is provided "as is" without warranty. Use at your own risk.
                    The author assumes no responsibility for any damage or data loss caused by this script.
                    Test thoroughly in a controlled environment before deploying to production.
    GitHub     :    https://github.com/InfrastructureHeroes/Scipts
    Version    :    0.5 FN 03.12.2025 Change Errorhandling and reporting. Add WSUS and Terminal Server License Server Check
    History    : 	
                    0.4 FN 30.09.2024 Add KMS detection, add some ports
                    0.3 FN 12.09.2024 Add some Ports
                    0.2 FN 23.12.2022 Housekeeping & Cleanup
                    0.1 FN 12.10.2022 Initial version.
    
.LINK
    https://github.com/InfrastructureHeroes/Scipts/blob/master/Network/Check-Network.ps1

#>

[CmdletBinding()]
param (
    [int]$targetMTU = 1500,
    [int]$mtuoh = 28,
    [string]$DNSDomain = (Get-DnsClientGlobalSetting).SuffixSearchList[0],
    [string]$logpath = "C:\Windows\System32\LogFiles"
)
#region Helper Functions
function New-CheckResult {
	<#
	.SYNOPSIS
		Creates a standardized check result object
	.PARAMETER Name
		Name of the check
	.PARAMETER Status
		Status of the check (OK, Warning, Failed)
	.PARAMETER Message
		Detailed message about the check result
	#>
	param($Name, $Status, $Message)
	[PSCustomObject]@{
		Check   = $Name
		Status  = $Status
		Message = $Message
		Time    = (Get-Date)
	}
}

#endregion Helper Functions

#region EVOTec Test LDAP
#Code for this region from https://evotec.xyz/testing-ldap-and-ldaps-connectivity-with-powershell/ under MIT license
#GitHub: https://github.com/EvotecIT/ADEssentials
function Test-LDAPPorts {
    <#
	.SYNOPSIS
		Test LDAP Port connectivity
    .DESCRIPTION
        Test LDAP Port connectivity
	.PARAMETER ServerName
		Name of the server to test
	.PARAMETER port
        Port number to test
	.LINK
        https://evotec.xyz/testing-ldap-and-ldaps-connectivity-with-powershell/
        https://github.com/EvotecIT/ADEssentials
    .NOTES
        Code for this region from https://evotec.xyz/testing-ldap-and-ldaps-connectivity-with-powershell/ under MIT license
        GitHub:     https://github.com/EvotecIT/ADEssentials
        LICENSE:    MIT License
	#>
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
    <#
	.SYNOPSIS
		Test all LDAP Ports on a givven Server
    .DESCRIPTION
        Test all LDAP Ports on a givven Server
	.PARAMETER ComputerName
		Name of the server to test
	.PARAMETER GCPortLDAP
        Port number for Global Catalog LDAP
    .PARAMETER GCPortLDAPSSL
        Port number for Global Catalog LDAPS
    .PARAMETER PortLDAP
        Port number for LDAP
    .PARAMETER PortLDAPS
        Port number for LDAPS
	.LINK
        https://evotec.xyz/testing-ldap-and-ldaps-connectivity-with-powershell/
    .NOTES
        Code for this region from https://evotec.xyz/testing-ldap-and-ldaps-connectivity-with-powershell/ under MIT license
        GitHub:     https://github.com/EvotecIT/ADEssentials
        LICENSE:    MIT License
	#>
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
    <#
	.SYNOPSIS
		Try to test UDP Port connectivity, due to the nature of UDP this is not 100% reliable
    .DESCRIPTION
        Try to test UDP Port connectivity, due to the nature of UDP this is not 100% reliable
	.PARAMETER target
		Name of the server to test
	.PARAMETER UDPport
        Port number to test
	.LINK
        https://github.com/InfrastructureHeroes/Scipts/
    .NOTES
        Author     :    Fabian Niesen
		Requires   :    PowerShell Version 5.1
        License    :    Except for the LDAP Test Code, witch is licensed by Evotec under MIT License 
                        (Code for LDAP Test from https://evotec.xyz/testing-ldap-and-ldaps-connectivity-with-powershell/ under MIT license),
                        The MIT License (MIT)
                        Copyright (c) 2022-2025 Fabian Niesen
                        Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation 
                        files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, 
                        merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is 
                        furnished to do so, subject to the following conditions:
                        The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
                        The Software is provided "as is", without warranty of any kind, express or implied, including but not limited to the warranties 
                        of merchantability, fitness for a particular purpose and noninfringement. In no event shall the authors or copyright holders be 
                        liable for any claim, damages or other liability, whether in an action of contract, tort or otherwise, arising from, out of or in 
                        connection with the software or the use or other dealings in the Software.
        Disclaimer :    This script is provided "as is" without warranty. Use at your own risk.
                        The author assumes no responsibility for any damage or data loss caused by this script.
                        Test thoroughly in a controlled environment before deploying to production.
        GitHub     :    https://github.com/InfrastructureHeroes/Scipts       
	#>
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
$ScriptVersion = "0.5"
if ($Host.Name -eq "ServerRemoteHost") { Write-Error -Exception "RemoteShell detected" -Message "Please use local PowerShell, remote PowerShell Sessions are not supported" ; break }
Set-Location $PSScriptRoot
$ScriptName = $myInvocation.MyCommand.Name
$ScriptName = $ScriptName.Substring(0, $scriptName.Length - 4)
$LogName = (Get-Date -UFormat "%Y%m%d-%H%M") + "-" + $scriptName + "_" + $ENV:COMPUTERNAME +".log"
Start-Transcript -Path "$logpath\$LogName" -Append
Write-Output "Starting $ScriptName Version $ScriptVersion"
$results = @()

IF ( $DNSDomain -like "")
    {
        throw "DNSDomain not Valid. Please use the Parameter >-DNSDomain domain.tld<"
    }

#region IPv6 Check
try {
    Write-Verbose "Get IPv6 Status (Based on Microsoft KB929852)"
    $IPv6State = Get-ItemPropertyValue "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" "DisabledComponents" -ErrorAction SilentlyContinue
    
    if ($IPv6State -eq 50) {
        $results += New-CheckResult -Name 'IPv6 Configuration' -Status 'OK' -Message "IPv6 disabled on Interfaces and prefer IPv4 over IPv6 (Based on Microsoft KB929852)"
    } else {
        $results += New-CheckResult -Name 'IPv6 Configuration' -Status 'Warning' -Message "IPv6 is not properly disabled (Value: $IPv6State)"
    }
} catch {
    $results += New-CheckResult -Name 'IPv6 Configuration' -Status 'Warning' -Message "Could not determine IPv6 status"
}
#endregion IPv6 Check

#region DNS Search Suffix Check
try {
    $dnsSearchSuffix = (Get-DnsClientGlobalSetting).SuffixSearchList
    if ($dnsSearchSuffix.Count -gt 0) {
        $results += New-CheckResult -Name 'DNS Search Suffix' -Status 'OK' -Message "DNS Search Suffix: $($dnsSearchSuffix -join ', ')"
    } else {
        $results += New-CheckResult -Name 'DNS Search Suffix' -Status 'Warning' -Message "No DNS Search Suffix configured"
    }
} catch {
    $results += New-CheckResult -Name 'DNS Search Suffix' -Status 'Failed' -Message $_.Exception.Message
}
#endregion DNS Search Suffix Check

#region Network Interfaces Check
try {
    Write-Verbose "Scan for Networkinterfaces"
    $networkConfig = Get-WmiObject Win32_NetworkAdapterConfiguration -filter "ipenabled = 'true'"
    
    foreach ($nc in $networkConfig) {
        $NIPI = Get-NetIPInterface -InterfaceIndex $($nc.InterfaceIndex) -AddressFamily IPv4
        $IP = $nc.IPAddress[0]
        $checkName = "NIC: $($NIPI.ifAlias)"
        
        # NetBios Check
        $NetBios = $nc.TcpipNetbiosOptions
        if ($NetBios -eq 2) {
            $results += New-CheckResult -Name "$checkName - NetBios" -Status 'OK' -Message "NetBios over TCP/IP is disabled"
        } else {
            $results += New-CheckResult -Name "$checkName - NetBios" -Status 'Warning' -Message "NetBios over TCP/IP is not disabled"
        }
        
        # DNS Server Check
        $DNSServer1 = $nc.DNSServerSearchOrder[0]
        if ($DNSServer1 -match $IP -or $DNSServer1 -match "127.*") {
            $results += New-CheckResult -Name "$checkName - DNS Server" -Status 'Warning' -Message "Primary DNS is local Server: $DNSServer1"
        } else {
            $results += New-CheckResult -Name "$checkName - DNS Server" -Status 'OK' -Message "Primary DNS: $DNSServer1"
        }
        
        # MTU Check
        $MTU = $NIPI.NlMtu
        if ($targetMTU -eq $MTU) {
            $results += New-CheckResult -Name "$checkName - MTU" -Status 'OK' -Message "MTU as expected ($MTU bytes)"
        } else {
            $results += New-CheckResult -Name "$checkName - MTU" -Status 'Warning' -Message "MTU Size is $MTU, expected $targetMTU bytes"
        }
        
        # DHCP Check
        $results += New-CheckResult -Name "$checkName - DHCP" -Status 'OK' -Message "DHCP is $($NIPI.Dhcp)"
    }
} catch {
    $results += New-CheckResult -Name 'Network Interfaces' -Status 'Failed' -Message $_.Exception.Message
}
#endregion Network Interfaces Check

#region Test Domain access
try {
    $DCs2 = (((nltest /dclist:$DNSDomain).trim() | Select-String -Pattern ".$DNSDomain") | Select-Object -skip 1)
    $DCs2 = ($DCs2 -split " ") -match ".$DNSDomain"
    
    if ($DCs2.Count -gt 0) {
        $results += New-CheckResult -Name "Domain Controllers" -Status 'OK' -Message "Found $($DCs2.Count) DC(s): $($DCs2 -join ', ')"
    } else {
        $results += New-CheckResult -Name "Domain Controllers" -Status 'Failed' -Message "No Domain Controllers found for domain $DNSDomain"
    }
    
    ForEach ($DC in $DCs2) {
        [String]$IP = (Resolve-DNSname $DC -Type A -ErrorAction SilentlyContinue).IPAddress
        
        # ICMP/Ping Check
        if (Test-Connection -ComputerName $DC -Count 1 -ErrorAction SilentlyContinue) {
            $results += New-CheckResult -Name "$DC - ICMP" -Status 'OK' -Message "$DC ($IP) is reachable with ICMP"
            
            # Sysvol Check
            try {
                Get-ChildItem -Path \\$DC\sysvol\$DNSDomain\ -ErrorAction Stop | Out-Null
                $results += New-CheckResult -Name "$DC - Sysvol" -Status 'OK' -Message "Sysvol on $DC is accessible"
            } catch {
                $results += New-CheckResult -Name "$DC - Sysvol" -Status 'Warning' -Message "Sysvol on $DC NOT accessible"
            }
            
            # MTU Tests
            $MTUPing = ping $DC -n 1 -l 1400 -f
            if ($MTUPing[2] -like "*fragmented*") {
                $results += New-CheckResult -Name "$DC - MTU 1400" -Status 'Warning' -Message "$DC not reachable with MTU 1400"
            } else {
                $results += New-CheckResult -Name "$DC - MTU 1400" -Status 'OK' -Message "$DC is reachable with MTU 1400"
            }
            
            $MTUPing = ping $DC -n 1 -l $($targetMTU - $mtuoh) -f
            if ($MTUPing[2] -like "*fragmented*") {
                $results += New-CheckResult -Name "$DC - Target MTU $targetMTU" -Status 'Warning' -Message "$DC not reachable with target MTU $targetMTU"
            } else {
                $results += New-CheckResult -Name "$DC - Target MTU $targetMTU" -Status 'OK' -Message "$DC is reachable with target MTU $targetMTU"
            }
            
            $NIPI = Get-NetIPInterface -InterfaceIndex (Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | Select-Object -First 1).IfIndex -AddressFamily IPv4
            $MTU = $NIPI.NlMtu
            $MTUPing = ping $DC -n 1 -l $($MTU - $mtuoh) -f
            if ($MTUPing[2] -like "*fragmented*") {
                $results += New-CheckResult -Name "$DC - Local MTU $MTU" -Status 'Warning' -Message "$DC not reachable with local MTU $MTU"
            } else {
                $results += New-CheckResult -Name "$DC - Local MTU $MTU" -Status 'OK' -Message "$DC is reachable with local MTU $MTU"
            }
        } else {
            $results += New-CheckResult -Name "$DC - ICMP" -Status 'Failed' -Message "$DC is not reachable with ICMP"
        }
        
        # TCP Port Tests
        $tcpPorts = @(
            @{ Name = 'WinRM'; Port = 5985 },
            @{ Name = 'WinRMs'; Port = 5986 },
            @{ Name = 'Kerberos'; Port = 88 },
            @{ Name = 'KerberosPW'; Port = 464 },
            @{ Name = 'ADWS'; Port = 9389 },
            @{ Name = 'DNS'; Port = 53 },
            @{ Name = 'RPC'; Port = 135 },
            @{ Name = 'SMB'; Port = 445 },
            @{ Name = 'Legacy NetBios'; Port = 139 }
        )
        
        foreach ($portTest in $tcpPorts) {
            $tcpResult = Test-NetConnection -ComputerName $DC -Port $portTest.Port -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
            if ($tcpResult.TcpTestSucceeded) {
                $results += New-CheckResult -Name "$DC - TCP $($portTest.Name) (Port $($portTest.Port))" -Status 'OK' -Message "TCP Port $($portTest.Port) is open"
            } else {
                $results += New-CheckResult -Name "$DC - TCP $($portTest.Name) (Port $($portTest.Port))" -Status 'Warning' -Message "TCP Port $($portTest.Port) is closed or filtered"
            }
        }
        
        # UDP Port Tests
        $udpPorts = @(
            @{ Name = 'Kerberos'; Port = 88 },
            @{ Name = 'KerberosPW'; Port = 464 },
            @{ Name = 'DNS'; Port = 53 },
            @{ Name = 'SMB'; Port = 445 },
            @{ Name = 'W32Time/NTP'; Port = 123 },
            @{ Name = 'Legacy NetBios'; Port = 137 },
            @{ Name = 'Legacy NetBios'; Port = 138 }
        )
        
        foreach ($portTest in $udpPorts) {
            $udpResult = Test-UDP -target $DC -UDPport $portTest.Port
            if ($udpResult) {
                $results += New-CheckResult -Name "$DC - UDP $($portTest.Name) (Port $($portTest.Port))" -Status 'OK' -Message "UDP Port $($portTest.Port) responds (might be filtered)"
            } else {
                $results += New-CheckResult -Name "$DC - UDP $($portTest.Name) (Port $($portTest.Port))" -Status 'Warning' -Message "UDP Port $($portTest.Port) no response"
            }
        }
        
        # LDAP Connection Test
        try {
            $ldapResult = Test-LDAP $DC
            if ($ldapResult.AvailablePorts) {
                $results += New-CheckResult -Name "$DC - LDAP" -Status 'OK' -Message "LDAP available on ports: $($ldapResult.AvailablePorts)"
            } else {
                $results += New-CheckResult -Name "$DC - LDAP" -Status 'Warning' -Message "LDAP not available on any port"
            }
        } catch {
            $results += New-CheckResult -Name "$DC - LDAP" -Status 'Failed' -Message $_.Exception.Message
        }
    }
} catch {
    $results += New-CheckResult -Name 'Domain Access' -Status 'Failed' -Message $_.Exception.Message
}
#endregion Test Domain access
#region KMS Server Check
try {
    $kmsInfo = nslookup -type=srv _vlmcs._tcp | Select-String -Pattern "port|svr hostname"
    
    if ($kmsInfo.count -gt 0) {
        [int]$kmsport = (($kmsInfo | Select-String -Pattern "port" ) -split("="))[1].trim()
        $kmsserver = (($kmsInfo | Select-String -Pattern "svr hostname") -split("="))[1].trim()
        
        $results += New-CheckResult -Name "KMS Server Discovery" -Status 'OK' -Message "Found Microsoft KMS server: $kmsserver on port $kmsport"
        
        $kmsTest = Test-NetConnection -ComputerName $kmsserver -Port $kmsport -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
        if ($kmsTest.TcpTestSucceeded) {
            $results += New-CheckResult -Name "KMS Server Connection" -Status 'OK' -Message "MS KMS Server (TCP $kmsport) is accessible"
        } else {
            $results += New-CheckResult -Name "KMS Server Connection" -Status 'Warning' -Message "MS KMS Server (TCP $kmsport) is not accessible"
        }
    } else {
        $results += New-CheckResult -Name "KMS Server Discovery" -Status 'Warning' -Message "No Microsoft Key Management server found"
    }
} catch {
    $results += New-CheckResult -Name "KMS Server" -Status 'Failed' -Message $_.Exception.Message
}
#endregion KMS Server Check

#region WSUS Server Check
try {
    $wsusReg = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
    $wsusValues = @('WUServer','WUStatusServer','UpdateServiceUrlAlternate')
    foreach ($name in $wsusValues) {
        $val = $null
        try { $val = (Get-ItemProperty -Path $wsusReg -Name $name -ErrorAction SilentlyContinue).$name } catch { $val = $null }
        if (-not $val) {
            $results += New-CheckResult -Name "WSUS - $name" -Status 'Warning' -Message "Registry value $name not set"
            continue
        }
        $entries = @()
        if ($val -is [array]) { $entries = $val } else { $entries = @($val) }
        foreach ($entry in $entries) {
            $entry = $entry.Trim()
            $wsushost = $null
            $portsToTest = @()
            if ($entry -match '^\w+://') {
                try { $uri = [uri]$entry } catch { $uri = $null }
                if ($uri) {
                    $wsushost = $uri.Host
                    if ($entry -match ':\d+') {
                        $portsToTest = @($uri.Port)
                    } else {
                        if ($uri.Scheme -eq 'https') { $portsToTest = @(8531,443) } else { $portsToTest = @(8530,80) }
                    }
                } else {
                    $wsushost = $entry
                    $portsToTest = @(8530,8531)
                }
            } else {
                if ($entry -match '^(?<h>[^:]+):(?<p>\d+)$') {
                    $wsushost = $matches['h']
                    $portsToTest = @([int]$matches['p'])
                } else {
                    $wsushost = $entry
                    $portsToTest = @(8530,8531)
                }
            }
            If ($portsToTest -eq 8531) { $portsToTest += 8530 } 
            elseif ($portsToTest -eq 443 ) { $portsToTest += 80}
            $portsWorked = @()
            foreach ($p in $portsToTest) {
                $tcp = Test-NetConnection -ComputerName $wsushost -Port $p -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
                if ($tcp.TcpTestSucceeded) { $portsWorked += $p }
            }
            if ($portsWorked.Count -gt 0) {
                $results += New-CheckResult -Name "WSUS - $name ($wsushost)" -Status 'OK' -Message "Reachable on ports: $($portsWorked -join ',')"
            } else {
                $results += New-CheckResult -Name "WSUS - $name ($wsushost)" -Status 'Warning' -Message "Not reachable (tested ports: $($portsToTest -join ','))"
            }
        }
    }
} catch {
    $results += New-CheckResult -Name 'WSUS Server' -Status 'Failed' -Message $_.Exception.Message
}
#endregion WSUS Server Check

#region Terminal Services License Servers
try {
    $tsReg = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\LicenseServers'
    if (-not (Test-Path $tsReg)) {
        Write-Output "Terminal Services LicenseServers registry path not found - skipping check"
    } else {
        $props = (Get-ItemProperty -Path $tsReg -ErrorAction SilentlyContinue).PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' }
        $servers = @()
        foreach ($p in $props) {
            if ($p.Value -is [array]) { $servers += $p.Value } else { $servers += $p.Value }
        }
        $servers = $servers | Where-Object { $_ -and $_.ToString().Trim() -ne '' } | ForEach-Object { $_.ToString().Trim() } | Sort-Object -Unique

        if ($servers.Count -eq 0) {
            $results += New-CheckResult -Name 'Terminal Services LicenseServers' -Status 'Warning' -Message 'No LicenseServers values configured'
        } else {
            foreach ($s in $servers) {
                $host = $s
                # Common ports to verify reachability for license/RDS related traffic
                $ports = @(135,3389,1688)
                $icmpOk = $false
                try { $icmpOk = Test-Connection -ComputerName $host -Count 1 -Quiet -ErrorAction SilentlyContinue } catch { $icmpOk = $false }
                $portsOk = @()
                foreach ($p in $ports) {
                    $res = Test-NetConnection -ComputerName $host -Port $p -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
                    if ($res.TcpTestSucceeded) { $portsOk += $p }
                }
                if ($icmpOk -or $portsOk.Count -gt 0) {
                    $msg = "Reachable"
                    if ($icmpOk) { $msg += " (ICMP)" }
                    if ($portsOk.Count -gt 0) { $msg += " on ports: $($portsOk -join ',')" }
                    $results += New-CheckResult -Name "Terminal Services LicenseServer ($host)" -Status 'OK' -Message $msg
                } else {
                    $results += New-CheckResult -Name "Terminal Services LicenseServer ($host)" -Status 'Warning' -Message "Not reachable (tested: ICMP, ports $($ports -join ','))"
                }
            }
        }
    }
} catch {
    $results += New-CheckResult -Name 'Terminal Services LicenseServers' -Status 'Failed' -Message $_.Exception.Message
}
#endregion Terminal Services License Servers

#region Output Summary
$results | Format-Table -AutoSize
#endregion Output Summary
# set exit code: non-zero if any Failed
if ($results | Where-Object { $_.Status -match 'Failed' }) {
        exit 2
} elseif ($results | Where-Object { $_.Status -match 'Warning' }) {
        exit 1
} else {
        exit 0
}
Stop-Transcript 