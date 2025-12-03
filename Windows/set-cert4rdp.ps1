#requires -version 5.0
#Requires -RunAsAdministrator

<#
	.SYNOPSIS
		Set RDP Certificate based on issuing CA.  
	.DESCRIPTION
        Set RDP Certificate based on issuing CA. Works only if only one Certificate from the Issuing CA is installed.
	.EXAMPLE  
        .\set-cert4rdp.ps1 -caName "Issuing CA"
        Set the Cert from the Issuing CA.

    .PARAMETER caName
        Name of issung CA

	.NOTES
		Author     :    Fabian Niesen
		Filename   :    .\set-cert4rdp.ps1
		Requires   :    PowerShell Version 5.0
        License    :    The MIT License (MIT)
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
		
		Version    :    0.2 FN 03.12.2025 Changed License to MIT, housekeeping Header
        History    :    0.1 FN 24.09.2024 Initial version.
    .LINK
        https://github.com/InfrastructureHeroes/Scipts/tree/master/Windows
#>
[cmdletbinding()]
Param(
    [string]$caName = ""
)
$scriptversion = "0.2"
Write-Output "set-cert4rdp.ps1 Version $scriptversion "
# Path to the RDP SSL configuration in the registry
$rdpRegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"

# Open certificate store (local computer)
$certs = Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object { $_.Issuer -like "*$caName*" }

if ($certs -and $certs.Count -eq 1) {
    # If exactly one certificate was found
    $cert = $certs[0]
    $thumbprint = $($cert.Thumbprint -replace '\s+', '')
    # Add thumbprint in the registry for RDP SSL certificate
    Set-ItemProperty -Path $rdpRegPath -Name "SSLCertificateSHA1Hash" -Value ([byte[]]($thumbprint -split '(?<=\G.{2})(?!$)' | ForEach-Object { "0x$_" }))
    Write-Output "The thumbprint $thumbprint was successfully entered in the registry."
    $cert = Get-ChildItem -Path "Cert:\LocalMachine\My" | Where-Object { $_.Thumbprint -eq $thumbprint }
    $keyPath = $cert.PrivateKey.CspKeyContainerInfo.UniqueKeyContainerName
    $keyPath = "C:\ProgramData\Microsoft\Crypto\RSA\MachineKeys\" + $keyPath
    # Set permissions for NETWORK SERVICE
    $acl = Get-Acl -Path $keyPath
    $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("NETWORK SERVICE", "Read", "Allow")
    $acl.SetAccessRule($accessRule)
    Set-Acl -Path $keyPath -AclObject $acl
    Write-Output "Private key permissions have been updated for certificates with thumbprint $thumbprint."
} elseif ($certs.Count -gt 1) {
    Write-Output "Several certificates from the CA $caName were found. Please check the certificates."
} else {
    Write-Output "No certificate found from the CA $caName."
}