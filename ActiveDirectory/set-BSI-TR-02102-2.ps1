#requires -version 5.1
#requires -module GroupPolicy

<#
    .SYNOPSIS
		Configures Windows Server security settings to comply with the BSI TR-02102-2 guideline (2025), focusing on cryptographic protocols, cipher suites, key lengths, and elliptic curves. The script disables insecure protocols (e.g., SSL 2.0, SSL 3.0, TLS 1.0, TLS 1.1), enables secure ones (TLS 1.2, TLS 1.3), and adjusts registry and Group Policy settings to enhance security. It is primarily designed for domain controllers but can be applied to other servers after compatibility testing.

	.DESCRIPTION
		The PowerShell script set-BSI-TR-02102-2.ps1 is designed to configure Windows Server security settings in compliance with the BSI TR-02102-2 "Cryptographic Mechanisms: Recommandations and Key Lengths: Use of Transport Layer Security (TLS)" Version: 2025-1 technical guideline. It focuses on securing cryptographic protocols, cipher suites, key lengths, and elliptic curves to meet IT baseline protection measures. The script primarily targets domain controllers but can also be applied to other servers, provided compatibility is ensured.

        The script disables insecure protocols such as SSL 2.0, SSL 3.0, TLS 1.0, and TLS 1.1 while enabling and configuring TLS 1.2 and TLS 1.3 as recommended. It also deactivates weak ciphers like Triple DES (due to the SWEET32 vulnerability) and hash algorithms such as MD5 and SHA. Recommended ciphers, including AES 128/256 and TLS 1.2/1.3-compliant cipher suites, are enabled. Additionally, elliptic curves like brainpoolP256r1, brainpoolP384r1, and brainpoolP512r1 are activated, while NIST curves (e.g., NistP256, NistP384) are disabled, except for curve25519, which remains active for compatibility.

        Key lengths for Diffie-Hellman and RSA are increased to a minimum of 3000 bits, aligning with the guideline's requirements. The script also enforces strong cryptography for .NET Framework by enabling the SchUseStrongCrypto setting. It applies these changes via Group Policy (Set-GPRegistryValue) and registry modifications, ensuring centralized management across domain controllers.

        While the script addresses key recommendations from Chapter 3 of the BSI TR-02102-2, it does not cover all aspects, such as quantum-safe algorithms or advanced key management. It includes disclaimers and emphasizes the need for thorough testing in a controlled environment before deployment. Compatibility with third-party systems like VMware, NAS devices, and appliances should also be verified, as these may not support the latest TLS versions or cipher suites.

        In summary, this script provides a robust foundation for implementing BSI TR-02102-2 recommendations on Windows Servers. However, it requires careful validation, testing, and adaptation to the specific needs of the environment. It is intended for educational purposes and should not be used in production without proper evaluation and backup measures.
    
        DISCLAIMER
        This script is provided "as is" without any warranty of any kind, express or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose, and noninfringement. 
        Use of this script is at your own risk. The author assumes no responsibility for any damage or data loss caused by the use of this script.
        This Script may cause your system to be no longer able to logon to your Domain.
        It is strongly recommended to test this script in a controlled environment before deploying it to production systems.
        Ensure you have proper backups and a rollback plan in place before applying any changes.
        Verify that your Domain Controller, Kerberos and all other Windows certificates are compatible with the settings applied by this script.
        Compatibility with third-party systems, applications, or devices is not guaranteed and must be verified by the user.

    .PARAMETER DCgpoName
        Specifies the name of the Group Policy Object (GPO) to be created or updated. This GPO will contain the security settings defined by the script.
        Default: 'BSI-TR-02102-2'

    .PARAMETER 2026support
        Specifies whether to enable support for cryptographic algorithms and settings that are only recommended until 2026. This setting was required in my Testdomain to maintain compatibility with AD logon.
        Acceptable values: 0 (disable), 1 (enable)
        Default: 0

    .EXAMPLE
        .\set-BSI-TR-02102-2.ps1 -DCgpoName "BSI-TR-02102-2" -support2026 1
        This example creates or updates a GPO named "BSI-TR-02102-2" and enables support for cryptographic settings recommended until 2026.

    .EXAMPLE
        .\set-BSI-TR-02102-2.ps1 -DCgpoName "BSI-TR-02102-2"
        This example creates or updates a GPO named "BSI-TR-02102-2" without enabling settings recommended only until 2026.

	.NOTES
		Author     : Fabian Niesen
		Filename   : set-BSI-TR-02102-2.ps1
		Requires   : PowerShell Version 5.1, Windows Server 2022 oder 2025, GPMC installed
        License    : GNU General Public License v3 (GPLv3)
        (c) 2025 Fabian Niesen, www.infrastrukturhelden.de
        This script is licensed under the GNU General Public License v3 (GPLv3), except for 3rd party code (e.g. Function Get-GPPolicyKey). 
        You can redistribute it and/or modify it under the terms of the GPLv3 as published by the Free Software Foundation.
        This script is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of
        MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details. 
        See https://www.gnu.org/licenses/gpl-3.0.html for the full license text.
		Version    : 0.1
		History    : 0.1   FN  26.04.2025  initial version
                    
    .LINK
        Blog DE: folgt bei Gelegenheit - https://www.infrastrukturhelden.de/
        Blog EN: comming soon - https://www.infrastructureheroes.org
        BSI-TR-02102-2 EN: https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TG02102/BSI-TR-02102-2.html
        BSI-TR-02102-2 DE: https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Publikationen/TechnischeRichtlinien/TR02102/BSI-TR-02102-2.html
        Script: https://github.com/InfrastructureHeroes/Scipts/blob/master/ActiveDirectory/set-BSI-TR-02102-2.ps1
#>
[cmdletbinding()]
Param(
[Parameter(Mandatory=$false)][string]$DCgpoName = 'BSI-TR-02102-2',
[Parameter(Mandatory=$false)][ValidateSet(0, 1)][int]$support2026 = 1 
)
Write-Host "DISCLAIMER:" -ForegroundColor Yellow
Write-Host "This script is provided 'as is' without any warranty of any kind, express or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose, and noninfringement." -ForegroundColor Yellow
Write-Host "Use of this script is at your own risk. The author assumes no responsibility for any damage or data loss caused by the use of this script." -ForegroundColor Yellow
Write-Host "This Script may cause your system to be no longer able to logon to your Domain." -ForegroundColor Yellow
Write-Host "It is strongly recommended to test this script in a controlled environment before deploying it to production systems." -ForegroundColor Yellow
Write-Host "Ensure you have proper backups and a rollback plan in place before applying any changes." -ForegroundColor Yellow
Write-Host "Verify that your Domain Controller, Kerberos and all other Windows certificates are compatible with the settings applied by this script." -ForegroundColor Yellow
Write-Host "Compatibility with third-party systems, applications, or devices is not guaranteed and must be verified by the user." -ForegroundColor Yellow
$consent = Read-Host "Do you agree to proceed? Type 'Y' to continue or any other key to exit"
if ($consent -ne 'Y') { Write-Host "You did not agree to the disclaimer. Exiting script." -ForegroundColor Red ; exit }

Write-Output "Create GPO for BSI-TR-02102-2: $DCgpoName"
Try { New-GPO -Name $DCgpoName -Comment 'Please check https:// for more information' -ErrorAction Stop } Catch { Write-Host 'GPO already exists' -ForegroundColor Yellow }

Write-Output "Set BSI-TR-02102-2 settings in GPO: $DCgpoName"

Set-GPRegistryValue -Name $DCgpoName -Key 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Server' -ValueName Enabled -Value 0 -Type DWord | Out-Null
Set-GPRegistryValue -Name $DCgpoName -Key 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Client' -ValueName Enabled -Value 0 -Type DWord | Out-Null
# Disable TLS 1.0 for SChannel (BSI-TR-02102-2 Chapter 3.2)
Set-GPRegistryValue -Name $DCgpoName -Key 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -ValueName Enabled -Value 0 -Type DWord | Out-Null
Set-GPRegistryValue -Name $DCgpoName -Key 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client' -ValueName Enabled -Value 0 -Type DWord | Out-Null

# Disable TLS 1.1 for SChannel (BSI-TR-02102-2 Chapter 3.2)
Set-GPRegistryValue -Name $DCgpoName -Key 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -ValueName Enabled -Value 0 -Type DWord | Out-Null
Set-GPRegistryValue -Name $DCgpoName -Key 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' -ValueName Enabled -Value 0 -Type DWord | Out-Null

# SSL2 is not recomended (BSI-TR-02102-2 Chapter 3.2)
Set-GPRegistryValue -Name $DCgpoName -Key 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server' -ValueName Enabled -Value 0 -Type DWord | Out-Null
Set-GPRegistryValue -Name $DCgpoName -Key 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client' -ValueName Enabled -Value 0 -Type DWord | Out-Null

# SSL3 is not recomended (BSI-TR-02102-2 Chapter 3.2)
Set-GPRegistryValue -Name $DCgpoName -Key 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server' -ValueName Enabled -Value 0 -Type DWord | Out-Null
Set-GPRegistryValue -Name $DCgpoName -Key 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client' -ValueName Enabled -Value 0 -Type DWord | Out-Null

#  TLS 1.2 is recommended
Set-GPRegistryValue -Name $DCgpoName -Key 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -ValueName Enabled -Value 1 -Type DWord | Out-Null
Set-GPRegistryValue -Name $DCgpoName -Key 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -ValueName DisabledByDefault -Value 0 -Type DWord | Out-Null
Set-GPRegistryValue -Name $DCgpoName -Key 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -ValueName Enabled -Value 1 -Type DWord | Out-Null
Set-GPRegistryValue -Name $DCgpoName -Key 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -ValueName DisabledByDefault -Value 0 -Type DWord | Out-Null

# TLS 1.3  is recommended
Set-GPRegistryValue -Name $DCgpoName -Key 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server' -ValueName Enabled -Value 1 -Type DWord | Out-Null
Set-GPRegistryValue -Name $DCgpoName -Key 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server' -ValueName DisabledByDefault -Value 0 -Type DWord | Out-Null
Set-GPRegistryValue -Name $DCgpoName -Key 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client' -ValueName Enabled -Value 1 -Type DWord | Out-Null
Set-GPRegistryValue -Name $DCgpoName -Key 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client' -ValueName DisabledByDefault -Value 0 -Type DWord | Out-Null

# 3DES is not recommended (SWEET32 vulnerability)
Set-GPRegistryValue -Name $DCgpoName -Key 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 168' -ValueName Enabled -Value 0 -Type DWord | Out-Null

# Older Ciphers
Set-GPRegistryValue -Name $DCgpoName -Key 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\DES 56' -ValueName Enabled -Value 0 -Type DWord | Out-Null
Set-GPRegistryValue -Name $DCgpoName -Key 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\NULL' -ValueName Enabled -Value 0 -Type DWord | Out-Null
Set-GPRegistryValue -Name $DCgpoName -Key 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 40/128' -ValueName Enabled -Value 0 -Type DWord | Out-Null
Set-GPRegistryValue -Name $DCgpoName -Key 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 56/128' -ValueName Enabled -Value 0 -Type DWord | Out-Null
Set-GPRegistryValue -Name $DCgpoName -Key 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 128/128' -ValueName Enabled -Value 0 -Type DWord | Out-Null
Set-GPRegistryValue -Name $DCgpoName -Key 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 40/128' -ValueName Enabled -Value 0 -Type DWord | Out-Null
Set-GPRegistryValue -Name $DCgpoName -Key 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 56/128' -ValueName Enabled -Value 0 -Type DWord | Out-Null
Set-GPRegistryValue -Name $DCgpoName -Key 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 128/128' -ValueName Enabled -Value 0 -Type DWord | Out-Null
Set-GPRegistryValue -Name $DCgpoName -Key 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 64/128' -ValueName Enabled -Value 0 -Type DWord | Out-Null


# AES128 is recommended (BSI-TR-02102-2 Chapter 3.3.1 and 3.4.4)
Set-GPRegistryValue -Name $DCgpoName -Key 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\AES 128/128' -ValueName Enabled -Value 1 -Type DWord | Out-Null

# AES256 is recommended (BSI-TR-02102-2 Chapter 3.3.1 and 3.4.4)
Set-GPRegistryValue -Name $DCgpoName -Key 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\AES 256/256' -ValueName Enabled -Value 1 -Type DWord | Out-Null

# SHA Hash is not recommended (BSI-TR-02102-2 Chapter 3.3.3)
Set-GPRegistryValue -Name $DCgpoName -Key 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\SHA' -ValueName Enabled -Value 0 -Type DWord | Out-Null
Set-GPRegistryValue -Name $DCgpoName -Key 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\SHA256' -ValueName Enabled -Value 1 -Type DWord | Out-Null
Set-GPRegistryValue -Name $DCgpoName -Key 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\SHA384' -ValueName Enabled -Value 1 -Type DWord | Out-Null

# MD5 Hash is not recommended (BSI-TR-02102-2 Chapter 3.3.3)
Set-GPRegistryValue -Name $DCgpoName -Key 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\MD5' -ValueName Enabled -Value 0 -Type DWord | Out-Null

# ECDH Key Exchange is recommended till 2026 for TLS 1.2 (BSI-TR-02102-2 Chapter 3.3.1.2)
Set-GPRegistryValue -Name $DCgpoName -Key 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman' -ValueName Enabled -Value $support2026 -Type DWord | Out-Null

# ECDH Key Exchange is recommended till 2026 for TLS 1.2 (BSI-TR-02102-2 Chapter 3.3.1.2)
Set-GPRegistryValue -Name $DCgpoName -Key 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\ECDH' -ValueName Enabled -Value $support2026 -Type DWord | Out-Null

# RSA / PKCS Key Exchange is recommended till 2026 for TLS 1.2 (BSI-TR-02102-2 Chapter 3.3.3) # 
Set-GPRegistryValue -Name $DCgpoName -Key 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\PKCS' -ValueName Enabled -Value $support2026 | Out-Null

# TLS 1.2 Chiphers (BSI-TR-02102-2 Chapter 3.3.4)
$Chiphersuites = "TLS_AES_256_GCM_SHA384,TLS_AES_128_GCM_SHA256,TLS_AES_128_CCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,TLS_DHE_RSA_WITH_AES_128_GCM_SHA256"
#Set SSL Chiphers (Inkl. bis 2026 Zugelassene Chiphersuiten)
IF ( $support2026 -eq 1) {
    $chiphersuites += ",TLS_RSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_128_GCM_SHA256,TLS_RSA_WITH_AES_256_CBC_SHA384,TLS_RSA_WITH_AES_128_CBC_SHA256,TLS_PSK_WITH_AES_256_GCM_SHA384,TLS_PSK_WITH_AES_128_GCM_SHA256,TLS_PSK_WITH_AES_256_CBC_SHA384,TLS_PSK_WITH_AES_128_CBC_SHA256"
    Write-Output "2026support is enabled - Chiphersuites for 2026 are included"
} 
Set-GPRegistryValue -Name $DCgpoName -Key 'HKLM\Software\Policies\Microsoft\Cryptography\Configuration\SSL\00010002' -Type String -ValueName "Functions" -Value $Chiphersuites | Out-Null

#ECC Curven
$ECCCurves = "brainpoolP512r1","brainpoolP384r1","brainpoolP256r1","curve25519"
Set-GPRegistryValue -Name $DCgpoName -Key 'HKLM\Software\Policies\Microsoft\Cryptography\Configuration\SSL\00010002' -ValueName 'EccCurves' -Value $ECCCurves -Type MultiString | Out-Null

#Schlüssellänge für Diffie-Hellman und RSA (BSI-TR-02102-2 Chapter 3.6.1)
Set-GPRegistryValue -Name $DCgpoName -Key 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman' -ValueName ClientMinKeyBitLength -Value 0xBB8 -Type DWord | Out-Null
Set-GPRegistryValue -Name $DCgpoName -Key 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\PKCS' -ValueName ClientMinKeyBitLength -Value 0xBB8 -Type DWord | Out-Null

#Stron Crypto für .Net
Set-GPRegistryValue -Name $DCgpoName -Key 'HKLM\SOFTWARE\Microsoft\.NetFramework\v4.0.30319' -Valuename 'SchUseStrongCrypto' -value 1 -Type DWord  | Out-Null
Set-GPRegistryValue -Name $DCgpoName -Key 'HKLM\SOFTWARE\WOW6432Node\Microsoft\.NetFramework\v4.0.30319' -Valuename 'SchUseStrongCrypto' -value 1 -Type DWord | Out-Null 
Set-GPRegistryValue -Name $DCgpoName -Key 'HKLM\SOFTWARE\Microsoft\.NetFramework\v4.0.30319' -Valuename 'SystemDefaultTlsVersions' -value 1 -Type DWord  | Out-Null
Set-GPRegistryValue -Name $DCgpoName -Key 'HKLM\SOFTWARE\WOW6432Node\Microsoft\.NetFramework\v4.0.30319' -Valuename 'SystemDefaultTlsVersions' -value 1 -Type DWord | Out-Null 
Set-GPRegistryValue -Name $DCgpoName -Key 'HKLM\SOFTWARE\Microsoft\.NetFramework\v2.0.50727' -Valuename 'SchUseStrongCrypto' -value 1 -Type DWord  | Out-Null
Set-GPRegistryValue -Name $DCgpoName -Key 'HKLM\SOFTWARE\WOW6432Node\Microsoft\.NetFramework\v2.0.50727' -Valuename 'SchUseStrongCrypto' -value 1 -Type DWord | Out-Null
Set-GPRegistryValue -Name $DCgpoName -Key 'HKLM\SOFTWARE\Microsoft\.NetFramework\v2.0.50727' -Valuename 'SystemDefaultTlsVersions' -value 1 -Type DWord  | Out-Null
Set-GPRegistryValue -Name $DCgpoName -Key 'HKLM\SOFTWARE\WOW6432Node\Microsoft\.NetFramework\v2.0.50727' -Valuename 'SystemDefaultTlsVersions' -value 1 -Type DWord | Out-Null


#WinRm
Set-GPRegistryValue -Name $DCgpoName -Key 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp' -ValueName DefaultSecureProtocols -Value 0x2800 -Type DWord | Out-Null
Set-GPRegistryValue -Name $DCgpoName -Key 'HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp' -ValueName DefaultSecureProtocols -Value 0x2800 -Type DWord | Out-Null

#WinINET
Set-GPRegistryValue -Name $DCgpoName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings' -ValueName SecureProtocols -Value 0x2800 -Type DWord | Out-Null

Write-Output "GPO $DCgpoName created and settings applied."
Write-Output "Please link the GPO to the desired OU or domain."
