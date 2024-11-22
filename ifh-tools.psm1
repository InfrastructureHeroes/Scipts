<#
	.DESCRIPTION
        Powershell Module for various IFH Scripts
    .NOTES
		Author     :    Fabian Niesen
		Filename   :    ifh-toold.psm1
		Requires   :    PowerShell Version 5.1
		
		Version    :    
        History    :    
                        0.1 FN 14.11.2024 Initial Version
        
    .LINK
        https://github.com/InfrastructureHeroes/Scipts
#>
$global:IFHModelVer = "0.1"
$global:IFHeventLogName = "IFHTools"
$global:scriptName = $MyInvocation.MyCommand.Name -replace '\.psm1$', ''
function Start-Log {
    param (
        [string]$logDirectory = "C:\Logs",
        [string]$IFHlogfileName = "IFHlogfile.txt"
    )
    # Erstelle das Verzeichnis, falls es nicht existiert
    if (-not (Test-Path -Path $logDirectory)) {
        New-Item -ItemType Directory -Path $logDirectory | Out-Null
    }
    # Erstelle den Dateinamen mit Datum und Skriptname
    $datePart = (Get-Date -Format "yyyyMMdd-HHmm")
    IF (IsNull $scriptName ) { $scriptName = "NoScript"}
    $IFHlogfileName = $datePart +"_" + $scriptName + ".log"

    # Setze den Pfad für die Logdatei
    $global:IFHlogfile = Join-Path -Path $logDirectory -ChildPath $IFHlogfileName

    # Erstelle die Logdatei, falls sie nicht existiert
    if (-not (Test-Path -Path $IFHlogfile)) {
        New-Item -ItemType File -Path $IFHlogfile | Out-Null
    }
    $ifheventLogExists = Get-EventLog -LogName * | Where-Object { $_.LogDisplayName -eq $IFHeventLogName }
    if (-not $ifheventLogExists ) {
        $isAdmin = (New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        $ErrorActionPreference = $ea
        if ($isAdmin) {
            New-EventLog -LogName $IFHeventLogName -Source $IFHeventLogName 
            # Definieren Sie den Pfad zum Eventlog in der Registry, z.B. für ein benutzerdefiniertes Log "IFHTools"
            $eventLogPath = "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\" + $IFHeventLogName

            # Berechtigungen des Registry-Schlüssels abrufen
            $acl = Get-Acl -Path $eventLogPath
            $sid = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-545")
            $account = $sid.Translate([System.Security.Principal.NTAccount])
            # Erstellen Sie eine Zugriffsregel für Authentifizierte Benutzer mit den spezifischen Berechtigungen #FIXME
            $accessRule = New-Object System.Security.AccessControl.RegistryAccessRule(
                $account.Value, 
                "ReadKey, WriteKey",  # Ermöglicht das Hinzufügen von Einträgen und Quellen
                "ContainerInherit,ObjectInherit",
                "None",
                "Allow"
            )

            # Zugriffsregel zur ACL hinzufügen
            $acl.SetAccessRule($accessRule)

            # Setzen Sie die geänderte ACL zurück auf den Registry-Schlüssel
            Set-Acl -Path $eventLogPath -AclObject $acl
            $reboot = $true
            Write-Host "Berechtigungen für 'Authentifizierte Benutzer' zum Hinzufügen von Einträgen und Quellen im Eventlog wurden erfolgreich geändert. Neustart erforderlich!"
            Write-Log "Das Eventlog 'IFHTools' wurde erstellt." -EventID 100
        } else {
            try {
                Start-Process powershell -ArgumentList "-Command `"New-EventLog -LogName '$IFHeventLogName' -Source '$IFHeventLogName'`"" -Verb RunAs
                Write-Log "Das Eventlog 'IFHTools' wurde erstellt." -EventID 100
            } catch {
                Write-Log "Fehler beim Anlegen des EventLog $IFHeventLogName - Wahrscheinlich fehlende Administratorrechte: $_" -LogLevel 2 -EventID 403
            }
            return
        }
    } else {
        Write-Host "Das Eventlog 'IFHTools' existiert bereits."
    }
    Write-Host "Logdatei erstellt: $IFHlogfile"
    Write-Log -EventID 100 -logLevel 0 -Message "Start IFHlogfile - IFH Module Version $IFHModelVer"
    return $IFHlogfile
}

function Write-Log {
    param (
        [string]$Message,
        [int]$EventID = 100,
        [int]$LogLevel = 0,
        [string]$eventsource=$IFHeventLogName
    )

    if (-not $IFHlogfile) { Start-Log }
    # Bestimme den LogLevel-Text
    switch ($LogLevel) {
        0 { $levelText = "INFO"; Write-Host $Message }
        1 { $levelText = "WARNING"; Write-Warning $Message }
        2 { $levelText = "ERROR"; Write-Host "ERROR: $Message" -ForegroundColor Red }
        3 { $levelText = "DEBUG"; Write-Debug $Message }
        default { $levelText = "UNKNOWN"; Write-Host $Message  }
    }

    # Logeintrag im Eventlog
    $ifheventLogExists = Get-EventLog -LogName * | Where-Object { $_.LogDisplayName -eq $IFHeventLogName }
    if ($ifheventLogExists ) {
        try { Write-EventLog -LogName $IFHeventLogName -Source $eventsource -EventID $EventID -EntryType Information -Message "$levelText : $Message" -ErrorAction Stop }
        catch { Write-Error $_.Exception.Message }
    } else { Write-host "EventLog $IFHeventLogName does not exists"}
    # Logeintrag in die Logdatei im OneTrace-Format
    $logEntry = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [$levelText] (EventID: $EventID) $Message"
    Add-Content -Path $IFHlogfile -Value $logEntry
}

function Get-DC { Begin { Write-Log "Start DC detection" }
#FIXME add Location awareness 
#FIXME Test all DC until  one is reachable
Process {
    Try {
        IF ( (Get-WindowsFeature -Name RSAT-AD-PowerShell).InstallState -like "Installed") 
        {
            Write-Log -Message "Use RSAT-AD-PowerShell for DC detection"
            $global:LDAPDOM = (Get-ADDomain).DistinguishedName
            $global:DNSDOM = (Get-ADDomain).DNSRoot.toLower()
            $DC=(Get-ADDomainController -Filter {OperationMasterRoles -like "PDC*"}).Hostname
            if ((Test-Connection $DC -Count 1) -eq $false)
                {
                    Write-Log -Message "Found RSAT-AD-PowerShell - PDC not reachable - Fallback mode" -LogLevel 2
                    $DC = (Get-ADDomainController).Hostname
                    if ((Test-Connection $DC -Count 1) -eq $false)
                    {
                        Write-Log -Message "DC not reachable - Abort" -LogLevel 2
                        Break;                
                    }
                } Else {
                    Write-Log -Message "Found RSAT-AD-PowerShell - Using PDC"
                }
        }
        else {
            Write-Log -Message "RSAT-AD-PowerShell not found, fall back to NLtest - the determined DC might not be the PDC!"
            $global:DNSDOM = [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties().DomainName
            $global:LDAPDOM = "DC=" + ($DNSDOM -replace '\.',',DC=')
            $DCs = (((nltest /dsgetdc:$DNSDOM /PDC).Trim() | Select-String -Pattern ".$DNSDOM") | select-Object -First 1 ) -split " " -match ".$DNSDOM" -replace "\\",""
            (Test-Connection $DC -Count 1)
            Write-Log -Message "Set DC to $DC"
        }
    }
    Catch {
        Write-Log -message "GET-DC - $($_.Exception.Message)" -loglevel 3
        $global:DNSDOM = [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties().DomainName
        $global:LDAPDOM = "DC=" + ($DNSDOM -replace '\.',',DC=')
        $DCs = (((nltest /dclist:$DNSDOM).trim() | Select-String -Pattern ".$DNSDOM") | Select-Object -skip 1 ) -split " " -match ".$DNSDOM"
        $DC = $DCs[0].ToString()
        Write-Log -Message "Set DC to $DC"
    }
}
END { return $DC }
}

function IsNull($objectToCheck) {
        <#
        .COPYRIGHT
        Original Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT license.
    #>
    if ($objectToCheck -eq $null) { return $true }
    if ($objectToCheck -is [String] -and $objectToCheck -eq [String]::Empty) { return $true }
    if ($objectToCheck -is [DBNull] -or $objectToCheck -is [System.Management.Automation.Language.NullString]) { return $true }
    return $false
}

Function Set-RunPSOnce {
    <#
        .COPYRIGHT
        Copyright (c) 2022 Fabian Niesen. All rights reserved. Licensed under the MIT license.
    #>

    param (
        [Parameter(Mandatory = $true)]
        [string]$Name,
        [Parameter(Mandatory = $true)]
        [string]$File,
        [string]$Parameter = " "
    )
    [string]$runOnce = "%systemroot%\System32\WindowsPowerShell\v1.0\powershell.exe -executionpolicy bypass -noexit -Command $File " + $Parameter
    Write-Log -Message "RunOnce Command: $runOnce"
    New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce" -Name $Name -Value $runOnce -PropertyType ExpandString
}

Function Set-Network {
    <#
        .COPYRIGHT
        Copyright (c) 2022 Fabian Niesen. All rights reserved. Licensed under the MIT license.
    #>

    param (
        [string]$DNSDomain,
        [switch]$DisableNetbios,
        [switch]$DisableIPv6Interfaces,
        [boolean]$global:reboot,
        [switch]$autoreboot
        
    )
    Write-Verbose "DNSDomain: $DNSDomain - DisableNetbios: $DisableNetbios - DisableIPv6Interfaces: $DisableIPv6Interfaces"
    Write-Verbose "Scan for Networkinterfaces"
    $networkConfig = Get-WmiObject Win32_NetworkAdapterConfiguration -filter "ipenabled = 'true'"
    IF ( $DNSDomain -ne "")
    {   
        Write-Verbose "Set DNSDomain"
        $networkConfig.SetDnsDomain($DNSDomain)
        Write-Verbose "Set Dynamic DNS Registration"
        $networkConfig.SetDynamicDNSRegistration($true,$true)
        ipconfig /registerdns
    }
    IF ($DisableNetbios)
    {
        $netbt = 'HKLM:\SYSTEM\CurrentControlSet\Services\netbt\Parameters\interfaces'
        $netbtdev = Get-ChildItem $netbt | ForEach-Object { Get-ItemProperty -Path "$netbt\$($_.pschildname)" -name NetBiosOptions } | Where-Object { $_.NetbiosOptions -lt 2 }
        Write-Verbose "netbtdev: $netbtdev"
        Write-Verbose "Count: $($netbtdev.Count)"
        IF ( ($netbtdev).Count -gt 0 ) {
            Write-Log -Message "NetBios enabled devices detected"
            $netbtdev | Set-ItemProperty -name NetBiosOptions -value 2
            Write-Log -Message "Reboot is Required - Sorry"
            $reboot = $true
            #shutdown.exe /t 300 /r /c "Reboot required to disable NetBios over TCP/IP" /d p:2:4
        } ELSE {
            Write-Log -Message "All devices have NetBios over TCP/IP disabled. Nothing to do. Have a nice day!"
        }
    }
    if ($DisableIPv6Interfaces)
    {
        Write-Verbose "Disable IPv6 on Interfaces and prefer IPv4 over IPv6 (Based on Microsoft KB929852)"
        Try {
            $IPv6State = Get-ItemPropertyValue "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" "DisabledComponents" -ErrorAction SilentlyContinue
            }
            Catch { $IPv6State = -1 }
            If ($IPv6State -eq 50 ) {Write-Log -Message "IPv6 diabled on Interfaces and prefer IPv4 over IPv6 (Based on Microsoft KB929852)"} 
            else 
            { 
                Write-Warning "IPv6 is not proper disabled!"
                reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" /v DisabledComponents /t REG_DWORD /d 0x32 /f
                Write-Log -Message "Disable IPv6 - Reboot is Required - Sorry"
                $reboot = $true
            }
            
        
    }
    IF ($autoreboot) {shutdown.exe /t 300 /r /c "Reboot required to network configuration changes" /d p:2:4}
    IF ( $reboot ) 
    { 
        Try {new-Variable -Name reboot -Value $true -Scope Global -ErrorAction Stop }
        Catch {Set-Variable -Name reboot -Value $true -Scope Global -Force}
    }
}

Function start-wait {
    <#
        .COPYRIGHT
        Copyright (c) 2022 Fabian Niesen. All rights reserved. Licensed under the MIT license.
    #>

    param (
        [Parameter(Mandatory = $true)][int]$seconds,
        [string]$Comment ="Something magic is happend in the background"
    )
    Begin { 
        Write-Verbose -Message "$($MyInvocation.InvocationName) function..."
        Write-Log -Message $Comment
    }
    Process {
        For ($i=1; $i -le $seconds; $i++)
        {
        Write-Progress -Activity "Please Wait - $Comment - $i of $seconds seconds" -Status "$([Math]::round($i / $seconds*100 , 2))% Complete:" -PercentComplete (($i / $seconds)*100) -id 25
        Start-Sleep -Seconds 1
        }
    }
    End { Write-Verbose "Returning..." }
}

Function Get-PendingRebootStatus {
    <#
    .Synopsis
        This will check to see if a server or computer has a reboot pending.
        For updated help and examples refer to -Online version.
    
    .NOTES
        Name: Get-PendingRebootStatus
        Author: theSysadminChannel, Fabian Niesen 
        Version: 1.2 FN
        DateCreated: 2018-Jun-6
        DateModified: 2023-Jan-20
    
    .LINK
        https://thesysadminchannel.com/remotely-check-pending-reboot-status-powershell
        
    
    .PARAMETER ComputerName
        By default it will check the local computer.
    
    .EXAMPLE
        Get-PendingRebootStatus -ComputerName PAC-DC01, PAC-WIN1001
    
        Description:
        Check the computers PAC-DC01 and PAC-WIN1001 if there are any pending reboots.
    #>
    
        [CmdletBinding()]
        Param (
            [Parameter(Mandatory = $false)][switch]$AutoReboot,  
            [Parameter(Mandatory = $false)][int]$wait = 30
        )
    
        BEGIN {}
    
        PROCESS {
            Try {
                $Computer = $env:COMPUTERNAME
                $PendingReboot = $false
                $HKLM = [UInt32] "0x80000002"
                $WMI_Reg = [WMIClass] "\\$Computer\root\default:StdRegProv"
                if ($WMI_Reg) {
                    if (($WMI_Reg.EnumKey($HKLM,"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\")).sNames -contains 'RebootPending') {$PendingReboot = $true ; Write-Log -message "Component Based Servicing: RebootPending" -LogLevel 2}
                    if (($WMI_Reg.EnumKey($HKLM,"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\")).sNames -contains 'RebootRequired') {$PendingReboot = $true ; Write-Log -message "WindowsUpdate: RebootRequired" -LogLevel 2}
                    if (($WMI_Reg.EnumKey($HKLM,"SYSTEM\CurrentControlSet\Control\Session Manager")).sNames -contains 'PendingFileRenameOperations') {$PendingReboot = $true ; Write-Log -message "Session Manager: PendingFileRenameOperations" -LogLevel 2}
                    if (($WMI_Reg.EnumKey($HKLM,"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update")).sNames -contains 'PostRebootReporting') {$PendingReboot = $true ; Write-Log -message "WindowsUpdate: PostRebootReporting" -LogLevel 2}
                    if (($WMI_Reg.EnumKey($HKLM,"SYSTEM\CurrentControlSet\Control\Session Manager")).sNames -contains 'PendingFileRenameOperations2') {$PendingReboot = $true ; Write-Log -message "Session Manager: PendingFileRenameOperations2" -LogLevel 2}
                    if (($WMI_Reg.EnumKey($HKLM,"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\")).sNames -contains 'RebootInProgress') {$PendingReboot = $true ; Write-Log -message "Component Based Servicing: RebootInProgress" -LogLevel 2}
                    if (($WMI_Reg.EnumKey($HKLM,"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\")).sNames -contains 'PackagesPending') {$PendingReboot = $true ; Write-Log -message "Component Based Servicing: PackagesPending" -LogLevel 2}
                    if (($WMI_Reg.EnumKey($HKLM,"SOFTWARE\Microsoft\ServerManager")).sNames -contains 'CurrentRebootAttempts') {$PendingReboot = $true ; Write-Log -message "ServerManager: CurrentRebootAttempts" -LogLevel 2}
                    if (($WMI_Reg.EnumKey($HKLM,"SYSTEM\CurrentControlSet\Services\Netlogon")).sNames -contains 'JoinDomain') {$PendingReboot = $true ; Write-Log -message "Netlogon: JoinDomain" -LogLevel 2}
                    #Checking for SCCM namespace
                    $SCCM_Namespace = Get-WmiObject -Namespace ROOT\CCM\ClientSDK -List -ComputerName $Computer -ErrorAction Ignore
                    if ($SCCM_Namespace) {
                        if (([WmiClass]"\\$Computer\ROOT\CCM\ClientSDK:CCM_ClientUtilities").DetermineIfRebootPending().RebootPending -eq $true) {$PendingReboot = $true ; Write-Log -message "SCCM: RebootPending" -LogLevel 2}
                    }
                }
            } catch {
                Write-Error $_.Exception.Message
            } finally {
                #Clearing Variables
                $null = $WMI_Reg
                $null = $SCCM_Namespace
                IF ($PendingReboot) { $reboot = $true }
            }
        }
    
        END { Return $PendingReboot }
}

function Restart-IfRequired {
    param (
        [int]$actstep,
        [bool]$reboot = $false,
        [bool]$runonce = $false
    )
    Write-Log "Start ifreboot, State: $reboot"
    IF ( Get-PendingRebootStatus ) { $reboot = $true ; Write-Log -Message "Pending reboot detected"}
    if ($reboot) {
        Write-Log "Der Rechner wird in 60 Sekunden neu gestartet, da der Parameter 'reboot' auf true gesetzt ist."
        Clear-Variable -Name arg -Force -ErrorAction SilentlyContinue
        [string]$arg = " "
        Write-Log -message "Provided Parameter:    $Param"
        Write-Log -message "Provided ScriptParam:  $scriptparam"
        Write-Log -message "Provided Scriptsource: $scriptsource"
        If ($null -ne $Param ) {
            Write-Log -Message "Parameter provided: >$Param<"
            $arg = $Param
        }
        Else {
            Write-log -Message "No Parameter detected, start autodetection."
            $scriptparam | format-table -Property * -AutoSize
            IF ( $scriptparam.Count -eq 1 )
            {
                Write-host "PARA.Key: $(($scriptparam | Select-Object -ExpandProperty Keys  )) - PARA.Value: $(($scriptparam | Select-Object -ExpandProperty Values  ))"
                        IF ( $(($scriptparam | Select-Object -ExpandProperty Keys  )) -like "verbose") {$arg += " -Verbose"}
                        ELSEIF ( $(($scriptparam | Select-Object -ExpandProperty Keys  )) -notlike "step") 
                        { 
                            IF ( $(($scriptparam | Select-Object -ExpandProperty Values  )) -like "True" -or $(($scriptparam | Select-Object -ExpandProperty Values  )) -like $true ) { $arg += " -"+$(($scriptparam | Select-Object -ExpandProperty Keys  ) | Out-String) +':$True ' }
                            ELSEIF ( $(($scriptparam | Select-Object -ExpandProperty Values  )) -like "False" -or $(($scriptparam | Select-Object -ExpandProperty Values  )) -like $false ) { $arg += " -"+$(($scriptparam | Select-Object -ExpandProperty Keys  ) | Out-String) +':$False ' }
                            ELSE {$arg += " -$(($scriptparam | Select-Object -ExpandProperty Keys  ) ) $(($scriptparam | Select-Object -ExpandProperty Values  ) ) " }
                            Write-Log -Message "Detected Parameter: $(($scriptparam | Select-Object -ExpandProperty Keys  ) | Out-String) - Value: $(($scriptparam | Select-Object -ExpandProperty Values  ) | Out-String)"
                        }
            }
            Else {
                for ($i = 0; $i -lt $scriptparam.Count; $i++) {
                    Write-host "PARA.Key: $(($scriptparam | Select-Object -ExpandProperty Keys  )[$i]) - PARA.Value: $(($scriptparam | Select-Object -ExpandProperty Values  )[$i])"
                        IF ( $(($scriptparam | Select-Object -ExpandProperty Keys  )[$i]) -like "verbose") {$arg += " -Verbose"}
                        ELSEIF ( $(($scriptparam | Select-Object -ExpandProperty Keys  )[$i]) -notlike "step") 
                        { 
                            IF ( $(($scriptparam | Select-Object -ExpandProperty Values  )[$i]) -like "True" -or $(($scriptparam | Select-Object -ExpandProperty Values  )[$i]) -like $true ) { $arg += " -"+$(($scriptparam | Select-Object -ExpandProperty Keys  )[$i] | Out-String) + ' $True ' }
                            ELSEIF ( $(($scriptparam | Select-Object -ExpandProperty Values  )[$i]) -like "False" -or $(($scriptparam | Select-Object -ExpandProperty Values  )[$i]) -like $false ) { $arg += " -"+$(($scriptparam | Select-Object -ExpandProperty Keys  )[$i] | Out-String) +' $False ' }
                            ELSE {$arg += " -$(($scriptparam | Select-Object -ExpandProperty Keys  )[$i] ) $(($scriptparam | Select-Object -ExpandProperty Values  )[$i] ) " }
                            Write-Log -Message "Detected Parameter: $(($scriptparam | Select-Object -ExpandProperty Keys  )[$i] | Out-String) - Value: $(($scriptparam | Select-Object -ExpandProperty Values  )[$i] | Out-String)"
                        }
                    }
                }
        }
        IF ($actstep -ne "") { $arg += " -step $actstep " }
        $arg = $arg -replace "`n|`r"

        #FIXME Cleanup old RunOnce
        IF ($runonce -eq $true) 
        { 
            Write-Log -Message "Set RunOnce - $scriptsource - Use Parameter: $arg "
            Try { Set-RunPSOnce -Name "$scriptsource" -File $scriptsource -Parameter $arg -ErrorAction Stop } Catch {Write-log -Message "Error - Runonce not set: $($_.Exception.Message) " -LogLevel 2 -EventID 666 } 
        }
        Start-wait -Seconds 60
        Restart-Computer -Force
    } else {
        Write-Log "Kein Neustart erforderlich."
    }
}

# Exportiere die Funktionen
Export-ModuleMember -Function *