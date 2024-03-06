#requires -version 5.1

<#
	.SYNOPSIS
		Remove Azure Arc Setup if installed. Reboot will happend automaticaly.
	
    .DESCRIPTION
		Remove Azure Arc Setup if installed. Reboot will happend automaticaly.

	.EXAMPLE  
        Remove-AzureArc.ps1

	.NOTES
		Author     :    Fabian Niesen
		Filename   :    Remove-AzureArc.ps1
		Requires   :    PowerShell Version 5.1
		

		Version    :    1.0

		History    :    FN 06.03.2024 Initiale Version
    .LINK
        https://github.com/InfrastructureHeroes/Scipts
#>
#REGION Functions
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
        Param ()
    
        BEGIN {}
    
        PROCESS {
            Try {
                $Computer = $env:COMPUTERNAME
                $PendingReboot = $false
                $HKLM = [UInt32] "0x80000002"
                $WMI_Reg = [WMIClass] "\\$Computer\root\default:StdRegProv"
                if ($WMI_Reg) {
                    if (($WMI_Reg.EnumKey($HKLM,"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\")).sNames -contains 'RebootPending') {$PendingReboot = $true ; Write-output "Component Based Servicing: RebootPending"}
                    if (($WMI_Reg.EnumKey($HKLM,"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\")).sNames -contains 'RebootRequired') {$PendingReboot = $true ; Write-output "WindowsUpdate: RebootRequired"}
                    if (($WMI_Reg.EnumKey($HKLM,"SYSTEM\CurrentControlSet\Control\Session Manager")).sNames -contains 'PendingFileRenameOperations') {$PendingReboot = $true ; Write-output "Session Manager: PendingFileRenameOperations"}
                    if (($WMI_Reg.EnumKey($HKLM,"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update")).sNames -contains 'PostRebootReporting') {$PendingReboot = $true ; Write-output "WindowsUpdate: PostRebootReporting"}
                    if (($WMI_Reg.EnumKey($HKLM,"SYSTEM\CurrentControlSet\Control\Session Manager")).sNames -contains 'PendingFileRenameOperations2') {$PendingReboot = $true ; Write-output "Session Manager: PendingFileRenameOperations2"}
                    if (($WMI_Reg.EnumKey($HKLM,"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\")).sNames -contains 'RebootInProgress') {$PendingReboot = $true ; Write-output "Component Based Servicing: RebootInProgress"}
                    if (($WMI_Reg.EnumKey($HKLM,"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\")).sNames -contains 'PackagesPending') {$PendingReboot = $true ; Write-output "Component Based Servicing: PackagesPending"}
                    if (($WMI_Reg.EnumKey($HKLM,"SOFTWARE\Microsoft\ServerManager")).sNames -contains 'CurrentRebootAttempts') {$PendingReboot = $true ; Write-output "ServerManager: CurrentRebootAttempts"}
                    if (($WMI_Reg.EnumKey($HKLM,"SYSTEM\CurrentControlSet\Services\Netlogon")).sNames -contains 'JoinDomain') {$PendingReboot = $true ; Write-output "Netlogon: JoinDomain"}
                    #Checking for SCCM namespace
                    $SCCM_Namespace = Get-WmiObject -Namespace ROOT\CCM\ClientSDK -List -ComputerName $Computer -ErrorAction Ignore
                    if ($SCCM_Namespace) {
                        if (([WmiClass]"\\$Computer\ROOT\CCM\ClientSDK:CCM_ClientUtilities").DetermineIfRebootPending().RebootPending -eq $true) {$PendingReboot = $true ; Write-output "SCCM: RebootPending"}
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
#ENDREGION Functions
$AzureArc = $( (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction SilentlyContinue ).UBR -ge 2031)
IF ( -not $AzureArc) 
    { Write-Output "Patchlevel is not high enough for Azure Arc - No action required " }
Else {
    # Get-WindowsFeature -Name AzureArcSetup
    IF ( (get-WindowsFeature -Name AzureArcSetup).InstallState -like "Installed" ) {Write-Warning "AzureArc is Installed - Remove Feature Restart required" ; Uninstall-WindowsFeature -Name AzureArcSetup -Restart:$false -confirm:$false  }
    ELSE { Write-Output "Windows Arc is not installed"}
    IF ( Get-PendingRebootStatus ) { 
        Write-Warning "Reboot required - Will reboot in 60 sec. Use >Shutdown.exe /a< to abort."
        shutdown.exe /t 60 /r /c "Reboot required" /d p:2:4 
    }
}