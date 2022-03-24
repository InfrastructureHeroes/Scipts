<#
	.SYNOPSIS
		
	.DESCRIPTION
		
	.EXAMPLE  
        
	.INPUTS
		Keine.
	.OUTPUTS
		Keine.
	.NOTES
		Author     : Fabian Niesen
		Filename   : 
		Requires   : PowerShell Version 2.0
		
		Version    : 0.1
		History    : 0.1   FN  26.111.2015  initial version
                    
    .LINK
        
#>
# Variable declaration
$DOM =""
$NETBIOS =""
$SMADMIPW =""

# End of declaration - do not edit below this Point!

$ErrorActionPreference = "Stop"
$before = Get-Date
$date = get-date -format yyyyMMdd-HHmm
$ErrorLog =$BackupPath+$date+"-error.log"
$WarningLog =$BackupPath+$date+"-warning.log"

If (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole( [Security.Principal.WindowsBuiltInRole] "Administrator"))
{
    Write-Warning "You need Admin Permissions to run this script!"| Out-file $ErrorLog -Append
    break    
}

  Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools  Import-Module ADDSDeployment  Install-ADDSForest `
  -CreateDnsDelegation:$false `
  -DatabasePath "C:\Windows\NTDS" `
  -DomainMode "Win2012R2" `
  -DomainName $DOM `
  -DomainNetbiosName $NETBIOS `
  -ForestMode "Win2012R2" `
  -InstallDns:$true `
  -LogPath "C:\Windows\NTDS" `
  -NoRebootOnCompletion:$false `
  -SysvolPath "C:\Windows\SYSVOL" `
  -Force:$true `
  -SafeModeAdministratorPassword (ConvertTo-SecureString $SMADMIPW -AsPlainText -Force)




$after = Get-Date

$time = $after - $before
$buildTime = "`nBuild finished in ";
if ($time.Minutes -gt 0)
{
    $buildTime += "{0} minute(s) " -f $time.Minutes;
}

$buildTime += "{0} second(s)" -f $time.Seconds;
Write-host "$buildTime" 