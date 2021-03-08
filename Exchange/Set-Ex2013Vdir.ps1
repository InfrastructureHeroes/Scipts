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
		Filename   : set-ex2013vdir.ps1
		Requires   : PowerShell Version 3.0
		
		Version    : 0.1
		History    : 
    .LINK
        
#>

Param(
	[Parameter(Mandatory=$false, ValueFromPipeline=$False)]
	[String]$InternalHost=$null,
    [Parameter(Mandatory=$false, ValueFromPipeline=$False)]
    [String]$ExternalHost=$null

)
$before = Get-Date
Set-AdServerSettings -ViewEntireForest $true

Write-Host "Found the following Exchange Server"
Get-ExchangeServer | ft Name,Site,ServerRole,Edition,AdminDisplayVersion -AutoSize 

IF (!($InternalHost -like "$null"))
    {
    IF (!($ExternalHost -like "$null"))
    {
      Write-Host "Set Internalhost $InternalHost and Externalhost $ExternalHost"
      Get-ExchangeServer | ? { $_.ServerRole -like "*ClientAccess*" }| Get-WebservicesVirtualDirectory | Set-WebservicesVirtualDirectory -InternalURL https://$InternalHost/EWS/Exchange.asmx -ExternalURL https://$ExternalHost/EWS/Exchange.asmx
      Get-ExchangeServer | ? { $_.ServerRole -like "*ClientAccess*" }| Get-OwaVirtualDirectory | Set-OwaVirtualDirectory -InternalURL https://$InternalHost/owa -ExternalURL https://$ExternalHost/owa
      Get-ExchangeServer | ? { $_.ServerRole -like "*ClientAccess*" }| Get-ecpVirtualDirectory | Set-ecpVirtualDirectory -InternalURL https://$InternalHost/ecp -ExternalURL https://$ExternalHost/ecp
      Get-ExchangeServer | ? { $_.ServerRole -like "*ClientAccess*" }| Get-ActiveSyncVirtualDirectory | Set-ActiveSyncVirtualDirectory -InternalURL https://$InternalHost/Microsoft-Server-ActiveSync -ExternalURL https://$ExternalHost/Microsoft-Server-ActiveSync
      Get-ExchangeServer | ? { $_.ServerRole -like "*ClientAccess*" }| Get-OABVirtualDirectory | Set-OABVirtualDirectory -InternalUrl https://$InternalHost/OAB -ExternalURL https://$ExternalHost/OAB
      Get-ExchangeServer | ? { $_.ServerRole -like "*ClientAccess*" }| get-mapivirtualdirectory | Set-MapiVirtualDirectory -InternalUrl https://$InternalHost/mapi -ExternalURL https://$ExternalHost/mapi
      Get-ExchangeServer | ? { $_.ServerRole -like "*ClientAccess*" }| Set-ClientAccessServer -AutodiscoverServiceInternalUri https://$InternalHost/Autodiscover/Autodiscover.xml
      get-OutlookAnywhere | Set-OutlookAnywhere -InternalHostname $InternalHost -ExternalHostName $ExternalHost -InternalClientAuthenticationMethod ntlm -InternalClientsRequireSsl:$True -ExternalClientAuthenticationMethod NTLM -ExternalClientsRequireSsl:$True
    }
    ELSE
    {
      Write-Host "Set Internalhost $InternalHost"
      Get-ExchangeServer | ? { $_.ServerRole -like "*ClientAccess*" }| Get-WebservicesVirtualDirectory | Set-WebservicesVirtualDirectory -InternalURL https://$InternalHost/EWS/Exchange.asmx -externalurl $null
      Get-ExchangeServer | ? { $_.ServerRole -like "*ClientAccess*" }| Get-OwaVirtualDirectory | Set-OwaVirtualDirectory -InternalURL https://$InternalHost/owa -externalurl $null
      Get-ExchangeServer | ? { $_.ServerRole -like "*ClientAccess*" }| Get-ecpVirtualDirectory | Set-ecpVirtualDirectory -InternalURL https://$InternalHost/ecp -externalurl $null
      Get-ExchangeServer | ? { $_.ServerRole -like "*ClientAccess*" }| Get-ActiveSyncVirtualDirectory | Set-ActiveSyncVirtualDirectory -InternalURL https://$InternalHost/Microsoft-Server-ActiveSync -externalurl $null
      Get-ExchangeServer | ? { $_.ServerRole -like "*ClientAccess*" }| Get-OABVirtualDirectory | Set-OABVirtualDirectory -InternalUrl https://$InternalHost/OAB -externalurl $null
      Get-ExchangeServer | ? { $_.ServerRole -like "*ClientAccess*" }| get-mapivirtualdirectory | Set-MapiVirtualDirectory -InternalUrl https://$InternalHost/mapi -externalurl $null
      Get-ExchangeServer | ? { $_.ServerRole -like "*ClientAccess*" }| Set-ClientAccessServer -AutodiscoverServiceInternalUri https://$InternalHost/Autodiscover/Autodiscover.xml
      get-OutlookAnywhere | Set-OutlookAnywhere -InternalHostname $InternalHost -InternalClientAuthenticationMethod ntlm -InternalClientsRequireSsl:$True
    }}
ELSE
    {
      Write-Warning "InternalHost not set, no changes made"
    }
Write-Host "Actual Exchange settings"
Write-host "========================"
Write-Host "Autodiscover Uri"
get-exchangeserver | ? { $_.ServerRole -like "*ClientAccess*" }| get-ClientAccessServer | ft Name,AutodiscoverServiceInternalUri,AutoDiscoverSiteScope -AutoSize
Write-Host "OwaVirtualDirectory"
get-exchangeserver | ? { $_.ServerRole -like "*ClientAccess*" }| Get-OwaVirtualDirectory | ft ServerName,Name,ExternalUrl,InternalUrl -AutoSize
Write-Host "EcpVirtualDirectory"
get-exchangeserver | ? { $_.ServerRole -like "*ClientAccess*" }| Get-EcpVirtualDirectory | ft Server,Name,ExternalUrl,InternalUrl,AdminEnabled -AutoSize
Write-Host "OABVirtualDirectory"
get-exchangeserver | ? { $_.ServerRole -like "*ClientAccess*" }| Get-OABVirtualDirectory | ft Server,Name,ExternalUrl,InternalUrl -AutoSize
Write-Host "ActiveSyncVirtualDirectory"
get-exchangeserver | ? { $_.ServerRole -like "*ClientAccess*" }| Get-ActiveSyncVirtualDirectory | ft Server,Name,ExternalUrl,InternalUrl -AutoSize
Write-Host "mapiVirtualDirectory"
get-exchangeserver | ? { $_.ServerRole -like "*ClientAccess*" }| Get-mapiVirtualDirectory | ft Server,Name,ExternalUrl,InternalUrl -AutoSize
Write-Host "WebservicesVirtualDirectory"
get-exchangeserver | ? { $_.ServerRole -like "*ClientAccess*" }| Get-WebservicesVirtualDirectory | ft Server,Name,ExternalUrl,InternalUrl -AutoSize
Write-Host "OutlookAnywhere"
get-exchangeserver | Get-outlookAnywhere | ft Name,ExternalHostname,InternalHostname -AutoSize

$after = Get-Date

$time = $after - $before
$buildTime = "`nBuild finished in ";
if ($time.Minutes -gt 0)
{
    $buildTime += "{0} minute(s) " -f $time.Minutes;
}

$buildTime += "{0} second(s)" -f $time.Seconds;
Write-host $buildTime 