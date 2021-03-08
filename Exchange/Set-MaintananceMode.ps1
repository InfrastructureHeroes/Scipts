<#
	.SYNOPSIS
		Setting Exchange 2013 DAG to Maintenence mode
	.DESCRIPTION
		Setting Exchange 2013 DAG to Maintenence mode
	.EXAMPLE  
        
	.INPUTS
		Mode: start | stop
        Source: (Optional, otherwise will autodetect)
        Target: (Optional, otherwise will autodetect)
        DAG: (Optional, otherwise will autodetect)
        TARGETSITE: (Optional, otherwise will autodetect)
	.OUTPUTS
		Keine.
	.NOTES
		Author     : Fabian Niesen
		Filename   : set-MaintananceMode.ps1
		Requires   : PowerShell Version 3.0
		
		Version    : 0.2
		History    : 
    .LINK
        
#>
<# Known issues / Fix List
  Auto redistibution for active databases did not work at this version
  Autodetection for MODE ist not implemented

#>
[cmdletbinding()]
Param(
	[Parameter(Mandatory=$false, ValueFromPipeline=$False)]
    [ValidateNotNullOrEmpty()]
    [ValidateSet("start","stop")]
    [String]$Mode=$null,
    
    [Parameter(Mandatory=$false, ValueFromPipeline=$False)]
	[String]$Source=$env:COMPUTERNAME,
    
    [Parameter(Mandatory=$false, ValueFromPipeline=$False)]
    [String]$target=$null,

    [Parameter(Mandatory=$false, ValueFromPipeline=$False)]
    [String]$targetsite=$null,

    [Parameter(Mandatory=$false, ValueFromPipeline=$False)]
    [String]$dag=$null
)

function checkqueue()
{
    $MessageCount = Get-Queue -Server $Source | ?{($_.Identity -notlike "*\Poison") -and ($_.Identity -notlike "*\Shadow\*")} | Select MessageCount
    $i = 0
    foreach ( $count in $MessageCount)
    {
        $i +=$count.MessageCount
    }
    IF ($i -ne 0 )
    {
        Write-Output "Still $i messages in the queque, please wait. Recheck in 30 seconds."
        Start-Sleep -Seconds 30
        checkqueue
    }
    ELSE
    {
        Write-Output "All queues empty"  
    }
}

    Function Load-ExchangeModule {
        Write-Verbose 'Loading Exchange PowerShell module'
        If( -not ( Get-Command Connect-ExchangeServer -ErrorAction SilentlyContinue)) {
            $SetupPath= (Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\ExchangeServer\v15\Setup -Name MsiInstallPath -ErrorAction SilentlyContinue).MsiInstallPath
            If( $SetupPath -and (Test-Path "$SetupPath\bin\RemoteExchange.ps1" )) {
                . "$SetupPath\bin\RemoteExchange.ps1" | Out-Null
                Try {
                    Connect-ExchangeServer $($env:COMPUTERNAME+"."+$env:USERDNSDOMAIN)
                }
                Catch {
                    Write-Warning 'Problem loading Exchange module'
                }
            }
            Else {
                Write-Warning "Can't determine installation path to load Exchange module"
            }
        }
        Else {
            Write-Warning 'Exchange module already loaded'
        }
    }

### Proof for administrative permissions (UAC)
If (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole( [Security.Principal.WindowsBuiltInRole] "Administrator"))
{
    Write-Error "This script needs to be run as administrator!!!"    
    break
}

### insert Exchange connection!
#Try { Import-Module ActiveDirectory -ErrorAction Stop } Catch { Write-Warning "ActiveDirectory Powershell Module not found!" }
Load-ExchangeModule

Set-ADServerSettings -ViewEntireForest $true
Write-Verbose "Analyzing $Source"
IF ($dag -like $null) { $dag = $(Get-DatabaseAvailabilityGroup).Name } ELSE { Write-Verbose "DAG preseted with $dag" }
Write-Verbose "DAG >$dag< is selected"
$DagMember = $(Get-DatabaseAvailabilityGroup $dag -status).Servers.Name
$exchangeServers = $DagMember | Get-ExchangeServer | Select Identity,Fqdn,IsClientAccessServer,IsMailboxServer,IsHubTransportServer,IsFrontendTransportServer,ServerRole,Site,AdminDisplayVersion
Write-Verbose "Found the following Exchnage Servers within the DAG: $($exchangeServers.Identity)"
$exchangeServerSource = Get-ExchangeServer -Identity $Source | Select Identity,Fqdn,IsClientAccessServer,IsMailboxServer,IsHubTransportServer,IsFrontendTransportServer,ServerRole,Site,AdminDisplayVersion
Write-Verbose "Source Server is $($exchangeServerSource.Fqdn)"
IF ($targetsite -ne $null) { $site = $targetsite } ELSE {$site = $exchangeServerSource.Site.Name}
$PAM = $(Get-DatabaseAvailabilityGroup $dag -status ).PrimaryActiveManager.Name
Write-Verbose "Found PAM: $PAM"

### Insert AutoDetection for Maintenance

IF ($Mode -eq "start")
{
    ### Find proper target
    IF ($target -like $null)
    {
      Write-Verbose "No Target provided, starting autodiscovery"
  
      [array]$alt = $exchangeServers | ? {($_.Site.Name -match $Site) -and ($_.IsMailboxServer -match $true) -and ($_.Identity -notmatch $Source) }
      IF ( $alt.count -ge 1)
      {
        Write-Output "Found $($alt.count) Exchange Mailbox server within the same site"
        $target = $alt[0].Fqdn
        Write-Output "Choose $target as target"
      }
      Else
      {
        Write-Warning "No other Mailbox Server found within the same site! Choose from a other site!"
        Write-Warning "To avoid, cancel within 10 seconds and Please specify Target or Targetsite"
        Start-Sleep -Seconds 10
        [array]$alt = $exchangeServers | ? {($_.IsMailboxServer -match $true) -and ($_.Identity -notmatch $Source) }
        Write-Output "Found $($alt.count) Exchange Mailbox server within other sites"
        $target = $alt[0].Fqdn
        Write-Output "Choose $target as target"
      }
    }

    ### Disable HubTransport
    Write-Verbose "Disable HubTransport"
    Set-ServerComponentState $Source -Component HubTransport -State Draining -Requester Maintenance
    Write-Verbose "Redirecting Messages"
    Redirect-Message -Server $Source -Target $target -Confirm:$false

    ### Check and move PAM
    IF ( $PAM -match $Source)
    {
        Write-Output "PAM is running on the Source server, move it to: $target"
        Move-ClusterGroup -Cluster $dag -name "Cluster group" -node:$target
        Start-Sleep -Seconds 10
        $PAM = $(Get-DatabaseAvailabilityGroup $dag -status ).PrimaryActiveManager.Name
        IF ( $PAM -match $Source)
        {
            Write-Warning "PAM still on the Source Server please check"
            break
        }
        ELSE
        {
            Write-Output "Successfully moved the PAM to $PAM"
        }
    }
    Invoke-Command -ComputerName $Source -ArgumentList $Source {Suspend-ClusterNode $args[0]}
    ### Check and move active Databases
    Write-Verbose "Check and move active Databases"
    Try { Get-MailboxDatabaseCopyStatus -Server $Source -Active -ErrorAction stop } Catch { $ADB = "No Active" }
    IF ($ADB -like "No Active")
    {
        Write-Output "No active Database found"
    }
    ELSE
        {
        [array]$ADBs = Get-MailboxDatabaseCopyStatus -Server $Source -Active | Select DatabaseName,Status,ActiveDatabaseCopy
        IF ($ADBs.Count -ge 1)
        {
            Foreach ($ADB in $ADBs) 
            {
                Write-Verbose "Move Database $ADB to $target"
                Move-ActiveMailboxDatabase $ADB -ActivateOnServer $target
            }
        }
    }
    Set-MailboxServer $Source -DatabaseCopyActivationDisabledAndMoveNow $true
    Set-MailboxServer $Source -DatabaseCopyAutoActivationPolicy Blocked
    Write-Verbose "Checking queues"
    checkqueue
    Set-ServerComponentState $Source -Component ServerWideOffline -State Inactive -Requester Maintenance
    IF (Invoke-Command -ComputerName $Source {Restart-Service MSExchangeTransport | Out-Null})
    {
        Write-Verbose "Successfully restarted MSExchangeTransport service"
    }
    ELSE
    {
        Write-Warning "Restart of MSExchangeTransport service failed"
    }
    IF ($Source.IsClientAccessServer -match $true )
    {
        Write-Verbose "CAS detected"
        IF (Invoke-Command -ComputerName $Source {Restart-Service MSExchangeFrontEndTransport | Out-Null})
            {
                Write-Verbose "Successfully restarted MSExchangeFrontEndTransport service"
            }
            ELSE
            {
                Write-Warning "Restart of MSExchangeFrontEndTransport service failed"
            }
    } 
    Write-Output "Server $source is now in maintenance mode, please proceed"

}
ELSEIF ($Mode -eq "stop")
{
    Set-ServerComponentState $Source -Component ServerWideOffline -State Active -Requester Maintenance
    Invoke-Command -ComputerName $Source -ArgumentList $Source {Resume-ClusterNode $args[0]}
    Set-MailboxServer $Source -DatabaseCopyActivationDisabledAndMoveNow $false
    Set-MailboxServer $Source -DatabaseCopyAutoActivationPolicy Unrestricted
    Set-ServerComponentState $Source -Component HubTransport -State Active -Requester Maintenance
    IF (Invoke-Command -ComputerName $Source {Restart-Service MSExchangeTransport | Out-Null})
    {
        Write-Verbose "Successfully restarted MSExchangeTransport service"
    }
    ELSE
    {
        Write-Warning "Restart of MSExchangeTransport service failed"
    }
    IF ($Source.IsClientAccessServer -match $true )
    {
        Write-Verbose "CAS detected"
        IF (Invoke-Command -ComputerName $Source {Restart-Service MSExchangeFrontEndTransport | Out-Null})
            {
                Write-Verbose "Successfully restarted MSExchangeFrontEndTransport service"
            }
            ELSE
            {
                Write-Warning "Restart of MSExchangeFrontEndTransport service failed"
            }
    } 
    Start-Sleep -Seconds 30
    Get-HealthReport $Source | ? { $_:alertvalue -ne "healthy"}
    Get-ServerComponentState $Source | ft Component,State -AutoSize
    ### Find Databases for Activation and move them
    <# Benötigt credentials um als Admin zu laufen
    Write-Verbose "Starting relocating active Mailbox database copies"
    Invoke-Command -ComputerName $Source -Authentication Credssp -Credential $cred -ScriptBlock { c: ; cd "\Program Files\Microsoft\Exchange Server\V15\Scripts" ; .\RedistributeActiveDatabases.ps1 -BalanceDbsByActivationPreference -DAG $args[0] -LogEvents } -ArgumentList "$dag"
    #>
}
ELSE
{
  Write-Warning "No Mode selected"
}