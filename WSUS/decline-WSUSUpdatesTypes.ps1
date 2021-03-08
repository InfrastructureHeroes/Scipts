
<#PSScriptInfo

.VERSION 1.4

.GUID 8facf0bf-cade-41a6-8855-5c80e0b50ed9

.AUTHOR Fabian Niesen (Infrastrukturhelden.de)

.COMPANYNAME

.COPYRIGHT Fabian Niesen 2018

.TAGS Update

.LICENSEURI

.PROJECTURI https://www.infrastrukturhelden.de/microsoft-infrastruktur/wsus/windows-server-update-services-bereinigen.html

.ICONURI

.EXTERNALMODULEDEPENDENCIES 

.REQUIREDSCRIPTS

.EXTERNALSCRIPTDEPENDENCIES

.RELEASENOTES
First version with Config File. Might be a little bit buggy. Any comments or issues with this release are Welcome.

.PRIVATEDATA

#> 



<#
.SYNOPSIS
Decline several Update Types in Windows Server Update Services (WSUS)

.DESCRIPTION
Decline several Update Types in Windows Server Update Services (WSUS). For example Beta and Preview Updates, Updates for Itanium, Drivers, Dell Hardware, Surface Hardware, SharePoint Updates in Office Channel, 
Language on Demand Feature updates and superseded updates. The scrips send, if configured a list of the decliened updates.

.EXAMPLE 
decline-WSUSUpdatesTypes.ps1 -Preview -Itanium -Superseded -SmtpServer "Mail.domai.tld" -EmailLog

.EXAMPLE
decline-WSUSUpdatesTypes.ps1 -Preview -Itanium -SharePoint 

.PARAMETER Preview
Decline Updates with the phrases -Preview- or -Beta- in the title or the attribute -beta- set

.PARAMETER Itanium
Decline Updates with the phrases -ia64- or -itanium-

.PARAMETER LanguageFeatureOnDemand
Decline Updates with the phrases -LanguageFeatureOnDemand- or -Lang Pack (Language Feature) Feature On Demand- or -LanguageInterfacePack-

.PARAMETER Sharepoint
Decline Updates with the phrases -SharePoint Enterprise Server- or -SharePoint Foundation- or -SharePoint Server- or -FAST Search Server- Some of these are part of the Office Update Channel

.PARAMETER Dell
Decline Updates with the phrases -Dell- for reducing for example the updates in the drivers category, if no Dell Hardware is used

.PARAMETER Surface
Decline Updates with the phrases -Surface- and -Microsoft-

.PARAMETER Drivers
Decline Updates with the Classification -Drivers-

.PARAMETER OfficeWebApp
Decline Updates with the phrases -Excel Web App- or -Office Web App- or -Word Web App- or -PowerPoint Web App-

.PARAMETER Officex86
Decline Updates with the phrases -32-Bit- and one of these -Microsoft Office-, -Microsoft Access-, -Microsoft Excel-, -Microsoft Outlook-, -Microsoft Onenote-, -Microsoft PowerPoint-, -Microsoft Publisher-, -Microsoft Word-

.PARAMETER Officex64
Decline Updates with the phrases -64-Bit- and one of these -Microsoft Office-, -Microsoft Access-, -Microsoft Excel-, -Microsoft Outlook-, -Microsoft Onenote-, -Microsoft PowerPoint-, -Microsoft Publisher-, -Microsoft Word-

.PARAMETER Superseded
Decline Updates with the attribute -IsSuperseded-

.NOTES
Author     : Fabian Niesen
Filename   : decline-WSUSUpdatesTypes.ps1
Requires   : PowerShell Version 3.0
	
Version    : 1.4
History    : 1.4  Add Config file
             1.3  Coments, Header added
             1.2  Fix issues
             1.1  added Mail funtion
             1.0  initial version
                     
.LINK
https://www.infrastrukturhelden.de/microsoft-infrastruktur/wsus/windows-server-update-services-bereinigen.html
#>
[cmdletbinding()]
Param(
	[Parameter(Position=1)]
    [string]$WsusServer = ([system.net.dns]::GetHostByName('localhost')).hostname,
	[Parameter(Position=2)]
    [bool]$UseSSL = $False,
	[Parameter(Position=3)]
    [int]$PortNumber = 8530,
    [Parameter(Position=4)]
    [switch]$Preview,
    [Parameter(Position=5)]
    [switch]$Itanium,
    [Parameter(Position=6)]
    [switch]$LanguageFeatureOnDemand,
    [Parameter(Position=7)]
    [switch]$Sharepoint,
    [Parameter(Position=8)]
    [switch]$Dell,
    [Parameter(Position=9)]
    [switch]$Surface,
    [Parameter(Position=10)]
    [switch]$OfficeWebApp,
    [Parameter(Position=11)]
    [switch]$Drivers,
    [Parameter(Position=12)]
    [switch]$Officex86,
    [Parameter(Position=13)]
    [switch]$Officex64,
    [Parameter(Position=14)]
    [switch]$Superseded,
    [Parameter(Position=15)]
    [switch]$ListNeeded,
    [Parameter(Position=16)]
    [string]$SmtpServer,
    [Parameter(Position=17)]
	[string]$From,
    [Parameter(Position=18)]
	[string]$To,
    [Parameter(Position=19)]
	[string]$Subject = "WSUS Update Report $WsusServer",
    [Parameter(Position=20)]
    [switch]$WhatIf,
    [Parameter(Position=21)]
    [switch]$TLS,
    [Parameter(Position=22)]
    [switch]$SmtpAuth,
    [Parameter(Position=23)]
    [string]$smtppw = "",
    [Parameter(Position=24)]
    [string]$smtpuser = "",
    [Parameter(Position=25)]
	[switch]$EmailLog,
    [Parameter(Position=26)]
    [switch]$TestMail,
    [Parameter(Position=27)]
    [switch]$Default,
    [Parameter(Position=28)]
    [switch]$save,
    [switch]$load
)

cls
$conffile = "./decline-WSUSUpdatesType.clixml"

IF ($save) 
    {  
    IF (Test-Path -Path $conffile)
        {
        Write-Debug "Configfile found, overwrite"
        }
    $WsusServer,$UseSSL,$PortNumber,$Preview,$Itanium,$LanguageFeatureOnDemand,$Sharepoint,$Dell,$Surface,$OfficeWebApp,$Drivers,$Officex86,$Officex64,$Superseded,$ListNeeded,$SmtpServer,$From,$To,$Subject,$WhatIf,$TLS,$SmtpAuth,$smtppw,$smtpuser,$EmailLog | Export-CliXml $conffile -Force -Depth 2
    #Get-Variable | Export-Clixml
    Write-Output "Settings saved to $conffile"
    break
    }
IF ($load)
    {
    IF (Test-Path -Path $conffile)
        {
        Write-Debug "Configfile found, loading"
        Import-CliXml $conffile | Set-Variable 
        }
    }

$TestBody = "<h1>Testmail from $WsusServer</h1><BR>Send over: $SmtpServer"
$Style = "<Style>BODY{font-size:12px;font-family:verdana,sans-serif;color:navy;font-weight:normal;}" + "TABLE{border-width:1px;cellpadding=10;border-style:solid;border-color:navy;border-collapse:collapse;}" + "TH{font-size:12px;border-width:1px;padding:10px;border-style:solid;border-color:navy;}" + "TD{font-size:10px;border-width:1px;padding:10px;border-style:solid;border-color:navy;}</Style>"
$Table = @{Name="Title";Expression={[string]$_.Title}},@{Name="KB Article";Expression={[string]::join(' | ',$_.KnowledgebaseArticles[0])}},@{Name="Classification";Expression={[string]$_.UpdateClassificationTitle}},@{Name="Product Title";Expression={[string]::join(' | ',$_.ProductTitles[0])}},@{Name="MsrcSeverity";Expression={[string]::join(' | ',$_.MsrcSeverity)}},@{Name="CreationDate";Expression={[string]::join(' | ',$_.CreationDate)}},@{Name="Product Family";Expression={[string]::join(' | ',$_.ProductFamilyTitles[0])}},@{Name="Kind of Patch";Expression={[string]::join(' | ',$_.PatchType)}}

IF ($Default) { $Preview = $true; $Itanium = $true ; $LanguageFeatureOnDemand = $true}
	
    Function SendEmailStatus($From, $To, $Subject, $SmtpServer, $BodyAsHtml, $Body)
	{	$SmtpMessage = New-Object System.Net.Mail.MailMessage $From, $To, $Subject, $Body
		$SmtpMessage.IsBodyHTML = $BodyAsHtml
		$SmtpClient = New-Object System.Net.Mail.SmtpClient $SmtpServer 
        IF ($TLS) { $SmtpClient.EnableSsl = $true }
        IF ($SmtpAuth) { $SmtpClient.Credentials = New-Object System.Net.NetworkCredential($smtpuser, $smtppw) }
		$SmtpClient.Send($SmtpMessage)
		If($? -eq $False){Write-Warning "$($Error[0].Exception.Message) | $($Error[0].Exception.GetBaseException().Message)"}
		$SmtpMessage.Dispose()
		Remove-Variable SmtpClient
		Remove-Variable SmtpMessage
	}
$Updates = $null
[reflection.assembly]::LoadWithPartialName("Microsoft.UpdateServices.Administration") | out-null
$WsusServerAdminProxy = [Microsoft.UpdateServices.Administration.AdminProxy]::GetUpdateServer($WsusServer,$UseSSL,$PortNumber);


IF ($WhatIF) { Write-Warning "WhatIF Mode, no changes will be made!!!"}
IF ($Preview -eq $true) 
{
    Write-Output "Declining of Beta and Preview updates selected, starting query."
    $BetaUpdates = $WsusServerAdminProxy.GetUpdates() | ?{-not $_.IsDeclined -and ($_.Title -match �preview|beta� -or -not $_.IsDeclined -and $_.IsBeta -eq $true)}
    Write-Output "Found $($BetaUpdates.count) Preview or Beta Updates to decline"
    If($BetaUpdates) 
    {
      IF (! $WhatIF) {$BetaUpdates | %{$_.Decline()}}
	  $BetaUpdates | Add-Member -MemberType NoteProperty -Name PatchType -value BetaUpdate 
      $Updates = $Updates + $BetaUpdates
        
    }
    Else
    {"No Preview / Beta Updates found that needed declining. Come back next 'Patch Tuesday' and you may have better luck."}
}

IF ($Itanium -eq $true)
{
    Write-Output "Declining of Itanium updates selected, starting query."
    $ItaniumUpdates = $WsusServerAdminProxy.GetUpdates() | ?{-not $_.IsDeclined -and $_.Title -match �ia64|itanium�}
    Write-Output "Found $($ItaniumUpdates.count) Itanium Updates to decline"
    If($ItaniumUpdates) 
    {
      IF (! $WhatIF) {$ItaniumUpdates | %{$_.Decline()}}
      $ItaniumUpdates | Add-Member -MemberType NoteProperty -Name PatchType -value "Itanium"
      $Updates = $Updates + $ItaniumUpdates
    }
    Else
    {"No Itanium Updates found that needed declining. Come back next 'Patch Tuesday' and you may have better luck."}  
}

IF ($LanguageFeatureOnDemand -eq $true)
{
    Write-Output "Declining of Language Feature on Demand selected, starting query."
    $LanguageFeatureOnDemandU = $WsusServerAdminProxy.GetUpdates() | ?{-not $_.IsDeclined -and $_.Title -match �LanguageFeatureOnDemand|Lang Pack (Language Feature) Feature On Demand|LanguageInterfacePack�}
    Write-Output "Found $($LanguageFeatureOnDemandU.count) LanguageFeatureOnDemand to decline"
    If($LanguageFeatureOnDemandU) 
    {
      IF (! $WhatIF) {$LanguageFeatureOnDemandU | %{$_.Decline()}}
      $LanguageFeatureOnDemandU | Add-Member -MemberType NoteProperty -Name PatchType -value "LanguageFeatureOnDemand"
      $Updates = $Updates + $LanguageFeatureOnDemandU
    }
    Else
    {"No LanguageFeatureOnDemand Updates found that needed declining. Come back next 'Patch Tuesday' and you may have better luck."}
}


IF ($Sharepoint -eq $true)
{
    Write-Output "Declining of Sharepoint Updates selected, starting query."
    $SharepointU = $WsusServerAdminProxy.GetUpdates() | ?{-not $_.IsDeclined -and $_.Title -match �SharePoint Enterprise Server|SharePoint Foundation|SharePoint Server|FAST Search Server�}
    Write-Output "Found $($SharepointU.count) Sharepoint Updates to decline"
    If($SharepointU) 
    {
      IF (! $WhatIF) {$SharepointU | %{$_.Decline()}}
      $SharepointU | Add-Member -MemberType NoteProperty -Name PatchType -value "SharePoint"
      $Updates = $Updates + $SharepointU
    }
    Else
    {"No Sharepoint Updates found that needed declining. Come back next 'Patch Tuesday' and you may have better luck."}
}

IF ($Dell -eq $true)
{
    Write-Output "Declining of Dell Updates selected, starting query."
    $DellU = $WsusServerAdminProxy.GetUpdates() | ?{-not $_.IsDeclined -and $_.Title -match �Dell�}
    Write-Output "Found $($DellU.count) Dell Updates to decline"
    If($DellU) 
    {
      IF (! $WhatIF) {$DellU | %{$_.Decline()}}
      $DellU | Add-Member -MemberType NoteProperty -Name PatchType -value "Dell"
      $Updates = $Updates + $DellU
    }
    Else
    {"No Dell Updates found that needed declining. Come back next 'Patch Tuesday' and you may have better luck."}
}

IF ($Surface -eq $true)
{
    Write-Output "Declining of Microsoft Surface updates selected, starting query."
    $SurfaceU = $WsusServerAdminProxy.GetUpdates() | ?{-not $_.IsDeclined -and $_.Title -match �Surface� -and $_.Title -match �Microsoft�}
    Write-Output "Found $($SurfaceU.count) Microsoft Surface updates to decline"
    If($SurfaceU) 
    {
      IF (! $WhatIF) {$SurfaceU | %{$_.Decline()}}
      $SurfaceU | Add-Member -MemberType NoteProperty -Name PatchType -value "Surface"
      $Updates = $Updates + $SurfaceU
    }
    Else
    {"No Surface Updates found that needed declining. Come back next 'Patch Tuesday' and you may have better luck."}
}

IF ($Officex86 -eq $true)
{
    Write-Output "Declining of Office updates for 32 bit selected, starting query."
    $Officex86U = $WsusServerAdminProxy.GetUpdates() | ?{-not $_.IsDeclined -and $_.Title -match �Microsoft Office|Microsoft Access|Microsoft Excel|Microsoft Outlook|Microsoft Onenote|Microsoft PowerPoint|Microsoft Publisher|Microsoft Word� -and $_.Title -match �32-Bit�}
    Write-Output "Found $($Officex86U.count) Microsoft Surface updates to decline"
    If($Officex86U) 
    {
      IF (! $WhatIF) {$Officex86U | %{$_.Decline()}}
      $Officex86U | Add-Member -MemberType NoteProperty -Name PatchType -value "Office x86"
      $Updates = $Updates + $Officex86U
    }
    Else
    {"No Office updates for 32 bit found that needed declining. Come back next 'Patch Tuesday' and you may have better luck."}
}

IF ($Officex64 -eq $true)
{
    Write-Output "Declining of Office updates for 64 bit selected, starting query."
    $Officex64U = $WsusServerAdminProxy.GetUpdates() | ?{-not $_.IsDeclined -and $_.Title -match �Microsoft Office|Microsoft Access|Microsoft Excel|Microsoft Outlook|Microsoft Onenote|Microsoft PowerPoint|Microsoft Publisher|Microsoft Word� -and $_.Title -match �64-Bit�}
    Write-Output "Found $($Officex64U.count) Microsoft Surface updates to decline"
    If($Officex64U) 
    {
      IF (! $WhatIF) {$Officex64U | %{$_.Decline()}}
      $Officex64U | Add-Member -MemberType NoteProperty -Name PatchType -value "Office x64"
      $Updates = $Updates + $Officex64U
    }
    Else
    {"No Office updates for 64 bit found that needed declining. Come back next 'Patch Tuesday' and you may have better luck."}
}

IF ($Drivers -eq $true) 
{
    Write-Output "Declining of Drivers selected, starting query."
    $DriversUpdates = $WsusServerAdminProxy.GetUpdates() | ?{-not $_.IsDeclined -and $_.Classification -match �Drivers�}
    Write-Output "Found $($DriversUpdates.count) Drivers to decline"
    If($DriversUpdates) 
    {
      IF (! $WhatIF) {$DriversUpdates | %{$_.Decline()}}
      $DriversUpdates | Add-Member -MemberType NoteProperty -Name PatchType -value "Driver Update" 
      $Updates = $Updates + $DriversUpdates
        
    }
    Else
    {"No Driver found that needed declining. Come back next 'Patch Tuesday' and you may have better luck."}
}

IF ($OfficeWebApp -eq $true)
{
    Write-Output "Declining of Office WebApp Updates selected, starting query."
    $OfficeWebAppU = $WsusServerAdminProxy.GetUpdates() | ?{-not $_.IsDeclined -and $_.Title -match �Excel Web App|Office Web App|Word Web App|PowerPoint Web App�}
    Write-Output "Found $($OfficeWebAppU.count) Office WebApp Updates to decline"
    If($OfficeWebAppU) 
    {
      IF (! $WhatIF) {$OfficeWebAppU | %{$_.Decline()}}
      $OfficeWebAppU | Add-Member -MemberType NoteProperty -Name PatchType -value "OfficeWebApp"
      $Updates = $Updates + $OfficeWebAppU
    }
    Else
    {"No OfficeWebApp Updates found that needed declining. Come back next 'Patch Tuesday' and you may have better luck."}
}

IF ($Superseded -eq $true )
{
    Write-Output "Declining Superseded Updates selected, starting query."
    $SupersededU = $WsusServerAdminProxy.GetUpdates() | ?{-not $_.IsDeclined -and $_.IsSuperseded -eq $true}
    Write-Output "Found $($SupersededU.count) Superseded Updates to decline"
    If($SupersededU) 
    {
      IF (! $WhatIF) {$SupersededU | %{$_.Decline()}}
      $SupersededU | Add-Member -MemberType NoteProperty -Name PatchType -value "Superseded"
      $Updates = $Updates + $SupersededU
    }
    Else
    {"No IsSuperseded Updates found that needed declining. Come back next 'Patch Tuesday' and you may have better luck."}
}

$Updates | select $Table | sort -Property "KB Article" | ft -AutoSize -Property "Kind of Patch",Title,"KB Article"

IF ($EmailLog -and $Updates.Count -ge 1)
{
    $Body = "<h1>Declined Updates</h1>$($Updates | Select $Table | ConvertTo-HTML -head $Style)"
}
Else
{
    $Body =""
}

IF ($WhatIf) { $Body += "<br><p>WhatIf mode enabled!!</p>" }

IF ($ListNeeded -eq $true)
{
    Write-Output "List needed updates selected, starting query."
    $updatescope = New-Object Microsoft.UpdateServices.Administration.UpdateScope
    $updatescope.ApprovedStates = [Microsoft.UpdateServices.Administration.ApprovedStates]::NotApproved
    $updatescope.IncludedInstallationStates = [Microsoft.UpdateServices.Administration.UpdateInstallationStates]::NotInstalled
    $NeededUpdates = $WsusServerAdminProxy.GetUpdates($updatescope)
    Write-Output "Found $($NeededUpdates.count) needed Updates"
    If($NeededUpdates) 
    {
      #IF (! $WhatIF) {$SupersededU | %{$_.Decline()}}
      Write-Output "Needed Updates:"
      $NeededUpdates | Select $Table | FT -AutoSize 
      $Body = $Body +"<br><h1>Needed Updates</h1>"+$($NeededUpdates | Select $Table | ConvertTo-HTML -head $Style)
    }
    Else
    {"No Needed Updates found to list. Come back next 'Patch Tuesday' and you may have better luck."}
}

If($TestMail){SendEmailStatus -From $From -To $To -Subject $Subject -SmtpServer $SmtpServer -BodyAsHtml $True -Body $TestBody }
If($EmailLog){SendEmailStatus -From $From -To $To -Subject $Subject -SmtpServer $SmtpServer -BodyAsHtml $True -Body $Body}