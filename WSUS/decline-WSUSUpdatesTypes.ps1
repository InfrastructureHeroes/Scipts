#requires -version 5.1

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
  Author     :  Fabian Niesen
  Filename   :  decline-WSUSUpdatesTypes.ps1
  Requires   :  PowerShell Version 5.1
  License    :  The MIT License (MIT)
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
  Disclaimer :  This script is provided "as is" without warranty. Use at your own risk.
                The author assumes no responsibility for any damage or data loss caused by this script.
                Test thoroughly in a controlled environment before deploying to production.
  Version    :  1.8
  History    :  1.8 FN 03.12.2025  change to MIT License, housekeeping Header, add Edge Beta / Dev channel to Preview filter
                1.7  Add "Dev" to filter for -Preview (#3), Replace powershell alias with full commands
                1.6  Add WSUS internal Cleanup Trigger
                1.5  Add ARM64, LTSB2015, LTSB2016, LTSC2019 to script
                1.4  Add Config file
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
    [switch]$ARM64,
    [Parameter(Position=7)]
    [switch]$Win10LTSB2015,
    [Parameter(Position=8)]
    [switch]$Win10LTSB2016,
    [Parameter(Position=9)]
    [switch]$Win10LTSC2019,
        [Parameter(Position=10)]
    [switch]$LanguageFeatureOnDemand,
    [Parameter(Position=11)]
    [switch]$Sharepoint,
    [Parameter(Position=12)]
    [switch]$Dell,
    [Parameter(Position=13)]
    [switch]$Surface,
    [Parameter(Position=14)]
    [switch]$OfficeWebApp,
    [Parameter(Position=15)]
    [switch]$Drivers,
    [Parameter(Position=16)]
    [switch]$Officex86,
    [Parameter(Position=17)]
    [switch]$Officex64,
    [Parameter(Position=18)]
    [switch]$Superseded,
    [Parameter(Position=19)]
    [switch]$ListNeeded,
    [Parameter(Position=20)]
    [string]$SmtpServer,
    [Parameter(Position=21)]
	[string]$From,
    [Parameter(Position=22)]
	[string]$To,
    [Parameter(Position=23)]
	[string]$Subject = "WSUS Update Report $WsusServer",
    [Parameter(Position=24)]
    [switch]$WhatIf,
    [Parameter(Position=25)]
    [switch]$TLS,
    [Parameter(Position=26)]
    [switch]$SmtpAuth,
    [Parameter(Position=27)]
    [string]$smtppw = "",
    [Parameter(Position=28)]
    [string]$smtpuser = "",
    [Parameter(Position=29)]
	[switch]$EmailLog,
    [Parameter(Position=30)]
    [switch]$TestMail,
    [Parameter(Position=31)]
    [switch]$Default,
    [switch]$CleanupObsoleteComputers,
    [switch]$ExpiredUpdatesDeclined,
    [switch]$save,
    [switch]$load
)

$scriptversion = "1.8"
Write-Output "Starting decline-WSUSUpdatesTypes.ps1 version $scriptversion"
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
    $BetaUpdates = $WsusServerAdminProxy.GetUpdates() | Where-Object{-not $_.IsDeclined -and ($_.Title -match "preview|edge-beta|edge-dev|beta channel|prerelease" -or $_.IsBeta -eq $true)}
    Write-Output "Found $($BetaUpdates.count) Preview or Beta Updates to decline"
    If($BetaUpdates) 
    {
      IF (! $WhatIF) {$BetaUpdates | ForEach-Object{$_.Decline()}}
	  $BetaUpdates | Add-Member -MemberType NoteProperty -Name PatchType -value BetaUpdate 
      $Updates = $Updates + $BetaUpdates
        
    }
    Else
    {"No Preview / Beta Updates found that needed declining. Come back next 'Patch Tuesday' and you may have better luck."}
}

IF ($Itanium -eq $true)
{
    Write-Output "Declining of Itanium updates selected, starting query."
    $ItaniumUpdates = $WsusServerAdminProxy.GetUpdates() | Where-Object{-not $_.IsDeclined -and $_.Title -match "ia64|itanium"}
    Write-Output "Found $($ItaniumUpdates.count) Itanium Updates to decline"
    If($ItaniumUpdates) 
    {
      IF (! $WhatIF) {$ItaniumUpdates | ForEach-Object{$_.Decline()}}
      $ItaniumUpdates | Add-Member -MemberType NoteProperty -Name PatchType -value "Itanium"
      $Updates = $Updates + $ItaniumUpdates
    }
    Else
    {"No Itanium Updates found that needed declining. Come back next 'Patch Tuesday' and you may have better luck."}  
}

IF ($ARM64 -eq $true)
{
    Write-Output "Declining of ARM64 updates selected, starting query."
    $ARM64Updates = $WsusServerAdminProxy.GetUpdates() | Where-Object{-not $_.IsDeclined -and $_.Title -match "ARM64"}
    Write-Output "Found $($ARM64Updates.count) ARM64 Updates to decline"
    If($ARM64Updates) 
    {
      IF (! $WhatIF) {$ARM64Updates | ForEach-Object{$_.Decline()}}
      $ARM64Updates | Add-Member -MemberType NoteProperty -Name PatchType -value "ARM64"
      $Updates = $Updates + $ARM64Updates
    }
    Else
    {"No ARM64 Updates found that needed declining. Come back next 'Patch Tuesday' and you may have better luck."}  
}

IF ($Win10LTSB2015 -eq $true)
{
    Write-Output "Declining of Windows 10 Version 1507 (aka. LTSB 2015) updates selected, starting query."
    $Win10LTSB2015Updates = $WsusServerAdminProxy.GetUpdates() | Where-Object{-not $_.IsDeclined -and $_.Title -match "Windows 10 Version 1507"}
    Write-Output "Found $($Win10LTSB2015Updates.count) Windows 10 Version 1507 Updates to decline"
    If($Win10LTSB2015Updates) 
    {
      IF (! $WhatIF) {$Win10LTSB2015Updates | ForEach-Object{$_.Decline()}}
      $Win10LTSB2015Updates | Add-Member -MemberType NoteProperty -Name PatchType -value "Win10LTSB2015"
      $Updates = $Updates + $Win10LTSB2015Updates
    }
    Else
    {"No Windows 10 Version 1507 (aka. LTSB 2015) Updates found that needed declining. Come back next 'Patch Tuesday' and you may have better luck."}  
}

IF ($Win10LTSB2016 -eq $true)
{
    Write-Output "Declining of Windows 10 Version 1607 (aka. LTSB 2016) updates selected, starting query."
    $Win10LTSB2016Updates = $WsusServerAdminProxy.GetUpdates() | Where-Object{-not $_.IsDeclined -and $_.Title -match "Windows 10 Version 1607"}
    Write-Output "Found $($Win10LTSB2016Updates.count) Windows 10 Version 1607 Updates to decline"
    If($Win10LTSB2016Updates) 
    {
      IF (! $WhatIF) {$Win10LTSB2016Updates | ForEach-Object{$_.Decline()}}
      $Win10LTSB2016Updates | Add-Member -MemberType NoteProperty -Name PatchType -value "Win10LTSB2016"
      $Updates = $Updates + $Win10LTSB2016Updates
    }
    Else
    {"No Windows 10 Version 1607 (aka. LTSB 2016) Updates found that needed declining. Come back next 'Patch Tuesday' and you may have better luck."}  
}

IF ($Win10LTSC2019 -eq $true)
{
    Write-Output "Declining of Windows 10 Version 1809 (aka. LTSC 2019) updates selected, starting query."
    $Win10LTSC2019Updates = $WsusServerAdminProxy.GetUpdates() | Where-Object{-not $_.IsDeclined -and $_.Title -match "Windows 10 Version 1809"}
    Write-Output "Found $($Win10LTSC2019Updates.count) Windows 10 Version 1809 Updates to decline"
    If($Win10LTSC2019Updates) 
    {
      IF (! $WhatIF) {$Win10LTSC2019Updates | ForEach-Object{$_.Decline()}}
      $Win10LTSC2019Updates | Add-Member -MemberType NoteProperty -Name PatchType -value "Win10LTSC2019"
      $Updates = $Updates + $Win10LTSC2019Updates
    }
    Else
    {"No Windows 10 Version 1809 (aka. LTSC 2019) Updates found that needed declining. Come back next 'Patch Tuesday' and you may have better luck."}  
}

IF ($LanguageFeatureOnDemand -eq $true)
{
    Write-Output "Declining of Language Feature on Demand selected, starting query."
    $LanguageFeatureOnDemandU = $WsusServerAdminProxy.GetUpdates() | Where-Object{-not $_.IsDeclined -and $_.Title -match "LanguageFeatureOnDemand|Lang Pack (Language Feature) Feature On Demand|LanguageInterfacePack"}
    Write-Output "Found $($LanguageFeatureOnDemandU.count) LanguageFeatureOnDemand to decline"
    If($LanguageFeatureOnDemandU) 
    {
      IF (! $WhatIF) {$LanguageFeatureOnDemandU | ForEach-Object{$_.Decline()}}
      $LanguageFeatureOnDemandU | Add-Member -MemberType NoteProperty -Name PatchType -value "LanguageFeatureOnDemand"
      $Updates = $Updates + $LanguageFeatureOnDemandU
    }
    Else
    {"No LanguageFeatureOnDemand Updates found that needed declining. Come back next 'Patch Tuesday' and you may have better luck."}
}


IF ($Sharepoint -eq $true)
{
    Write-Output "Declining of Sharepoint Updates selected, starting query."
    $SharepointU = $WsusServerAdminProxy.GetUpdates() | Where-Object{-not $_.IsDeclined -and $_.Title -match "SharePoint Enterprise Server|SharePoint Foundation|SharePoint Server|FAST Search Server"}
    Write-Output "Found $($SharepointU.count) Sharepoint Updates to decline"
    If($SharepointU) 
    {
      IF (! $WhatIF) {$SharepointU | ForEach-Object{$_.Decline()}}
      $SharepointU | Add-Member -MemberType NoteProperty -Name PatchType -value "SharePoint"
      $Updates = $Updates + $SharepointU
    }
    Else
    {"No Sharepoint Updates found that needed declining. Come back next 'Patch Tuesday' and you may have better luck."}
}

IF ($Dell -eq $true)
{
    Write-Output "Declining of Dell Updates selected, starting query."
    $DellU = $WsusServerAdminProxy.GetUpdates() | Where-Object{-not $_.IsDeclined -and $_.Title -match "Dell"}
    Write-Output "Found $($DellU.count) Dell Updates to decline"
    If($DellU) 
    {
      IF (! $WhatIF) {$DellU | ForEach-Object{$_.Decline()}}
      $DellU | Add-Member -MemberType NoteProperty -Name PatchType -value "Dell"
      $Updates = $Updates + $DellU
    }
    Else
    {"No Dell Updates found that needed declining. Come back next 'Patch Tuesday' and you may have better luck."}
}

IF ($Surface -eq $true)
{
    Write-Output "Declining of Microsoft Surface updates selected, starting query."
    $SurfaceU = $WsusServerAdminProxy.GetUpdates() | Where-Object{-not $_.IsDeclined -and $_.Title -match "Surface" -and $_.Title -match "Microsoft"}
    Write-Output "Found $($SurfaceU.count) Microsoft Surface updates to decline"
    If($SurfaceU) 
    {
      IF (! $WhatIF) {$SurfaceU | ForEach-Object{$_.Decline()}}
      $SurfaceU | Add-Member -MemberType NoteProperty -Name PatchType -value "Surface"
      $Updates = $Updates + $SurfaceU
    }
    Else
    {"No Surface Updates found that needed declining. Come back next 'Patch Tuesday' and you may have better luck."}
}

IF ($Officex86 -eq $true)
{
    Write-Output "Declining of Office updates for 32 bit selected, starting query."
    $Officex86U = $WsusServerAdminProxy.GetUpdates() | Where-Object{-not $_.IsDeclined -and $_.Title -match "Microsoft Office|Microsoft Access|Microsoft Excel|Microsoft Outlook|Microsoft Onenote|Microsoft PowerPoint|Microsoft Publisher|Microsoft Word" -and $_.Title -match "32-Bit"}
    Write-Output "Found $($Officex86U.count) Microsoft Surface updates to decline"
    If($Officex86U) 
    {
      IF (! $WhatIF) {$Officex86U | ForEach-Object{$_.Decline()}}
      $Officex86U | Add-Member -MemberType NoteProperty -Name PatchType -value "Office x86"
      $Updates = $Updates + $Officex86U
    }
    Else
    {"No Office updates for 32 bit found that needed declining. Come back next 'Patch Tuesday' and you may have better luck."}
}

IF ($Officex64 -eq $true)
{
    Write-Output "Declining of Office updates for 64 bit selected, starting query."
    $Officex64U = $WsusServerAdminProxy.GetUpdates() | Where-Object{-not $_.IsDeclined -and $_.Title -match "Microsoft Office|Microsoft Access|Microsoft Excel|Microsoft Outlook|Microsoft Onenote|Microsoft PowerPoint|Microsoft Publisher|Microsoft Word" -and $_.Title -match "64-Bit"}
    Write-Output "Found $($Officex64U.count) Microsoft Surface updates to decline"
    If($Officex64U) 
    {
      IF (! $WhatIF) {$Officex64U | ForEach-Object{$_.Decline()}}
      $Officex64U | Add-Member -MemberType NoteProperty -Name PatchType -value "Office x64"
      $Updates = $Updates + $Officex64U
    }
    Else
    {"No Office updates for 64 bit found that needed declining. Come back next 'Patch Tuesday' and you may have better luck."}
}

IF ($Drivers -eq $true) 
{
    Write-Output "Declining of Drivers selected, starting query."
    $DriversUpdates = $WsusServerAdminProxy.GetUpdates() | Where-Object{-not $_.IsDeclined -and $_.Classification -match "Drivers"}
    Write-Output "Found $($DriversUpdates.count) Drivers to decline"
    If($DriversUpdates) 
    {
      IF (! $WhatIF) {$DriversUpdates | ForEach-Object{$_.Decline()}}
      $DriversUpdates | Add-Member -MemberType NoteProperty -Name PatchType -value "Driver Update" 
      $Updates = $Updates + $DriversUpdates
        
    }
    Else
    {"No Driver found that needed declining. Come back next 'Patch Tuesday' and you may have better luck."}
}

IF ($OfficeWebApp -eq $true)
{
    Write-Output "Declining of Office WebApp Updates selected, starting query."
    $OfficeWebAppU = $WsusServerAdminProxy.GetUpdates() | Where-Object{-not $_.IsDeclined -and $_.Title -match "Excel Web App|Office Web App|Word Web App|PowerPoint Web App"}
    Write-Output "Found $($OfficeWebAppU.count) Office WebApp Updates to decline"
    If($OfficeWebAppU) 
    {
      IF (! $WhatIF) {$OfficeWebAppU | ForEach-Object{$_.Decline()}}
      $OfficeWebAppU | Add-Member -MemberType NoteProperty -Name PatchType -value "OfficeWebApp"
      $Updates = $Updates + $OfficeWebAppU
    }
    Else
    {"No OfficeWebApp Updates found that needed declining. Come back next 'Patch Tuesday' and you may have better luck."}
}

IF ($Superseded -eq $true )
{
    Write-Output "Declining Superseded Updates selected, starting query."
    $SupersededU = $WsusServerAdminProxy.GetUpdates() | Where-Object{-not $_.IsDeclined -and $_.IsSuperseded -eq $true}
    Write-Output "Found $($SupersededU.count) Superseded Updates to decline"
    If($SupersededU) 
    {
      IF (! $WhatIF) {$SupersededU | ForEach-Object{$_.Decline()}}
      $SupersededU | Add-Member -MemberType NoteProperty -Name PatchType -value "Superseded"
      $Updates = $Updates + $SupersededU
    }
    Else
    {"No IsSuperseded Updates found that needed declining. Come back next 'Patch Tuesday' and you may have better luck."}
}

IF ($CleanupObsoleteComputers) #Add other Cleanscopes => Invoke-WsusServerCleanup Seit WSUS2012
{
  #Add path for WSUS API Admin DLL
  add-Type -Path "C:\Program Files\Update Services\API\Microsoft.UpdateServices.Administration.dll"
  $CleanupScope = New-Object Microsoft.UpdateServices.Administration.CleanupScope($supersededUpdates,$expiredUpdates,$obsoleteUpdates,$compressUpdates,$obsoleteComputers,$unneededContentFiles)
  $CleanupTask = $WsusServerAdminProxy.GetCleanupManager()
  $CleanupResult = $CleanupTASK.PerformCleanup($CleanupScope)
  IF ($CleanupObsoleteComputers) 
  { 
    $CleanupObsoleteComputersU = $CleanupResult.ObsoleteComputersDeleted | Add-Member -MemberType NoteProperty -Name PatchType -value "ObsolateComputer"
    $Updates = $Updates + $CleanupObsoleteComputersU 
  }
  IF ($ExpiredUpdatesDeclined) 
  { 
    $ExpiredUpdatesDeclinedU = $CleanupResult.ExpiredUpdatesDeclined | Add-Member -MemberType NoteProperty -Name PatchType -value "ExpiredUpdatesDeclined"
    $Updates = $Updates + $ExpiredUpdatesDeclinedU 
  }
}

$Updates | Select-Object $Table | Sort-Object -Property "KB Article" | Format-Table -AutoSize -Property "Kind of Patch",Title,"KB Article"

IF ($EmailLog -and $Updates.Count -ge 1)
{
    $Body = "<h1>Declined Updates</h1>$($Updates | Select-Object $Table | ConvertTo-HTML -head $Style)"
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
      #IF (! $WhatIF) {$SupersededU | ForEach-Object{$_.Decline()}}
      Write-Output "Needed Updates:"
      $NeededUpdates | Select-Object $Table | Format-Table -AutoSize 
      $Body = $Body +"<br><h1>Needed Updates</h1>"+$($NeededUpdates | Select-Object $Table | ConvertTo-HTML -head $Style)
    }
    Else
    {"No Needed Updates found to list. Come back next 'Patch Tuesday' and you may have better luck."}
}

If($TestMail){SendEmailStatus -From $From -To $To -Subject $Subject -SmtpServer $SmtpServer -BodyAsHtml $True -Body $TestBody }
If($EmailLog){SendEmailStatus -From $From -To $To -Subject $Subject -SmtpServer $SmtpServer -BodyAsHtml $True -Body $Body}
