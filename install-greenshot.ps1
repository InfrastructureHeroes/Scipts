<#
.SYNOPSIS
Install ZIP-Version of GreenShot and create StartMenu entry
	
.DESCRIPTION
Install ZIP-Version of GreenShot and create StartMenu entry. This can be used to avoid the open Webpage in the Installer. 
The installer also open the Website if it is used with /Verysilent.
This Skript was created for Unattened installation with MDT.

.EXAMPLE 
C:\PS> install-greenshot.ps1

.NOTES
Author     : Fabian Niesen (www.fabian-niesen.de)
Filename   : install-greenshot
Requires   : PowerShell Version 3.0
Version    : 1.0
History    : 1.0.0   FN  08/07/2019  initial version

.LINK
https://www.infrastrukturhelden.de
#>
Expand-Archive -Force C:\Programme\Greenshot\Greenshot-NO-INSTALLER-1.2.10.6-RELEASE.zip C:\Programme\Greenshot
Remove-Item C:\Programme\Greenshot\Greenshot-NO-INSTALLER-1.2.10.6-RELEASE.zip
$WshShell = New-Object -comObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut("C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Greenshot.lnk")
$Shortcut.TargetPath = "C:\Programme\Greenshot\Greenshot.exe"
$Shortcut.Save() 