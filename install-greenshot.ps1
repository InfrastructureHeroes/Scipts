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
Author     :    Fabian Niesen (www.fabian-niesen.de)
Filename   :    install-greenshot.ps1
Requires   :    PowerShell Version 3.0
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
Version    :    1.1
History    :    1.1   FN  03.12.2025 Change License to MIT, housekeeping Header
                1.0   FN  08/07/2019  initial version

.LINK
https://www.infrastrukturhelden.de
#>
Expand-Archive -Force C:\Programme\Greenshot\Greenshot-NO-INSTALLER-1.2.10.6-RELEASE.zip C:\Programme\Greenshot
Remove-Item C:\Programme\Greenshot\Greenshot-NO-INSTALLER-1.2.10.6-RELEASE.zip
$WshShell = New-Object -comObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut("C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Greenshot.lnk")
$Shortcut.TargetPath = "C:\Programme\Greenshot\Greenshot.exe"
$Shortcut.Save() 