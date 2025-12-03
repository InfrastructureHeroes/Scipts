<#
.SYNOPSIS
Small Power Shell script to send files from a directory via mail.

.DESCRIPTION
Small Power Shell script to send files from a directory via mail and move them into an archive. Each mail contain only a single file. There is a filter for the file type.
This script is designed to be executed as scheduled task.

.EXAMPLE 
send-files.ps1 -sourcepath "C:\User\Fabian\Scaned-PDF" -archivepath "$sourcepath\Archive" -filetype "*.pdf" -SmtpServer mail.infrastrukturhelden.de -From Script@infrastrukturhelden.de -To john.doe@infrastrukturhelden.de

.PARAMETER sourcepath
Path where to look for files. Subfolders will not be used!

.PARAMETER archivepath
Path where file will moved after sending

.PARAMETER filetype
Filter for file types

.PARAMETER SmtpServer
SmtpServer witch is uses to send the mail

.PARAMETER From
Mail From

.PARAMETER To
Mail To

.PARAMETER Subject
Subject of the Mail

.PARAMETER SmtpAuth
Switch if SMTP needs authentication

.PARAMETER smtppw
Password for SMTP User. Only need with SmtpAuth.

.PARAMETER smtpuser
SMTP Username. Only need with SmtpAuth.

.PARAMETER SmtpPort
Portnumber for SMTP if non Standard

.PARAMETER Body
Mail body, no HTML.

.NOTES
Author     :    Fabian Niesen
Filename   :    send-files.ps1
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
Version    :    1.3
History    :    
                1.3 FN  03.12.2025 Change License to MIT, housekeeping Header
                1.2 FN 25.10.2025 Change License to GPLv3
                1.1 FN 27.08.2022 Add SMTP Port (for #4)
                1.0 FN initial version

.LINK
https://www.infrastrukturhelden.de/?p=13527
#>
[cmdletbinding()]
Param(
    [Parameter(Position=1)]
    [string]$sourcepath,
    [Parameter(Position=2)]
    [string]$archivepath,
    [Parameter(Position=3)]
    [string]$filetype="*.pdf",
    [Parameter(Position=10)]
    [string]$SmtpServer,
    [Parameter(Position=17)]
	[string]$From,
    [Parameter(Position=18)]
	[string]$To,
    [Parameter(Position=19)]
	[string]$Subject = "PDF Report: ",
    [Parameter(Position=22)]
    [switch]$SmtpAuth,
    [Parameter(Position=23)]
    [string]$smtppw,
    [Parameter(Position=24)]
    [string]$smtpuser,
    [Parameter(Position=25)]
    [int]$SmtpPort,
    [Parameter(Position=28)]
    [string]$Body = "Please see attachment."
)
$schriptversion = "1.3"
Write-Output "send-files.ps1 Version $scriptversion "
IF ($SmtpAuth) {
    Write-Debug "Using SMTP Auth"
    $password = ConvertTo-SecureString $smtppw -AsPlainText -Force
    $cred = New-Object System.Management.Automation.PSCredential ($smtpuser, $password)
    }
IF ($SmtpPort) { $SmtpClient.Port = $SmtpPort }
$sources = Get-ChildItem $sourcepath -Filter $filetype -Depth 0

ForEach ( $source in $sources) 
{
$file = $source.FullName
$SubjectM = $Subject + $source.Name
Write-Debug $file 
Write-Debug "Send-MailMessage"
IF ($SmtpAuth) { Send-MailMessage  -To $To -From $From -Subject $SubjectM -SmtpServer $SmtpServer -Attachments $file -Credential $cred -UseSsl }
ELSE { Send-MailMessage  -To $To -From $From -Subject $SubjectM -SmtpServer $SmtpServer -Attachments $file -UseSsl }
Write-Debug "Move File"
Move-Item -Path $file -Destination $archivepath
}