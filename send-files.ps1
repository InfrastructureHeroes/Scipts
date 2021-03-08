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

.PARAMETER Body
Mail body, no HTML.

.NOTES
Author     : Fabian Niesen
Filename   : 
Requires   : PowerShell Version 3.0
	
Version    : 1.0
History    : 1.0  initial version
                     
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
    [Parameter(Position=28)]
    [string]$Body = "Please see attachment."
)

IF ($SmtpAuth) {
  Write-Debug "Using SMTP Auth"
  $password = ConvertTo-SecureString $smtppw -AsPlainText -Force
  $cred = New-Object System.Management.Automation.PSCredential ($smtpuser, $password)
  }

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