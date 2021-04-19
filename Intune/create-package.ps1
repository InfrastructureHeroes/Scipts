<#
.SYNOPSIS
Create Intunewin Files from Sourcefolders

.DESCRIPTION
Create Intunewin Files from Sourcefolders. Install Comands must be located in install.cmd

.EXAMPLE 
create-package.ps1 -workpath "path to Install" -ContentPrepTool "Path to ContentPrepTool Executable file"

.PARAMETER workpath 
Workfolder for Win32 app packaging. Source files must be in subfolder "Source\Application Name". Output will be in "Output"

.PARAMETER ContentPrepTool
Path to ContentPrepTool Executable file

.NOTES
Author     : Fabian Niesen
Filename   : create-package.ps1
Requires   : PowerShell Version 3.0
Version    : 1.0
History    : 1.0.0   FN  19.04.2021  initial version

.LINK
https://github.com/FabianNiesen/Infrastrukturhelden.de
#>

Param(
	[Parameter(Mandatory=$false, Position=0, ValueFromPipeline=$False)]
	[String]$workpath = "C:\Users\fabian_niesen\OneDrive - Dell Technologies\Documents\_Install",
	[Parameter(Mandatory=$false, Position=0, ValueFromPipeline=$False)]
	[String]$ContentPrepTool ="C:\Users\fabian_niesen\OneDrive - Dell Technologies\Documents\GitHub\Microsoft-Win32-Content-Prep-Tool\IntuneWinAppUtil.exe"
)
$date = get-date -format yyyyMMdd-HHmm
Write-Progress -activity "Preparing Workdir: $workdir" -Status "starting" -PercentComplete "0" -Id 1
[int]$i = "0"
$Sources = (Get-ChildItem -Path $($workpath+"\Source")).Name 
foreach ($Source in $Sources)
{
$i++
Write-Progress -activity "Processing Sources" -Status "$($Source)" -PercentComplete (($i / $Sources.count)*100) -Id 1
Write-Verbose $Source
$c = $workpath+"\Source\"+$Source
$s = $workpath+"\Source\"+$Source+"\install.cmd"
$o = $workpath+"\Output\"+$date+"\"+$Source
Write-Verbose "Starte ContentPrep"
& $ContentPrepTool -c $c -s $s -o $o -q
Write-Verbose "ContentPrep abgeschlossen"
}
