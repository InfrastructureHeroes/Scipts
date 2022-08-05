<#
.SYNOPSIS
Download and install the actual version of AzCopy for the executing User
	
.DESCRIPTION
Download and install the actual version of AzCopy for the executing User

.EXAMPLE 
C:\PS> Install-AzCopy.ps1

.EXAMPLE 
C:\PS> Install-AzCopy.ps1 -targetfolder'C:\Program Files'


.PARAMETER 	targetfolder 
Path to install AzCopy. Default is UserProfile

.NOTES
Author     : Fabian Niesen (www.fabian-niesen.de)
Filename   : Install-AzCopy.ps1
Requires   : PowerShell Version 3.0
Version    : 1.0
History    : 1.0   FN  05.08.2022  initial version

.LINK
https://github.com/InfrastructureHeroes/Scipts
#>

Param(
	[Parameter(Mandatory=$false, Position=0, ValueFromPipeline=$true)]
	[String]$targetfolder = $env:USERPROFILE
)

#Internal parameters
$zipfile = $targetfolder + "\AzCopy.zip"
$azfolder =  $targetfolder + "\AzCopy"
#Download AzCopy to Profile
Invoke-WebRequest -Uri "https://aka.ms/downloadazcopy-v10-windows" -OutFile $zipfile -UseBasicParsing

#Expand Archive and remove ZIP
Expand-Archive $zipfile $azfolder -Force
Remove-Item $zipfile -Force
#Move exe from Subfolder, but leave subfolder for Version lookup
Get-ChildItem $($azfolder +"\*\azcopy.exe") | Move-Item -Destination $azfolder -Force
#Set Path for the user
$userenvpath = [System.Environment]::GetEnvironmentVariable("Path", "User")
IF ($userenvpath.contains($azfolder)) { Write-Output "Path already set" } Else { [System.Environment]::SetEnvironmentVariable("PATH", $userenv + ";"+$azfolder , "User") }