Write-Verbose "Check for Admin"
If (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
{   
$arguments = "& '" + $myinvocation.mycommand.definition + "'"
Start-Process powershell -Verb runAs -ArgumentList $arguments
Break
}
$ErrorActionPreference = "Stop"

If (-not (Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue))
{
    try { Install-PackageProvider -Name NuGet -Force -Confirm:$false | Out-Null }
    catch { Throw "Could not install the NuGet package provider: $($_.Exception.Message)" }
}
ELSE { Write-Output "NuGet Provider already configured"}

If (-not (Get-Module -ListAvailable -Name PowerShellGet))
{
    try { Install-Module PowerShellGet -Force -Confirm:$false }
    catch { Throw "Could not install the PowerShellGet module: $($_.Exception.Message)" }
}
ELSE { Write-Output "PowershellGet already installed"}

If (-not (Get-Command Connect-AzAccount -ErrorAction SilentlyContinue))
{
    try { Install-Module Az -Force -Confirm:$false }
    catch { Throw "Could not install the Az module: $($_.Exception.Message)" }
}
ELSE { Write-Output "Az Module already installed"}
