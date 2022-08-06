Write-Verbose "Check for Admin"
If (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
{   
$arguments = "& '" + $myinvocation.mycommand.definition + "'"
Start-Process powershell -Verb runAs -ArgumentList $arguments
Break
}
If (!(Get-PackageProvider NuGet -ErrorAction SilentlyContinue).count -ge 1 ) { Install-PackageProvider -Name NuGet -Force -Confirm:$false } ELSE { Write-Output "NuGet Provider already configured"}
If (!(get-module PowerShellGet -ErrorAction SilentlyContinue).count -ge 1 ) { Install-Module PowerShellGet -Force -Confirm:$false } ELSE { Write-Output "PowershellGet already installed"}
If (!(get-command Connect-AzAccount -ErrorAction SilentlyContinue).count -ge 1 ) { Install-Module Az -Force -Confirm:$false } ELSE { Write-Output "Az Module already installed"}