<#
.SYNOPSIS
    Utilize PSGetSid by Mark Russinovich (Sysinternals) to gather the Windows SID from all online Computer within the Active Directory.
.DESCRIPTION
    Utilize PSGetSid by Mark Russinovich (Sysinternals) to gather the Windows SID from all online Computer within the Active Directory. It also gather some Additional information from the Active Directory.
    Download and extract PSGetSid from PSTools: https://download.sysinternals.com/files/PSTools.zip
    For more details about duplicated SID check Marks article: https://learn.microsoft.com/en-us/archive/blogs/markrussinovich/the-machine-sid-duplication-myth-and-why-sysprep-matters
.EXAMPLE 
C:\PS> Get-WindowsSid.ps1

.NOTES
Author     : Fabian Niesen (www.fabian-niesen.de)
Filename   : Get-WindowsSid.ps1
Requires   : PowerShell Version 3.0
Version    : 1.0
History    : 1.0   FN  24.09.2022  first official

.LINK
https://github.com/InfrastructureHeroes/Scipts
https://www.infrastructureheroes.org/microsoft-infrastructure/microsoft-windows/the-windows-sid-and-an-old-problem/
https://www.infrastrukturhelden.de/microsoft-infrastruktur/microsoft-windows/die-windows-sid-und-ein-altes-problem/
#>

Param(
[String]$PSGetSid = ".\PsGetsid64.exe",
[switch]$CSV
)

#ToDo: Test for local PsGetsid64.exe, ask for Path or Download
#ToDo: Add Parameter for CSV Export
#ToDo: Test for PSGetSid exists
$ErrorActionPreference = "SilentlyContinue"
Set-Location $PSScriptRoot
$ScriptName = $myInvocation.MyCommand.Name
$ScriptName = $ScriptName.Substring(0, $scriptName.Length - 4)
$LogName = (Get-Date -UFormat "%Y%m%d-%H%M") + "-" + $scriptName + "_" + $ENV:COMPUTERNAME +".log"
Start-Transcript -Path "$PSScriptRoot\$LogName" -Append

try {
        Get-ItemProperty -Path "REGISTRY::HKEY_CURRENT_USER\Software\Sysinternals\PsGetSid" -ErrorAction Stop | Select-Object -ExpandProperty "EulaAccepted" -ErrorAction Stop | Out-Null
    }
    catch {
    Write-Verbose "no EULA"
    & $PSGetSid
    $accepteula = Read-Host "Do you Accept the EULA? (Y/N)"
    IF ( $accepteula -match "y" -or $accepteula -match "z")
    { & $PSGetSid -accepteula }
    ELSE { Break } 
    }
$Computers = Get-ADComputer -Filter "Enabled -eq 'true'" -Properties name,LastLogonDate,OperatingSystem,OperatingSystemVersion,whenChanged,DNSHostName | Sort-Object | Select-Object name,LastLogonDate,OperatingSystem,OperatingSystemVersion,whenChanged,DNSHostName
$Computers | Add-Member -MemberType NoteProperty -Name 'SID' -Value $null
$Computers | Add-Member -MemberType NoteProperty -Name 'Online' -Value $null
$SIDs = @()
$SIDs | Add-Member -MemberType NoteProperty -Name 'Online' -Value $null
$SIDs | Add-Member -MemberType NoteProperty -Name 'SID' -Value $null
Write-Progress -activity "Processing PSsid" -Status "starting" -PercentComplete "0" -Id 1
[int]$i = 0
[int]$j = $($Computers).count
ForEach ($Computer in $Computers)
{
    Write-Progress -activity "Processing PSsid - $i of $j" -Status "$($Computer.name)" -PercentComplete (($i / $j *100)) -Id 1 -ErrorAction SilentlyContinue
    $i++
    [bool]$Computer.Online = [bool]$(Test-Connection $($Computer.DNSHostName) -Count 3 -ErrorAction SilentlyContinue)
    IF ( $($Computer.Online) -eq $true)
    { 
        Write-Verbose "$($Computer.DNSHostName) - Starte PSSID"
        $pssid =  (& $PSGetSid \\$($Computer.name) -nobanner) | Select-String -Pattern "S-1-5-21-"
        $Computer.SID = $pssid
    } ELSEIF ( $($Computer.Online) -eq $false) {
        Write-Verbose "$($Computer.DNSHostName) - System Offline"
    } Else { Write-host "WTF $($Computer.DNSHostName)" }
    Write-Verbose "Value: $Computer"
    $SIDs += $Computer
}
$SIDs | Format-Table -Property name,Online,SID,LastLogonDate,OperatingSystem,OperatingSystemVersion,whenChanged -AutoSize
IF ( $CSV) 
{
    $csvpath = "$PSScriptRoot\"+(Get-Date -UFormat "%Y%m%d-%H%M")+"-SID.csv"
    Write-Output "CSV file generated - $csvpath"
    $SIDs | Export-Csv -Path $csvpath -Force -Delimiter ";" -NoTypeInformation
}