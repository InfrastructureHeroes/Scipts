#requires -version 4.0
#Requires -RunAsAdministrator
<#
	.SYNOPSIS
		Check local EventLog for signes of issues with Local GPO and fixed them if needed.
	.DESCRIPTION
		Check local EventLog for signes of issues with Local GPO and fixed them if needed. Malformed local GPO prevent GPO processing. This mean changes in GPOs will not be processed by this client. The script needs to be run with Administrative permissions.
	.EXAMPLE  
        .\configure-AD.ps1 -XMLfile .\securead.xml

    .PARAMETER XMLfile
        Path to XML config file

	.NOTES
		Author     :    Fabian Niesen
		Filename   :    configure-AD.ps1
		Requires   :    PowerShell Version 4.0
		
		Version    :    0.3
		History    :    0.3 23.12.2022 FN Some Cleanup and Housekeeping
                    0.2 08.03.2021 FN Found in personal archive and published to GitHub
                    0.1 FN 2016 Initial version.
    .LINK
        https://github.com/InfrastructureHeroes/Scipts/blob/master/GPO/Check-LocalGroupPolicy.ps1
#>
[cmdletbinding()]
Param(
[Parameter(Mandatory=$false, Position=2, ValueFromPipeline=$False)]
[bool]$needfix = $false,
[Parameter(Mandatory=$false, Position=1, ValueFromPipeline=$False)]
$logpath = "C:\Windows\System32\LogFiles\"
)
$ScriptName = $myInvocation.MyCommand.Name
$ScriptName = $ScriptName.Substring(0, $ScriptName.Length - 4)
$LogName = $ScriptName + "_" + $env:computername + "_" + (Get-Date -UFormat "%Y%m%d") + ".log"
$logfile = $logpath + $LogName
"$(get-date -format yyyyMMdd-HHmm) Starting $ScriptName" | Out-File $logfile -Append 
# Function to start a CLI application and return the exit code - This could maybe also be done with Invoke-GPUpdate today, but I have no malformed device to test.
# Based upon https://powersheller.wordpress.com/2011/03/29/powershell-re-creating-the-local-group-policy-database-file/
Function Start-CliApplication { 
    param ( [string]$application, [string]$arguments )
    # Build Startinfo and set options according to parameters
    $startInfo = new-object System.Diagnostics.ProcessStartInfo 
    $startInfo.FileName = $application
    $startInfo.Arguments = $arguments
    $startInfo.WindowStyle = "Hidden"
    $startInfo.CreateNoWindow = $true
    $startInfo.UseShellExecute = $false  
    # Start the process
    $process = [System.Diagnostics.Process]::Start($startinfo)
  
    # Wait until the process finished
    Do {
        If( -not $process.HasExited ) {
            $process.Refresh()
        }
    } While( -not $process.WaitForExit(1000) )
     
    # Output the exitcode
    Write-Output $process.exitcode
}

"$(get-date -format yyyyMMdd-HHmm) Processing Eventlog" | Out-File $logfile -Append 

$eventGpoProcessingFailed  = Get-EventLog System -Newest 500 | where { $_.eventID -eq "1096"  }

IF ( $eventGpoProcessingFailed -ne $null)
{
"$(get-date -format yyyyMMdd-HHmm) Found EventID 1096"| Out-File $logfile -Append 
  $FilePath = $($eventGpoProcessingFailed[0] | select -ExpandProperty ReplacementStrings)[8]
"$(get-date -format yyyyMMdd-HHmm) Find corupted local GPO: $FilePath" | Out-File $logfile -Append 
"$(get-date -format yyyyMMdd-HHmm) Set NeedFix"| Out-File $logfile -Append 
  $needfix = $true
}

IF ( $needfix -eq $true)
{
      "$(get-date -format yyyyMMdd-HHmm) Fix required, Try to delete File: $FilePath"| Out-File $logfile -Append 
      Remove-Item -LiteralPath $FilePath -Force
      "$(get-date -format yyyyMMdd-HHmm) Test if file is deleted"| Out-File $logfile -Append 
      IF ( !(Test-Path $FilePath))
      {
        "$(get-date -format yyyyMMdd-HHmm) File removed, starting GPUPDATE"| Out-File $logfile -Append 
        Start-Sleep -Seconds 5
        $gpupdateResult = Start-CliApplication "gpupdate" "/force"
        If ($gpUpdateResult -eq 0) 
        {
          "$(get-date -format yyyyMMdd-HHmm) Group Policy Update Successful"| Out-File $logfile -Append 
        }
        Else 
        { 
          "$(get-date -format yyyyMMdd-HHmm) Group Policy Update Failed"| Out-File $logfile -Append 
          break
        }
      }
      ELSE
      {
        "$(get-date -format yyyyMMdd-HHmm) Can not remove $FilePath, please check"| Out-File $logfile -Append 
        break
      }
}
ELSE {"$(get-date -format yyyyMMdd-HHmm) Noting to do"| Out-File $logfile -Append }