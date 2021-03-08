[cmdletbinding()]
Param(
[Parameter(Mandatory=$false, Position=2, ValueFromPipeline=$False)]
[bool]$needfix = $false,
[Parameter(Mandatory=$false, Position=1, ValueFromPipeline=$False)]
$logfile = "C:\Temp\Check-LocalGroupPolicy.log"
)

# Function to start a CLI application and return the exit code
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
    Write $process.exitcode
}

"$(get-date -format yyyyMMdd-HHmm) Check UAC" | Out-File $logfile -Append 
### Proof for administrative permissions (UAC)
If (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole( [Security.Principal.WindowsBuiltInRole] "Administrator"))
{
    "$(get-date -format yyyyMMdd-HHmm) This script need to be run administrative permissions. Exit Scripts" | Out-File $logfile -Append 
    break
}


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