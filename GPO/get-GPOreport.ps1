## Code sniplet from the path - not sure if its work...
$ErrorActionPreference = "Stop"


$GPOitem = New-Object psobject
$GPOitem | Add-Member -MemberType NoteProperty -Name 'Policy' -Value $null
$GPOitem | Add-Member -MemberType NoteProperty -Name 'LinkPath' -Value $null
$GPOitem | Add-Member -MemberType NoteProperty -Name 'LinkEnabled' -Value $null
$GPOitem | Add-Member -MemberType NoteProperty -Name 'LinkNoOverride' -Value $null
$result = @{} 
try
{
  Import-Module grouppolicy 
}
catch
{
Write-Warning "GroupPolicy Module ist missing. Please install first" | Out-file $ErrorLog -Append
break
}
$CSV = "\\UNC\Dokumentation\Intern\_Microsoft\GPOReport.CSV"
"Policy, LinkPath, LinkEnabled, LinkNoOverride" | Out-file $CSV -Force 

$GPOS = get-GPO -all
Write-host "Found $($GPOS.count) GPO"
FOREACH ( $GPO in $GPOS)
{
    [XML]$GPOv = Get-GPOReport -Name $GPO.DisplayName -ReportType XML
    #$GPOv.GPO | Write-Verbose 
    $m = $GPOv.GPO.LinksTo.count 
    Write-verbose "$m Links found $($GPO.DisplayName)"
    IF ($GPOv.GPO.LinksTo.count -gt 0)
    {
    
        Foreach ($link in $GPOv.GPO.LinksTo) 
        {
      
          $GPOitem.Policy= $GPO.DisplayName
          $GPOitem.LinkPath= $link.SOMPath
          $GPOitem.LinkEnabled= $link.Enabled
          $GPOitem.LinkNoOverride= $link.NoOverride
          $GPOReport += , $GPOitem
          "$($GPO.DisplayName),$($link.SOMPath),$($link.Enabled),$($link.NoOverride)" | Out-file $CSV -Append
        }
    }
    ELSEIF ($GPOv.GPO.LinksTo.count -ne "0")
    {
      Write-Verbose "Count ne 0"     
      
      $GPOitem.Policy= $GPO.DisplayName
      $GPOitem.LinkPath= $GPOv.GPO.LinksTo.SOMPath
      $GPOitem.LinkEnabled= $GPOv.GPO.LinksTo.Enabled
      $GPOitem.LinkNoOverride= $GPOv.GPO.LinksTo.NoOverride
      $GPOReport += , $GPOitem
      "$($GPO.DisplayName),$($link.SOMPath),$($link.Enabled),$($link.NoOverride)" | Out-file $CSV -Append
    }
    ELSE 
    {
      Write-Warning "No Link found $($GPO.DisplayName) $m"
      $GPOitem.Policy= $GPO.DisplayName
      $GPOReport += , $GPOitem
      "$($GPO.DisplayName),,," | Out-file $CSV -Append
    }
    
}
