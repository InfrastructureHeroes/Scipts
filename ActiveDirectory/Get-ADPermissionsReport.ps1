##requires -version 5.1
##requires -modules activedirectory

<#
	.SYNOPSIS
		Get CSV Report about all Permisions in Active Directory
	.DESCRIPTION
		Get CSV Report about all Permisions in Active Directory
	.PARAMETER showresult
		Shows permissions as Shell output - not recommended
	.PARAMETER Export
		Activate CSV Export
	.PARAMETER Exportpath
		Path to CSV file for Export, default: "C:\Temp\$(Get-Date -Format "yyyyMMdd-HHmm")-ADPermissionReport.csv"
	.EXAMPLE  
		Shows permissions as Shell output - not recommended
		get-ADPermisionReport.ps1 -showresult
	.EXAMPLE
		Export report as CSV to c:\temp\ifhpermissionreport.csv
		get-ADPermisionReport.ps1 -export -ExportFile c:\temp\ifhpermissionreport.csv
	.INPUTS
		Keine.
	.OUTPUTS
		Keine.
	.NOTES
		Author     :	Fabian Niesen
		Filename   :	get-ADPermisionReport.ps1
		Requires   :	PowerShell Version 5.1
		
		Version    :	0.2
		History    : 	0.2   FN 28.04.2024 Add Parameters
						0.1   FN 27.04.2024 initial version
                    
    .LINK
        https://www.infrastrukturhelden.de
#>
[CmdletBinding(DefaultParameterSetName='showresult')]
Param(
	[Parameter(ParameterSetName = "export" ,Mandatory=$false)]
    [Parameter(ParameterSetName = "showresult" ,Mandatory=$false)]
	[switch]$export,
	[Parameter(ParameterSetName = "export" ,Mandatory=$true)]
	[string]$ExportFile = "C:\Temp\$(Get-Date -Format "yyyyMMdd-HHmm")-ADPermissionReport.csv",
	[Parameter(ParameterSetName = "export" ,Mandatory=$false)]
    [Parameter(ParameterSetName = "showresult" ,Mandatory=$false)]
	[switch]$showresult
)
# Array for report.
$report = @()
$schemaIDGUID = @{}
# ignore duplicate errors if any #
$ErrorActionPreference = 'SilentlyContinue'
Get-ADObject -SearchBase (Get-ADRootDSE).schemaNamingContext -LDAPFilter '(schemaIDGUID=*)' -Properties name, schemaIDGUID | ForEach-Object {$schemaIDGUID.add([System.GUID]$_.schemaIDGUID,$_.name)}
Get-ADObject -SearchBase "CN=Extended-Rights,$((Get-ADRootDSE).configurationNamingContext)" -LDAPFilter '(objectClass=controlAccessRight)' -Properties name, rightsGUID | ForEach-Object {$schemaIDGUID.add([System.GUID]$_.rightsGUID,$_.name)}
$ErrorActionPreference = 'Continue'
$OUs = (Get-ADOrganizationalUnit -filter *).DistinguishedName
$i = 0
foreach($OU in $OUs){ 
    $i++
    Write-Progress -activity "Query Permissions, please wait." -Status "$i of $($OUs.count): $($OU)" -PercentComplete (($i / $OUs.count)*100) -Id 1
    $report += Get-Acl -Path "AD:\$OU" | Select-Object -ExpandProperty Access | Select-Object @{name='organizationalunit';expression={$OU}}, @{name='objectTypeName';expression={if ($_.objectType.ToString() -eq '00000000-0000-0000-0000-000000000000') {'All'} Else {$schemaIDGUID.Item($_.objectType)}}}, @{name='inheritedObjectTypeName';expression={$schemaIDGUID.Item($_.inheritedObjectType)}}, * 
}
Write-Progress -activity "Query Permissions, please wait." -Completed -Id 1
IF ($showresult) { $report | Format-Table -AutoSize }
IF ($export) { $report | Export-Csv -Path "$ExportFile" -NoTypeInformation -Force -Delimiter ";"}