#requires -version 2.0
#requires -modules activedirectory


<#
	.SYNOPSIS
		Locate user Lockouts in Active Directory
	.DESCRIPTION
		Query all DC and Locate user Lockouts in Active Directory within the last 24h. As default the result is shown as Grid-View, but CSV Export is possible.
        A lunchtime project...
	.EXAMPLE  
        .\LocateADLockout-v2.ps1 -filter "bn" -CSVOUT $true -Gridview $false -CSVpath 
	.INPUTS
		-RunAs For future use
        -filter only DC's with this pattern in the Hostname
        -Gridview Output as GridView
        -CSVOUT Export as CSV
        -CSVpath Exportpath for CSV
	.OUTPUTS
		Keine.
	.NOTES
		Author     : Fabian Niesen
		Filename   : Locate-ADLockout.ps1
		Requires   : PowerShell Version 2.0
		
		Version    : 1.0
		History    : 1.0
                    
    .LINK
        https://www.infrastrukturhelden.de
#>

Param(
	[Parameter(Mandatory=$false, ValueFromPipeline=$True)]
	[String]$RunAs = $false,
	[Parameter(Mandatory=$false, ValueFromPipeline=$True)]
	[String]$filter ="*",
	[Parameter(Mandatory=$false, ValueFromPipeline=$True)]
	[String]$Gridview =$true,    
	[Parameter(Mandatory=$false, ValueFromPipeline=$True)]
	[String]$CSVOUT = $false,
	[Parameter(Mandatory=$false, ValueFromPipeline=$True)]
	[String]$CSVpath = "changeme"
)

$LogOuts = @()


#@{label=''}, @{label=''},@{label=''}, @{label=''}, @{label=''}
$DCs =  Get-ADDomainController -Filter  { HostName -like "$filter" }
ForEach ($DC in $DCs)
{
Write-Output "Starte Remote PowerShell Session zu: "$DC.HostName
$temp = Invoke-Command -ComputerName $DC.HostName -ScriptBlock { Get-EventLog -LogName "Security" -After (Get-Date).AddDays(-1) | Where-Object { $_.EventID -match '4740' -or $_.EventID -match '644'} }
ForEach ($t in $temp)
  {
  $Log = New-Object -TypeName psobject
  $Log | Add-Member -MemberType NoteProperty -Name TimeGenerated -Value $t.TimeGenerated
  $Log | Add-Member -MemberType NoteProperty -Name DC -Value $t.ReplacementStrings[4]
  $Log | Add-Member -MemberType NoteProperty -Name Benutzer -Value $t.ReplacementStrings[0]
  $Log | Add-Member -MemberType NoteProperty -Name Quelle -Value $t.ReplacementStrings[1]
  $Log | Add-Member -MemberType NoteProperty -Name LoginID -Value $t.ReplacementStrings[6]
  $LogOuts += $Log
  }
}

IF ($Gridview -eq $true) { $LogOuts | Out-GridView -Title "Account Lockouts" }
IF ($CSVOUT -eq $true) 
  {
    IF ($CSVpath -like "changeme")
      {
        Write-Verbose "No Path found"
        $CSVpath = Read-Host -Prompt "Bitte geben Sie einen Dateinamen inklusive Pfad an"
      }
    $LogOuts | Export-Csv -Path $CSVpath -Delimiter ";" -NoTypeInformation
  }

<# If I have to much time left...
### Runas Auswertung der Aufgabenplanung pro User und System
  IF ($RunAs -eq $true) 
  {
    $SchedService.Connect($ComputerName)
    $TaskFolder = $SchedService.GetFolder("")
    $RootTasks = $TaskFolder.GetTasks("")
    Foreach ($Task in $RootTasks)
    {
    Switch ($Task.State)
    {
    0 {$Status = "Unknown"}
    1 {$Status = "Disabled"}
    3 {$Status = "Ready"}
    4 {$Status = "Running"}
    }#End Switch ($Task.State)
    $Xml = $Task.Xml
    #The code below parses the Xml String Data for the "RunAs User" that is returned from the Schedule.Service COM Object
    [String]$RunUser = $Xml[(($Xml.LastIndexOf("<UserId>"))+8)..(($Xml.LastIndexOf("</UserId>"))-1)]
    $RunUser = $RunUser.Replace(" ","").ToUpper()
    $Result = New-Object PSObject -Property @{
    ServerName=$ComputerName
    TaskName=$Task.Name
    RunAs=$RunUser
    LastRunTime=$Task.LastRunTime
    NextRunTime=$Task.NextRunTime
    }#End $Result = New-Object
    $Result = $Result | Select-Object Servername, TaskName, RunAs, LastRunTime, NextRunTime

#>

# SIG # Begin signature block
# MIINhAYJKoZIhvcNAQcCoIINdTCCDXECAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUY5VekahfDkMzynRQdVSHw6kI
# pG2gggrDMIIE1zCCA7+gAwIBAgIQQqUulpP/t+xNJTeKzXz8XzANBgkqhkiG9w0B
# AQsFADB1MQswCQYDVQQGEwJJTDEWMBQGA1UEChMNU3RhcnRDb20gTHRkLjEpMCcG
# A1UECxMgU3RhcnRDb20gQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkxIzAhBgNVBAMT
# GlN0YXJ0Q29tIENsYXNzIDMgT2JqZWN0IENBMB4XDTE2MDcyMDA4MjM0MFoXDTE5
# MDcyMDA4MjM0MFowZDELMAkGA1UEBhMCREUxHDAaBgNVBAgME05vcmRyaGVpbi1X
# ZXN0ZmFsZW4xDTALBgNVBAcMBEJvbm4xEzARBgNVBAoMCnN0ZWVwIEdtYkgxEzAR
# BgNVBAMMCnN0ZWVwIEdtYkgwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQDEym9W07bauIxBdWBD29HJRWbPEZXE7y/slfD1z2Ldf5dNcbhBN++AcFmmitfD
# 9wC4qa6Masw2bcILUqyxY0kTb1zUpV5RPJ389e2mzvsgaQyIsqB+tIUHxdhiyRzc
# i9yFmNybCErwEzNueU37BAxpc21OYn44IExSfP26qsKlEi1KxukHv+pWZbLfZpCt
# T/WE+lZxNTxzjDezk9c0m5wQ+HSShcFUwViBf/h2Ov+05ZhH7j1RjvUSmLSyx0cs
# JL8jaMszouYlRPHnbghD3UD500TjlkT+sstf6JqInGyNYcfa0bsFwbuoKz3SndH1
# RGQ/b4riT5GW0wOljsRtpglBAgMBAAGjggFyMIIBbjAOBgNVHQ8BAf8EBAMCB4Aw
# EwYDVR0lBAwwCgYIKwYBBQUHAwMwCQYDVR0TBAIwADAdBgNVHQ4EFgQUEPS1SOLL
# CkfWuYxHbJz2dHucaNowbQYIKwYBBQUHAQEEYTBfMCQGCCsGAQUFBzABhhhodHRw
# Oi8vb2NzcC5zdGFydHNzbC5jb20wNwYIKwYBBQUHMAKGK2h0dHA6Ly9haWEuc3Rh
# cnRzc2wuY29tL2NlcnRzL3NjYS5jb2RlMy5jcnQwNgYDVR0fBC8wLTAroCmgJ4Yl
# aHR0cDovL2NybC5zdGFydHNzbC5jb20vc2NhLWNvZGUzLmNybDAjBgNVHRIEHDAa
# hhhodHRwOi8vd3d3LnN0YXJ0c3NsLmNvbS8wUQYDVR0gBEowSDAIBgZngQwBBAEw
# PAYLKwYBBAGBtTcBAgUwLTArBggrBgEFBQcCARYfaHR0cHM6Ly93d3cuc3RhcnRz
# c2wuY29tL3BvbGljeTANBgkqhkiG9w0BAQsFAAOCAQEAAmEyPAwytipNaWO1N/gf
# c/dMMbf4nKGaIIYSTaguZwdgVwbWEegJ7b51i8kB1+nI3qg+Ez89kmT/Ano4Ot+V
# 7IOx8Hvpfqy1eXKOl2oHVXqEzoZJV/nNf+TFJRk5PKORS8lJIEss9slS79bw4ejI
# LaowcfgHLwmP9yeL3M860edWB+yL00VOVUnYM/Jb2SkCvd1buLUVUluMz1tZdh+s
# B/sGcf2I0sxS8mCbPFuIGJ2LBq859W8MDM4BO1i4tQnLKi5i/VlbVelUtaMTbndS
# WbRn3828k5QnajErzR2C2cAI6Lya8TsKTKKz1I2etM7gPy16II/ygR5q6KoON9n1
# mjCCBeQwggPMoAMCAQICEHgiQ6FT3ygKH/rhXNAoTIYwDQYJKoZIhvcNAQELBQAw
# fTELMAkGA1UEBhMCSUwxFjAUBgNVBAoTDVN0YXJ0Q29tIEx0ZC4xKzApBgNVBAsT
# IlNlY3VyZSBEaWdpdGFsIENlcnRpZmljYXRlIFNpZ25pbmcxKTAnBgNVBAMTIFN0
# YXJ0Q29tIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MB4XDTE1MTIxNjAxMDAwNVoX
# DTMwMTIxNjAxMDAwNVowdTELMAkGA1UEBhMCSUwxFjAUBgNVBAoTDVN0YXJ0Q29t
# IEx0ZC4xKTAnBgNVBAsTIFN0YXJ0Q29tIENlcnRpZmljYXRpb24gQXV0aG9yaXR5
# MSMwIQYDVQQDExpTdGFydENvbSBDbGFzcyAzIE9iamVjdCBDQTCCASIwDQYJKoZI
# hvcNAQEBBQADggEPADCCAQoCggEBANhsJTYUZFx5zWGYAp8FlVG8yEBmyldXMpNl
# oFW7wnrfr/7lVSgyZ+ZjL8LvZcDB5nftTaSlvd5MCOJW9WlMICRksLS/2vo5b/Bs
# OjIs5A9j8FSt0far4mtE0dlu5mQ3+6hbn2tgjW+m6aksqDymsAIAAW/NFKCsyrDl
# qNOaujXkfmdpbe0keZqKfDDw7DoHZygP9e6KaDn0pcuheiYNa+T+cqlrV8Tw3sZm
# zPyxv/itSCiR3G+yo9LKDZwVFfRj/tpAJhFAodHEw9Swna2FRYlpA1TZg93QSEDe
# u6HjTR9AJPHA4I4SRhsIL5LuGWVhuxT1hX2pLmKSL2mPACV3etcCAwEAAaOCAWYw
# ggFiMA4GA1UdDwEB/wQEAwIBBjAfBgNVHSUEGDAWBggrBgEFBQcDAwYKKwYBBAGC
# Nz0BATASBgNVHRMBAf8ECDAGAQH/AgEAMDIGA1UdHwQrMCkwJ6AloCOGIWh0dHA6
# Ly9jcmwuc3RhcnRzc2wuY29tL3Nmc2NhLmNybDBmBggrBgEFBQcBAQRaMFgwJAYI
# KwYBBQUHMAGGGGh0dHA6Ly9vY3NwLnN0YXJ0c3NsLmNvbTAwBggrBgEFBQcwAoYk
# aHR0cDovL2FpYS5zdGFydHNzbC5jb20vY2VydHMvY2EuY3J0MB0GA1UdDgQWBBRm
# ep7NnHOGammgrvqMuxiPCOzVBDAfBgNVHSMEGDAWgBROC+8apEBbpRdphzDKNGhD
# 0EGu8jA/BgNVHSAEODA2MDQGBFUdIAAwLDAqBggrBgEFBQcCARYeaHR0cDovL3d3
# dy5zdGFydHNzbC5jb20vcG9saWN5MA0GCSqGSIb3DQEBCwUAA4ICAQALH3fwpLbm
# kgX1R/F0c6VgGrehmK66gJnxuJbU+iPpymMFgggAr5TMITlT1VGYaAHA4PZTvlgR
# mL3ZrhHnn+/TI03MZyt4XluVm0qju0w0R+EpeUZHycXTKK51G8Jjvfn9u1GnsgKT
# QFNeep1p+f40LvQai2wLQgCJ4ScvqIUK5+2FJvS4yNOugZejNyw45duXUyWukBah
# G2fQFcW6yZuvjHHh7qfAi2Dyv1w6FeJeHNP/tPhYdQK6bRKDM//EDFyXY/+xEWaB
# REDDI8D2HJVvJ8p0AIZQatPNBiF7AdiPSZVBYwhXBr9n7NwOrFkqARvHmecrdQ1h
# IwSMUtIuvHtRUJKin6J4dJWDnvO3llnKrhHYnpu4SgzC6Dk2KGbppnbaxP8x4rJd
# jWkkiltYfYuv0oy8UjEPHZAvlqhGmnc2q5kvVc0NtXgD5IipE8xybXrI9nd5uErP
# hR4eSvguRy5aNusuF//bdcB9lGhMM3V2QyLRgABXh34TwfBVSvLrnwThqC06t66n
# iXyxqA/98iad8PdAHfSkyRBMMNxk0LVSETfJ/FtVJr6JvWPfQgRxek+L8s6sw/bb
# 4Jr6LnCCQjaChoDFrn0CevRgDsodMJbbFPToTJk8sgOOK1D3mWOAhLL1G765DD80
# ytzX/aOOXA5wfpQTTzIb/6SPXHX1nKRYyTGCAiswggInAgEBMIGJMHUxCzAJBgNV
# BAYTAklMMRYwFAYDVQQKEw1TdGFydENvbSBMdGQuMSkwJwYDVQQLEyBTdGFydENv
# bSBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTEjMCEGA1UEAxMaU3RhcnRDb20gQ2xh
# c3MgMyBPYmplY3QgQ0ECEEKlLpaT/7fsTSU3is18/F8wCQYFKw4DAhoFAKB4MBgG
# CisGAQQBgjcCAQwxCjAIoAKAAKECgAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcC
# AQQwHAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYE
# FP8IdNLO8hTUzYNJpRoTG5P7aAtJMA0GCSqGSIb3DQEBAQUABIIBAGtwmWDP5UfK
# KVx9Gz7hb8iWerlkk87ADhtIyFJs8LtBM5eSHCTmzTn3BEv5TsAIqCb692w70i1d
# c812ehjpZbR6hvumMtBG+YgggqbxuaMzrppBJbMKZ/L3dWQY4LNpvEU+O+Vv0fhc
# +abVe7sJXuUjGzgQYpiMkWyWUVQvh/gOJo4ytCvwfdP1D6PUPabvVsWd0Xzzh37U
# 4jGaYTDg45DoO/Wa812j/+abYwqCAZuwkN0P++n+QTBBZQR47d6vFwTymiGEPiLB
# hAraXkOw7e/BCmORydk3asLmHc0OVJmKqiedKpuSgy8wfScVH5nz3Y1ugSeHTuQ9
# v8QIjIQpH/0=
# SIG # End signature block
