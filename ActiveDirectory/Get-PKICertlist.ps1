param (
    [switch]$revoked,
    [switch]$denied,
    [string]$CAserver,
    [String]$SeachFilter
)

IF (-not $CAserver){
    [String]$LDAPDOM = (Get-ADDomain).DistinguishedName
    $CAServer=(Get-ADObject $((Get-ChildItem "ad:\CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,$LDAPDOM").distinguishedName) -Properties dNSHostName ).dNSHostName
}
$DispositionFilters = @()
IF ($revoked) {$DispositionFilters += "Revoked"}
IF ($denied) {$DispositionFilters += "Denied"}
$certutilCommand = "certutil -out 'Request ID,Issued Common Name,Certificate Template,Request Disposition,Certificate Expiration Date,Certificate Effective Date,Revocation Date,Issued Email Address,Requester Name,Caller Name,Public Key Length,Serial Number' -view csv"
Write-Verbose $certutilCommand
$certificates = Invoke-Command -ComputerName $CAserver -ScriptBlock { param ($cmd) Invoke-Expression $cmd } -ArgumentList $certutilCommand 
Write-progress -Activity "Analysiere Zertifikate" -Status "Verbinde zu $CAserver" -id 1 -PercentComplete 0
$i = 0
$CAcerts = @()
$CAcerts = $certificates[1..($certificates.Length - 1)].Replace("EMPTY","") | ForEach-Object {
    $i++
    Write-Progress -activity "Analysiere Zertifikate " -Status "$i von $($certificates.Length - 1)" -PercentComplete (($i / $certificates.Length *100)) -id 1
    $fields = $_ -split '","'
    $SANCommand = 'certutil -restrict "RequestId = ' +$fields[0].Replace('"','') +'" -view '
    Try {$SAN = (Invoke-Command -ComputerName $CAserver -ScriptBlock { param ($cmd) Invoke-Expression $cmd } -ArgumentList $SANCommand | Where-Object { $_ -like "*DNS Name*" -or $_ -like "*IP Address*" }).trim().Replace("DNS Name=","").Replace("IP Address=", "") -join ","}
    Catch {$SAN = $null}
    [PSCustomObject]@{
        RequestID              = [int]$fields[0].Replace('"','')
        CommonName             = [string]$fields[1]
        CertificateTemplate    = [string]$( IF ( $fields[2] -like "1.3.6.1.4.1*") { ($fields[2] -split " ")[1..$(($fields[2] -split " ").count)] -join " " } Else { $fields[2] } )
        DispositionMessage     = ($fields[3] -split " ")[2]
        NotAfter               = [datetime]::ParseExact($fields[4], "dd.MM.yyyy HH:mm", $null)
        NotBefore              = [datetime]::ParseExact($fields[5], "dd.MM.yyyy HH:mm", $null)
        RevocationDate         = $fields[6]
        EmailAdress            = [string]$fields[7]
        Requester              = [string]$fields[8]
        Caller                 = [string]$fields[9]
        PublicKeyLength        = [int]$fields[10]
        SerialNumber           = $fields[11].Replace('"','')
        SubjectAlternativeNames= $SAN
    }
} 
Write-Progress -activity "Analysiere Zertifikate" -Completed -id 1
If (  $DispositionFilters.Length -eq 0 ) { 
    $DispositionFilters += "Issued"
} Else {
    $DispositionFilters += "Issued"
    Write-Verbose "Alle Zertiifkate die bis zum $targetDate Ablaufen und nach dem $pastDate ausgestellt wurden mit dem Filter: $DispositionFilters"
}
$CAcerts = $CAcerts | Where-Object {  $DispositionFilters -Contains $_.DispositionMessage }
$SeachFilter = "*" + $SeachFilter.Replace("*","") + "*"
$CAcerts = $CAcerts | Where-Object { $_.CommonName -like $SeachFilter -or $_.SubjectAlternativeNames -like $SeachFilter }

if ($ExportCsvPath){
    if ($ExportCsvPath -notlike "*.csv")
    {
    if ((Test-Path $ExportCsvPath) -eq $true)
        { $ExportCsvPath=$ExportCsvPath + "\CertExpiration.csv" }
    else
        {
            Write-Host "Der Pfad $ExportCsvPath ist nicht vorhanden - export nicht möglich."
            $CAcerts| Format-Table -AutoSize
        }
    }
    Remove-Item $ExportCsvPath -Force -ErrorAction SilentlyContinue
    $issuedCerts  |export-csv -NoClobber -Delimiter ";" -Encoding UTF8 -Path $ExportCsvPath -NoTypeInformation -Force -Append
    Write-Output "Sie finden den Export hier: $ExportCsvPath"
}
$CAcerts = $CAcerts | Sort-Object -Property "RequestID"
If ( (Get-Item 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Server\ServerLevels\').GetValue("Server-Gui-Mgmt") -eq 1) {
    $CAcerts | out-gridview -Title "Zertifikate die den Suchfilter $SeachFilter entsprechen"
} Else {
    $CAcerts| Format-Table -AutoSize
}
Write-Warning -Message "Achtung: Zurückgezogene Zertifikate können nicht wiederhergestellt werden! Wenn diese versehentlich zurückgezogen werden, müssen neue Zertifikate ausgestellt werden!"
$proceed = Read-Host -Prompt "Wollen Sie gefundenen $($CAcerts.Count) Zertifikate zurückziehen? Es erfolgt für jedes Zertifikate eine Bestätigung! (j/n)"
if ($proceed -eq "j") {
    ForEach ($cert in $CAcerts) {
        Write-Output "Möchten Sie das folgende Zertifikat wirklich zurziehen?"
        $cert | Format-List -Property *
        $proceed = Read-Host -Prompt "Sind Sie sicher das das Zertifikat zurückgezogen werden soll? J/N"
        if ($proceed -eq "j") {
            Write-Output "Zertifikat wird zurückgezogen..."
            [int]$reason = Read-Host -Prompt "Geben Sie die Zahl des Grunds für die Zurückziehung des Zertifikats ein: 
            1 = Schlüssel kompromitiert (Sicherheitsvorfall) 
            4 = Zertifikat wurde ersetzt (Superseded)
            5 = System wurde deprovisioniert
            Welcher Grund soll angegeben werden: [1|4|5] "
            $revokecmd = "certutil.exe -revoke $($cert.SerialNumber) $reason"
            Write-Output "CMD: $revokecmd"
            Try {Invoke-Command -ComputerName $CAserver -ScriptBlock { param ($cmd) Invoke-Expression $cmd } -ArgumentList $revokecmd }
            Catch {$SAN = $null}
        }

    }   
    
}