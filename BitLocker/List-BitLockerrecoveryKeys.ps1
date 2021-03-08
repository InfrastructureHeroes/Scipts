$computers = get-adobject -Filter * | Where-Object {$_.ObjectClass -eq "msFVE-RecoveryInformation"}

$key = (read-host -Prompt "Enter starting portion of recovery key ID").ToUpper()
$records = $computers | where {$_.DistinguishedName -like "*{$key*"}
foreach ($rec in $records) {
    $computer = get-adcomputer -identity ($records.DistinguishedName.Split(",")[1]).split("=")[1]
    $recoveryPass = Get-ADObject -Filter {objectclass -eq 'msFVE-RecoveryInformation'} -SearchBase $computer.DistinguishedName -Properties 'msFVE-RecoveryPassword' | where {$_.DistinguishedName -like "*$key*"}
    [pscustomobject][ordered]@{
        Computer = $computer
        'Recovery Key ID' = $rec.Name.Split("{")[1].split("}")[0]
        'Recovery Password' = $recoveryPass.'msFVE-RecoveryPassword'
    } | Format-List
}