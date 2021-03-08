$Pin = ConvertTo-SecureString "123456" -AsPlainText -Force
Add-BitlockerKeyProtector -MountPoint $env:SystemDrive -RecoveryPasswordProtector
$BLV = Get-BitLockerVolume -MountPoint "C:"Backup-BitLockerKeyProtector -MountPoint "C:" -KeyProtectorId $BLV.KeyProtector[0].KeyProtectorId
Enable-BitLocker -MountPoint C: -TpmAndPinProtector -Pin $Pin -SkipHardwareTest -UsedSpaceOnly
While ((Get-BitLockerVolume -MountPoint $env:SystemDrive).VolumeStatus -eq "EncryptionInProgress") {
    $encPercent = (Get-BitLockerVolume -MountPoint $env:SystemDrive).EncryptionPercentage
    Write-Progress -Activity "Encrypting $env:SystemDrive" -PercentComplete $encPercent -Status "$encPercent% complete"
    sleep -m 1000
}
Write-Progress -Activity "Encrypting $env:SystemDrive" -Status "Done" -Completed
