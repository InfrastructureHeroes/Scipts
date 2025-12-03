<#
	.SYNOPSIS
		Legt Dokuwiki Animals an.
	.DESCRIPTION
		Legt Dokuwiki Animals an. Inklusive AD-Gruppen, ACL, Konfig, NTFS Rechte, ....
	.EXAMPLE  
        New-DokuwikiAnimal.ps1 -Animal IT
	.INPUTS
		Animal
	.OUTPUTS
		Keine.
	.NOTES
		Author     :  Fabian Niesen
		Filename   :  New-DokuwikiAnimal.ps1
		Requires   :  PowerShell Version 3.0
		License    :  The MIT License (MIT)
                  Copyright (c) 2022-2025 Fabian Niesen
                  Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation 
                  files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, 
                  merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is 
                  furnished to do so, subject to the following conditions:
                  The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
                  The Software is provided "as is", without warranty of any kind, express or implied, including but not limited to the warranties 
                  of merchantability, fitness for a particular purpose and noninfringement. In no event shall the authors or copyright holders be 
                  liable for any claim, damages or other liability, whether in an action of contract, tort or otherwise, arising from, out of or in 
                  connection with the software or the use or other dealings in the Software.
    Disclaimer :  This script is provided "as is" without warranty. Use at your own risk.
                  The author assumes no responsibility for any damage or data loss caused by this script.
                  Test thoroughly in a controlled environment before deploying to production.
		Version    : 0.1
		History    : 0.1 Los geht es
    .LINK
        http://wiki.domain.tld/
		
	Offene Punkte / Knowing Bugs

#>
[cmdletbinding()]
Param(
	[Parameter(Mandatory=$false, Position=1, ValueFromPipeline=$False)]
	[String]$Animal="!notset!"
)

clear-host 

$wwwroot ="C:\inetpub\wwwroot"
$farmpath = $wwwroot+"\wiki"
$GroupOU = "OU=Wiki,OU=Gruppen,DC=domain,DC=tld"
$wikiadmins = "RG-WEB-Wiki-Admins"
$GroupPreFix = "RG-WEB-Wiki-"
$ErrorActionPreference = "Stop"
$before = Get-Date
$date = get-date -format yyyyMMdd-HHmm

### Proof for administrative permissions (UAC)
If (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole( [Security.Principal.WindowsBuiltInRole] "Administrator"))
{
  Write-Warning "Not run as administrator! You failed ;)"
    break
} 

Write-Host "Lade ActiveDirectory Module"
try
{
  Import-Module ActiveDirectory 
}
catch
{
Write-Warning "ActiveDirectory Module ist missing. Please install first"
break
}

If ($Animal -eq "!notset!") { 
  Write-Host ""
  $Animal = $( Read-Host "Bitte geben Sie den Namen des neuen Wiki ein (Ohne den Begriff 'Wiki')" )
  Write-Host ""
}

#Check Sonderzeichen und Leerzeichen !!!!!!!!!!!
$cleananimal = $($Animal -replace " ","").ToLower()

$animalpath = $farmpath+"\"+$cleananimal

Write-Host "Wiki wird eingerichtet unter $animalpath"
Write-Host ""
Write-verbose "Lege Verzeichnis an"
IF (Test-Path $animalpath) {Write-Warning "Das Verzeichnis $animalpath existiert bereits"} 
ELSE
{ new-item -Path $animalpath -ItemType directory| Out-Null }

Write-Host "Lege die AD-Gruppen mit dem Prefix $($GroupPreFix+$Animal) in der OU $GroupOU"
#Anlegen der AD-Gruppen
$GroupRead = $GroupPreFix+$Animal+"-Lesen"
$GroupEditor = $GroupPreFix+$Animal+"-Editor"
$GroupManager = $GroupPreFix+$Animal+"-Manager"
$GroupAdmins = $GroupPreFix+$Animal+"-Admins"

try { New-ADGroup -Name $GroupRead -SamAccountName $GroupRead -GroupCategory Security -GroupScope Global -DisplayName $GroupRead -Path $GroupOU -Description "Leserechte für das Wiki $Animal"}
catch {Write-Warning "Die Gruppe $GroupRead existiert bereits"}
try { New-ADGroup -Name $GroupEditor -SamAccountName $GroupEditor -GroupCategory Security -GroupScope Global -DisplayName $GroupEditor -Path $GroupOU -Description "Editorrechte für das Wiki $Animal"}
catch {Write-Warning "Die Gruppe $GroupEditor existiert bereits"}
try { New-ADGroup -Name $GroupManager -SamAccountName $GroupManager -GroupCategory Security -GroupScope Global -DisplayName $GroupManager -Path $GroupOU -Description "Managementrechte für das Wiki $Animal"}
catch {Write-Warning "Die Gruppe $GroupManager existiert bereits"}
try { New-ADGroup -Name $GroupAdmins -SamAccountName $GroupAdmins -GroupCategory Security -GroupScope Global -DisplayName $GroupAdmins -Path $GroupOU -Description "Adminrechte für das Wiki $Animal"}
catch {Write-Warning "Die Gruppe $GroupAdmins existiert bereits"}

Write-Host "Füge die Wiki-Admins zu den Admins hinzu hinzu, befülle die Lesegruppe mit Editoren, Manager und Admins."
try { Add-ADGroupMember $GroupAdmins $wikiadmins}
catch {Write-Warning "$wikiadmins sind bereits in $GroupAdmins enthalten"}
try { Add-ADGroupMember $GroupRead $GroupEditor,$GroupManager,$GroupAdmins}
catch {Write-Warning "Die Editoren, Manager und Admins haben bereits Leserechte"}
try { Add-ADGroupMember "RG-WEB-Wiki-Benutzer" $GroupRead}
catch {Write-Warning "Die Gruppe $GroupRead ist bereits in der Gruppe RG-WEB-Wiki-Benutzer enthalten"}
Write-Host ""

Write-Verbose "Setzte NTFS Rechte"
#Setzen der NTFS Rechte 
$inherit = [system.security.accesscontrol.InheritanceFlags]"ContainerInherit, ObjectInherit"
$propagation = [system.security.accesscontrol.PropagationFlags]"InheritOnly"
$modify = [System.Security.AccessControl.FileSystemRights]"Read, Write, Modify, ExecuteFile" 
$read = [System.Security.AccessControl.FileSystemRights]"ReadAndExecute"

### ==== For Schleife für NTFS Einfügen ==== ###
### Schleife umbauen nach verzeichnissen statt Gruppen, wäre schneller !!
### Setzt eigentlich noch zuviele Rechte!!!! 

$groups = @($GroupRead,$GroupEditor,$GroupManager,$GroupAdmins)
#foreach ($group in $groups) 
#{
  $group = $GroupRead
  Write-Host "Setzte NTFS Rechte für $group"
  ##NTFS für WWWROOT
  $Acl = Get-ACL -Path $wwwroot
  Write-Debug "$($acl | FL)"
  $Ar = New-Object  system.security.accesscontrol.filesystemaccessrule($GroupRead,$read,"None","None","Allow")
  Write-Debug "$($Ar | FL)"
  $Acl.AddAccessRule($Ar)
  Write-Debug "$($acl | FL)"
  Write-Verbose "Set-ACL lesen WWWroot"
  Set-Acl -Path $wwwroot -AclObject $Acl

  Write-Verbose "NTFS für Farm"
  $Acl = Get-ACL -Path  $farmpath
  $Ar = New-Object  system.security.accesscontrol.filesystemaccessrule($GroupRead,$read,"None","None","Allow")
  $Acl.AddAccessRule($Ar)
  Set-Acl $farmpath $Acl
  
  ##NTFS für Farmer
 $Acl = Get-ACL -Path $($wwwroot+"\dokuwiki")
  $Ar = New-Object  system.security.accesscontrol.filesystemaccessrule($GroupRead,$modify,$inherit, $propagation, "Allow")  
  $Acl.AddAccessRule($Ar)
  Set-Acl $($wwwroot+"\dokuwiki") $Acl  
 
  ##NTFS Für Animal
  $Acl = Get-ACL -Path $animalpath
  $Ar = New-Object  system.security.accesscontrol.filesystemaccessrule($GroupRead,$modify,$inherit, $propagation, "Allow")
  $Acl.AddAccessRule($Ar)
  Set-Acl $animalpath $Acl


#}
### ==== Ende der Schleife für NTFS ==== ###

#Anlegen des Animal
Write-Host ""
Write-Host "Erzeuge das Child Wiki"

new-item -Path $($animalpath+"\data\") -ItemType directory| Out-Null
new-item -Path $($animalpath+"\conf\") -ItemType directory| Out-Null
  
Write-Verbose "Setzte NTFS für Animal Conf"
  $Acl = Get-ACL -Path  $($animalpath+"\conf")
  $Ar = New-Object  system.security.accesscontrol.filesystemaccessrule($GroupAdmins,$modify,$inherit, $propagation, "Allow")
  $Acl.AddAccessRule($Ar)
  Set-Acl $($animalpath+"\conf") $Acl

$verz = @("attic","cache","index","locks","media","media_attic","media_meta","meta","pages","tmp")
foreach ($ver in $verz) {
new-item -Path $($animalpath+"\data\"+$ver) -ItemType directory | Out-Null
}
$conffiles = @("local.php","local.protected.php","acl.auth.php","users.auth.php","plugins.local.php")
foreach ($conffile in $conffiles) {
new-item -Path $($animalpath+"\conf\"+$conffile) -ItemType File| Out-Null
}
Copy-Item -Path $($wwwroot+"\dokuwiki\data\pages\wiki") -Destination $($animalpath+"\data\pages\") -Recurse
Copy-Item -Path $($wwwroot+"\dokuwiki\data\pages\playground") -Destination $($animalpath+"\data\pages\") -Recurse
Copy-Item -Path $($wwwroot+"\dokuwiki\data\meta\wiki") -Destination $($animalpath+"\data\meta\") -Recurse
Copy-Item -Path $($wwwroot+"\dokuwiki\data\media\wiki\logo.png") -Destination $($animalpath+"\data\media\")

### Writing 
$lc = $animalpath+"\conf\local.protected.php"
Write-Host "Befülle die Konfiguration $lc"
"<?php" | Out-File $lc 
"`$conf['title'] = '$Animal Wiki';" | Out-File $lc -Append 
"`$conf['lang'] = 'de';" | Out-File $lc -Append 
"`$conf['license'] = '0';" | Out-File $lc -Append 
"`$conf['useacl'] = 1;" | Out-File $lc -Append 
"`$conf['authtype'] = 'authad';" | Out-File $lc -Append 
"`$conf['superuser'] = '@$GroupAdmins';" | Out-File $lc -Append 
"`$conf['manager'] = '@$GroupManager';" | Out-File $lc -Append 
"`$conf['plugin']['authad']['account_suffix'] = '@domain.tld';" | Out-File $lc -Append 
"`$conf['plugin']['authad']['base_dn'] = 'DC=domain,DC=tld';" | Out-File $lc -Append 
"`$conf['plugin']['authad']['domain_controllers'] = 'dc02.domain.tld, dc01.domain.tld';" | Out-File $lc -Append 
"`$conf['plugin']['authad']['sso'] = 1;" | Out-File $lc -Append 
"`$conf['plugin']['authad']['expirywarn'] = 5;" | Out-File $lc -Append 
"`$conf['plugin']['authad']['recursive_groups'] = 1;" | Out-File $lc -Append 
"`$conf['plugin']['authad']['admin_username'] = 'SVC-WEB-WikiSSO';" | Out-File $lc -Append 
"`$conf['plugin']['authad']['admin_password'] = 'Pa$$w0rd';" | Out-File $lc -Append 
"`$conf['basedir'] = '/$cleananimal/';" | Out-File $lc -Append 
"`$conf['useheading'] = 'content';" | Out-File $lc -Append 
"`$conf['sneaky_index'] = 1;" | Out-File $lc -Append 
"`$conf['disableactions'] = 'register,resendpwd,profile,profile_delete';" | Out-File $lc -Append 
"`$conf['remoteuser'] = '@$GroupRead';" | Out-File $lc -Append 
"`$conf['target']['interwiki'] = '_blank';" | Out-File $lc -Append 
"`$conf['target']['extern'] = '_blank';" | Out-File $lc -Append 
"`$conf['target']['windows'] = '_blank';" | Out-File $lc -Append 
"`$conf['subscribers'] = 1;" | Out-File $lc -Append 
"`$conf['mailfrom'] = 'wiki@domain.tld';" | Out-File $lc -Append 
"`$conf['mailprefix'] = '$Animal Wiki: ';" | Out-File $lc -Append 
"`$conf['gzip_output'] = 1;" | Out-File $lc -Append 
"`$conf['plugin']['publish']['no_apr_namespaces'] = 'wiki playgound';" | Out-File $lc -Append
#"`$conf['plugin']['publish']['hide drafts'] = 1;" | Out-File $lc -Append
"`$conf['plugin']['publish']['hide_approved_banner'] = 1;" | Out-File $lc -Append
"`$conf['plugin']['publish']['author groups'] = '@$GroupManager';" | Out-File $lc -Append
"`$conf['savedir'] = DOKU_CONF.'../data';" | Out-File $lc -Append
"`$conf['updatecheck'] = 0;" | Out-File $lc -Append

$file_content = Get-Content "$lc";
[System.IO.File]::WriteAllLines("$lc", $file_content);


##Setzen der ACL
### Writing acl.auth.php
$aclc = $animalpath+"\conf\acl.auth.php"
Write-Host "Befülle die ACL $aclc"
$file= "acl.auth.php"
"# acl.auth.php" | Out-File $aclc 
"# <?php exit()?>" | Out-File $aclc -Append 
"# Don't modify the lines above" | Out-File $aclc -Append 
"# Access Control Lists" | Out-File $aclc -Append 
"*	@$($GroupAdmins -replace '-','%2d')	16" | Out-File $aclc -Append 
"*	@$($GroupManager -replace '-','%2d')	16" | Out-File $aclc -Append 
"*	@$($GroupEditor -replace '-','%2d')	8" | Out-File $aclc -Append 
"*	@$($GroupRead -replace '-','%2d')	1" | Out-File $aclc -Append 
$file_content = Get-Content "$aclc";
[System.IO.File]::WriteAllLines("$aclc", $file_content);

## Startseite
$startpage = $animalpath+"\data\pages\start.txt"
Write-Host "Befülle die Startseite"
"====== Willkommen im $Animal Wiki ======" |Out-File $startpage -Append
"===== Wichtiger Hinweis zur Nutzung der Wikis =====" |Out-File $startpage -Append
"Jede Änderung an einer Seite wird Protokolliert und ist eindeutig einer Person mit Zeitstempel zuordenbar. Bitte bedenken Sie dies beim Ändern oder hinzufügen von Inhalten, dass Ihre Kollegen dies sehen können. Den Zeitpunkt und Autor der letzten Änderung finden Sie unten Rechts. \\ \\ Sollte dies nicht gewünscht sein, empfehlen wir eine Zentrale Instanz zum ändern der Beträge, zum Beispiel ein Sekretariat. Eine Abschaltung dieser Funktion ist aus technischen Gründen nicht möglich." |Out-File $startpage -Append
"==== Handhabung des DokuWiki ====" |Out-File $startpage -Append
"  * [[wiki:syntax|DokuWiki Syntax]]" |Out-File $startpage -Append
"  * [[playground:playground|Spielplatz zum üben]]" |Out-File $startpage -Append

$file_content = Get-Content "$startpage"
[System.IO.File]::WriteAllLines("$startpage", $file_content)

##Setzten des NTFS Owner

<#  $owner = New-Object System.Security.Principal.NTAccount("steep\$GroupAdmins")
  Write-Host "Setze den NTFS Owner für $animalpath auf $owner"
  $Acl = $(get-Item $animalpath).GetAccessControl()
  $Acl.SetOwner($owner)
  set-acl -aclobject $Acl -path $animalpath

#Ownervererbung geht noch nicht !!!!!!
#>

## Anwender Infos
Write-Host ""
Write-Host "============================================================================="
Write-Host ""
Write-Host "Das $Animal Wiki ist nun unter http://wiki.domain.tld/$cleananimal/ erreichbar"
Write-Host "Für die Berechtigung bitte Gruppen verwenden, und keine Benutzer in die Gruppen $GroupEditor und $GroupRead "
Write-Host "Die Gruppen mit Leserechten fügen Sie bitte der Gruppe $GroupRead hinzu"
Write-Host "Die Gruppen mit Editierechten fügen Sie bitte der Gruppe $GroupEditor hinzu"
Write-Host "Die Gruppen mit Managementrechten fügen Sie bitte der Gruppe $GroupManager hinzu"
#Write-Host "Die Gruppen mit Adminrechten fügen Sie bitte der Gruppe $GroupAdmins hinzu, dies ist nur im Ausnahmefall zulässig."