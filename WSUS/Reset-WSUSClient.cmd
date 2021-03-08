@Echo off
Echo ===WSUS Client reset by Fabian Niesen - www.infratrukturhelden.de ===
Echo Stopping BITS
net stop bits
ECHO =Stopping Windows Update Service=
net stop wuauserv
timeout /t 30 /nobreak
Echo =de-register wuaueng.dll=
%windir%\system32\regsvr32.exe /s /u wuaueng.dll
echo =Deleting AU cache...=
del /f /s /q %windir%\SoftwareDistribution\*.* 
del /f /s /q %windir%\windowsupdate.log
echo =Registering DLLs...=
%windir%\system32\regsvr32.exe /s %windir%\system32\wuaueng.dll
%windir%\system32\regsvr32.exe /s %windir%\system32\MSXML.DLL 
%windir%\system32\regsvr32.exe /s %windir%\system32\MSXML2.DLL 
%windir%\system32\regsvr32.exe /s %windir%\system32\MSXML3.DLL 
%windir%\system32\regsvr32.exe /s %windir%\system32\wups2.dll 
%windir%\system32\regsvr32.exe /s %windir%\system32\wuaueng1.dll
%windir%\system32\regsvr32.exe /s %windir%\system32\wuaueng.dll
%windir%\system32\regsvr32.exe /s %windir%\system32\wuapi.dll
%windir%\system32\regsvr32.exe /s %windir%\system32\atl.dll 
%windir%\system32\regsvr32.exe /s %windir%\system32\jscript.dll 
%windir%\system32\regsvr32.exe /s %windir%\system32\softpub.dll 
%windir%\system32\regsvr32.exe /s %windir%\system32\wuapi.dll 
%windir%\system32\regsvr32.exe /s %windir%\system32\wuaueng1.dll 
%windir%\system32\regsvr32.exe /s %windir%\system32\wucltui.dll 
%windir%\system32\regsvr32.exe /s %windir%\system32\wups.dll 
%windir%\system32\regsvr32.exe /s %windir%\system32\wuweb.dll 
ECHO =Cleaning registry...=
reg delete HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate /v AccountDomainSid /f
reg delete HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate /v PingID /f
reg delete HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate /v SusClientId /f
reg Delete HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate /v SusClientIDValidation /f
Echo =Starting BITS=
net start bits
ECHO =Starting Windows Update Services=
net start wuauserv
Timeout /t 30 /nobreak
ECHO =Reset Authorisation and Detect now=
wuauclt.exe /resetauthorization /detectnow
usoclient StartScan
Echo =Done...=
