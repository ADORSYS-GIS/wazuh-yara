@echo off

setlocal enableDelayedExpansion

reg Query "HKLM\Hardware\Description\System\CentralProcessor\0" | find /i "x86" > NUL && SET OS=32BIT || SET OS=64BIT


if %OS%==32BIT (
    SET log_file_path="%programfiles%\ossec-agent\active-response\active-responses.log"
)

if %OS%==64BIT (
    SET log_file_path="%programfiles(x86)%\ossec-agent\active-response\active-responses.log"
)

set input=
for /f "delims=" %%a in ('PowerShell -command "$logInput = Read-Host; Write-Output $logInput"') do (
    set input=%%a
)


set json_file_path="C:\Program Files (x86)\ossec-agent\active-response\stdin.txt"
set syscheck_file_path=
echo %input% > %json_file_path%

for /F "tokens=* USEBACKQ" %%F in (`Powershell -Nop -C "(Get-Content 'C:\Program Files (x86)\ossec-agent\active-response\stdin.txt'|ConvertFrom-Json).parameters.alert.syscheck.path"`) do (
set syscheck_file_path=%%F
)

del /f %json_file_path%
set yara_exe_path="C:\Program Files (x86)\ossec-agent\active-response\bin\yara\yara64.exe"
set yara_rules_path="C:\Program Files (x86)\ossec-agent\active-response\bin\yara\rules\yara-rules-core.yar"

::--------------------------Main Workflow------------------------------------::
:: Execute Yara scan on the specified file
set "message=Yara Scan Results:"
set malware_detected=false
for /f "tokens=1,* delims= " %%a in ('powershell -command "& \"%yara_exe_path%\" \"%yara_rules_path%\" \"%syscheck_file_path%\""') do (
    echo wazuh-yara: INFO - Scan result: %%a %%b >> %log_file_path%
    set "message=%message%; Malware: %%a File: %%b"
    if "%%a" NEQ "" (
        set malware_detected=true
    )
)
:: If malware is detected, send a notification and log the results
if !malware_detected! == true (
    call :Notify-User "Wazuh Alert" "%message%"
)

goto:eof
::-------------------------------- Notification Function--------------------------::

:: Function to send a toast notification
:Notify-User
setlocal
set "title=%~1"
set "message=%~2"
set "iconPath=C:\ProgramData\ossec-agent\wazuh-logo.png"

:: Use PowerShell to get the logged-in user's session ID and username
for /f "tokens=*" %%a in ('powershell -Command "(Get-Process -IncludeUserName -Name explorer | Select-Object -First 1).SessionId"') do (
    set "sessionId=%%a"
)
for /f "tokens=*" %%a in ('powershell -Command "(Get-Process -IncludeUserName -Name explorer | Select-Object -First 1).UserName"') do (
    set "username=%%a"
)

:: Check if a session ID was found
if "%sessionId%"=="" (
    echo No logged-in user session found. Logging to Event Log.
    goto:end
)

:: If a session ID and username were found, create a scheduled task to run the notification in the user's session
echo Sending notification in user session (Username: %username%, Session ID: %sessionId%).

:: Create a temporary PowerShell script to send the notification
set "psScript=%TEMP%\send_notification.ps1"
echo Import-Module BurntToast; > "%psScript%"
echo if (Test-Path '%iconPath%') { >> "%psScript%"
echo     New-BurntToastNotification -Text '%title%', '%message%' -AppLogo '%iconPath%'; >> "%psScript%"
echo } else { >> "%psScript%"
echo     New-BurntToastNotification -Text '%title%', '%message%'; >> "%psScript%"
echo } >> "%psScript%"


:: Create a scheduled task to run the PowerShell script in the user's context
set "taskName=WazuhNotificationTask"
schtasks /create /tn "%taskName%" /sc once /st 00:00 /ru "%username%" /rl highest /tr "powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -File \"%psScript%\"" /f

:: Run the scheduled task immediately
schtasks /run /tn "%taskName%"

:: Delete the scheduled task after it runs
schtasks /delete /tn "%taskName%" /f

:: Delete the temporary PowerShell script
:: del "%psScript%"

echo Notification sent via BurntToast: %message% >> "%TEMP%\wazuh_notifications.log"

:end
endlocal

goto:eof
