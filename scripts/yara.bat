@echo off
setlocal enableDelayedExpansion

::------------------------- Gather parameters -------------------------::

:: Determine OS architecture (32-bit or 64-bit)
reg Query "HKLM\Hardware\Description\System\CentralProcessor\0" | find /i "x86" > NUL && SET OS=32BIT || SET OS=64BIT

:: Set log file path based on OS architecture
if %OS%==32BIT (
    SET log_file_path="%programfiles%\ossec-agent\active-response\active-responses.log"
) else (
    SET log_file_path="%programfiles(x86)%\ossec-agent\active-response\active-responses.log"
)

:: Read JSON input from stdin
set input=
for /f "delims=" %%a in ('PowerShell -command "$logInput = $input = $Host.UI.ReadLine(); Write-Output $input"') do (
    set input=%%a
)

:: Parse JSON to get the file path
set json_file_path="%TEMP%\stdin.txt"
echo %input% > %json_file_path%

set syscheck_file_path=
for /F "tokens=* USEBACKQ" %%F in (`Powershell -Nop -C "(Get-Content '%json_file_path%' | ConvertFrom-Json).parameters.alert.syscheck.path"`) do (
    set syscheck_file_path=%%F
    echo DEBUG: syscheck_file_path=!syscheck_file_path! >> %log_file_path%
)

del /f %json_file_path%

:: Set Yara paths
set yara_exe_path="C:\Program Files (x86)\ossec-agent\active-response\bin\yara\yara64.exe"
set yara_rules_path="C:\Program Files (x86)\ossec-agent\active-response\bin\yara\rules\yara_rules.yar"

:: Log the file being scanned
echo Scanning file: !syscheck_file_path! >> %log_file_path%

::------------------------- Execution Policy Handling -----------------------::

:: Store the current execution policy
for /f "tokens=*" %%P in ('powershell -command "Get-ExecutionPolicy -Scope CurrentUser"') do (
    set original_policy=%%P
)

:: Set execution policy to RemoteSigned if more restrictive
powershell -command "if ((Get-ExecutionPolicy -Scope CurrentUser) -eq 'Restricted') { Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser -Force }"

::------------------------- Notification Function -----------------------::

:: Function to send a notification using PowerShell's BurntToast
:send_notification
setlocal
set message=%~1
set title=Wazuh Alert
set appIconPath="C:\ProgramData\ossec-agent\wazuh-logo.png"

:: Check if BurntToast module is available
powershell -command "if (-not (Get-Module -ListAvailable -Name BurntToast)) { Write-Output 'WARNING: BurntToast module not found. Please install it using: Install-Module -Name BurntToast -Force -Scope CurrentUser' >> %log_file_path% } else { Import-Module BurntToast; New-BurntToastNotification -AppLogo %appIconPath% -Text '%title%', '%message%' }"
endlocal
goto :eof

::------------------------- Main workflow --------------------------::

:: Execute Yara scan on the specified file
set malware_detected=false
set scan_results=
for /f "delims=" %%a in ('powershell -command "& %yara_exe_path% %yara_rules_path% !syscheck_file_path!"') do (
    echo wazuh-yara: INFO - Scan result: %%a >> %log_file_path%
    set scan_results=!scan_results!%%a\n
    if "%%a" NEQ "" (
        set malware_detected=true
    )
)

:: If malware is detected, send a notification and log the results
if !malware_detected! == true (
    echo wazuh-yara: INFO - Malware detected in file: !syscheck_file_path! >> %log_file_path%
    call :send_notification "Yara scan results:\n\n!scan_results!"
)

::------------------------- Restore Execution Policy -----------------------::

:: Restore the original execution policy
powershell -command "Set-ExecutionPolicy -ExecutionPolicy !original_policy! -Scope CurrentUser -Force"

:: Clean up and exit
exit /b