# Set strict mode and define the error handling
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Variables
$logLevel = "INFO"
$tempDir = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath ([System.IO.Path]::GetRandomFileName())


# Function to handle logging
function Log {
    param(
        [string]$level,
        [string]$message
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    if ($level -eq "ERROR" -or ($level -eq "WARNING" -and $logLevel -ne "ERROR") -or ($level -eq "INFO" -and $logLevel -eq "INFO")) {
        Write-Host "$timestamp [$level] $message"
    }
}

# Function to print steps
function Print-Step {
    param(
        [int]$step,
        [string]$message
    )

    Log "INFO" "------ Step $step : $message ------"
}

# Function to clean up temporary files
function Cleanup {
    Log "INFO" "Cleaning up temporary files..."
    Remove-Item -Path $tempDir -Force -Recurse -ErrorAction SilentlyContinue
}

# Function to check if the script is running with administrator privileges
function Ensure-Admin {
    if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
        Write-Host "Please run this script as an Administrator." -ForegroundColor Red
        exit
    }
}

# Function to check if Python is installed and has the correct version
function Check-PythonInstalled {
    try {
        $pythonVersion = & python --version 2>&1
        if ($pythonVersion -match "Python (\d+)\.(\d+)\.(\d+)") {
            $majorVersion = [int]$matches[1]
            $minorVersion = [int]$matches[2]
            $patchVersion = [int]$matches[3]
            
            if ($majorVersion -ge 3 -and $minorVersion -ge 9) {
                Write-Host "Python $majorVersion.$minorVersion.$patchVersion is installed and is a recent version." -ForegroundColor Green
                return $true
            } else {
                Write-Host "Python version is $majorVersion.$minorVersion.$patchVersion. Please install Python 3.9 or later and run the script again." -ForegroundColor Red
                exit
            }
        } else {
            throw "Python is not installed or not properly configured."
        }
    } catch {
        Write-Host "Python is not installed or not properly configured. Installing Python..." -ForegroundColor Yellow
        $pythonInstallerPath = Join-Path -Path $tempDir -ChildPath "python-3.9.0-amd64.exe"
        Invoke-WebRequest -Uri "https://www.python.org/ftp/python/3.9.0/python-3.9.0-amd64.exe" -OutFile $pythonInstallerPath
        Start-Process -FilePath $pythonInstallerPath -ArgumentList "/quiet InstallAllUsers=1 PrependPath=1" -Wait
        Remove-Item -Path $pythonInstallerPath

        # Update environment variables
        [System.Environment]::SetEnvironmentVariable("Path", [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";C:\Program Files\Python39", "Process")

        # Update pip to the latest version
        try {
            & python -m pip install --upgrade pip
        } catch {
            Write-Error "Failed to update pip: $_"
            exit 1
        }
    }
}

# Function to check if Visual C++ Redistributable is installed
function Check-VCppInstalled {
    $vcppKey = "HKLM:\SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\x64"
    if (Test-Path $vcppKey) {
        $vcppInstalled = Get-ItemProperty -Path $vcppKey
        if ($vcppInstalled -and $vcppInstalled.Installed -eq 1) {
            Write-Host "Visual C++ Redistributable is installed." -ForegroundColor Green
            return $true
        }
    }
    Write-Host "Visual C++ Redistributable is not installed. Installing Visual C++ Redistributable..." -ForegroundColor Yellow
    Invoke-WebRequest -Uri "https://aka.ms/vs/16/release/vc_redist.x64.exe" -OutFile "$env:TEMP\vc_redist.x64.exe"
    Start-Process -FilePath "$env:TEMP\vc_redist.x64.exe" -ArgumentList "/quiet /install" -Wait
    Remove-Item -Path "$env:TEMP\vc_redist.x64.exe"
}

# Function to download and extract YARA
function Download-YARA {
    Invoke-WebRequest -Uri "https://github.com/VirusTotal/yara/releases/download/v4.2.3/yara-4.2.3-2029-win64.zip" -OutFile "$env:TEMP\yara-4.2.3-2029-win64.zip"
    Expand-Archive -Path "$env:TEMP\yara-4.2.3-2029-win64.zip" -DestinationPath "$env:TEMP" -Force
    Remove-Item -Path "$env:TEMP\yara-4.2.3-2029-win64.zip"
}

# Function to install YARA
function Install-YARA {
    Ensure-Admin

    # Check for Python and Visual C++ Redistributable
    Check-PythonInstalled
    Check-VCppInstalled

    # Download and extract YARA
    Download-YARA

    # Create YARA directory and copy executable
    $yaraDir = "C:\Program Files (x86)\ossec-agent\active-response\bin\yara"
    New-Item -ItemType Directory -Path $yaraDir -Force
    Copy-Item -Path "$env:TEMP\yara64.exe" -Destination $yaraDir

    # Install valhallaAPI module
    pip install valhallaAPI

    # Create and save the Python script to download YARA rules
    $pythonScript = @"
from valhallaAPI.valhalla import ValhallaAPI

v = ValhallaAPI(api_key='1111111111111111111111111111111111111111111111111111111111111111')
response = v.get_rules_text()

with open('yara_rules.yar', 'w') as fh:
    fh.write(response)
"@
    $pythonScript | Out-File -FilePath "$env:TEMP\download_yara_rules.py" -Encoding utf8

    # Run the Python script to download YARA rules
    python.exe "$env:TEMP\download_yara_rules.py"

    # Create YARA rules directory and copy the rules
    $rulesDir = "C:\Program Files (x86)\ossec-agent\active-response\bin\yara\rules"
    New-Item -ItemType Directory -Path $rulesDir -Force
    Copy-Item -Path "$env:TEMP\yara_rules.yar" -Destination $rulesDir

    # Create the yara.bat script
    $yaraBatContent = @"
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
    echo DEBUG: syscheck_file_path=!syscheck_file_path! >> %log_file_path%
)

del /f %json_file_path%
set yara_exe_path="C:\Program Files (x86)\ossec-agent\active-response\bin\yara\yara64.exe"
set yara_rules_path="C:\Program Files (x86)\ossec-agent\active-response\bin\yara\rules\yara_rules.yar"
echo !syscheck_file_path! >> %log_file_path%

set malware_detected=false
for /f "delims=" %%a in ('powershell -command "& \"%yara_exe_path%\" \"%yara_rules_path%\" \"%syscheck_file_path%\""') do (
    echo wazuh-yara: INFO - Scan result: %%a >> %log_file_path%
    if "%%a" NEQ "0" (
        set malware_detected=true
        echo DEBUG: malware_detected=!malware_detected! >> %log_file_path%
    )
)

if !malware_detected! == true (
    del /f !syscheck_file_path!
    echo wazuh-yara: INFO - Malware file !syscheck_file_path! removed >> %log_file_path%
)

exit /b
"@
    $yaraBatContent | Out-File -FilePath "C:\Program Files (x86)\ossec-agent\active-response\bin\yara.bat" -Encoding utf8

    # Update Wazuh agent configuration
    Update-WazuhConfig
}

# Function to update Wazuh agent configuration
function Update-WazuhConfig {
    $userName = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name.Split('\')[1]
    $configFilePath = "C:\Program Files (x86)\ossec-agent\ossec.conf"

    [xml]$configXml = Get-Content -Path $configFilePath

    $syscheckNode = $configXml.ossec_config.syscheck

    if ($syscheckNode -ne $null) {
        $existingNode = $syscheckNode.directories | Where-Object { $_.InnerText -eq "C:\Users\$userName\Downloads" }

        if ($existingNode -eq $null) {
            $newDirectoryNode = $configXml.CreateElement("directories")
            $newDirectoryNode.SetAttribute("realtime", "yes")
            $newDirectoryNode.InnerText = "C:\Users\$userName\Downloads"
            $syscheckNode.AppendChild($newDirectoryNode) | Out-Null
            $configXml.Save($configFilePath)
            Write-Output "Directory C:\Users\$userName\Downloads added to syscheck configuration."
        } else {
            Write-Output "Directory C:\Users\$userName\Downloads is already in the syscheck configuration."
        }

        $existingNode = $syscheckNode.file_limit

        if ($existingNode -eq $null) {
            Write-Host "Adding file_limit to Wazuh agent configuration..." -ForegroundColor Yellow
            try {
                $fileLimitNode = $configXml.CreateElement("file_limit")
                $enabledNode = $configXml.CreateElement("enabled")
                $enabledNode.InnerText = "no"
                $fileLimitNode.AppendChild($enabledNode) | Out-Null
                $syscheckNode.AppendChild($fileLimitNode) | Out-Null
                $configXml.Save($configFilePath)
                Write-Host "file_limit added to syscheck configuration." -ForegroundColor Green
            } catch {
                Write-Host "Failed to add file_limit to syscheck configuration: $_" -ForegroundColor Red
                exit 1
            }
        } else {
            Write-Host "file_limit is already in the syscheck configuration." -ForegroundColor Green
        }
    } else {
        Write-Host "<syscheck> node not found in the configuration file." -ForegroundColor Red
    }

    Restart-Service -Name WazuhSvc
    Write-Host "Configuration completed successfully." -ForegroundColor Green
}

try {
    Install-YARA
} finally {
    Cleanup
    Log "INFO" "Temporary files cleaned up."
}
