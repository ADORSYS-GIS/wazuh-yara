# Set strict mode and define the error handling
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Variables
$logLevel = "INFO"
$tempDir = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath ([System.IO.Path]::GetRandomFileName())
$TEMP_DIR = $env:TEMP

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


# Function to download and extract YARA
function Download-YARA {
    # Determine the architecture
    $arch = if ([Environment]::Is64BitOperatingSystem) { "win64" } else { "win32" }
    $yaraVersion = "v4.5.2-2326"
    $yaraUrl = "https://github.com/VirusTotal/yara/releases/download/v4.5.2/yara-$yaraVersion-$arch.zip"
    
    # Download the appropriate YARA version
    Invoke-WebRequest -Uri $yaraUrl -OutFile "$env:TEMP\yara-$yaraVersion-$arch.zip"
    
    # Extract the downloaded archive
    Expand-Archive -Path "$env:TEMP\yara-$yaraVersion-$arch.zip" -DestinationPath "$env:TEMP" -Force
    
    # Remove the downloaded archive
    Remove-Item -Path "$env:TEMP\yara-$yaraVersion-$arch.zip"
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

    

    # Ensure valhallaAPI module is installed
try {
    pip show valhallaAPI -q
} catch {
    Write-Host "valhallaAPI module not found. Installing..." -ForegroundColor Yellow
    pip install valhallaAPI
}

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
try {
    Start-Process python.exe -ArgumentList "$env:TEMP\download_yara_rules.py" -Wait -NoNewWindow
} catch {
    Write-Host "Failed to run the Python script to download YARA rules: $_" -ForegroundColor Red
    exit 1
}

# Verify if the yara_rules.yar file exists
$yaraRulesPath = "$env:TEMP\yara_rules.yar"
if (Test-Path -Path $yaraRulesPath) {
    # Create YARA rules directory and copy the rules
    $rulesDir = "C:\Program Files (x86)\ossec-agent\active-response\bin\yara\rules"
    New-Item -ItemType Directory -Path $rulesDir -Force
    Copy-Item -Path $yaraRulesPath -Destination $rulesDir -Force
    Write-Host "YARA rules downloaded and copied to $rulesDir." -ForegroundColor Green
} else {
    Write-Host "Failed to download YARA rules. The file $yaraRulesPath does not exist." -ForegroundColor Red
    exit 1
}

    
    # Download yara.bat script
    $yaraBatURL = "https://raw.githubusercontent.com/ADORSYS-GIS/wazuh-yara/refs/heads/3-Windows-Agent-Install-Script/scripts/yara.bat"

    Invoke-WebRequest -Uri $yaraBatUrl -FilePath "C:\Program Files (x86)\ossec-agent\active-response\bin\yara.bat" -Encoding utf8
    

    # Update Wazuh agent configuration
    Update-WazuhConfig

    # Add YARA to the environment variables if not already present
    $yaraPath = "C:\Program Files (x86)\ossec-agent\active-response\bin\yara"
    $currentPath = [System.Environment]::GetEnvironmentVariable("Path", "Machine")
    if ($currentPath -notcontains $yaraPath) {
        [System.Environment]::SetEnvironmentVariable("Path", "$currentPath;$yaraPath", "Machine")
        Write-Host "YARA path added to environment variables." -ForegroundColor Green
    } else {
        Write-Host "YARA path already exists in environment variables." -ForegroundColor Yellow
    }
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