# Set strict mode and define the error handling
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Variables
$TEMP_DIR = $env:TEMP

# Function to handle logging

function Log {
    param (
        [string]$Level,
        [string]$Message,
        [string]$Color = "White"  # Default color
    )
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "$Timestamp $Level $Message" -ForegroundColor $Color
}

# Logging helpers with colors
function InfoMessage {
    param ([string]$Message)
    Log "[INFO]" $Message "White"
}

function WarnMessage {
    param ([string]$Message)
    Log "[WARNING]" $Message "Yellow"
}

function ErrorMessage {
    param ([string]$Message)
    Log "[ERROR]" $Message "Red"
}

function SuccessMessage {
    param ([string]$Message)
    Log "[SUCCESS]" $Message "Green"
}

function PrintStep {
    param (
        [int]$StepNumber,
        [string]$Message
    )
    Log "[STEP]" "Step ${StepNumber}: $Message" "White"
}

# Exit script with an error message
function ErrorExit {
    param ([string]$Message)
    ErrorMessage $Message
    exit 1
}

# Function to clean up temporary files
function Cleanup {
    InfoMessage "Cleaning up temporary files..."

    Remove-Item -Path "$TEMP_DIR\yara64.exe" -Force -Recurse -ErrorAction SilentlyContinue
    Remove-Item -Path "$TEMP_DIR\yarac64.exe" -Force -Recurse -ErrorAction SilentlyContinue
    Remove-Item -Path "$TEMP_DIR\yara_rules.yar" -Force -Recurse -ErrorAction SilentlyContinue
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

# Helper to verify that the installed YARA version is in the 4.5.x family
function Test-YaraVersionCompatible {
    param ([string]$Version)

    if ([string]::IsNullOrWhiteSpace($Version)) {
        return $false
    }

    if ($Version -match '([0-9]+)\.([0-9]+)') {
        $major = $Matches[1]
        $minor = $Matches[2]
        return ($major -eq "4" -and $minor -eq "5")
    }

    return $false
}

# Function to install YARA
function Install-YARA {
    Ensure-Admin

    # Download and extract YARA
    Download-YARA

    # Create YARA directory and copy executable
    $yaraDir = "C:\Program Files (x86)\ossec-agent\active-response\bin\yara"
    New-Item -ItemType Directory -Path $yaraDir -Force
    Copy-Item -Path "$env:TEMP\yara64.exe" -Destination $yaraDir

    # Download Yara Rules
    $yaraRulesUrl = "https://raw.githubusercontent.com/ADORSYS-GIS/wazuh-yara/refs/heads/main/rules/yara_rules.yar"
    
    # Define the file path to save the YARA rules
    $yaraRulesFile = "$env:TEMP\yara_rules.yar"
    
    # Download the YARA rules file
    try {
        InfoMessage "Downloading YARA rules from GitHub..."
        Invoke-WebRequest -Uri $yaraRulesUrl -OutFile $yaraRulesFile -UseBasicParsing
        InfoMessage "YARA rules saved to $yaraRulesFile" 
    } catch {
        ErrorMessage "Failed to download YARA rules: $_" 
        exit 1
    }

# Verify if the yara_rules.yar file exists
$yaraRulesPath = "$env:TEMP\yara_rules.yar"
if (Test-Path -Path $yaraRulesPath) {
    # Create YARA rules directory and copy the rules
    $rulesDir = "C:\Program Files (x86)\ossec-agent\active-response\bin\yara\rules"
    New-Item -ItemType Directory -Path $rulesDir -Force
    Copy-Item -Path $yaraRulesPath -Destination $rulesDir -Force
    InfoMessage "YARA rules downloaded and copied to $rulesDir." 
} else {
    ErrorMessage "Failed to download YARA rules. The file $yaraRulesPath does not exist." -ForegroundColor Red
    exit 1
}

    #Download the yara.bat script
    $yaraBatURL = "https://raw.githubusercontent.com/ADORSYS-GIS/wazuh-yara/refs/heads/main/scripts/yara.bat"
    $yaraBatDir =  "C:\Program Files (x86)\ossec-agent\active-response\bin\yara.bat"
    
    
    # Download the appropriate YARA version
    Invoke-WebRequest -Uri $yaraBatURL -OutFile $yaraBatDir
    InfoMessage "Yara Bat Script Downloaded and copied into $yaraBatDir "

    # Update Wazuh agent configuration
    Update-WazuhConfig

    # Add YARA to the environment variables if not already present
    $yaraPath = "C:\Program Files (x86)\ossec-agent\active-response\bin\yara"
    $currentPath = [System.Environment]::GetEnvironmentVariable("Path", "Machine")
    if ($currentPath -notcontains $yaraPath) {
        [System.Environment]::SetEnvironmentVariable("Path", "$currentPath;$yaraPath", "Machine")
        InfoMessage "YARA path added to environment variables." 
    } else {
        WarnMessage "YARA path already exists in environment variables." 
    }

    # Validate final installation artifacts
    Validate-Installation
}

# Function to update Wazuh agent configuration
function Update-WazuhConfig {
    $userName = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name.Split('\')[1]
    $configFilePath = "C:\Program Files (x86)\ossec-agent\ossec.conf"

    [xml]$configXml = Get-Content -Path $configFilePath

    $syscheckNode = $configXml.ossec_config.syscheck

    if ($null -ne $syscheckNode) {
        $existingNode = $syscheckNode.directories | Where-Object { $_.InnerText -eq "C:\Users\$userName\Downloads" }

        if ($null -eq $existingNode) {
            $newDirectoryNode = $configXml.CreateElement("directories")
            $newDirectoryNode.SetAttribute("realtime", "yes")
            $newDirectoryNode.InnerText = "C:\Users\$userName\Downloads"
            $syscheckNode.AppendChild($newDirectoryNode) | Out-Null
            $configXml.Save($configFilePath)
            InfoMessage "Directory C:\Users\$userName\Downloads added to syscheck configuration."
        } else {
            InfoMessage "Directory C:\Users\$userName\Downloads is already in the syscheck configuration."
        }

        $existingFileLimitNode = $syscheckNode.SelectSingleNode("file_limit") 

        if ($existingFileLimitNode -eq $null) {
            InfoMessage "Adding file_limit to Wazuh agent configuration..." 
            try {
                $fileLimitNode = $configXml.CreateElement("file_limit")
                $enabledNode = $configXml.CreateElement("enabled")
                $enabledNode.InnerText = "no"
                $fileLimitNode.AppendChild($enabledNode) | Out-Null
                $syscheckNode.AppendChild($fileLimitNode) | Out-Null
                $configXml.Save($configFilePath)
                InfoMessage "file_limit added to syscheck configuration." 
            } catch {
                WarnMessage "Failed to add file_limit to syscheck configuration: $_" 
                exit 1
            }
        } else {
            InfoMessage "file_limit is already in the syscheck configuration." 
        }
    } else {
        ErrorMessage "<syscheck> node not found in the configuration file." 
    }
    
     # Update frequency value in the configuration file
    $configFilePath = "C:\Program Files (x86)\ossec-agent\ossec.conf"
    if (-Not (Test-Path $configFilePath)) { ErrorMessage "Config file not found." }

    [xml]$configXml = Get-Content -Path $configFilePath
    $frequencyNode = $configXml.ossec_config.SelectSingleNode("//frequency")

    if ($frequencyNode) {
        if ($frequencyNode.InnerText -in "300", "43200") { $frequencyNode.InnerText = "21600" }
        SuccessMessage "Frequency updated successfully in Wazuh agent configuration file."
    } else {
        InfoMessage "No frequency updates were necessary."
        $newNode = $configXml.CreateElement("frequency")
        $newNode.InnerText = "21600"
        $configXml.ossec_config.AppendChild($newNode) | Out-Null
    }

    # Save the modified XML file
    $configXml.Save($configFilePath)


    Restart-Service -Name WazuhSvc
    SuccessMessage "Configuration completed successfully." 
}

# Function to validate the YARA installation artifacts and configuration
function Validate-Installation {
    $validationStatus = $true

    $yaraDir = "C:\Program Files (x86)\ossec-agent\active-response\bin\yara"
    $yaraExe = Join-Path $yaraDir "yara64.exe"
    $rulesPath = Join-Path $yaraDir "rules\yara_rules.yar"
    $yaraBatPath = "C:\Program Files (x86)\ossec-agent\active-response\bin\yara.bat"

    InfoMessage "Validating YARA installation..."
    if (Test-Path -Path $yaraExe) {
        try {
            $installedVersion = & $yaraExe --version 2>$null

            if (Test-YaraVersionCompatible -Version $installedVersion) {
                SuccessMessage "YARA executable found. Version $installedVersion is compatible (4.5.x)."
            } else {
                WarnMessage "YARA version $installedVersion is not in the supported 4.5.x series."
                $validationStatus = $false
            }
        } catch {
            ErrorMessage "Unable to determine YARA version from $yaraExe. $_"
            $validationStatus = $false
        }
    } else {
        ErrorMessage "YARA executable not found at $yaraExe."
        $validationStatus = $false
    }

    if (Test-Path -Path $rulesPath) {
        SuccessMessage "YARA rules file found at $rulesPath."
    } else {
        WarnMessage "YARA rules file is missing at $rulesPath."
        $validationStatus = $false
    }

    if (Test-Path -Path $yaraBatPath) {
        SuccessMessage "yara.bat script found at $yaraBatPath."
    } else {
        WarnMessage "yara.bat script is missing at $yaraBatPath."
        $validationStatus = $false
    }

    if ($validationStatus) {
        SuccessMessage "YARA installation and configuration validated successfully."
    } else {
        ErrorMessage "YARA installation validation failed. See warnings above."
        exit 1
    }
}

try {
    Install-YARA
} finally {
    Cleanup
    InfoMessage "Temporary files cleaned up."
}