# Set strict mode and define the error handling
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Function to handle logging
function Log {
    param (
        [string]$Level,
        [string]$Message,
        [string]$Color = "White"
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

# Function to check if the script is running with administrator privileges
function Ensure-Admin {
    if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
        ErrorMessage "This script requires Administrator privileges. Please run as Administrator."
        exit 1
    }
}

# Function to uninstall YARA using the provided script
function Uninstall-YARA {
    $uninstallScriptUrl = "https://raw.githubusercontent.com/ADORSYS-GIS/wazuh-yara/refs/heads/main/scripts/uninstall.ps1"
    $tempScriptPath = "$env:TEMP\uninstall-yara.ps1"
    
    try {
        InfoMessage "Downloading YARA uninstall script..."
        Invoke-WebRequest -Uri $uninstallScriptUrl -OutFile $tempScriptPath -UseBasicParsing
    } catch {
        ErrorMessage "Failed to download uninstall script: $_"
        return $false
    }
    
    if (Test-Path $tempScriptPath) {
        try {
            InfoMessage "Executing YARA uninstallation..."
            & $tempScriptPath
            SuccessMessage "YARA uninstallation completed."
            return $true
        } catch {
            ErrorMessage "Error executing uninstall script: $_"
            return $false
        } finally {
            InfoMessage "Cleaning up uninstall script..."
            Remove-Item -Path $tempScriptPath -Force -ErrorAction SilentlyContinue
        }
    } else {
        ErrorMessage "Uninstall script download failed."
        return $false
    }
}

# Function to add Windows Defender log monitoring
function Add-DefenderMonitoring {
    $configFilePath = "C:\Program Files (x86)\ossec-agent\ossec.conf"
    
    # Verify config file exists
    if (-not (Test-Path $configFilePath)) {
        ErrorMessage "Wazuh configuration file not found at $configFilePath"
        return $false
    }

    # Load XML configuration
    try {
        [xml]$configXml = Get-Content -Path $configFilePath
    } catch {
        ErrorMessage "Failed to parse configuration file: $_"
        return $false
    }
    
    # Check if <syscheck> node exists and add file_limit if not present
    $syscheckNode = $configXml.ossec_config.syscheck
    if ($null -ne $syscheckNode) {
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

    # Check if Windows Defender monitoring already exists
    $defenderExists = $false
    foreach ($node in $configXml.ossec_config.localfile) {
        if ($node.location -eq "Microsoft-Windows-Windows Defender/Operational") {
            $defenderExists = $true
            InfoMessage "Windows Defender monitoring is already configured."
            break
        }
    }

    # Add configuration if missing
    if (-not $defenderExists) {
        try {
            # Create new XML node
            $newNode = $configXml.CreateElement("localfile")
            
            $locationElement = $configXml.CreateElement("location")
            $locationElement.InnerText = "Microsoft-Windows-Windows Defender/Operational"
            $newNode.AppendChild($locationElement) | Out-Null
            
            $formatElement = $configXml.CreateElement("log_format")
            $formatElement.InnerText = "eventchannel"
            $newNode.AppendChild($formatElement) | Out-Null
            
            $configXml.ossec_config.AppendChild($newNode) | Out-Null
            $configXml.Save($configFilePath)
            SuccessMessage "Added Windows Defender monitoring to configuration."
            return $true
        } catch {
            ErrorMessage "Failed to update configuration: $_"
            return $false
        }
    }
    return $true
}

# Function to restart Wazuh service
function Restart-WazuhService {
    try {
        $service = Get-Service -Name WazuhSvc -ErrorAction Stop
        if ($service.Status -eq 'Running') {
            InfoMessage "Restarting Wazuh service..."
            Restart-Service -Name WazuhSvc -Force
            # Wait for service to stabilize
            Start-Sleep -Seconds 10
            $newStatus = (Get-Service -Name WazuhSvc).Status
            if ($newStatus -eq 'Running') {
                SuccessMessage "Wazuh service restarted successfully."
                return $true
            } else {
                WarnMessage "Wazuh service is in unexpected state: $newStatus"
                return $false
            }
        } else {
            WarnMessage "Wazuh service is not running. Current state: $($service.Status)"
            return $false
        }
    } catch {
        ErrorMessage "Failed to restart Wazuh service: $_"
        return $false
    }
}

# Main script execution
Ensure-Admin

# Step 1: Uninstall YARA
$yaraRemoved = Uninstall-YARA

# Step 2: Add Defender monitoring
$defenderAdded = Add-DefenderMonitoring

# Step 3: Restart service if changes were made
if ($yaraRemoved -or $defenderAdded) {
    $restartSuccess = Restart-WazuhService
    if ($restartSuccess) {
        SuccessMessage "All operations completed successfully."
    } else {
        WarnMessage "Operations completed but service restart had issues."
    }
} else {
    InfoMessage "No changes made. Wazuh configuration remains unchanged."
}