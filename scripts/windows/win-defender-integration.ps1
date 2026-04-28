# Set strict mode and define the error handling
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Variables
if (-not $env:WAZUH_YARA_REPO_REF) { 
    $env:WAZUH_YARA_REPO_REF = "main"
}
$WAZUH_YARA_REPO_REF = $env:WAZUH_YARA_REPO_REF
$WAZUH_YARA_REPO_URL = "https://raw.githubusercontent.com/ADORSYS-GIS/wazuh-yara/$WAZUH_YARA_REPO_REF"

# Source shared utilities
$TEMP_DIR = $env:TEMP
try {
    $ChecksumsURL = "$WAZUH_YARA_REPO_URL/checksums.sha256"
    $UtilsURL = "$WAZUH_YARA_REPO_URL/scripts/shared/utils.ps1"
    
    $global:ChecksumsPath = Join-Path $TEMP_DIR "checksums.sha256"
    $UtilsPath = Join-Path $TEMP_DIR "utils.ps1"

    Invoke-WebRequest -Uri $ChecksumsURL -OutFile $ChecksumsPath -ErrorAction Stop
    Invoke-WebRequest -Uri $UtilsURL -OutFile $UtilsPath -ErrorAction Stop

    # Verification function (bootstrap)
    function Get-FileChecksum-Bootstrap {
        param([string]$FilePath)
        return (Get-FileHash -Path $FilePath -Algorithm SHA256).Hash.ToLower()
    }

    $ExpectedHash = (Select-String -Path $ChecksumsPath -Pattern "scripts/shared/utils.ps1").Line.Split(" ")[0]
    $ActualHash = Get-FileChecksum-Bootstrap -FilePath $UtilsPath

    if ([string]::IsNullOrWhiteSpace($ExpectedHash) -or ($ActualHash -ne $ExpectedHash.ToLower())) {
        Write-Error "Checksum verification failed for utils.ps1"
        exit 1
    }

    . $UtilsPath
}
catch {
    Write-Error "Failed to initialize utilities: $($_.Exception.Message)"
    exit 1
}

# Function to uninstall YARA using the provided script
function Uninstall-YARA {
    $uninstallScriptUrl = "$WAZUH_YARA_REPO_URL/scripts/windows/uninstall.ps1"
    $tempScriptPath = "$env:TEMP\uninstall-yara.ps1"
    
    try {
        InfoMessage "Downloading YARA uninstall script..."
        Download-And-VerifyFile -Url $uninstallScriptUrl -Destination $tempScriptPath -ChecksumPattern "scripts/windows/uninstall.ps1" -FileName "YARA uninstall script" -ChecksumUrl $WAZUH_YARA_REPO_URL/checksums.sha256
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