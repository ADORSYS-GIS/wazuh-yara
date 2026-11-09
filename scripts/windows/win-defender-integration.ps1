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

    $script:ChecksumsPath = Join-Path $TEMP_DIR "checksums.sha256"
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
        InfoMessage -Message "Downloading YARA uninstall script..."
        Get-And-VerifyFile -Url $uninstallScriptUrl -Destination $tempScriptPath -ChecksumPattern "scripts/windows/uninstall.ps1" -FileName "YARA uninstall script" -ChecksumUrl $WAZUH_YARA_REPO_URL/checksums.sha256
    } catch {
        ErrorMessage -Message "Failed to download uninstall script: $_"
        return $false
    }

    if (Test-Path $tempScriptPath) {
        try {
            InfoMessage -Message "Executing YARA uninstallation..."
            & $tempScriptPath
            SuccessMessage -Message "YARA uninstallation completed."
            return $true
        } catch {
            ErrorMessage -Message "Error executing uninstall script: $_"
            return $false
        } finally {
            InfoMessage -Message "Cleaning up uninstall script..."
            Remove-Item -Path $tempScriptPath -Force -ErrorAction SilentlyContinue
        }
    } else {
        ErrorMessage -Message "Uninstall script download failed."
        return $false
    }
}

# Function to add a <file_limit> node to the syscheck configuration if missing
function Add-FileLimitMonitoring {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
        [xml]$ConfigXml,
        [string]$ConfigFilePath
    )
    $syscheckNode = $ConfigXml.ossec_config.syscheck
    if ($null -eq $syscheckNode) {
        ErrorMessage -Message "<syscheck> node not found in the configuration file."
        return
    }

    $existingFileLimitNode = $syscheckNode.SelectSingleNode("file_limit")
    if ($null -eq $existingFileLimitNode) {
        InfoMessage -Message "Adding file_limit to Wazuh agent configuration..."
        try {
            $fileLimitNode = $ConfigXml.CreateElement("file_limit")
            $enabledNode = $ConfigXml.CreateElement("enabled")
            $enabledNode.InnerText = "no"
            $fileLimitNode.AppendChild($enabledNode) | Out-Null
            $syscheckNode.AppendChild($fileLimitNode) | Out-Null
            $ConfigXml.Save($ConfigFilePath)
            InfoMessage -Message "file_limit added to syscheck configuration."
        } catch {
            WarnMessage -Message "Failed to add file_limit to syscheck configuration: $_"
            exit 1
        }
    } else {
        InfoMessage -Message "file_limit is already in the syscheck configuration."
    }
}

# Function to add Windows Defender log monitoring
function Add-DefenderMonitoring {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param()
    $configFilePath = "C:\Program Files (x86)\ossec-agent\ossec.conf"

    # Verify config file exists
    if (-not (Test-Path $configFilePath)) {
        ErrorMessage -Message "Wazuh configuration file not found at $configFilePath"
        return $false
    }

    # Load XML configuration
    try {
        [xml]$configXml = Get-Content -Path $configFilePath
    } catch {
        ErrorMessage -Message "Failed to parse configuration file: $_"
        return $false
    }

    # Check if <syscheck> node exists and add file_limit if not present
    Add-FileLimitMonitoring -ConfigXml $configXml -ConfigFilePath $configFilePath

    # Check if Windows Defender monitoring already exists
    $defenderExists = $false
    foreach ($node in $configXml.ossec_config.localfile) {
        if ($node.location -eq "Microsoft-Windows-Windows Defender/Operational") {
            $defenderExists = $true
            InfoMessage -Message "Windows Defender monitoring is already configured."
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
            SuccessMessage -Message "Added Windows Defender monitoring to configuration."
            return $true
        } catch {
            ErrorMessage -Message "Failed to update configuration: $_"
            return $false
        }
    }
    return $true
}

# Function to restart Wazuh service
function Restart-WazuhService {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param()
    try {
        $service = Get-Service -Name WazuhSvc -ErrorAction Stop
        if ($service.Status -eq 'Running') {
            InfoMessage -Message "Restarting Wazuh service..."
            Restart-Service -Name WazuhSvc -Force
            # Wait for service to stabilize
            Start-Sleep -Seconds 10
            $newStatus = (Get-Service -Name WazuhSvc).Status
            if ($newStatus -eq 'Running') {
                SuccessMessage -Message "Wazuh service restarted successfully."
                return $true
            } else {
                WarnMessage -Message "Wazuh service is in unexpected state: $newStatus"
                return $false
            }
        } else {
            WarnMessage -Message "Wazuh service is not running. Current state: $($service.Status)"
            return $false
        }
    } catch {
        ErrorMessage -Message "Failed to restart Wazuh service: $_"
        return $false
    }
}

# Main script execution
Test-AdminPrivilege

# Step 1: Uninstall YARA
$yaraRemoved = Uninstall-YARA

# Step 2: Add Defender monitoring
$defenderAdded = Add-DefenderMonitoring

# Step 3: Restart service if changes were made
if ($yaraRemoved -or $defenderAdded) {
    $restartSuccess = Restart-WazuhService
    if ($restartSuccess) {
        SuccessMessage -Message "All operations completed successfully."
    } else {
        WarnMessage -Message "Operations completed but service restart had issues."
    }
} else {
    InfoMessage -Message "No changes made. Wazuh configuration remains unchanged."
}