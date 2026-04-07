# Set strict mode for error handling
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

# Restart wazuh agent
function Restart-WazuhAgent {
    InfoMessage "Restarting wazuh agent..."
    $service = Get-Service -Name WazuhSvc -ErrorAction SilentlyContinue
    if($service) {
        try {
            Restart-Service -Name WazuhSvc -ErrorAction Stop
            InfoMessage "Wazuh Agent restarted succesfully"
        }
        catch {
            ErrorMessage "Failed to restart Wazuh Agent: $($_.Exception.Message)"
        }
    }
    else {
        InfoMessage "Wazuh Service does not exist"
    }
}

#Uninstall Yara
function Uninstall-Yara {
    $yaraDir = "C:\Program Files (x86)\ossec-agent\active-response\bin\yara"
    $yaraBatFile = "C:\Program Files (x86)\ossec-agent\active-response\bin\yara.bat"
    InfoMessage "Removing YARA..."
    if (Test-Path -Path $yaraDir) {
        Remove-Item -Path $yaraDir -Force -Recurse -ErrorAction SilentlyContinue
        InfoMessage "YARA directory removed: $yaraDir"
    } else {
        WarnMessage "YARA directory not found: $yaraDir. Skipping..."
    }
    
    InfoMessage "Removing YARA batch file"
    if (Test-Path -Path $yaraBatFile) {
        Remove-Item -Path $yaraBatFile -Force -ErrorAction SilentlyContinue
        InfoMessage "YARA batch file removed: $yaraBatFile"
    } else {
        WarnMessage "YARA batch file not found: $yaraBatFile. Skipping..."
    }

    #Remove YARA path from environment variables
    Remove-SystemPath $yaraDir
}

#Remove from Path
function Remove-SystemPath {
    param (
        [string]$PathToRemove
    )

    # Get the current system Path
    $currentPath = [System.Environment]::GetEnvironmentVariable("Path", [System.EnvironmentVariableTarget]::Machine)

    # Split the Path into an array
    $pathArray = $currentPath -split ';'

    # Check if the specified path exists
    if ($pathArray -contains $PathToRemove) {
        InfoMessage "The path '$PathToRemove' exists in the system Path. Proceeding to remove it."

        # Remove the specified path
        $updatedPathArray = $pathArray | Where-Object { $_ -ne $PathToRemove }

        # Join the array back into a single string
        $updatedPath = ($updatedPathArray -join ';').TrimEnd(';')

        # Update the system Path
        [System.Environment]::SetEnvironmentVariable("Path", $updatedPath, [System.EnvironmentVariableTarget]::Machine)

        InfoMessage "Successfully removed '$PathToRemove' from the system Path."
    } else {
        WarnMessage "The path '$PathToRemove' does not exist in the system Path. No changes were made."
    }
}


#Remove ossec configuration modifications
function Remove-OssecConfigurations {
    InfoMessage "Removing OSSEC configuration modifications..."

    $configFilePath = "C:\Program Files (x86)\ossec-agent\ossec.conf"
    if (Test-Path -Path $configFilePath) {
        [xml]$configXml = Get-Content -Path $configFilePath

        $syscheckNode = $configXml.ossec_config.syscheck
        if ($null -ne $syscheckNode) {

            # Remove any added directories
            InfoMessage "Removing syscheck directory: C:\Users\$([System.Environment]::UserName)\Downloads ..."
            $downloadDirNode = $syscheckNode.directories | Where-Object { $_.InnerText -eq "C:\Users\$([System.Environment]::UserName)\Downloads" }
            if ($null -ne $downloadDirNode) {
                $syscheckNode.RemoveChild($downloadDirNode) | Out-Null
                InfoMessage "Removed syscheck directory: C:\Users\$([System.Environment]::UserName)\Downloads"
            }
            else {
                WarnMessage "Syscheck directory: C:\Users\$([System.Environment]::UserName)\Downloads not found. Skipping..."
            }

            InfoMessage "Removing file_limit node from ossec configuration"
            # Remove <file_limit> if it exists
            $fileLimitNode = $syscheckNode.file_limit
            if ($null -ne $fileLimitNode) {
                $syscheckNode.RemoveChild($fileLimitNode) | Out-Null
                InfoMessage "Removed file_limit from syscheck configuration"
            }
            else {
                WarnMessage "file_limit node not found in syscheck node. Skipping..."
            }

            $configXml.Save($configFilePath)
            Restart-WazuhAgent
            InfoMessage "Wazuh configuration restored and service restarted"
        } else {
            WarnMessage "No <syscheck> node found in Wazuh configuration"
        }
    } else {
        WarnMessage "Wazuh configuration file not found: $configFilePath"
    }
}

#Main Uninstall Function
function Uninstall-All {
    try {
        Uninstall-Yara
        Remove-OssecConfigurations
        Restart-WazuhAgent
        SuccessMessage "YARA and components uninstalled successfully"
    }
    catch {
        ErrorMessage "YARA Uninstall Failed: $($_.Exception.Message)"
    }
}

Uninstall-All