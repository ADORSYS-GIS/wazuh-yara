

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

# Restart wazuh agent
function Restart-WazuhAgent {
    InfoMessage "Restarting wazuh agent..."
    try {
        Restart-Service -Name WazuhSvc -ErrorAction Stop
        InfoMessage "Wazuh Agent restarted succesfully"
    }
    catch {
        ErrorMessage "Failed to restart Wazuh Agent: $($_.Exception.Message)"
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
            Restart-Service -Name WazuhSvc -ErrorAction SilentlyContinue
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