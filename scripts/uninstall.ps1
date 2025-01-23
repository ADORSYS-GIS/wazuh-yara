$AgentVersion = "4.9.2-1"
$OssecPath = "C:\Program Files (x86)\ossec-agent"
$DownloadUrl = "https://packages.wazuh.com/4.x/windows/wazuh-agent-$AgentVersion.msi"
$TempFile = New-TemporaryFile


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
    $YaraDir = "C:\Program Files (x86)\ossec-agent\active-response\bin\yara"
    InfoMessage "Removing Yara..."
    try {
        Remove-Item -Path $YaraDir -Recurse -Force
        InfoMessage "Yara executable removed succesfully"
    }
    catch {
        WarnMessage "Yara executable is not installed. Skipping uninstallation"
    }
}

function Remove-YaraPath {
    

}


#Remove YARA rules and scripts




#Remove ossec configuration modifications


