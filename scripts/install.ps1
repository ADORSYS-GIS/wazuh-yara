# Set strict mode and define the error handling
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Variables
$logLevel = "INFO"
$user = "SYSTEM"
$group = "Administrators"

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

# Create a temporary directory
$tempDir = New-Item -ItemType Directory -Path ([System.IO.Path]::GetTempPath()) -Name ([System.IO.Path]::GetRandomFileName())

# Function to clean up temporary files
function Cleanup {
    Log "INFO" "Cleaning up temporary files..."
    Remove-Item $tempDir -Force -Recurse -ErrorAction SilentlyContinue
}

try {
    # Step 1: Install YARA and necessary tools
    Print-Step -step 1 -message "Installing YARA and necessary tools..."

    function Install-Yara {
        Log "INFO" "Installing YARA on Windows..."

        # Determine if the system is 64-bit or 32-bit
        $is64Bit = [Environment]::Is64BitOperatingSystem

        # Set the download URL based on the system architecture
        if ($is64Bit) {
            $yaraUrl = "https://github.com/VirusTotal/yara/releases/download/v4.5.2/yara-v4.5.2-2326-win64.zip"
        } else {
            $yaraUrl = "https://github.com/VirusTotal/yara/releases/download/v4.5.2/yara-v4.5.2-2326-win32.zip"
        }

        # Define the paths
        $yaraZipPath = Join-Path -Path $tempDir.FullName -ChildPath "yara.zip"
        $yaraExtractPath = Join-Path -Path $tempDir.FullName -ChildPath "yara"

        # Download the YARA zip file
        Log "INFO" "Downloading YARA from $yaraUrl..."
        Invoke-WebRequest -Uri $yaraUrl -OutFile $yaraZipPath -UseBasicParsing

        # Extract the zip file
        Log "INFO" "Extracting YARA..."
        Expand-Archive -Path $yaraZipPath -DestinationPath $yaraExtractPath

        # Move the extracted files to the appropriate directory
        $yaraInstallPath = "C:\Program Files\YARA"
        New-Item -ItemType Directory -Force -Path $yaraInstallPath
        Copy-Item -Path (Join-Path -Path $yaraExtractPath -ChildPath "*") -Destination $yaraInstallPath -Recurse -Force

        # Clean up the downloaded and extracted files
        Log "INFO" "Cleaning up downloaded and extracted files..."
        Remove-Item -Path $yaraZipPath -Force
        Remove-Item -Path $yaraExtractPath -Recurse -Force

        Log "INFO" "YARA installed successfully at $yaraInstallPath."
    }

    Install-Yara

    # Step 2: Download YARA rules
    Print-Step -step 2 -message "Downloading YARA rules..."

    $yaraRulesUrl = "https://valhalla.nextron-systems.com/api/v1/get"
    $yaraRulesFile = Join-Path -Path $tempDir.FullName -ChildPath "yara_rules.yar"
    $apiKey = "1111111111111111111111111111111111111111111111111111111111111111"
    $yaraRulesDestDir = "C:\ProgramData\ossec\ruleset\yara\rules"

    function Download-YaraRules {
        Log "INFO" "Downloading YARA rules..."

        $headers = @{
            "Accept" = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
            "Accept-Language" = "en-US,en;q=0.5"
            "Referer" = "https://valhalla.nextron-systems.com/"
            "Content-Type" = "application/x-www-form-urlencoded"
            "DNT" = "1"
            "Connection" = "keep-alive"
            "Upgrade-Insecure-Requests" = "1"
        }

        $body = @{
            demo = "demo"
            apikey = $apiKey
            format = "text"
        }

        Invoke-WebRequest -Uri $yaraRulesUrl -Headers $headers -Method Post -Body $body -OutFile $yaraRulesFile -UseBasicParsing

        if (Test-Path $yaraRulesFile -PathType Leaf) {
            New-Item -ItemType Directory -Force -Path $yaraRulesDestDir
            Move-Item -Path $yaraRulesFile -Destination $yaraRulesDestDir -Force
            Log "INFO" "YARA rules moved to $yaraRulesDestDir."
        } else {
            Log "ERROR" "Error occurred during YARA rules download."
            exit 1
        }
    }

    Download-YaraRules

    # Step 3: Download yara.ps1 script
    Print-Step -step 3 -message "Downloading yara.ps1 script..."

    $yaraScriptUrl = "https://raw.githubusercontent.com/ADORSYS-GIS/wazuh-yara/main/scripts/yara.ps1" #TODO: Update URL
    $yaraScriptPath = "C:\ProgramData\ossec\active-response\bin\yara.ps1"

    function Download-YaraScript {
        Log "INFO" "Downloading yara.ps1 script..."

        New-Item -ItemType Directory -Force -Path (Split-Path $yaraScriptPath -Parent)

        Invoke-WebRequest -Uri $yaraScriptUrl -OutFile "$tempDir\yara.ps1" -UseBasicParsing
        Move-Item -Path "$tempDir\yara.ps1" -Destination $yaraScriptPath -Force

        # Set permissions
        $acl = Get-Acl $yaraScriptPath
        $acl.SetOwner([System.Security.Principal.NTAccount] "$user")
        Set-Acl -Path $yaraScriptPath -AclObject $acl
        Log "INFO" "yara.ps1 script downloaded and installed successfully."
    }

    Download-YaraScript

    # Step 4: Update Wazuh agent configuration file
    Print-Step -step 4 -message "Updating Wazuh agent configuration file..."

    $ossecConfPath = "C:\Program Files (x86)\ossec-agent\ossec.conf"
    $ossecConfContent = Get-Content $ossecConfPath
    $updatedConfContent = $ossecConfContent -replace '(?s)(<directories>.*?</directories>)', '$1<directories realtime="yes">C:\ProgramData\ossec\tmp\yara\malware</directories>'
    $updatedConfContent | Set-Content $ossecConfPath
    Log "INFO" "Wazuh agent configuration file updated successfully."

    # Step 5: Update frequency in Wazuh agent configuration file
    Print-Step -step 5 -message "Updating frequency in Wazuh agent configuration file..."

    $ossecConfContent = Get-Content $ossecConfPath
    $updatedConfContent = $ossecConfContent -replace '<frequency>43200</frequency>', '<frequency>300</frequency>'
    $updatedConfContent | Set-Content $ossecConfPath
    Log "INFO" "Frequency in Wazuh agent configuration file updated successfully."

    # Step 6: Restart Wazuh agent
    Print-Step -step 6 -message "Restarting Wazuh agent..."

    function Restart-WazuhAgent {
        Log "INFO" "Restarting Wazuh agent..."
        $wazuhService = Get-Service -Name "WazuhAgent" -ErrorAction SilentlyContinue
        if ($wazuhService -and $wazuhService.Status -ne "Stopped") {
            Restart-Service -Name "WazuhAgent" -Force
            Log "INFO" "Wazuh agent restarted successfully."
        } else {
            Log "ERROR" "Failed to restart Wazuh agent."
            exit 1
        }
    }

    Restart-WazuhAgent

} finally {
    # Clean up temporary files
    Cleanup
    Log "INFO" "Temporary files cleaned up."
}
