# Set strict mode and define the error handling
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Variables
if (-not $env:WAZUH_YARA_REPO_REF) { 
    $env:WAZUH_YARA_REPO_REF = "main"
}
$WAZUH_YARA_REPO_REF = $env:WAZUH_YARA_REPO_REF
$WAZUH_YARA_REPO_URL = "https://raw.githubusercontent.com/ADORSYS-GIS/wazuh-yara/$WAZUH_YARA_REPO_REF"
$WAZUH_YARA_RULES_URL = "$WAZUH_YARA_REPO_URL/rules/yara_rules.yar"
$WAZUH_YARA_BAT_URL = "$WAZUH_YARA_REPO_URL/scripts/windows/yara.bat"

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

function Cleanup {
    InfoMessage "Cleaning up temporary files..."

    Remove-Item -Path "$TEMP_DIR\yara64.exe" -Force -Recurse -ErrorAction SilentlyContinue
    Remove-Item -Path "$TEMP_DIR\yarac64.exe" -Force -Recurse -ErrorAction SilentlyContinue
    Remove-Item -Path "$TEMP_DIR\yara_rules.yar" -Force -Recurse -ErrorAction SilentlyContinue
}

# Function to download and extract YARA
function Download-YARA {
    # Determine the architecture
    $arch = if ([Environment]::Is64BitOperatingSystem) { "win64" } else { "win32" }
    $yaraVersion = if ($env:YARA_VERSION) { $env:YARA_VERSION } else { "4.5.2" }
    $yaraUrl = "https://github.com/VirusTotal/yara/releases/download/v$yaraVersion/yara-v$yaraVersion-2326-$arch.zip"
    $yaraZipPath = "$TEMP_DIR\yara-$yaraVersion-$arch.zip"
    
    # Download the appropriate YARA version
    Download-File -Url $yaraUrl -Destination $yaraZipPath -Description "YARA $yaraVersion for $arch"
    
    # Extract the downloaded archive
    Expand-Archive -Path $yaraZipPath -DestinationPath "$TEMP_DIR" -Force
    
    # Remove the downloaded archive
    Remove-Item -Path $yaraZipPath
}

# Function to install YARA
function Install-YARA {
    Ensure-Admin

    # Download and extract YARA
    Download-YARA

    # Create YARA directory and copy executable
    $yaraDir = "C:\Program Files (x86)\ossec-agent\active-response\bin\yara"
    New-Item -ItemType Directory -Path $yaraDir -Force
    Copy-Item -Path "$TEMP_DIR\yara64.exe" -Destination $yaraDir
    
    # Define the file path to save the YARA rules
    $yaraRulesFile = "$TEMP_DIR\yara_rules.yar"
    
    # Download the YARA rules file (no checksum verification available)
    Download-And-VerifyFile -Url $WAZUH_YARA_RULES_URL -Destination $yaraRulesFile -FileName "YARA rules" -ChecksumPattern "rules/yara_rules.yar" -ChecksumUrl $WAZUH_YARA_REPO_URL/checksums.sha256

    # Verify if the yara_rules.yar file exists
    $yaraRulesPath = "$TEMP_DIR\yara_rules.yar"
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
    $yaraBatDir =  "C:\Program Files (x86)\ossec-agent\active-response\bin\yara.bat"
    
    # Download the appropriate YARA version
    Download-And-VerifyFile -Url $WAZUH_YARA_BAT_URL -Destination $yaraBatDir -ChecksumPattern "scripts/windows/yara.bat" -FileName "YARA batch script" -ChecksumUrl $WAZUH_YARA_REPO_URL/checksums.sha256

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

try {
    Install-YARA
} finally {
    Cleanup
    InfoMessage "Temporary files cleaned up."
}