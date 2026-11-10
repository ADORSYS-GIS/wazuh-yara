# Set strict mode for error handling
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Logging with timestamp
function Log {
    param (
        [string]$Level,
        [string]$Message
    )
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Output "$Timestamp $Level $Message"
}

function InfoMessage {
    param ([string]$Message)
    Log -Level "[INFO]" -Message $Message
}

function WarnMessage {
    param ([string]$Message)
    Log -Level "[WARNING]" -Message $Message
}

function ErrorMessage {
    param ([string]$Message)
    Log -Level "[ERROR]" -Message $Message
}

function SuccessMessage {
    param ([string]$Message)
    Log -Level "[SUCCESS]" -Message $Message
}

function PrintStep {
    param (
        [int]$StepNumber,
        [string]$Message
    )
    Log -Level "[STEP]" -Message "Step ${StepNumber}: $Message"
}

function ErrorExit {
    param ([string]$Message)
    ErrorMessage -Message $Message
    exit 1
}

function Assert-AdminPrivilege {
    if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
        ErrorExit "This script requires administrative privileges. Please run it as Administrator."
    }
}

function Get-BinDirectory {
    if ([Environment]::Is64BitOperatingSystem) {
        return "C:\Program Files (x86)\ossec-agent"
    } else {
        return "C:\Program Files\ossec-agent"
    }
}

function Get-FileChecksum {
    param([string]$FilePath)
    if (-not (Test-Path $FilePath)) {
        throw "File not found: $FilePath"
    }
    return (Get-FileHash -Path $FilePath -Algorithm SHA256).Hash.ToLower()
}

function Test-Checksum {
    param(
        [string]$FilePath,
        [string]$ExpectedHash
    )
    $actualHash = Get-FileChecksum -FilePath $FilePath
    if ($actualHash -ne $ExpectedHash.ToLower()) {
        ErrorMessage -Message "Checksum verification FAILED for $FilePath!"
        ErrorMessage -Message "  Expected: $ExpectedHash"
        ErrorMessage -Message "  Got:      $actualHash"
        return $false
    }
    return $true
}

function Get-File {
    [CmdletBinding()]
    param(
        [string]$Url,
        [string]$Destination,
        [string]$Description = "file",
        [int]$MaxRetries = 3
    )

    InfoMessage -Message "Downloading $Description..."

    $destDir = Split-Path -Parent $Destination
    if (-not (Test-Path $destDir)) {
        New-Item -ItemType Directory -Path $destDir -Force | Out-Null
    }

    $attempt = 0
    while ($attempt -lt $MaxRetries) {
        try {
            Invoke-WebRequest -Uri $Url -OutFile $Destination -UseBasicParsing
            SuccessMessage -Message "$Description downloaded successfully"
            return
        } catch {
            $attempt++
            if ($attempt -lt $MaxRetries) {
                WarnMessage -Message "Download failed, retrying ($attempt/$MaxRetries)..."
                Start-Sleep -Seconds 2
            }
        }
    }

    ErrorExit "Failed to download $Description from $Url after $MaxRetries attempts"
}

function Get-And-VerifyFile {
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param(
        [string]$Url,
        [string]$Destination,
        [string]$ChecksumPattern,
        [string]$FileName = "Unknown file",
        [string]$ChecksumFile = $script:ChecksumsPath,
        [string]$ChecksumUrl = $null
    )

    Get-File -Url $Url -Destination $Destination -Description $FileName

    # If a direct checksum URL is provided, download it and use it as the source of truth
    if (-not [string]::IsNullOrWhiteSpace($ChecksumUrl)) {
        $tempChecksumFile = Join-Path ([System.IO.Path]::GetTempPath()) "checksums-$([System.Guid]::NewGuid().ToString()).sha256"
        Get-File -Url $ChecksumUrl -Destination $tempChecksumFile -Description "checksum file"
        $ChecksumFile = $tempChecksumFile
    }

    if (-not [string]::IsNullOrWhiteSpace($ChecksumFile) -and (Test-Path -Path $ChecksumFile)) {
        $expectedHash = (Select-String -Path $ChecksumFile -Pattern $ChecksumPattern).Line.Split(" ")[0]
        if (-not [string]::IsNullOrWhiteSpace($expectedHash)) {
            if (-not (Test-Checksum -FilePath $Destination -ExpectedHash $expectedHash)) {
                ErrorExit "$FileName checksum verification failed"
            }
            InfoMessage -Message "$FileName checksum verification passed."
        } else {
            ErrorExit "No checksum found for $FileName in $ChecksumFile using pattern $ChecksumPattern"
        }

        # Cleanup temporary checksum file if it was downloaded from a URL
        if (-not [string]::IsNullOrWhiteSpace($ChecksumUrl) -and (Test-Path -Path $ChecksumFile)) {
            Remove-Item -Path $ChecksumFile -Force -ErrorAction SilentlyContinue
        }
    } else {
        ErrorExit "Checksum file not found at $ChecksumFile, cannot verify $FileName"
    }

    SuccessMessage -Message "$FileName downloaded and verified successfully."
    return $true
}