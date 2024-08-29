# Use the official PowerShell image as the base
FROM mcr.microsoft.com/powershell:latest

# Set default shell to PowerShell
SHELL ["powershell", "-Command"]

# Install Chocolatey
RUN pwsh -Command "Set-ExecutionPolicy Bypass -Scope Process; \
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; \
    iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))"

# Verify Chocolatey installation
RUN choco --version

# Install Pester module
RUN pwsh -Command "Install-Module -Name Pester -Force -SkipPublisherCheck"

# Set the working directory
WORKDIR /app

# Default command to run the tests
CMD ["pwsh", "-Command", "Invoke-Pester -Path . -OutputFormat NUnitXml -OutputFile ./TestResults.xml"]
