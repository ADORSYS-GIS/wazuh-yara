# yara.Tests.ps1

Import-Module Pester
. .\install.ps1  # Import the script containing your functions



Describe 'Install-Yara' {
    BeforeEach {
        Mock Get-Command { return @{CommandType = 'Application'} }
        Mock Invoke-Expression { }
    }

    It 'should throw an error if Chocolatey is not installed' {
        Mock Get-Command { return $null }
        { Install-Yara } | Should -Throw 'Chocolatey is required to install YARA and dependencies. Please install Chocolatey first.'
    }

    It 'should install YARA and other tools if Chocolatey is installed' {
        Install-Yara
        Assert-MockCalled Invoke-Expression -Exactly 1 -Scope It
    }
}

Describe 'Download-YaraRules' {
    BeforeEach {
        Mock Invoke-WebRequest { return @{StatusCode = 200} }
        Mock Test-Path { return $true }
        Mock Move-Item { }
        Mock New-Item { }
    }

    It 'should download and move the YARA rules file' {
        Download-YaraRules
        Assert-MockCalled Invoke-WebRequest -Exactly 1 -Scope It
        Assert-MockCalled Move-Item -Exactly 1 -Scope It
    }

    It 'should throw an error if download fails' {
        Mock Test-Path { return $false }
        { Download-YaraRules } | Should -Throw 'Error occurred during YARA rules download.'
    }
}

Describe 'Download-YaraScript' {
    BeforeEach {
        Mock Invoke-WebRequest { }
        Mock New-Item { }
        Mock Move-Item { }
        Mock Get-Acl { return @{Owner = "SYSTEM"} }
        Mock Set-Acl { }
    }

    It 'should download and move the yara.bat script' {
        Download-YaraScript
        Assert-MockCalled Invoke-WebRequest -Exactly 1 -Scope It
        Assert-MockCalled Move-Item -Exactly 1 -Scope It
    }

    It 'should set permissions for yara.bat' {
        Download-YaraScript
        Assert-MockCalled Set-Acl -Exactly 1 -Scope It
    }
}

Describe 'Update Wazuh Agent Configuration' {
    $ossecConfPath = "C:\Program Files (x86)\ossec-agent\ossec.conf"

    BeforeEach {
        Mock Get-Content { return @"
<directories>
    <directory>C:\ProgramData\ossec\tmp\yara\malware</directory>
</directories>
<frequency>43200</frequency>
"@ }
        Mock Set-Content { }
    }

    It 'should update directories in the ossec.conf file' {
        $expectedContent = @"
<directories>
    <directory>C:\ProgramData\ossec\tmp\yara\malware</directory>
</directories>
<directories realtime=""yes"">C:\ProgramData\ossec\tmp\yara\malware</directories>
<frequency>43200</frequency>
"@
        Update-WazuhAgentConfiguration
        Assert-MockCalled Set-Content -Exactly 1 -Scope It -ParameterFilter {
            $_ -like "*<directories realtime=`"yes`">C:\ProgramData\ossec\tmp\yara\malware</directories>*"
        }
    }

    It 'should update frequency in the ossec.conf file' {
        $expectedContent = @"
<directories>
    <directory>C:\ProgramData\ossec\tmp\yara\malware</directory>
</directories>
<frequency>300</frequency>
"@
        Update-WazuhAgentFrequency
        Assert-MockCalled Set-Content -Exactly 1 -Scope It -ParameterFilter {
            $_ -like "*<frequency>300</frequency>*"
        }
    }
}

Describe 'Restart-WazuhAgent' {
    BeforeEach {
        Mock Get-Service { return @{Status = "Running"} }
        Mock Restart-Service { }
    }

    It 'should restart Wazuh agent if running' {
        Restart-WazuhAgent
        Assert-MockCalled Restart-Service -Exactly 1 -Scope It
    }

    It 'should throw an error if Wazuh agent is not running' {
        Mock Get-Service { return $null }
        { Restart-WazuhAgent } | Should -Throw 'Failed to restart Wazuh agent.'
    }
}

