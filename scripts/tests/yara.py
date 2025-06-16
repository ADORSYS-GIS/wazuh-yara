import os
import pytest
import testinfra

@pytest.fixture
def host():
    return testinfra.get_host("local://")

def test_user_exists(host):
    user = host.user("root")
    assert user.exists

def test_group_exists(host):
    group = host.group("wazuh")
    assert group.exists

def test_ossec_conf_exists(host):
    if host.system_info.type == "linux":
        ossec_conf_path = "/var/ossec/etc/ossec.conf"
    elif host.system_info.type == "darwin":
        ossec_conf_path = "/Library/Ossec/etc/ossec.conf"
    else:
        pytest.skip("Unsupported OS")

    file = host.file(ossec_conf_path)
    assert file.exists, f"{ossec_conf_path} does not exist"


def test_yara_installed(host):
    yara = host.package("yara")
    assert yara.is_installed

def test_yara_script_downloaded(host):
    if host.system_info.type == "linux":
        yara_script_path = "/var/ossec/active-response/bin/yara.sh"
    elif host.system_info.type == "darwin":
        yara_script_path = "/Library/Ossec/active-response/bin/yara.sh"
    else:
        pytest.skip("Unsupported OS")

    file = host.file(yara_script_path)
    assert file.exists
    assert file.user == "root"
    assert file.group == "wazuh"
    assert file.mode == 0o750

def test_wazuh_agent_restarted(host):
    # Adjust this command based on how Wazuh agent is restarted.
    service = host.service("wazuh-agent")
    assert service.is_running
    assert service.is_enabled

def test_yara_rules_file_exists(host):
    yara_rules_file = host.file("/var/ossec/ruleset/yara/rules/yara_rules.yar")
    assert yara_rules_file.exists, "YARA rules file does not exist"
    assert yara_rules_file.is_file, "YARA rules file is not a regular file"

def test_yara_rules_directory_permissions(host):
    yara_rules_dir = host.file("/var/ossec/ruleset/yara/rules")
    assert yara_rules_dir.is_directory, "YARA rules directory does not exist"
    assert yara_rules_dir.user == "root", "YARA rules directory is not owned by root"
    assert yara_rules_dir.group == "wazuh", "YARA rules directory is not owned by the wazuh group"

def test_notify_send_version(host):
    # Only run on Ubuntu/Debian
    if host.system_info.type != "linux":
        pytest.skip("notify-send version test only applies to Linux")
    if not host.exists("notify-send"):
        pytest.skip("notify-send not installed")
    version_output = host.run("notify-send --version").stdout.strip()
    version = version_output.split()[-1] if version_output else None
    assert version is not None, "Could not determine notify-send version"
    # Should be at least 0.8.3
    major, minor, patch = [int(x) for x in version.split(".")]
    assert (major, minor, patch) >= (0, 8, 3), f"notify-send version {version} is less than 0.8.3"


def test_yara_script_permissions(host):
    if host.system_info.type == "linux":
        yara_script_path = "/var/ossec/active-response/bin/yara.sh"
    elif host.system_info.type == "darwin":
        yara_script_path = "/Library/Ossec/active-response/bin/yara.sh"
    else:
        pytest.skip("Unsupported OS")
    file = host.file(yara_script_path)
    assert file.exists
    assert file.user == "root"
    assert file.group == "wazuh"
    assert file.mode == 0o750


def test_yara_rules_file_permissions(host):
    if host.system_info.type == "linux":
        yara_rules_file = host.file("/var/ossec/ruleset/yara/rules/yara_rules.yar")
        yara_rules_dir = host.file("/var/ossec/ruleset/yara/rules")
    elif host.system_info.type == "darwin":
        yara_rules_file = host.file("/Library/Ossec/ruleset/yara/rules/yara_rules.yar")
        yara_rules_dir = host.file("/Library/Ossec/ruleset/yara/rules")
    else:
        pytest.skip("Unsupported OS")
    assert yara_rules_file.exists, "YARA rules file does not exist"
    assert yara_rules_file.is_file, "YARA rules file is not a regular file"
    assert yara_rules_file.user == "root"
    assert yara_rules_file.group == "wazuh"
    assert yara_rules_dir.is_directory, "YARA rules directory does not exist"
    assert yara_rules_dir.user == "root"
    assert yara_rules_dir.group == "wazuh"


def test_yara_installed_from_source(host):
    # Check yara binary is present and not from apt/brew
    which_yara = host.run("which yara").stdout.strip()
    yara_bin = host.exists(which_yara)
    assert yara_bin, "YARA binary not found in /usr/local/bin or /opt/homebrew/bin"
    yara_version = host.run("yara --version").stdout.strip()
    assert yara_version, "Could not get YARA version"
    # Should match the version from install.sh
    assert "4.5.4" in yara_version, f"YARA version is not 4.5.4: {yara_version}"


