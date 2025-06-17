import os
import pytest
import testinfra

@pytest.fixture
def host():
    return testinfra.get_host("local://")

# --- User and Group Tests ---
def test_user_exists(host):
    user = host.user("root")
    assert user.exists

def test_group_exists(host):
    group = host.group("wazuh")
    assert group.exists

# --- Wazuh Configuration File ---
def test_ossec_conf_exists(host):
    if host.system_info.type == "linux":
        ossec_conf_path = "/var/ossec/etc/ossec.conf"
    elif host.system_info.type == "darwin":
        ossec_conf_path = "/Library/Ossec/etc/ossec.conf"
    else:
        pytest.skip("Unsupported OS")
    file = host.file(ossec_conf_path)
    assert file.exists, f"{ossec_conf_path} does not exist"

# --- YARA Installation and Version ---
def test_yara_installed_from_source(host):
    expected_version = "4.5.4"
    which_yara = host.run("which yara").stdout.strip()
    assert which_yara, "YARA binary not found in PATH"
    yara_bin = host.exists(which_yara)
    assert yara_bin, f"YARA binary not found in {which_yara}"
    yara_version = host.run("yara --version").stdout.strip()
    assert yara_version, "Could not get YARA version"
    assert yara_version == expected_version, f"YARA version is not {expected_version}: {yara_version}"

# --- notify-send Version (Linux only) ---
def test_notify_send_version(host):
    expected_version = "0.8.3"
    if host.system_info.type != "linux":
        pytest.skip("notify-send version test only applies to Linux")
    if not host.exists("notify-send"):
        pytest.skip("notify-send not installed")
    version_output = host.run("notify-send --version").stdout.strip()
    assert version_output is not None, "Could not determine notify-send version"
    assert version_output == expected_version, f"notify-send version is not {expected_version}: {version_output}"
    
# --- zenity Installation (Linux only) ---
def test_zenity_installed(host):
    if host.system_info.type != "linux":
        pytest.skip("zenity installation test only applies to Linux")
    zenity = host.package("zenity")
    assert zenity.is_installed, "zenity is not installed"

# --- YARA Script and Rules File/Directory ---
def get_yara_script_path(host):
    if host.system_info.type == "linux":
        return "/var/ossec/active-response/bin/yara.sh"
    elif host.system_info.type == "darwin":
        return "/Library/Ossec/active-response/bin/yara.sh"
    else:
        pytest.skip("Unsupported OS")

def get_yara_rules_file_and_dir(host):
    if host.system_info.type == "linux":
        return (
            "/var/ossec/ruleset/yara/rules/yara_rules.yar",
            "/var/ossec/ruleset/yara/rules"
        )
    elif host.system_info.type == "darwin":
        return (
            "/Library/Ossec/ruleset/yara/rules/yara_rules.yar",
            "/Library/Ossec/ruleset/yara/rules"
        )
    else:
        pytest.skip("Unsupported OS")

def test_yara_script_downloaded(host):
    yara_script_path = get_yara_script_path(host)
    file = host.file(yara_script_path)
    assert file.exists
    assert file.user == "root"
    assert file.group == "wazuh"
    assert file.mode == 0o750

def test_yara_script_permissions(host):
    yara_script_path = get_yara_script_path(host)
    file = host.file(yara_script_path)
    assert file.exists
    assert file.user == "root"
    assert file.group == "wazuh"
    assert file.mode == 0o750

def test_yara_rules_file_exists(host):
    yara_rules_file, _ = get_yara_rules_file_and_dir(host)
    file = host.file(yara_rules_file)
    assert file.exists, "YARA rules file does not exist"
    assert file.is_file, "YARA rules file is not a regular file"

def test_yara_rules_file_permissions(host):
    yara_rules_file, yara_rules_dir = get_yara_rules_file_and_dir(host)
    file = host.file(yara_rules_file)
    dir = host.file(yara_rules_dir)
    assert file.exists, "YARA rules file does not exist"
    assert file.is_file, "YARA rules file is not a regular file"
    assert file.user == "root"
    assert file.group == "wazuh"
    assert dir.is_directory, "YARA rules directory does not exist"
    assert dir.user == "root"
    assert dir.group == "wazuh"

# --- Wazuh Agent Service ---
def test_wazuh_agent_restarted(host):
    service = host.service("wazuh-agent")
    assert service.is_running
    assert service.is_enabled


