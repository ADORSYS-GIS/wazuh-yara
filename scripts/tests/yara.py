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


def test_ossec_conf_content(host):
    if host.system_info.type == "linux":
        ossec_conf_path = "/var/ossec/etc/ossec.conf"
        fim_directories = '<directories realtime="yes">/home, /root, /bin, /sbin</directories>'
    elif host.system_info.type == "darwin":
        ossec_conf_path = "/Library/Ossec/etc/ossec.conf"
        fim_directories = '<directories realtime="yes">/Users, /Applications</directories>'
    else:
        pytest.skip("Unsupported OS")

    file = host.file(ossec_conf_path)
    assert file.contains(fim_directories), \
        "Missing expected directories configuration"
    assert file.contains('<frequency>43200</frequency>'), "Missing expected frequency setting"


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


