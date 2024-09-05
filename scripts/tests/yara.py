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
    assert file.exists
    assert file.contains('<directories realtime="yes">/home, /root, /bin, /sbin</directories>')
    assert file.contains('<frequency>300</frequency>')

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


def test_yara_rules_downloaded(host):
    yara_rules_dir = "/var/ossec/ruleset/yara/rules"
    yara_rules_file = os.path.join(yara_rules_dir, "yara_rules.yar")
    
    file = host.file(yara_rules_file)
    
    assert file.exists(), f"{yara_rules_file} does not exist"
    assert file.user == "root", f"File is not owned by 'root', but by {file.user}"
    assert file.group == "wazuh", f"File group is not 'wazuh', but {file.group}"

