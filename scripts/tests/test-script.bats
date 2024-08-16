#!/usr/bin/env bats

WAZUH_MANAGER="10.0.0.2"

if [ "$(uname -o)" = "GNU/Linux" ] && command -v groupadd >/dev/null 2>&1; then
    apt-get update && apt-get install -y curl gnupg2
    (curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import)
    chmod 644 /usr/share/keyrings/wazuh.gpg
    echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | tee -a /etc/apt/sources.list.d/wazuh.list
    apt-get update
    apt-get install wazuh-agent -y
    sed -i "s|MANAGER_IP|$WAZUH_MANAGER|g" /var/ossec/etc/ossec.conf
elif [ "$(which apk)" = "/sbin/apk" ]; then
    wget -O /etc/apk/keys/alpine-devel@wazuh.com-633d7457.rsa.pub https://packages.wazuh.com/key/alpine-devel%40wazuh.com-633d7457.rsa.pub
    echo "https://packages.wazuh.com/4.x/alpine/v3.12/main" >> /etc/apk/repositories
    apk update
    apk add wazuh-agent
    sed -i "s|MANAGER_IP|$WAZUH_MANAGER|g" /var/ossec/etc/ossec.conf
    /var/ossec/bin/wazuh-control start
else
    log ERROR "Unsupported OS for creating user."
    exit 1
fi

chmod +x /app/scripts/install.sh

# Test if the script runs without errors
@test "script runs without errors" {
  run /app/scripts/install.sh
  [ "$status" -eq 0 ]
}

# Test if the YARA rules were downloaded
@test "YARA rules downloaded" {
  /app/scripts/install.sh
  [ -f "/var/ossec/ruleset/yara/rules/yara_rules.yar" ]
}

# Test if the Wazuh agent configuration file is updated
@test "Wazuh agent configuration updated" {
  /app/scripts/install.sh
  grep -q '<directories realtime="yes">/tmp/yara/malware</directories>' "$OSSEC_CONF_PATH"
  grep -q '<frequency>300</frequency>' "$OSSEC_CONF_PATH"
}

# Test if the yara.sh script was downloaded
@test "yara.sh script downloaded" {
  /app/scripts/install.sh
  [ -f "/var/ossec/active-response/bin/yara.sh" ]
}

# Test if the Wazuh agent was restarted
@test "Wazuh agent restarted" {
  run /app/scripts/install.sh
  [ "$status" -eq 0 ]
  grep -q "Wazuh agent restarted successfully." "/var/ossec/etc/ossec.conf"
}
