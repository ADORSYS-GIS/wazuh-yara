#!/usr/bin/env bats

sh /app/scripts/tests/setup.sh

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
  if [ -f $OSSEC_CONF_PATH ]; then
      grep -q '<directories realtime="yes">\/home, \/root, \/bin, \/sbin</directories>' "$OSSEC_CONF_PATH"
      grep -q '<frequency>300</frequency>' "$OSSEC_CONF_PATH"
  fi
}

# Test if the yara.sh script was downloaded
@test "yara.sh script downloaded" {
  /app/scripts/install.sh
  [ -f "/var/ossec/active-response/bin/yara.sh" ]
}
