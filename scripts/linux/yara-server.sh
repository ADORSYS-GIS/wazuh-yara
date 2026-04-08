#!/bin/bash
# Wazuh - Yara server-side active response
# Copyright (C) 2025, ADORSYS GmbH & CO KG.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

# Check Bash version and re-execute with /bin/bash if it is >= 4
if [[ -n "${BASH_VERSION:-}" ]]; then
    bash_major="${BASH_VERSION%%.*}"
    if [[ "$bash_major" -lt 4 ]]; then
        if [[ -x "/bin/bash" ]]; then
            system_bash_version=$(/bin/bash -c 'echo $BASH_VERSION' 2>/dev/null)
            system_bash_major="${system_bash_version%%.*}"
            if [[ "$system_bash_major" -ge 4 ]] 2>/dev/null; then
                exec /bin/bash "$0" "$@"
            fi
        fi
        echo "Error: This script requires Bash 4.0 or later. Current version: $BASH_VERSION" >&2
        echo "Please install a newer version of Bash." >&2
        exit 1
    fi
fi

set -euo pipefail

#------------------------- Constants -------------------------#

YARA_PATH="/opt/wazuh/yara/bin"
YARA_RULES="/var/ossec/ruleset/yara/rules/yara_rules.yar"
OSSEC_CONF_PATH="/var/ossec/etc/ossec.conf"
LOG_FILE="/var/ossec/logs/active-responses.log"

#------------------------- Gather parameters -------------------------#

read -r INPUT_JSON
FILENAME=$(echo "$INPUT_JSON" | jq -r .parameters.alert.syscheck.path)

if [[ -z "$FILENAME" ]] || [[ "$FILENAME" = "null" ]]; then
    echo "wazuh-yara: ERROR - FILENAME parameter is empty from alert JSON." >> "${LOG_FILE}"
    exit 1
fi

#------------------------- Resolve YARA binary -------------------------#

YARA_BIN=""
if [[ -x "$YARA_PATH/yara" ]]; then
    YARA_BIN="$YARA_PATH/yara"
elif command -v yara >/dev/null 2>&1; then
    YARA_BIN="$(command -v yara)"
else
    echo "wazuh-yara: ERROR - No yara binary found in $YARA_PATH or in PATH." >> "${LOG_FILE}"
    exit 1
fi

#------------------------- Pre-scan validation -------------------------#

if [[ ! -f "$FILENAME" ]]; then
    echo "wazuh-yara: WARNING - File '$FILENAME' does not exist or is not a regular file. Skipping scan." >> "${LOG_FILE}"
    exit 0
fi

if [[ ! -f "$YARA_RULES" ]]; then
    echo "wazuh-yara: ERROR - Yara active response error. Yara path: ($YARA_PATH) and rules: ($YARA_RULES) parameters are mandatory and rules file must exist." >> "${LOG_FILE}"
    exit 1
fi

if [[ ! -f "$OSSEC_CONF_PATH" ]]; then
    echo "wazuh-yara: ERROR - OSSEC configuration file not found at: $OSSEC_CONF_PATH" >> "${LOG_FILE}"
    exit 1
fi

#------------------------- File stabilisation -------------------------#

size=0
actual_size=$(stat -c %s "${FILENAME}" 2>/dev/null || echo "0")
while [[ "${size}" -ne "${actual_size}" ]]; do
    sleep 1
    size=${actual_size}
    actual_size=$(stat -c %s "${FILENAME}" 2>/dev/null || echo "0")
done

#------------------------- Main workflow -------------------------#

echo "wazuh-yara: DEBUG - Starting Yara scan..." >> "${LOG_FILE}"

if ! "$YARA_BIN" -w -r "$YARA_RULES" "$FILENAME" &> /dev/null; then
    echo "wazuh-yara: DEBUG - Yara scan failed for '$FILENAME' (could not open file or other issue). Skipping further processing." >> "${LOG_FILE}"
    exit 0
fi

yara_output="$("$YARA_BIN" -w -r "$YARA_RULES" "$FILENAME")"

if [[ -n "$yara_output" ]]; then
    while IFS= read -r line; do
        echo "wazuh-yara: INFO - Scan result: $line" >> "${LOG_FILE}"
    done <<< "$yara_output"
else
    echo "wazuh-yara: DEBUG - No Yara rules matched for scanned files." >> "${LOG_FILE}"
fi

echo "wazuh-yara: DEBUG - Yara scan completed." >> "${LOG_FILE}"

exit 0
