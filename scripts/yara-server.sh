#!/bin/bash
# Wazuh - Yara server-side active response (auto-delete on detection)
# Copyright (C) 2025, ADORSYS GmbH & CO KG.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

# Check Bash version and re-execute with newer bash if needed
if [ -n "$BASH_VERSION" ]; then
    bash_major="${BASH_VERSION%%.*}"
    if [ "$bash_major" -lt 4 ]; then
        newer_bash=""
        if [ -x "/opt/homebrew/bin/bash" ]; then
            newer_bash="/opt/homebrew/bin/bash"
        elif [ -x "/usr/local/bin/bash" ]; then
            newer_bash="/usr/local/bin/bash"
        elif [ -x "/bin/bash" ]; then
            system_bash_version=$(/bin/bash -c 'echo $BASH_VERSION' 2>/dev/null)
            system_bash_major="${system_bash_version%%.*}"
            if [ "$system_bash_major" -ge 4 ] 2>/dev/null; then
                newer_bash="/bin/bash"
            fi
        fi
        if [ -n "$newer_bash" ]; then
            exec "$newer_bash" "$0" "$@"
        else
            echo "Error: This script requires Bash 4.0 or later. Current version: $BASH_VERSION" >&2
            echo "Please install a newer version of Bash." >&2
            exit 1
        fi
    fi
fi

if [ -n "$BASH_VERSION" ]; then
    set -euo pipefail
else
    set -eu
fi

#------------------------- Gather parameters -------------------------#
read INPUT_JSON
FILENAME=$(echo "$INPUT_JSON" | jq -r .parameters.alert.syscheck.path)

if [ -z "$FILENAME" ]; then
    echo "wazuh-yara: ERROR - FILENAME parameter is empty from alert JSON." >> "${LOG_FILE}"
    exit 1
fi


if [ "$(uname)" = "Darwin" ]; then
    YARA_PATH="/opt/yara/bin"
    YARA_RULES="/Library/Ossec/ruleset/yara/rules/yara_rules.yar"
    OSSEC_CONF_PATH="/Library/Ossec/etc/ossec.conf"
    LOG_FILE="/Library/Ossec/logs/active-responses.log"
elif [ "$(uname)" = "Linux" ]; then
    YARA_PATH="/usr/local/bin"
    YARA_RULES="/var/ossec/ruleset/yara/rules/yara_rules.yar"
    OSSEC_CONF_PATH="/var/ossec/etc/ossec.conf"
    LOG_FILE="/var/ossec/logs/active-responses.log"
else
    echo "wazuh-yara: ERROR - Unsupported OS: $(uname). This script only supports macOS and Linux." >> "${LOG_FILE}"
    exit 1
fi

# Determine which yara binary to use
YARA_BIN=""
if [ -x "$YARA_PATH/yara" ]; then
    YARA_BIN="$YARA_PATH/yara"
elif command -v yara >/dev/null 2>&1; then
    YARA_BIN="$(command -v yara)"
else
    echo "wazuh-yara: ERROR - No yara binary found in $YARA_PATH or in PATH." >> "${LOG_FILE}"
    exit 1
fi

if [[ ! -f "$FILENAME" ]]; then
    echo "wazuh-yara: WARNING - File '$FILENAME' does not exist or is not a regular file. Skipping scan." >> "${LOG_FILE}"
    exit 0
fi

size=0
actual_size=$(stat -c %s "${FILENAME}" 2>/dev/null || echo "0")
while [ ${size} -ne ${actual_size} ]; do
    sleep 1
    size=${actual_size}
    actual_size=$(stat -c %s "${FILENAME}" 2>/dev/null || echo "0")
done

if [[ ! $YARA_PATH ]] || [[ ! -f "$YARA_RULES" ]]; then
    echo "wazuh-yara: ERROR - Yara active response error. Yara path: ($YARA_PATH) and rules: ($YARA_RULES) parameters are mandatory and rules file must exist." >> "${LOG_FILE}"
    exit 1
fi

if [[ ! -f "$OSSEC_CONF_PATH" ]]; then
    echo "wazuh-yara: ERROR - OSSEC configuration file not found at: $OSSEC_CONF_PATH" >> "${LOG_FILE}"
    exit 1
fi

echo "wazuh-yara: DEBUG - Starting Yara scan..." >> "${LOG_FILE}"

#------------------------- Main workflow --------------------------#

# Use the selected YARA_BIN for scanning
if ! "$YARA_BIN" -w -r "$YARA_RULES" "$FILENAME" &> /dev/null; then
    echo "wazuh-yara: DEBUG - Yara scan failed for '$FILENAME' (could not open file or other issue). Skipping further processing." >> "${LOG_FILE}"
    exit 0
fi
yara_output="$($YARA_BIN -w -r "$YARA_RULES" "$FILENAME")"

if [[ $yara_output != "" ]]; then
    # Iterate every detected rule and append it to the LOG_FILE
    while read -r line; do
        echo "wazuh-yara: INFO - Scan result: $line" >> ${LOG_FILE}

        # Extract the rule and file from the Yara output
        rule="${line%% *}"
        detected_file="${line#* }"

        # Delete the detected file
        rm -f "$detected_file"
        if [ $? -eq 0 ]; then
            echo "wazuh-yara: SUCCESS - Delete file: $detected_file" >> "${LOG_FILE}"
        else
            echo "wazuh-yara: ERROR - Delete file: $detected_file" >> "${LOG_FILE}"
        fi
    done <<< "$yara_output"
else
    echo "wazuh-yara: DEBUG - No Yara rules matched for scanned files." >> "${LOG_FILE}"
fi

echo "wazuh-yara: DEBUG - Yara scan completed." >> "${LOG_FILE}"

exit 0;
