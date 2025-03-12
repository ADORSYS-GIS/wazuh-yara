#!/bin/bash
# Wazuh - Yara active response
# Copyright (C) 2025, ADORSYS GmbH & CO KG.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.


#------------------------- Gather parameters -------------------------#

# Extra arguments
read INPUT_JSON
FILENAME=$(echo $INPUT_JSON | jq -r .parameters.alert.syscheck.path)

YARA_PATH="/usr/local/bin"
if [ "$(uname)" = "Darwin" ]; then
    YARA_RULES="/Library/Ossec/ruleset/yara/rules/yara_rules.yar"
    if [ "$(uname -m)" = "arm64" ]; then
        YARA_PATH="/opt/homebrew/bin"
    fi
else
    YARA_RULES="/var/ossec/ruleset/yara/rules/yara_rules.yar"
    YARA_PATH="/usr/bin"
fi

# Set LOG_FILE path
LOG_FILE="logs/active-responses.log"

size=0
actual_size=$(stat -c %s ${FILENAME})
while [ ${size} -ne ${actual_size} ]; do
    sleep 1
    size=${actual_size}
    actual_size=$(stat -c %s ${FILENAME})
done

#----------------------- Analyze parameters -----------------------#

if [[ ! $YARA_PATH ]] || [[ ! $YARA_RULES ]]
then
    echo "wazuh-yara: ERROR - Yara active response error. Yara path: ($YARA_PATH) and rules: ($YARA_RULES) parameters are mandatory." >> ${LOG_FILE}
    exit 1
fi

#------------------- Notification Function -----------------------#

command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check if sudo is available or if the script is run as root
maybe_sudo() {
    if [ "$(id -u)" -ne 0 ]; then
        if command -v sudo >/dev/null 2>&1; then
            sudo "$@"
        else
            echo "wazuh-yara: ERROR - This script requires root privileges. Please run with sudo or as root." >> ${LOG_FILE}
            exit 1
        fi
    else
        "$@"
    fi
}

sed_alternative() {
    if command_exists gsed; then
        maybe_sudo gsed "$@"
    else
        maybe_sudo sed "$@"
    fi
}

send_notification() {
    local message="$1"
    local title="Wazuh Alert"
    local iconPath="/usr/share/pixmaps/wazuh-logo.png"
    if [ "$(uname)" = "Darwin" ]; then
        osascript -e "display dialog \"$message\" buttons {\"Dismiss\"} default button \"Dismiss\" with title \"$title\""
    elif [ "$(uname)" = "Linux" ]; then
        if [ -f "$iconPath" ]; then
            notify-send --app-name=Wazuh -u critical "$title" "$message" -i "$iconPath"
        else
            notify-send --app-name=Wazuh -u critical "$title" "$message"
        fi
    else
        echo "Unsupported OS for notifications: $(uname)" >> ${LOG_FILE}
    fi
    echo "Notification sent: $message"
}

#------------------------- Main workflow --------------------------#

# Execute Yara scan on the specified filename
yara_output="$("${YARA_PATH}"/yara -w -r "$YARA_RULES" "$FILENAME")"

if [[ $yara_output != "" ]]
then
    # Log each detection
    while read -r line; do
        echo "wazuh-yara: INFO - Scan result: $line" >> ${LOG_FILE}
    done <<< "$yara_output"

    # Format notification message with scan results
    message="Yara scan results:\n\n$(echo "$yara_output" | sed_alternative 's/^/- /')"
    if [ "$(uname)" = "Darwin" ]; then
        message=$(echo "$message" | tr '\n' '\r')
    fi

    # Send notification
    send_notification "$message"
fi

exit 0;