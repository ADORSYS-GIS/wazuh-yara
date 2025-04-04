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
send_notification() {
    local message="$1"
    local title="Wazuh Alert"
    local iconPath="/usr/share/pixmaps/wazuh-logo.png"

    if [ "$(uname)" = "Darwin" ]; then
        osascript -e "display dialog \"$message\" buttons {\"Dismiss\"} default button \"Dismiss\" with title \"$title\""
    elif [ "$(uname)" = "Linux" ]; then
        # Get the logged-in user
        USER=$(who | awk '{print $1}' | head -n 1)
        USER_UID=$(id -u "$USER")
        DBUS_PATH="/run/user/$USER_UID/bus"

        if [ -f "$iconPath" ]; then
             sudo -u "$USER" DISPLAY=:0 DBUS_SESSION_BUS_ADDRESS="unix:path=$DBUS_PATH" \
                notify-send --app-name=Wazuh -u critical "$title" "$message" -i "$iconPath"
        else
             sudo -u "$USER" DISPLAY=:0 DBUS_SESSION_BUS_ADDRESS="unix:path=$DBUS_PATH" \
                notify-send --app-name=Wazuh -u critical  "$title" "$message"
        fi
    else
        echo "Unsupported OS for notifications: $(uname)" >> ${LOG_FILE}
    fi
    echo "Notification sent: $message" >> ${LOG_FILE}
}

#------------------------- Main workflow --------------------------#

# Execute Yara scan on the specified filename
yara_output="$("${YARA_PATH}"/yara -w -r "$YARA_RULES" "$FILENAME")"

if [[ $yara_output != "" ]]
then
    message="Wazuh-Yara Scan results"
    # Log each detection
    while read -r line; do
        echo "wazuh-yara: INFO - Scan result: $line" >> ${LOG_FILE}

        # Extract the rule and file from the Yara output
        rule=$(echo "$line" | awk '{print $1}')
        detected_file=$(echo "$line" | awk '{print $2}')

        # append extra information to the message
        message="${message}\nMalware: $rule; File: $detected_file"
    done <<< "$yara_output"

    # Send notification
    send_notification "$message"
fi

exit 0;