#!/bin/bash
# Wazuh - Yara active response (macOS)
# Copyright (C) 2025, ADORSYS GmbH & CO KG.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

# Check Bash version and re-execute with newer bash if needed (macOS ships with bash 3)
if [[ -n "$BASH_VERSION" ]]; then
    bash_major="${BASH_VERSION%%.*}"
    if [[ "$bash_major" -lt 4 ]]; then
        newer_bash=""

        if [[ -x "/opt/homebrew/bin/bash" ]]; then
            newer_bash="/opt/homebrew/bin/bash"
        elif [[ -x "/usr/local/bin/bash" ]]; then
            newer_bash="/usr/local/bin/bash"
        elif [[ -x "/bin/bash" ]]; then
            system_bash_version=$(/bin/bash -c 'echo $BASH_VERSION' 2>/dev/null)
            system_bash_major="${system_bash_version%%.*}"
            if [[ "$system_bash_major" -ge 4 ]] 2>/dev/null; then
                newer_bash="/bin/bash"
            fi
        fi

        if [[ -n "$newer_bash" ]]; then
            exec "$newer_bash" "$0" "$@"
        else
            echo "Error: This script requires Bash 4.0 or later. Current version: $BASH_VERSION" >&2
            echo "Please install a newer version of Bash (e.g. via Homebrew: brew install bash)." >&2
            exit 1
        fi
    fi
fi

# Exit immediately if a command exits with a non-zero status.
if [[ -n "$BASH_VERSION" ]]; then
    set -euo pipefail
else
    set -eu
fi

#------------------------- Gather parameters -------------------------#

# Extra arguments
read INPUT_JSON
FILENAME=$(echo "$INPUT_JSON" | jq -r .parameters.alert.syscheck.path)

if [[ -z "$FILENAME" ]]; then
    echo "wazuh-yara: ERROR - FILENAME parameter is empty from alert JSON." >> "${LOG_FILE}"
    exit 1
fi

# Default paths and variables
YARA_PATH="/opt/wazuh/yara/bin"
YARA_RULES="/Library/Ossec/ruleset/yara/rules/yara_rules.yar"
OSSEC_CONF_PATH="/Library/Ossec/etc/ossec.conf"
LOG_FILE="/Library/Ossec/logs/active-responses.log"
iconPath="/Library/Application Support/Ossec/wazuh-logo.png"

if [[ ! -f "$FILENAME" ]]; then
    echo "wazuh-yara: WARNING - File '$FILENAME' does not exist or is not a regular file. Skipping scan." >> "${LOG_FILE}"
    exit 0
fi

size=0
# Wait for the file to be fully written before scanning (macOS uses stat -f %z)
actual_size=$(stat -f %z "${FILENAME}" 2>/dev/null || echo "0")
while [[ ${size} -ne ${actual_size} ]]; do
    sleep 1
    size=${actual_size}
    actual_size=$(stat -f %z "${FILENAME}" 2>/dev/null || echo "0")
done


#----------------------- Analyze parameters -----------------------#

if [[ ! $YARA_PATH ]] || [[ ! -f "$YARA_RULES" ]]
then
    echo "wazuh-yara: ERROR - Yara active response error. Yara path: ($YARA_PATH) and rules: ($YARA_RULES) parameters are mandatory and rules file must exist." >> "${LOG_FILE}"
    exit 1
fi

if [[ ! -f "$OSSEC_CONF_PATH" ]]
then
    echo "wazuh-yara: ERROR - OSSEC configuration file not found at: $OSSEC_CONF_PATH" >> "${LOG_FILE}"
    exit 1
fi

#------------------- Helper Functions -----------------------#

# Function to add an ignore path to ossec.conf
add_fim_ignore() {
    local file_to_ignore="$1"
    local temp_ossec_conf="${OSSEC_CONF_PATH}.tmp"

    if ! grep -q "<syscheck>" "$OSSEC_CONF_PATH"; then
        echo "wazuh-yara: WARNING - <syscheck> section not found in $OSSEC_CONF_PATH. Cannot add ignore rule for '$file_to_ignore'." >> "${LOG_FILE}"
        return 1
    fi

    if grep -q "<ignore>${file_to_ignore}</ignore>" "$OSSEC_CONF_PATH"; then
        echo "wazuh-yara: DEBUG - File '$file_to_ignore' is already ignored in FIM." >> "${LOG_FILE}"
        return 0
    fi

    awk -v file="${file_to_ignore}" '/<\/syscheck>/ {
        print "  <ignore>" file "</ignore>"
        print
        next
    }
    { print }' "$OSSEC_CONF_PATH" > "$temp_ossec_conf"

    if [[ $? -eq 0 ]] && [[ -s "$temp_ossec_conf" ]]; then
        mv "$temp_ossec_conf" "$OSSEC_CONF_PATH"
        echo "wazuh-yara: DEBUG - Added '$file_to_ignore' to FIM ignore list in $OSSEC_CONF_PATH." >> "${LOG_FILE}"

        /Library/Ossec/bin/wazuh-control restart >> "${LOG_FILE}" 2>&1
        echo "wazuh-yara: DEBUG - Wazuh agent restarted on macOS to apply FIM changes." >> "${LOG_FILE}"
        return 0
    else
        echo "wazuh-yara: ERROR - Failed to add '$file_to_ignore' to FIM ignore list." >> "${LOG_FILE}"
        return 1
    fi
}

#------------------- Confirmation Dialog -----------------------#

confirm_action_macos() {
    local action="$1"
    local confirmation_message="$2"
    local confirm_button="$action"
    local cancel_button="Cancel"

    local osascript_command="display dialog \"$confirmation_message\" with title \"Confirmation Required\" buttons {\"$cancel_button\", \"$confirm_button\"} default button \"$cancel_button\" with icon caution"
    local osascript_result=$(osascript -e "$osascript_command" 2>/dev/null)

    if [[ "$osascript_result" == *"button returned:$confirm_button"* ]]; then
        return 0
    else
        return 1
    fi
}

#------------------- Notification Function -----------------------#

send_notification_macos() {
    local title="Wazuh-Yara Malware Alert"
    local message_body="$1"
    local detected_files_paths_array_ref=$2

    local iconArg=""
    if [[ -f "$iconPath" ]]; then
        iconArg="with icon POSIX file \"$iconPath\""
    fi
    local osascript_command="display dialog \"$message_body\" with title \"$title\" buttons {\"Dismiss\", \"Ignore All\", \"Delete All\"} default button \"Dismiss\" $iconArg"
    local osascript_result=$(osascript -e "$osascript_command" 2>/dev/null)

    local user_action=""
    if [[ "$osascript_result" == *"button returned:Delete All"* ]]; then
        user_action="delete_all"
    elif [[ "$osascript_result" == *"button returned:Ignore All"* ]]; then
        user_action="ignore_all"
    else
        user_action="dismiss"
    fi

    local files_list_for_confirm=""
    for file_path in "${!detected_files_paths_array_ref}"; do
        files_list_for_confirm+="- ${file_path}\n"
    done
    files_list_for_confirm="${files_list_for_confirm%$'\n'}"

    case "$user_action" in
        "delete_all")
            local confirm_msg="Are you sure you want to DELETE these files?\n\n${files_list_for_confirm}\n\nThis action cannot be undone."
            if confirm_action_macos "Delete" "$confirm_msg"; then
                echo "wazuh-yara: DEBUG - User confirmed DELETE ALL detected files (macOS)." >> "${LOG_FILE}"
                local delete_success=()
                local delete_fail=()
                for file_path in "${!detected_files_paths_array_ref}"; do
                    echo "wazuh-yara: DEBUG - Attempting to delete file: ${file_path}" >> "${LOG_FILE}"
                    rm -f "${file_path}"
                    if [[ $? -eq 0 ]]; then
                        echo "wazuh-yara: SUCCESS - Delete file: ${file_path}" >> "${LOG_FILE}"
                        delete_success+=("${file_path}")
                    else
                        echo "wazuh-yara: ERROR - Delete file: ${file_path}" >> "${LOG_FILE}"
                        delete_fail+=("${file_path}")
                    fi
                done
                local notify_msg=""
                if [[ ${#delete_success[@]} -gt 0 ]]; then
                    notify_msg+="Deleted files successfully:\n"
                    for f in "${delete_success[@]}"; do notify_msg+="- $f\n"; done
                fi
                if [[ ${#delete_fail[@]} -gt 0 ]]; then
                    notify_msg+="Failed to delete:\n"
                    for f in "${delete_fail[@]}"; do notify_msg+="- $f\n"; done
                fi
                if [[ -n "$notify_msg" ]]; then
                    osascript -e "display notification (\"$notify_msg\") with title (\"Wazuh-Yara Delete Result\") subtitle (\"Wazuh\") sound name (\"default\")"
                fi
            else
                echo "wazuh-yara: DEBUG - User CANCELLED DELETE ALL operation (macOS)." >> "${LOG_FILE}"
            fi
            ;;
        "ignore_all")
            local confirm_msg="Are you sure you want to IGNORE these files from future FIM scans?\n\n${files_list_for_confirm}\n\nThis will modify Wazuh agent configuration and require a restart."
            if confirm_action_macos "Ignore" "$confirm_msg"; then
                echo "wazuh-yara: DEBUG - User confirmed IGNORE ALL detected files (macOS)." >> "${LOG_FILE}"
                local ignore_success=()
                local ignore_fail=()
                for file_path in "${!detected_files_paths_array_ref}"; do
                    if add_fim_ignore "${file_path}"; then
                        echo "wazuh-yara: SUCCESS - Ignore file: ${file_path}" >> "${LOG_FILE}"
                        ignore_success+=("${file_path}")
                    else
                        echo "wazuh-yara: ERROR - Ignore file: ${file_path}" >> "${LOG_FILE}"
                        ignore_fail+=("${file_path}")
                    fi
                done
                local notify_msg=""
                if [[ ${#ignore_success[@]} -gt 0 ]]; then
                    notify_msg+="Ignored files successfully:\n"
                    for f in "${ignore_success[@]}"; do notify_msg+="- $f\n"; done
                fi
                if [[ ${#ignore_fail[@]} -gt 0 ]]; then
                    notify_msg+="Failed to ignore:\n"
                    for f in "${ignore_fail[@]}"; do notify_msg+="- $f\n"; done
                fi
                if [[ -n "$notify_msg" ]]; then
                    osascript -e "display notification (\"$notify_msg\") with title (\"Wazuh-Yara Ignore Result\") subtitle (\"Wazuh\") sound name (\"default\")"
                fi
            else
                echo "wazuh-yara: DEBUG - User CANCELLED IGNORE ALL operation (macOS)." >> "${LOG_FILE}"
            fi
            ;;
        "dismiss")
            echo "wazuh-yara: DEBUG - User chose to DISMISS the notification (macOS)." >> "${LOG_FILE}"
            ;;
        *)
            echo "wazuh-yara: DEBUG - Notification dismissed or unknown action (macOS)." >> "${LOG_FILE}"
            ;;
    esac
    echo "Notification sent: $message_body" >> "${LOG_FILE}"
}


#------------------------- Main workflow --------------------------#

if ! "${YARA_PATH}"/yara -w -r "$YARA_RULES" "$FILENAME" &> /dev/null; then
    echo "wazuh-yara: DEBUG - Yara scan failed for '$FILENAME' (could not open file or other issue). Skipping further processing." >> "${LOG_FILE}"
    exit 0
fi
yara_output="$("${YARA_PATH}"/yara -w -r "$YARA_RULES" "$FILENAME")"


if [[ $yara_output != "" ]]
then
    declare -A detected_rules_by_file || detected_rules_by_file=()
    declare -a unique_detected_files || unique_detected_files=()

    while read -r line; do
        echo "wazuh-yara: INFO - Scan result: $line" >> "${LOG_FILE}"

        rule="${line%% *}"
        detected_file="${line#* }"

        if [[ -z "${detected_rules_by_file[$detected_file]+_}" ]]; then
            unique_detected_files+=("$detected_file")
        fi

        detected_rules_by_file["$detected_file"]+="- ${rule}\n"
    done <<< "$yara_output"

    notification_message="Malware detected by Yara:\n\n"
    declare -a detected_file_paths

    for file_path in "${unique_detected_files[@]}"; do
        notification_message+="\nFile: ${file_path}\n"
        notification_message+="Rules:\n"
        while IFS= read -r rule_line; do
            [[ -n "$rule_line" ]] && notification_message+="    $rule_line\n"
        done <<< "${detected_rules_by_file[$file_path]}"
        detected_file_paths+=("${file_path}")
    done

    notification_message="${notification_message%$'\n'}"

    send_notification_macos "$notification_message" "detected_file_paths[@]"
fi

exit 0;