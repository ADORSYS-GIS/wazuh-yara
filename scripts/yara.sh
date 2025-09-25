#!/bin/bash
# Wazuh - Yara active response
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
        # Try to find a newer bash
        newer_bash=""
        
        # Check common locations for newer bash
        if [ -x "/opt/homebrew/bin/bash" ]; then
            # macOS Apple Silicon with Homebrew
            newer_bash="/opt/homebrew/bin/bash"
        elif [ -x "/usr/local/bin/bash" ]; then
            # macOS Intel with Homebrew or Ubuntu with custom bash
            newer_bash="/usr/local/bin/bash"
        elif [ -x "/bin/bash" ]; then
            # Check if system bash is actually version 4+
            system_bash_version=$(/bin/bash -c 'echo $BASH_VERSION' 2>/dev/null)
            system_bash_major="${system_bash_version%%.*}"
            if [ "$system_bash_major" -ge 4 ] 2>/dev/null; then
                newer_bash="/bin/bash"
            fi
        fi
        
        # Re-execute with newer bash if found
        if [ -n "$newer_bash" ]; then
            exec "$newer_bash" "$0" "$@"
        else
            echo "Error: This script requires Bash 4.0 or later. Current version: $BASH_VERSION" >&2
            echo "Please install a newer version of Bash." >&2
            exit 1
        fi
    fi
fi

# Exit immediately if a command exits with a non-zero status.
if [ -n "$BASH_VERSION" ]; then
    set -euo pipefail
else
    set -eu
fi

#------------------------- Gather parameters -------------------------#

# Extra arguments
read INPUT_JSON
FILENAME=$(echo "$INPUT_JSON" | jq -r .parameters.alert.syscheck.path)

# Validate FILENAME is not empty after jq parsing
if [ -z "$FILENAME" ]; then
    echo "wazuh-yara: ERROR - FILENAME parameter is empty from alert JSON." >> "${LOG_FILE}"
    exit 1
fi

# Default paths and variables
if [ "$(uname)" = "Darwin" ]; then
    YARA_PATH="/opt/yara/bin"  # Direct prebuilt installation path
    YARA_RULES="/Library/Ossec/ruleset/yara/rules/yara_rules.yar"
    OSSEC_CONF_PATH="/Library/Ossec/etc/ossec.conf"
    LOG_FILE="/Library/Ossec/logs/active-responses.log"
    iconPath="/Library/Application Suport/Ossec/wazuh-logo.png"
elif [ "$(uname)" = "Linux" ]; then
    YARA_PATH="/usr/local/bin"
    YARA_RULES="/var/ossec/ruleset/yara/rules/yara_rules.yar"
    OSSEC_CONF_PATH="/var/ossec/etc/ossec.conf"
    LOG_FILE="/var/ossec/logs/active-responses.log"
    iconPath="/usr/share/pixmaps/wazuh-logo.png"
else
    echo "wazuh-yara: ERROR - Unsupported OS: $(uname). This script only supports macOS and Linux." >> "${LOG_FILE}"
    exit 1
fi

if [[ ! -f "$FILENAME" ]]; then
    echo "wazuh-yara: WARNING - File '$FILENAME' does not exist or is not a regular file. Skipping scan." >> "${LOG_FILE}"
    exit 0
fi

size=0
# Wait for the file to be fully written before scanning
actual_size=$(stat -c %s "${FILENAME}" 2>/dev/null || echo "0")
while [ ${size} -ne ${actual_size} ]; do
    sleep 1
    size=${actual_size}
    actual_size=$(stat -c %s "${FILENAME}" 2>/dev/null || echo "0")
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

    # Check if the <syscheck> section exists
    if ! grep -q "<syscheck>" "$OSSEC_CONF_PATH"; then
        echo "wazuh-yara: WARNING - <syscheck> section not found in $OSSEC_CONF_PATH. Cannot add ignore rule for '$file_to_ignore'." >> "${LOG_FILE}"
        return 1
    fi

    # Check if the ignore rule already exists
    if grep -q "<ignore>${file_to_ignore}</ignore>" "$OSSEC_CONF_PATH"; then
        echo "wazuh-yara: DEBUG - File '$file_to_ignore' is already ignored in FIM." >> "${LOG_FILE}"
        return 0
    fi

    # Use awk to insert the ignore tag before the closing </syscheck> tag
    awk -v file="${file_to_ignore}" '/<\/syscheck>/ {
        print "  <ignore>" file "</ignore>"
        print
        next
    }
    { print }' "$OSSEC_CONF_PATH" > "$temp_ossec_conf"

    if [ $? -eq 0 ] && [ -s "$temp_ossec_conf" ]; then
        mv "$temp_ossec_conf" "$OSSEC_CONF_PATH"
        echo "wazuh-yara: DEBUG - Added '$file_to_ignore' to FIM ignore list in $OSSEC_CONF_PATH." >> "${LOG_FILE}"
        
        # Restart Wazuh agent to apply FIM changes
        if [ "$(uname)" = "Darwin" ]; then
            /Library/Ossec/bin/wazuh-control restart >> "${LOG_FILE}" 2>&1
            echo "wazuh-yara: DEBUG - Wazuh agent restarted on macOS to apply FIM changes." >> "${LOG_FILE}"
        elif [ "$(uname)" = "Linux" ]; then
            systemctl restart wazuh-agent >> "${LOG_FILE}" 2>&1
            echo "wazuh-yara: DEBUG - Wazuh agent restarted on Linux to apply FIM changes." >> "${LOG_FILE}"
        fi
        return 0
    else
        echo "wazuh-yara: ERROR - Failed to add '$file_to_ignore' to FIM ignore list." >> "${LOG_FILE}"
        return 1
    fi
}

#------------------- Confirmation Dialogs -----------------------#

confirm_action_linux() {
    local action="$1"
    local confirmation_message="$2"
    local confirm_text="Yes, $action"
    local cancel_text="No, Cancel"

    # For zenity, we need to ensure the user's DBus session is targeted correctly
    local USER=$(who | awk '{print $1}' | head -n 1)
    local USER_UID=$(id -u "$USER")
    local DBUS_PATH="/run/user/$USER_UID/bus"

    local response=$(sudo -u "$USER" DISPLAY=:0 DBUS_SESSION_BUS_ADDRESS="unix:path=$DBUS_PATH" \
                     zenity --question \
                     --title="Confirmation Required" \
                     --text="$confirmation_message" \
                     --ok-label="$confirm_text" \
                     --cancel-label="$cancel_text" \
                     --width=400 2>/dev/null)
                     
    
    if [ "$?" -eq 0 ]; then # OK/Yes clicked
        return 0 # True (confirmed)
    else
        return 1 # False (canceled)
    fi
}

confirm_action_macos() {
    local action="$1"
    local confirmation_message="$2"
    local confirm_button="$action" # Use the action itself as the button text
    local cancel_button="Cancel"

    local osascript_command="display dialog \"$confirmation_message\" with title \"Confirmation Required\" buttons {\"$cancel_button\", \"$confirm_button\"} default button \"$cancel_button\" with icon caution"
    local osascript_result=$(osascript -e "$osascript_command" 2>/dev/null)

    if [[ "$osascript_result" == *"button returned:$confirm_button"* ]]; then
        return 0 # True (confirmed)
    else
        return 1 # False (canceled)
    fi
}


#------------------- Notification Function (Linux with notify-send) -----------------------#
send_notification_linux() {
    local title="Wazuh-Yara Malware Alert"
    local message_body="$1" # This will contain all findings
    local detected_files_paths_array_ref=$2 # Array reference for file paths

    USER=$(who | awk '{print $1}' | head -n 1)
    USER_UID=$(id -u "$USER")
    DBUS_PATH="/run/user/$USER_UID/bus"

    local notify_command=(sudo -u "$USER" DISPLAY=:0 DBUS_SESSION_BUS_ADDRESS="unix:path=$DBUS_PATH" notify-send --app-name=Wazuh -u critical)
    if [ -f "$iconPath" ]; then
        notify_command+=( -i "$iconPath" )
    fi
    # Add actions. notify-send returns the action ID if a button is clicked.
    notify_command+=( -A "delete_all=Delete All" -A "ignore_all=Ignore All" -A "dismiss=Dismiss" )
    notify_command+=( "$title" "$message_body" )
    # Execute notify-send and capture its output (the action ID)
    local user_action=$("${notify_command[@]}" 2>/dev/null)

    # Build list of files for confirmation dialogs
    local files_list_for_confirm=""
    for file_path in "${!detected_files_paths_array_ref}"; do
        files_list_for_confirm+="- ${file_path}\n"
    done
    files_list_for_confirm="${files_list_for_confirm%$'\n'}" # Remove trailing newline

    # Process the user's action
    case "$user_action" in
        "delete_all")
            local confirm_msg="Are you sure you want to DELETE these files?\n\n${files_list_for_confirm}\n\nThis action cannot be undone."
            if confirm_action_linux "Delete" "$confirm_msg"; then
                echo "wazuh-yara: DEBUG - User confirmed DELETE ALL detected files." >> "${LOG_FILE}"
                local delete_success=()
                local delete_fail=()
                for file_path in "${!detected_files_paths_array_ref}"; do
                    echo "wazuh-yara: DEBUG - Attempting to delete file: ${file_path}" >> "${LOG_FILE}"
                    rm -f "${file_path}"
                    if [ $? -eq 0 ]; then
                        echo "wazuh-yara: SUCCESS - Delete file: ${file_path}" >> "${LOG_FILE}"
                        delete_success+=("${file_path}")
                    else
                        echo "wazuh-yara: ERROR - Delete file: ${file_path}" >> "${LOG_FILE}"
                        delete_fail+=("${file_path}")
                    fi
                done
                # Show notification for result
                local notify_msg=""
                if [ ${#delete_success[@]} -gt 0 ]; then
                    notify_msg+="Deleted files successfully:\n"
                    for f in "${delete_success[@]}"; do
                        notify_msg+="- $f\n"
                    done
                fi
                if [ ${#delete_fail[@]} -gt 0 ]; then
                    notify_msg+="Failed to delete:\n"
                    for f in "${delete_fail[@]}"; do
                        notify_msg+="- $f\n"
                    done
                fi
                if [ -n "$notify_msg" ]; then
                    if [ -f "$iconPath" ]; then
                        sudo -u "$USER" DISPLAY=:0 DBUS_SESSION_BUS_ADDRESS="unix:path=$DBUS_PATH" \
                            notify-send --app-name=Wazuh -u critical -i "$iconPath" "Wazuh-Yara Delete Result" "$notify_msg"
                    else
                        sudo -u "$USER" DISPLAY=:0 DBUS_SESSION_BUS_ADDRESS="unix:path=$DBUS_PATH" \
                            notify-send --app-name=Wazuh -u critical "Wazuh-Yara Delete Result" "$notify_msg"
                    fi
                fi
            else
                echo "wazuh-yara: DEBUG - User CANCELLED DELETE ALL operation." >> "${LOG_FILE}"
            fi
            ;;
        "ignore_all")
            local confirm_msg="Are you sure you want to IGNORE these files from future FIM scans?\n\n${files_list_for_confirm}\n\nThis will modify Wazuh agent configuration and require a restart."
            if confirm_action_linux "Ignore" "$confirm_msg"; then
                echo "wazuh-yara: DEBUG - User confirmed IGNORE ALL detected files." >> "${LOG_FILE}"
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
                # Show notification for result
                local notify_msg=""
                if [ ${#ignore_success[@]} -gt 0 ]; then
                    notify_msg+="Ignored files successfully:\n"
                    for f in "${ignore_success[@]}"; do
                        notify_msg+="- $f\n"
                    done
                fi
                if [ ${#ignore_fail[@]} -gt 0 ]; then
                    notify_msg+="Failed to ignore:\n"
                    for f in "${ignore_fail[@]}"; do
                        notify_msg+="- $f\n"
                    done
                fi
                if [ -n "$notify_msg" ]; then
                    if [ -f "$iconPath" ]; then
                        sudo -u "$USER" DISPLAY=:0 DBUS_SESSION_BUS_ADDRESS="unix:path=$DBUS_PATH" \
                            notify-send --app-name=Wazuh -u critical -i "$iconPath" "Wazuh-Yara Ignore Result" "$notify_msg"
                    else
                        sudo -u "$USER" DISPLAY=:0 DBUS_SESSION_BUS_ADDRESS="unix:path=$DBUS_PATH" \
                            notify-send --app-name=Wazuh -u critical "Wazuh-Yara Ignore Result" "$notify_msg"
                    fi
                fi
            else
                echo "wazuh-yara: DEBUG - User CANCELLED IGNORE ALL operation." >> "${LOG_FILE}"
            fi
            ;;
        "dismiss")
            echo "wazuh-yara: DEBUG - User chose to DISMISS the notification." >> "${LOG_FILE}"
            ;;
        *)
            echo "wazuh-yara: DEBUG - Notification dismissed or unknown action (Linux)." >> "${LOG_FILE}"
            ;;
    esac
    echo "Notification sent: $message_body" >> "${LOG_FILE}"
}

#------------------- Notification Function (macOS with osascript) -----------------------#
send_notification_macos() {
    local title="Wazuh-Yara Malware Alert"
    local message_body="$1" # This will contain all findings
    local detected_files_paths_array_ref=$2 # Array reference for file paths

    # osascript display dialog doesn't directly return action IDs.
    # We define buttons and capture which button was pressed.
    # Try to use icon if available (macOS: must be .icns or .png, and full path)
    local iconArg=""
    if [ -f "$iconPath" ]; then
        iconArg="with icon POSIX file \"$iconPath\""
    fi
    local osascript_command="display dialog \"$message_body\" with title \"$title\" buttons {\"Dismiss\", \"Ignore All\", \"Delete All\"} default button \"Dismiss\" $iconArg"
    # Execute osascript and capture its output
    # 'button returned:BUTTON_NAME'
    local osascript_result=$(osascript -e "$osascript_command" 2>/dev/null)

    local user_action=""
    if [[ "$osascript_result" == *"button returned:Delete All"* ]]; then
        user_action="delete_all"
    elif [[ "$osascript_result" == *"button returned:Ignore All"* ]]; then
        user_action="ignore_all"
    else # Includes "Dismiss" or dialog closed
        user_action="dismiss"
    fi

    # Build list of files for confirmation dialogs
    local files_list_for_confirm=""
    for file_path in "${!detected_files_paths_array_ref}"; do
        files_list_for_confirm+="- ${file_path}\n"
    done
    files_list_for_confirm="${files_list_for_confirm%$'\n'}" # Remove trailing newline

    # Process the user's action
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
                    if [ $? -eq 0 ]; then
                        echo "wazuh-yara: SUCCESS - Delete file: ${file_path}" >> "${LOG_FILE}"
                        delete_success+=("${file_path}")
                    else
                        echo "wazuh-yara: ERROR - Delete file: ${file_path}" >> "${LOG_FILE}"
                        delete_fail+=("${file_path}")
                    fi
                done
                # Show notification for result
                local notify_msg=""
                if [ ${#delete_success[@]} -gt 0 ]; then
                    notify_msg+="Deleted files successfully:\n"
                    for f in "${delete_success[@]}"; do
                        notify_msg+="- $f\n"
                    done
                fi
                if [ ${#delete_fail[@]} -gt 0 ]; then
                    notify_msg+="Failed to delete:\n"
                    for f in "${delete_fail[@]}"; do
                        notify_msg+="- $f\n"
                    done
                fi
                if [ -n "$notify_msg" ]; then
                    if [ -f "$iconPath" ]; then
                        osascript -e "display notification (\"$notify_msg\") with title (\"Wazuh-Yara Delete Result\") sound name \"default\" subtitle \"Wazuh\"" -e "set theIcon to POSIX file \"$iconPath\" as alias" -e "display notification (\"$notify_msg\") with title (\"Wazuh-Yara Delete Result\") subtitle (\"Wazuh\") sound name (\"default\")"
                    else
                        osascript -e "display notification (\"$notify_msg\") with title (\"Wazuh-Yara Delete Result\")"
                    fi
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
                # Show notification for result
                local notify_msg=""
                if [ ${#ignore_success[@]} -gt 0 ]; then
                    notify_msg+="Ignored files successfully:\n"
                    for f in "${ignore_success[@]}"; do
                        notify_msg+="- $f\n"
                    done
                fi
                if [ ${#ignore_fail[@]} -gt 0 ]; then
                    notify_msg+="Failed to ignore:\n"
                    for f in "${ignore_fail[@]}"; do
                        notify_msg+="- $f\n"
                    done
                fi
                if [ -n "$notify_msg" ]; then
                    if [ -f "$iconPath" ]; then
                        osascript -e "display notification (\"$notify_msg\") with title (\"Wazuh-Yara Ignore Result\") sound name \"default\" subtitle \"Wazuh\"" -e "set theIcon to POSIX file \"$iconPath\" as alias" -e "display notification (\"$notify_msg\") with title (\"Wazuh-Yara Ignore Result\") subtitle (\"Wazuh\") sound name (\"default\")"
                    else
                        osascript -e "display notification (\"$notify_msg\") with title (\"Wazuh-Yara Ignore Result\")"
                    fi
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

# Execute Yara scan on the specified filename
# It's crucial to check for file existence BEFORE attempting Yara scan
if ! "${YARA_PATH}"/yara -w -r "$YARA_RULES" "$FILENAME" &> /dev/null; then
    echo "wazuh-yara: DEBUG - Yara scan failed for '$FILENAME' (could not open file or other issue). Skipping further processing." >> "${LOG_FILE}"
    exit 0 # Exit gracefully, as the file might be gone or inaccessible
fi
yara_output="$("${YARA_PATH}"/yara -w -r "$YARA_RULES" "$FILENAME")"


if [[ $yara_output != "" ]]
then
    declare -A detected_rules_by_file || detected_rules_by_file=()
    declare -a unique_detected_files || unique_detected_files=()

    # Collect all detected files and their rules, grouping by file path
    while read -r line; do
        echo "wazuh-yara: INFO - Scan result: $line" >> "${LOG_FILE}"

        # Extract the rule and file from the Yara output
        rule="${line%% *}"
        detected_file="${line#* }"

        # If this is the first time we see this file, add it to the unique list
        if [[ -z "${detected_rules_by_file[$detected_file]+_}" ]]; then
            unique_detected_files+=("$detected_file")
        fi
        
        # Append the rule to the list for this file, separated by newline
        detected_rules_by_file["$detected_file"]+="- ${rule}\n"
    done <<< "$yara_output"

    notification_message="Malware detected by Yara:\n\n"
    declare -a detected_file_paths # Array to store just the file paths for actions

    # Format the notification message for UI/UX (improved readability)
    for file_path in "${unique_detected_files[@]}"; do
        notification_message+="\nFile: ${file_path}\n"
        notification_message+="Rules:\n"
        # Split rules into lines and indent for clarity
        while IFS= read -r rule_line; do
            [[ -n "$rule_line" ]] && notification_message+="    $rule_line\n"
        done <<< "${detected_rules_by_file[$file_path]}"
        detected_file_paths+=("${file_path}")
    done

    # Remove the last extra newline for aesthetics if it exists
    notification_message="${notification_message%$'\n'}"


    # Send notification based on OS
    if [ "$(uname)" = "Linux" ]; then
        send_notification_linux "$notification_message" "detected_file_paths[@]" # Pass array name for indirection
    elif [ "$(uname)" = "Darwin" ]; then
        send_notification_macos "$notification_message" "detected_file_paths[@]" # Pass array name for indirection
    else
        echo "Unsupported OS for notifications: $(uname)" >> "${LOG_FILE}"
        echo "wazuh-yara: DEBUG - Simple log of findings: $notification_message" >> "${LOG_FILE}"
    fi
fi

exit 0;