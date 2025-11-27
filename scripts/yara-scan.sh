#!/bin/bash

# Simple Yara scan with recursive directory progress output
# Logs detection output to active-responses.log
# Prints scan estimation and real-time progress to terminal

set -uo pipefail

# Read Wazuh JSON input from stdin
read INPUT_JSON
SCAN_PATH=$(echo "$INPUT_JSON" | jq -r .parameters.alert.syscheck.path)

# Define paths
if [[ "$(uname)" == "Darwin" ]]; then
    YARA_BIN="/opt/yara/bin/yara"
    YARA_RULES="/Library/Ossec/ruleset/yara/rules/yara_rules.yar"
    LOG_FILE="/Library/Ossec/logs/active-responses.log"
elif [[ "$(uname)" == "Linux" ]]; then
    YARA_BIN="/usr/local/bin/yara"
    YARA_RULES="/var/ossec/ruleset/yara/rules/yara_rules.yar"
    LOG_FILE="/var/ossec/logs/active-responses.log"
else
    echo "Unsupported OS: $(uname)" >&2
    exit 1
fi

# Basic validation
if [[ -z "$SCAN_PATH" ]] || [[ ! -e "$SCAN_PATH" ]]; then
    echo "wazuh-yara: ERROR - Invalid path '$SCAN_PATH'" >> "$LOG_FILE"
    exit 0
fi

if [[ ! -f "$YARA_RULES" ]]; then
    echo "wazuh-yara: ERROR - Yara rules missing at $YARA_RULES" >> "$LOG_FILE"
    exit 1
fi

echo "Yara AR: starting. Target path: '$SCAN_PATH'"  # immediate feedback

# --- Estimation: terminal only, but don't go crazy for "/" ---
estimate_scan_time() {
    local p="$1"

    # For a full filesystem scan, don't try to be clever
    if [[ "$p" == "/" ]]; then
        echo "Estimated scan: entire filesystem ('/')."
        echo "Detailed size estimation skipped (would be very slow)."
        return
    fi

    if [[ -f "$p" ]]; then
        local s
        if [[ "$(uname)" == "Darwin" ]]; then
            s=$(stat -f '%z' "$p" 2>/dev/null || echo 0)
        else
            s=$(stat -c '%s' "$p" 2>/dev/null || echo 0)
        fi
        echo "Estimated scan: single file (~$(( (s+1048575)/1048576 )) MB)."
        return
    fi

    if [[ -d "$p" ]]; then
        local num size
        num=$(find "$p" -type f 2>/dev/null | wc -l | tr -d ' ')

        if [[ "$(uname)" == "Darwin" ]]; then
            size=$(find "$p" -type f -exec stat -f '%z' {} \; 2>/dev/null \
                   | awk '{s+=$1} END{print s+0}')
        else
            size=$(find "$p" -type f -printf '%s\n' 2>/dev/null \
                   | awk '{s+=$1} END{print s+0}')
        fi

        size=$(( (size+1048575)/1048576 ))
        local t=50
        local sec=$(( size / t ))
        [[ $sec -eq 0 && $size -gt 0 ]] && sec=1

        echo "Estimated scan: ~${num} files (~${size}MB)."
        echo "Estimated duration: ~$((sec/60))m $((sec%60))s (assuming ${t}MB/s)."
    fi
}

estimate_scan_time "$SCAN_PATH"
echo "Starting scan..."

# --- Actual scan ---
yara_output=""

if [[ -f "$SCAN_PATH" ]]; then
    echo "Scanning file: $SCAN_PATH"
    yara_output="$("$YARA_BIN" -w "$YARA_RULES" "$SCAN_PATH" 2>/dev/null || true)"
else
    # Walk directories; use process substitution to avoid subshell
    dir_counter=0
    while read -r dir; do
        echo "Scanning directory: $dir"
        out=$("$YARA_BIN" -w "$YARA_RULES" "$dir" 2>/dev/null || true)
        [[ -n "$out" ]] && yara_output+=$'\n'"$out"

        ((dir_counter++))
        # Optional: every 500 dirs, print a little heartbeat
        if (( dir_counter % 500 == 0 )); then
            echo "...still scanning (${dir_counter} directories so far)..."
        fi
    done < <(find "$SCAN_PATH" -type d 2>/dev/null)
fi

# --- Log results to active-responses.log ---
if [[ -n "$yara_output" ]]; then
    echo "wazuh-yara: ALERT - Yara detections in '$SCAN_PATH':" >> "$LOG_FILE"
    while IFS= read -r line; do
        [[ -n "$line" ]] && echo "wazuh-yara:   $line" >> "$LOG_FILE"
    done <<< "$yara_output"
else
    echo "wazuh-yara: INFO - No detections in '$SCAN_PATH'" >> "$LOG_FILE"
fi

echo "Yara scan completed."
exit 0
