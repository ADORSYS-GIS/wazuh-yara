#!/bin/bash

# Simple Yara scan with high-level progress output
# - Expects .parameters.alert.syscheck.path to be a JSON array of paths
# - Logs detection output to active-responses.log
# - Prints which large dir is being scanned (for '/')

set -uo pipefail

# --- Helper: trim whitespace (for safety) ---
trim() {
    local s="$1"
    s="${s#"${s%%[![:space:]]*}"}"  # leading
    s="${s%"${s##*[![:space:]]}"}"  # trailing
    printf '%s' "$s"
}

# Read full Wazuh JSON input from stdin (not just first line)
INPUT_JSON="$(cat)"

if [[ -z "$INPUT_JSON" ]]; then
    echo "wazuh-yara: ERROR - No JSON received on stdin" >&2
    exit 1
fi

# Expect: .parameters.alert.syscheck.path is an array
RAW_PATHS=$(echo "$INPUT_JSON" | jq -c '.parameters.alert.syscheck.path' 2>/dev/null || echo "null")

if [[ -z "$RAW_PATHS" || "$RAW_PATHS" == "null" ]]; then
    echo "wazuh-yara: ERROR - .parameters.alert.syscheck.path is null/empty or missing" >&2
    exit 1
fi

if ! echo "$RAW_PATHS" | jq -e 'type=="array"' >/dev/null 2>&1; then
    echo "wazuh-yara: ERROR - .parameters.alert.syscheck.path must be a JSON array" >&2
    exit 1
fi

# Build PATH_LIST[] from the JSON array
PATH_LIST=()
while IFS= read -r p; do
    PATH_LIST+=( "$(trim "$p")" )
done < <(echo "$RAW_PATHS" | jq -r '.[]')

# Define environment-specific paths
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

if [[ ! -f "$YARA_RULES" ]]; then
    echo "wazuh-yara: ERROR - Yara rules missing at $YARA_RULES" >> "$LOG_FILE"
    exit 1
fi

# Validate paths
VALID_PATHS=()
for p in "${PATH_LIST[@]}"; do
    [[ -z "$p" ]] && continue
    if [[ ! -e "$p" ]]; then
        echo "wazuh-yara: ERROR - Invalid path '$p'" >> "$LOG_FILE"
        continue
    fi
    VALID_PATHS+=( "$p" )
done

if ((${#VALID_PATHS[@]} == 0)); then
    echo "wazuh-yara: ERROR - No valid paths to scan (all invalid or empty)" >> "$LOG_FILE"
    exit 0
fi

# Print target paths
echo -n "Yara AR: starting. Target path(s): "
first=1
for p in "${VALID_PATHS[@]}"; do
    if (( first )); then
        echo -n "'$p'"
        first=0
    else
        echo -n ", '$p'"
    fi
done
echo

# --- Estimation (per path) ---
estimate_scan_time() {
    local p="$1"

    if [[ "$p" == "/" ]]; then
        echo "Estimated scan for '$p': entire filesystem ('/')."
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
        echo "Estimated scan for '$p': single file (~$(( (s+1048575)/1048576 )) MB)."
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

        echo "Estimated scan for '$p': ~${num} files (~${size}MB)."
        echo "Estimated duration: ~$((sec/60))m $((sec%60))s (assuming ${t}MB/s)."
    fi
}

# --- Actual scan, aggregated across paths ---
yara_output_all=""

scan_one_path() {
    local p="$1"
    local out=""

    echo
    echo "----"
    echo "Preparing to scan target: $p"
    estimate_scan_time "$p"
    echo "Starting scan for: $p"

    if [[ -f "$p" ]]; then
        echo "Scanning file: $p"
        out="$("$YARA_BIN" -w "$YARA_RULES" "$p" 2>/dev/null || true)"

    elif [[ -d "$p" ]]; then
        if [[ "$p" == "/" ]]; then
            echo "Scanning entire filesystem by top-level directories..."
            while IFS= read -r topdir; do
                echo "Scanning top-level directory: $topdir"
                part=$("$YARA_BIN" -w -r "$YARA_RULES" "$topdir" 2>/dev/null || true)
                if [[ -n "$part" ]]; then
                    [[ -n "$out" ]] && out+=$'\n'
                    out+="$part"
                fi
            done < <(find "$p" -mindepth 1 -maxdepth 1 -type d 2>/dev/null || true)
        else
            echo "Scanning directory tree: $p"
            out="$("$YARA_BIN" -w -r "$YARA_RULES" "$p" 2>/dev/null || true)"
        fi
    else
        echo "wazuh-yara: ERROR - Path is neither file nor directory '$p'" >> "$LOG_FILE"
        return 0
    fi

    if [[ -n "$out" ]]; then
        if [[ -n "$yara_output_all" ]]; then
            yara_output_all+=$'\n'
        fi
        yara_output_all+="$out"
    fi
}

for p in "${VALID_PATHS[@]}"; do
    scan_one_path "$p"
done

# --- Log results to active-responses.log ---
if [[ -n "$yara_output_all" ]]; then
    while IFS= read -r line; do
        [[ -n "$line" ]] && echo "wazuh-yara: INFO - Scan result: $line" >> "$LOG_FILE"
    done <<< "$yara_output_all"
else
    path_summary=$(IFS=', '; echo "${VALID_PATHS[*]}")
    echo "wazuh-yara: INFO - No detections in '$path_summary'" >> "$LOG_FILE"
fi

echo
echo "Yara scan completed."
exit 0
