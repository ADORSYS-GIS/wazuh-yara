#!/usr/bin/env bats

setup() {
    # Directory setup
    TEST_DIR="$(mktemp -d)"
    export TMP_DIR="$TEST_DIR"
    
    # Source the shared utilities
    REPO_ROOT="$(cd "$BATS_TEST_DIRNAME/.." && pwd)"
    # shellcheck source=scripts/shared/utils.sh
    source "$REPO_ROOT/scripts/shared/utils.sh"
}

teardown() {
    rm -rf "$TEST_DIR"
}

@test "command_exists detects existing commands" {
    run command_exists bash
    [ "$status" -eq 0 ]
    
    run command_exists sh
    [ "$status" -eq 0 ]
}

@test "command_exists returns non-zero for nonexistent commands" {
    run command_exists nonexistent_cmd_xyz_98765
    [ "$status" -ne 0 ]
}

@test "calculate_sha256 computes correct hash for empty file" {
    local empty_file="$TEST_DIR/empty.txt"
    touch "$empty_file"
    
    run calculate_sha256 "$empty_file"
    [ "$status" -eq 0 ]
    [ "$output" = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" ]
}

@test "calculate_sha256 computes correct hash for known content" {
    local sample_file="$TEST_DIR/sample.txt"
    printf "hello world" > "$sample_file"
    
    run calculate_sha256 "$sample_file"
    [ "$status" -eq 0 ]
    # sha256 of "hello world" is b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9
    [ "$output" = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9" ]
}

@test "calculate_sha256 falls back to shasum if sha256sum is not available" {
    local sample_file="$TEST_DIR/sample.txt"
    printf "fallback test" > "$sample_file"
    
    command_exists() {
        if [[ "$1" == "sha256sum" ]]; then
            return 1
        elif [[ "$1" == "shasum" ]]; then
            return 0
        fi
        return 1
    }
    shasum() {
        echo "mockhash12345  $sample_file"
    }
    
    run calculate_sha256 "$sample_file"
    [ "$status" -eq 0 ]
    [ "$output" = "mockhash12345" ]
}

@test "calculate_sha256 returns error if neither sha256sum nor shasum is available" {
    local sample_file="$TEST_DIR/sample.txt"
    touch "$sample_file"
    
    command_exists() {
        return 1
    }
    
    run calculate_sha256 "$sample_file"
    [ "$status" -eq 1 ]
    [[ "$output" =~ "No SHA256 tool available" ]]
}

@test "verify_checksum succeeds on matching sha256" {
    local sample_file="$TEST_DIR/sample.txt"
    printf "hello world" > "$sample_file"
    local expected="b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
    
    run verify_checksum "$sample_file" "$expected"
    [ "$status" -eq 0 ]
}

@test "verify_checksum fails on mismatched sha256" {
    local sample_file="$TEST_DIR/sample.txt"
    printf "hello world" > "$sample_file"
    local wrong_hash="0000000000000000000000000000000000000000000000000000000000000000"
    
    run verify_checksum "$sample_file" "$wrong_hash"
    [ "$status" -ne 0 ]
    [[ "$output" =~ "Checksum verification FAILED" ]]
}

@test "info_message outputs formatted INFO log" {
    run info_message "Test informational message"
    [ "$status" -eq 0 ]
    [[ "$output" =~ "[INFO]" ]]
    [[ "$output" =~ "Test informational message" ]]
}

@test "warn_message outputs formatted WARNING log" {
    run warn_message "Test warning message"
    [ "$status" -eq 0 ]
    [[ "$output" =~ "[WARNING]" ]]
    [[ "$output" =~ "Test warning message" ]]
}

@test "error_message outputs formatted ERROR log" {
    run error_message "Test error message"
    [ "$status" -eq 0 ]
    [[ "$output" =~ "[ERROR]" ]]
    [[ "$output" =~ "Test error message" ]]
}

@test "success_message outputs formatted SUCCESS log" {
    run success_message "Test success message"
    [ "$status" -eq 0 ]
    [[ "$output" =~ "[SUCCESS]" ]]
    [[ "$output" =~ "Test success message" ]]
}

@test "print_step outputs formatted STEP log" {
    run print_step "1/5" "Initialize environment"
    [ "$status" -eq 0 ]
    [[ "$output" =~ "[STEP]" ]]
    [[ "$output" =~ "1/5: Initialize environment" ]]
}

@test "error_exit prints message and exits with status 1" {
    run error_exit "Fatal abort triggered"
    [ "$status" -eq 1 ]
    [[ "$output" =~ "Fatal abort triggered" ]]
}

@test "detect_architecture detects x86_64 as amd64" {
    uname() {
        if [ "$1" = "-m" ]; then
            echo "x86_64"
        else
            command uname "$@"
        fi
    }
    export -f uname
    
    run detect_architecture
    [ "$status" -eq 0 ]
    [ "$output" = "amd64" ]
}

@test "detect_architecture detects aarch64 as arm64" {
    uname() {
        if [ "$1" = "-m" ]; then
            echo "aarch64"
        else
            command uname "$@"
        fi
    }
    export -f uname
    
    run detect_architecture
    [ "$status" -eq 0 ]
    [ "$output" = "arm64" ]
}

@test "detect_architecture detects arm64 as arm64" {
    uname() {
        if [ "$1" = "-m" ]; then
            echo "arm64"
        else
            command uname "$@"
        fi
    }
    export -f uname
    
    run detect_architecture
    [ "$status" -eq 0 ]
    [ "$output" = "arm64" ]
}

@test "detect_architecture detects amd64 as amd64" {
    uname() {
        if [ "$1" = "-m" ]; then
            echo "amd64"
        else
            command uname "$@"
        fi
    }
    export -f uname
    
    run detect_architecture
    [ "$status" -eq 0 ]
    [ "$output" = "amd64" ]
}

@test "detect_architecture aborts on unsupported architecture" {
    uname() {
        if [ "$1" = "-m" ]; then
            echo "riscv64"
        else
            command uname "$@"
        fi
    }
    export -f uname
    
    run detect_architecture
    [ "$status" -ne 0 ]
    [[ "$output" =~ "Unsupported architecture: riscv64" ]]
}

@test "check_disk_space succeeds when disk space is sufficient" {
    df() {
        echo "Filesystem 1K-blocks Used Available Use% Mounted on"
        echo "/dev/sda1   10485760 1024  5242880   1% /tmp"
    }
    export -f df
    
    run check_disk_space "$TEST_DIR" 102400
    [ "$status" -eq 0 ]
    [[ "$output" =~ "Sufficient disk space available" ]]
}

@test "check_disk_space fails when disk space is insufficient" {
    df() {
        echo "Filesystem 1K-blocks Used Available Use% Mounted on"
        echo "/dev/sda1   10485760 1024    10240   1% /tmp"
    }
    export -f df
    
    run check_disk_space "$TEST_DIR" 102400
    [ "$status" -ne 0 ]
    [[ "$output" =~ "Insufficient disk space" ]]
}

@test "download_file fails when url or destination is empty" {
    run download_file "" "$TEST_DIR/out" "test"
    [ "$status" -eq 1 ]
    [[ "$output" =~ "Usage: download_file" ]]
    
    run download_file "https://example.com" "" "test"
    [ "$status" -eq 1 ]
    [[ "$output" =~ "Usage: download_file" ]]
}

@test "download_file downloads successfully with curl mock" {
    local target_dest="$TEST_DIR/dest/file.txt"
    curl() {
        printf "mock downloaded payload"
        return 0
    }
    maybe_sudo() {
        "$@"
    }
    
    run download_file "https://fake.url/file.txt" "$target_dest" "Mocked file" 1
    [ "$status" -eq 0 ]
    [ -f "$target_dest" ]
    [ "$(cat "$target_dest")" = "mock downloaded payload" ]
    [[ "$output" =~ "Mocked file downloaded successfully" ]]
}

@test "download_file falls back to wget if curl is unavailable" {
    local target_dest="$TEST_DIR/dest/wget_file.txt"
    command_exists() {
        if [[ "$1" == "curl" ]]; then
            return 1
        elif [[ "$1" == "wget" ]]; then
            return 0
        fi
        return 0
    }
    wget() {
        printf "mock wget content"
        return 0
    }
    maybe_sudo() {
        "$@"
    }
    
    run download_file "https://fake.url/file.txt" "$target_dest" "Wget download" 1
    [ "$status" -eq 0 ]
    [ -f "$target_dest" ]
    [ "$(cat "$target_dest")" = "mock wget content" ]
    [[ "$output" =~ "Wget download downloaded successfully" ]]
}

@test "download_file fails when neither curl nor wget is available" {
    local target_dest="$TEST_DIR/dest/failed.txt"
    command_exists() {
        return 1
    }
    maybe_sudo() {
        "$@"
    }
    
    run download_file "https://fake.url/file.txt" "$target_dest" "Failed download" 1
    [ "$status" -eq 1 ]
    [[ "$output" =~ "Neither curl nor wget is available" ]]
}

@test "download_and_verify_file aborts when checksum file is missing" {
    local target_dest="$TEST_DIR/dest/payload.bin"
    curl() {
        printf "mock binary"
        return 0
    }
    maybe_sudo() {
        "$@"
    }
    
    run download_and_verify_file "https://fake.url/bin" "$target_dest" "pattern" "Mock Target" "" "$TEST_DIR/missing.sha256"
    [ "$status" -ne 0 ]
    [[ "$output" =~ "Checksum file not found" ]]
}

@test "download_and_verify_file aborts when pattern is not found in checksum file" {
    local target_dest="$TEST_DIR/dest/payload.bin"
    local checksum_file="$TEST_DIR/checksums.txt"
    echo "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 other.tar.gz" > "$checksum_file"
    
    curl() {
        printf "mock binary"
        return 0
    }
    maybe_sudo() {
        "$@"
    }
    
    run download_and_verify_file "https://fake.url/bin" "$target_dest" "payload.bin" "Mock Target" "" "$checksum_file"
    [ "$status" -ne 0 ]
    [[ "$output" =~ "No checksum found for Mock Target" ]]
}

@test "download_and_verify_file aborts when checksum verification fails" {
    local target_dest="$TEST_DIR/dest/payload.bin"
    local checksum_file="$TEST_DIR/checksums.txt"
    echo "0000000000000000000000000000000000000000000000000000000000000000 payload.bin" > "$checksum_file"
    
    curl() {
        printf "mock binary"
        return 0
    }
    maybe_sudo() {
        "$@"
    }
    
    run download_and_verify_file "https://fake.url/bin" "$target_dest" "payload.bin" "Mock Target" "" "$checksum_file"
    [ "$status" -ne 0 ]
    [[ "$output" =~ "Mock Target checksum verification failed" ]]
}

@test "download_and_verify_file succeeds with valid checksum" {
    local target_dest="$TEST_DIR/dest/payload.bin"
    local checksum_file="$TEST_DIR/checksums.txt"
    # sha256 of "mock binary content" is 85ed8bf4dc26608464df9fa5d2cb5ff6704d43c688673ae4aa4234ad02fb97b4
    echo "85ed8bf4dc26608464df9fa5d2cb5ff6704d43c688673ae4aa4234ad02fb97b4  payload.bin" > "$checksum_file"
    
    curl() {
        printf "mock binary content"
        return 0
    }
    maybe_sudo() {
        "$@"
    }
    
    run download_and_verify_file "https://fake.url/bin" "$target_dest" "payload.bin" "Mock Target" "" "$checksum_file"
    [ "$status" -eq 0 ]
    [ -f "$target_dest" ]
    [[ "$output" =~ "Mock Target downloaded and verified successfully." ]]
}

@test "cleanup function removes TMP_DIR and install directories" {
    local temp_install="$TEST_DIR/yara-install"
    mkdir -p "$temp_install"
    touch "$temp_install/testfile"
    
    export TMP_DIR="$TEST_DIR/temp_run"
    mkdir -p "$TMP_DIR"
    
    # Save original directory
    local old_pwd="$PWD"
    cd "$TEST_DIR"
    
    run cleanup
    [ "$status" -eq 0 ]
    [ ! -d "$TMP_DIR" ]
    [ ! -d "$temp_install" ]
    
    cd "$old_pwd"
}

@test "path constants are properly defined and non-empty" {
    [ -n "$YARA_LEGACY_PATH" ]
    [ "$YARA_LEGACY_PATH" = "/opt/yara" ]
    
    [ -n "$YARA_MODERN_PATH" ]
    [ "$YARA_MODERN_PATH" = "/opt/wazuh/yara" ]
    
    [ -n "$YARA_BIN_PATH" ]
    [ "$YARA_BIN_PATH" = "/usr/local/bin/yara" ]
    
    [ -n "$YARA_MODERN_BIN_PATH" ]
    [ "$YARA_MODERN_BIN_PATH" = "/opt/wazuh/yara/bin/yara" ]
}

@test "maybe_sudo runs directly when running as root (uid 0)" {
    id() {
        if [ "$1" = "-u" ]; then
            echo 0
        else
            command id "$@"
        fi
    }
    
    run maybe_sudo echo "root execution"
    [ "$status" -eq 0 ]
    [ "$output" = "root execution" ]
}

@test "maybe_sudo fails when non-root and sudo is unavailable" {
    id() {
        if [ "$1" = "-u" ]; then
            echo 1000
        else
            command id "$@"
        fi
    }
    command_exists() {
        if [[ "$1" == "sudo" ]]; then
            return 1
        fi
        command -v "$1" >/dev/null 2>&1
    }
    
    run maybe_sudo echo "should fail"
    [ "$status" -eq 1 ]
    [[ "$output" =~ "requires root privileges" ]]
}

@test "maybe_sudo uses sudo when non-root and sudo is available" {
    id() {
        if [ "$1" = "-u" ]; then
            echo 1000
        else
            command id "$@"
        fi
    }
    command_exists() {
        if [[ "$1" == "sudo" ]]; then
            return 0
        fi
        command -v "$1" >/dev/null 2>&1
    }
    sudo() {
        echo "called with sudo: $*"
    }
    
    run maybe_sudo echo "hello world"
    [ "$status" -eq 0 ]
    [[ "$output" =~ "called with sudo: echo hello world" ]]
}
