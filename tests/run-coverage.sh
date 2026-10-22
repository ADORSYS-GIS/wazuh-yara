#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
OUTPUT_DIR="${1:-$REPO_ROOT/coverage}"

mkdir -p "$OUTPUT_DIR"
cd "$REPO_ROOT"

echo "==> Running Bats unit tests under kcov..."
kcov --include-pattern=scripts/ "$OUTPUT_DIR/kcov" bats tests/test-utils.bats

SONAR_XML=$(find "$OUTPUT_DIR/kcov" -name "sonarqube.xml" | head -n1)
if [[ -z "$SONAR_XML" || ! -f "$SONAR_XML" ]]; then
    echo "Error: kcov did not generate sonarqube.xml" >&2
    exit 1
fi

cp "$SONAR_XML" "$OUTPUT_DIR/sonar-coverage.xml"
sed -i 's|path=".*scripts/|path="scripts/|g' "$OUTPUT_DIR/sonar-coverage.xml"

echo "==> SonarQube coverage report successfully generated at $OUTPUT_DIR/sonar-coverage.xml"
