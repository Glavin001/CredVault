#!/bin/bash
# CLI integration test — exercises the full credvault pipeline
# This test creates mock data, runs all commands, and validates output.

set -euo pipefail

CREDVAULT="${CREDVAULT_BIN:-./target/debug/credvault}"
TEST_DIR=$(mktemp -d)
KEY="cli-integration-test-key"
PASS="test-bundle-password-123"

cleanup() {
    rm -rf "$TEST_DIR"
}
trap cleanup EXIT

echo "=== CredVault CLI Integration Tests ==="
echo "Binary: $CREDVAULT"
echo "Test dir: $TEST_DIR"
echo ""

PASS_COUNT=0
FAIL_COUNT=0

assert_contains() {
    local label="$1"
    local haystack="$2"
    local needle="$3"
    if echo "$haystack" | grep -q "$needle"; then
        echo "  PASS: $label"
        PASS_COUNT=$((PASS_COUNT + 1))
    else
        echo "  FAIL: $label (expected to find '$needle')"
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
}

assert_file_exists() {
    local label="$1"
    local path="$2"
    if [ -f "$path" ]; then
        echo "  PASS: $label"
        PASS_COUNT=$((PASS_COUNT + 1))
    else
        echo "  FAIL: $label (file not found: $path)"
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
}

assert_exit_code() {
    local label="$1"
    local expected="$2"
    local actual="$3"
    if [ "$actual" -eq "$expected" ]; then
        echo "  PASS: $label"
        PASS_COUNT=$((PASS_COUNT + 1))
    else
        echo "  FAIL: $label (expected exit code $expected, got $actual)"
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
}

# ─── Test 1: test-setup ───────────────────────────────────
echo "--- Test 1: test-setup ---"
OUTPUT=$($CREDVAULT test-setup --output-dir "$TEST_DIR/chrome" --key "$KEY" 2>&1)
assert_contains "test-setup creates profile" "$OUTPUT" "Created mock Chrome profile"
assert_contains "test-setup shows count" "$OUTPUT" "8 credentials"
assert_file_exists "Login Data exists" "$TEST_DIR/chrome/Default/Login Data"

# ─── Test 2: scan ─────────────────────────────────────────
echo "--- Test 2: scan ---"
OUTPUT=$($CREDVAULT --data-dir "$TEST_DIR/chrome" --encryption-key "$KEY" scan 2>&1)
assert_contains "scan finds chrome" "$OUTPUT" "Chrome"
assert_contains "scan finds 8 creds" "$OUTPUT" "8"
assert_contains "scan shows OK status" "$OUTPUT" "OK"

# ─── Test 3: list (all) ───────────────────────────────────
echo "--- Test 3: list (all) ---"
OUTPUT=$($CREDVAULT --data-dir "$TEST_DIR/chrome" --encryption-key "$KEY" list 2>&1)
assert_contains "list shows github" "$OUTPUT" "github.com"
assert_contains "list shows aws" "$OUTPUT" "console.aws.amazon.com"
assert_contains "list shows docker" "$OUTPUT" "hub.docker.com"
assert_contains "list shows 8 found" "$OUTPUT" "8 credentials found"

# ─── Test 4: list --domain filter ─────────────────────────
echo "--- Test 4: list --domain filter ---"
OUTPUT=$($CREDVAULT --data-dir "$TEST_DIR/chrome" --encryption-key "$KEY" list --domain github.com 2>&1)
assert_contains "domain filter shows github" "$OUTPUT" "github.com"
assert_contains "domain filter 1 result" "$OUTPUT" "1 credentials found"

# ─── Test 5: list --search filter ─────────────────────────
echo "--- Test 5: list --search filter ---"
OUTPUT=$($CREDVAULT --data-dir "$TEST_DIR/chrome" --encryption-key "$KEY" list --search company 2>&1)
assert_contains "search finds company.com users" "$OUTPUT" "company.com"
assert_contains "search finds 3 results" "$OUTPUT" "3 credentials found"

# ─── Test 6: list --domain wildcard ───────────────────────
echo "--- Test 6: list --domain wildcard ---"
OUTPUT=$($CREDVAULT --data-dir "$TEST_DIR/chrome" --encryption-key "$KEY" list --domain "*.amazon.com" 2>&1)
assert_contains "wildcard finds aws" "$OUTPUT" "console.aws.amazon.com"
assert_contains "wildcard 1 result" "$OUTPUT" "1 credentials found"

# ─── Test 7: export CSV ──────────────────────────────────
echo "--- Test 7: export CSV ---"
OUTPUT=$($CREDVAULT --data-dir "$TEST_DIR/chrome" --encryption-key "$KEY" export \
    --domain github.com --format csv --output "$TEST_DIR/export.csv" 2>&1)
assert_contains "csv export success" "$OUTPUT" "Exported 1 credentials"
assert_file_exists "csv file exists" "$TEST_DIR/export.csv"
CSV_CONTENT=$(cat "$TEST_DIR/export.csv")
assert_contains "csv has header" "$CSV_CONTENT" "domain,url,username,password,type"
assert_contains "csv has github" "$CSV_CONTENT" "github.com"
assert_contains "csv has password" "$CSV_CONTENT" "ghp_xxxxxxxxxxxxxxxxxxxx"

# ─── Test 8: export .env ─────────────────────────────────
echo "--- Test 8: export .env ---"
OUTPUT=$($CREDVAULT --data-dir "$TEST_DIR/chrome" --encryption-key "$KEY" export \
    --domain github.com,console.aws.amazon.com --format env --output "$TEST_DIR/export.env" 2>&1)
assert_contains "env export success" "$OUTPUT" "Exported 2 credentials"
ENV_CONTENT=$(cat "$TEST_DIR/export.env")
assert_contains "env has github username" "$ENV_CONTENT" "GITHUB_COM_USERNAME=developer"
assert_contains "env has github password" "$ENV_CONTENT" "GITHUB_COM_PASSWORD=ghp_xxxxxxxxxxxxxxxxxxxx"
assert_contains "env has aws username" "$ENV_CONTENT" "CONSOLE_AWS_AMAZON_COM_USERNAME=admin@company.com"

# ─── Test 9: export agent-config ──────────────────────────
echo "--- Test 9: export agent-config ---"
OUTPUT=$($CREDVAULT --data-dir "$TEST_DIR/chrome" --encryption-key "$KEY" export \
    --domain github.com --format agent-config --output "$TEST_DIR/agent.json" \
    --label "Test Agent" 2>&1)
assert_contains "agent export success" "$OUTPUT" "Exported 1 credentials"
AGENT_CONTENT=$(cat "$TEST_DIR/agent.json")
assert_contains "agent has version" "$AGENT_CONTENT" '"version": 1'
assert_contains "agent has label" "$AGENT_CONTENT" '"label": "Test Agent"'
assert_contains "agent has github" "$AGENT_CONTENT" '"domain": "github.com"'
assert_contains "agent has password" "$AGENT_CONTENT" '"password": "ghp_xxxxxxxxxxxxxxxxxxxx"'

# ─── Test 10: export credvault (encrypted) ────────────────
echo "--- Test 10: export credvault (encrypted) ---"
OUTPUT=$($CREDVAULT --data-dir "$TEST_DIR/chrome" --encryption-key "$KEY" export \
    --domain github.com,console.aws.amazon.com,app.vercel.com \
    --format credvault --output "$TEST_DIR/bundle.cvlt" \
    --label "Integration Test" --expires 30d --password "$PASS" 2>&1)
assert_contains "credvault export success" "$OUTPUT" "Exported 3 credentials"
assert_contains "credvault export expiry" "$OUTPUT" "Expires:"
assert_file_exists "bundle file exists" "$TEST_DIR/bundle.cvlt"

# Verify it starts with CVLT magic
MAGIC=$(head -c 4 "$TEST_DIR/bundle.cvlt")
if [ "$MAGIC" = "CVLT" ]; then
    echo "  PASS: bundle has CVLT magic bytes"
    PASS_COUNT=$((PASS_COUNT + 1))
else
    echo "  FAIL: bundle missing CVLT magic bytes"
    FAIL_COUNT=$((FAIL_COUNT + 1))
fi

# ─── Test 11: read bundle ─────────────────────────────────
echo "--- Test 11: read bundle ---"
OUTPUT=$($CREDVAULT read "$TEST_DIR/bundle.cvlt" --password "$PASS" 2>&1)
assert_contains "read shows label" "$OUTPUT" "Integration Test"
assert_contains "read shows github" "$OUTPUT" "github.com"
assert_contains "read shows aws" "$OUTPUT" "console.aws.amazon.com"
assert_contains "read shows vercel" "$OUTPUT" "app.vercel.com"
assert_contains "read shows 3 creds" "$OUTPUT" "3 credentials in bundle"
assert_contains "read shows expires" "$OUTPUT" "Expires:"

# ─── Test 12: read bundle with wrong password ─────────────
echo "--- Test 12: read bundle with wrong password ---"
set +e
OUTPUT=$($CREDVAULT read "$TEST_DIR/bundle.cvlt" --password "wrong-password" 2>&1)
EXIT_CODE=$?
set -e
assert_exit_code "wrong password exits non-zero" 1 $EXIT_CODE

# ─── Test 13: export by ID ────────────────────────────────
echo "--- Test 13: export by ID ---"
OUTPUT=$($CREDVAULT --data-dir "$TEST_DIR/chrome" --encryption-key "$KEY" export \
    --ids "chrome-default:login:0004" --format csv --output "$TEST_DIR/by-id.csv" 2>&1)
assert_contains "id export success" "$OUTPUT" "Exported 1 credentials"
ID_CSV=$(cat "$TEST_DIR/by-id.csv")
assert_contains "id export has github" "$ID_CSV" "github.com"
assert_contains "id export has password" "$ID_CSV" "ghp_xxxxxxxxxxxxxxxxxxxx"

# ─── Test 14: export multiple IDs ─────────────────────────
echo "--- Test 14: export multiple IDs ---"
OUTPUT=$($CREDVAULT --data-dir "$TEST_DIR/chrome" --encryption-key "$KEY" export \
    --ids "chrome-default:login:0004,chrome-default:login:0005" \
    --format csv --output "$TEST_DIR/multi-id.csv" 2>&1)
assert_contains "multi-id export success" "$OUTPUT" "Exported 2 credentials"

# ─── Test 15: help flags ──────────────────────────────────
echo "--- Test 15: help flags ---"
OUTPUT=$($CREDVAULT --help 2>&1)
assert_contains "help shows scan" "$OUTPUT" "scan"
assert_contains "help shows list" "$OUTPUT" "list"
assert_contains "help shows export" "$OUTPUT" "export"
assert_contains "help shows read" "$OUTPUT" "read"

# ─── Summary ──────────────────────────────────────────────
echo ""
echo "=== Results ==="
echo "  Passed: $PASS_COUNT"
echo "  Failed: $FAIL_COUNT"
echo ""

if [ "$FAIL_COUNT" -gt 0 ]; then
    echo "SOME TESTS FAILED"
    exit 1
else
    echo "ALL TESTS PASSED"
    exit 0
fi
