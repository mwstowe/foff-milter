#!/bin/bash

# FOFF Milter Test Runner
# Usage: ./run_tests.sh [config_file]

set -e

# Default config
CONFIG="${1:-../hotel.yaml}"
MILTER="../target/release/foff-milter"
EMAIL_DIR="emails"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Counters
TOTAL=0
PASSED=0
FAILED=0

echo "🧪 FOFF Milter Test Suite"
echo "========================="
echo "Config: $CONFIG"
echo "Email directory: $EMAIL_DIR"
echo ""

# Check if milter exists
if [[ ! -f "$MILTER" ]]; then
    echo "❌ Milter binary not found: $MILTER"
    echo "Run: cargo build --release"
    exit 1
fi

# Check if config exists
if [[ ! -f "$CONFIG" ]]; then
    echo "❌ Config file not found: $CONFIG"
    exit 1
fi

# Test config validity
echo "🔍 Testing configuration..."
if ! $MILTER --test-config -c "$CONFIG" > /dev/null 2>&1; then
    echo "❌ Invalid configuration file: $CONFIG"
    exit 1
fi
echo "✅ Configuration valid"
echo ""

# Function to test a single email
test_email() {
    local email_file="$1"
    local filename=$(basename "$email_file")
    
    TOTAL=$((TOTAL + 1))
    
    # Determine expected result from filename
    if [[ "$filename" == SHOULD_PASS_* ]]; then
        expected="PASS"
    elif [[ "$filename" == SHOULD_FLAG_* ]]; then
        expected="FLAG"
    else
        echo "⚠️  SKIP: $filename (invalid naming convention)"
        return
    fi
    
    # Run test (keep stderr to avoid evaluation bugs)
    result=$($MILTER --test-email "$email_file" -c "$CONFIG" 2>&1)
    
    # Check if email was flagged
    if echo "$result" | grep -q "Result: TAG AS SPAM\|Result: REJECT"; then
        actual="FLAG"
    else
        actual="PASS"
    fi
    
    # Compare expected vs actual
    if [[ "$expected" == "$actual" ]]; then
        echo -e "✅ ${GREEN}PASS${NC}: $filename ($actual)"
        PASSED=$((PASSED + 1))
    else
        echo -e "❌ ${RED}FAIL${NC}: $filename (expected: $expected, got: $actual)"
        FAILED=$((FAILED + 1))
        
        # Show which rules matched for debugging
        if [[ "$actual" == "FLAG" ]]; then
            matched_rules=$(echo "$result" | grep "Matched rules:" | sed 's/.*Matched rules: //')
            echo "   Rules: $matched_rules"
        fi
    fi
}

# Run tests on all email files
if [[ -d "$EMAIL_DIR" ]]; then
    for email_file in "$EMAIL_DIR"/*.eml; do
        if [[ -f "$email_file" ]]; then
            test_email "$email_file"
        fi
    done
else
    echo "❌ Email directory not found: $EMAIL_DIR"
    exit 1
fi

# Summary
echo ""
echo "📊 Test Summary"
echo "==============="
echo -e "Total:  $TOTAL"
echo -e "Passed: ${GREEN}$PASSED${NC}"
echo -e "Failed: ${RED}$FAILED${NC}"

if [[ $FAILED -eq 0 ]]; then
    echo -e "\n🎉 ${GREEN}All tests passed!${NC}"
    exit 0
else
    echo -e "\n💥 ${RED}$FAILED test(s) failed${NC}"
    exit 1
fi
