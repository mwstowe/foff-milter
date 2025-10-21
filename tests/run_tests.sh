#!/bin/bash
# FOFF Milter Test Suite
# Tests both positive (should be caught) and negative (should pass) cases

set -e

# Change to parent directory so relative paths work
cd "$(dirname "$0")/.."

BINARY="./target/release/foff-milter"
CONFIG="./foff-milter.toml"
PASSED=0
FAILED=0

echo "🧪 FOFF Milter Test Suite"
echo "========================="

# Check if binary exists
if [ ! -f "$BINARY" ]; then
    echo "❌ Binary not found: $BINARY"
    echo "Run: cargo build --release"
    exit 1
fi

# Check if config exists
if [ ! -f "$CONFIG" ]; then
    echo "❌ Config not found: $CONFIG"
    exit 1
fi

echo "📧 Testing positive cases (should be caught)..."
for email in tests/positive/*.eml; do
    if [ -f "$email" ]; then
        echo -n "Testing $(basename "$email"): "
        output=$($BINARY --test-email "$email" -c "$CONFIG" 2>/dev/null)
        if echo "$output" | grep -q "Result: TAG AS SPAM\|Result: REJECT"; then
            echo "✅ CAUGHT"
            ((PASSED++))
        else
            echo "❌ MISSED"
            ((FAILED++))
        fi
    fi
done

echo
echo "📧 Testing negative cases (should pass)..."
for email in tests/negative/*.eml; do
    if [ -f "$email" ]; then
        echo -n "Testing $(basename "$email"): "
        output=$($BINARY --test-email "$email" -c "$CONFIG" 2>/dev/null)
        if echo "$output" | grep -q "Result: ACCEPT"; then
            echo "✅ PASSED"
            ((PASSED++))
        else
            echo "❌ BLOCKED"
            ((FAILED++))
        fi
    fi
done

echo
echo "📊 Test Results:"
echo "✅ Passed: $PASSED"
echo "❌ Failed: $FAILED"
echo "📈 Success Rate: $(( PASSED * 100 / (PASSED + FAILED) ))%"

if [ $FAILED -eq 0 ]; then
    echo "🎉 All tests passed!"
    exit 0
else
    echo "💥 Some tests failed!"
    exit 1
fi
