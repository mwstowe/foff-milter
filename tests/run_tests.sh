#!/bin/bash
# FOFF Milter Test Suite
# Tests both positive (should be caught) and negative (should pass) cases

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

# Test 1: Module Loading Test
echo "🔧 Testing module loading..."
EXPECTED_MODULES=23
MODULE_COUNT=$($BINARY --test-config -c $CONFIG 2>/dev/null | grep "Number of available modules:" | grep -o '[0-9]\+')

if [ "$MODULE_COUNT" -eq "$EXPECTED_MODULES" ]; then
    echo "✅ Module loading test: PASSED ($MODULE_COUNT/$EXPECTED_MODULES modules loaded)"
    ((PASSED++))
else
    echo "❌ Module loading test: FAILED ($MODULE_COUNT/$EXPECTED_MODULES modules loaded)"
    echo "   Expected $EXPECTED_MODULES modules, but only $MODULE_COUNT loaded"
    echo "   Check for YAML syntax errors in modules directory"
    ((FAILED++))
fi

# Check if config exists
if [ ! -f "$CONFIG" ]; then
    echo "❌ Config not found: $CONFIG"
    exit 1
fi

echo "🔧 Testing configuration validation..."
if $BINARY --test-config -c "$CONFIG" >/dev/null 2>&1; then
    echo "✅ Configuration is valid"
    ((PASSED++))
else
    echo "❌ Configuration is invalid"
    ((FAILED++))
fi

echo
for email in tests/positive/*.eml; do
    if [ -f "$email" ]; then
        echo -n "Testing $(basename "$email"): "
        output=$($BINARY --test-email "$email" -c "$CONFIG" 2>/dev/null || true)
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
        output=$($BINARY --test-email "$email" -c "$CONFIG" 2>/dev/null || true)
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

if [ $((PASSED + FAILED)) -gt 0 ]; then
    echo "📈 Success Rate: $(( PASSED * 100 / (PASSED + FAILED) ))%"
fi

if [ $FAILED -eq 0 ]; then
    echo "🎉 All tests passed!"
    exit 0
else
    echo "💥 Some tests failed!"
    exit 1
fi
