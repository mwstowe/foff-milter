#!/bin/bash
# FOFF Milter FULL Test Suite - All 266+ tests

cd "$(dirname "$0")/.."

# Determine binary
if [ -f "./target/release/foff-milter" ]; then
    BINARY="./target/release/foff-milter"
elif [ -f "./target/debug/foff-milter" ]; then
    BINARY="./target/debug/foff-milter"
else
    echo "❌ Binary not found"
    exit 1
fi

CONFIG="./foff-milter.toml"
PASSED=0
FAILED=0

echo "🧪 FOFF Milter FULL Test Suite"
echo "=============================="
echo "Using binary: $BINARY"

# Test configuration
echo "🔧 Testing configuration..."
if $BINARY --test-config -c "$CONFIG" >/dev/null 2>&1; then
    echo "✅ Configuration is valid"
    ((PASSED++))
else
    echo "❌ Configuration is invalid"
    ((FAILED++))
fi

# Test module loading
MODULE_COUNT=$($BINARY --test-config -c "$CONFIG" 2>/dev/null | grep -o "Number of available modules: [0-9]*" | grep -o "[0-9]*")
EXPECTED_MODULES=27
if [ "$MODULE_COUNT" = "$EXPECTED_MODULES" ]; then
    echo "✅ Module loading test: PASSED ($MODULE_COUNT/$EXPECTED_MODULES modules loaded)"
    ((PASSED++))
else
    echo "❌ Module loading test: FAILED ($MODULE_COUNT/$EXPECTED_MODULES modules loaded)"
    ((FAILED++))
fi

# Test ALL positive cases
echo
echo "📧 Testing ALL positive cases..."
pos_count=0
pos_passed=0
for email in tests/positive/*.eml; do
    [ ! -f "$email" ] && continue
    
    echo -n "Testing $(basename "$email"): "
    if timeout 30s $BINARY --test-email "$email" -c "$CONFIG" 2>/dev/null | grep -qE "(TAG AS SPAM|REJECT)"; then
        echo "✅ CAUGHT"
        ((PASSED++))
        ((pos_passed++))
    else
        echo "❌ MISSED"
        ((FAILED++))
    fi
    ((pos_count++))
done

# Test ALL negative cases  
echo
echo "📧 Testing ALL negative cases..."
neg_count=0
neg_passed=0
for email in tests/negative/*.eml; do
    [ ! -f "$email" ] && continue
    
    echo -n "Testing $(basename "$email"): "
    if timeout 30s $BINARY --test-email "$email" -c "$CONFIG" 2>/dev/null | grep -q "Result: ACCEPT"; then
        echo "✅ PASSED"
        ((PASSED++))
        ((neg_passed++))
    else
        echo "❌ BLOCKED"
        ((FAILED++))
    fi
    ((neg_count++))
done

# Results
echo
echo "📊 FULL Test Results:"
echo "✅ Passed: $PASSED"
echo "❌ Failed: $FAILED"
echo "📈 Success Rate: $(( PASSED * 100 / (PASSED + FAILED) ))%"
echo
echo "📧 Email Test Breakdown:"
echo "  Positive cases: $pos_passed/$pos_count passed"
echo "  Negative cases: $neg_passed/$neg_count passed"
echo "  Total emails tested: $((pos_count + neg_count))"

if [ $FAILED -eq 0 ]; then
    echo "🎉 All tests passed!"
    exit 0
else
    echo "❌ Some tests failed"
    exit 1
fi
