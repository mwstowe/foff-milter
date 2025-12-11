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
# Separate counters for setup tests vs email tests
SETUP_PASSED=0
SETUP_FAILED=0
EMAIL_PASSED=0
EMAIL_FAILED=0

echo "🧪 FOFF Milter FULL Test Suite"
echo "=============================="
echo "Using binary: $BINARY"

# Test configuration
echo "🔧 Testing configuration..."
if $BINARY --test-config -c "$CONFIG" >/dev/null 2>&1; then
    echo "✅ Configuration is valid"
    ((SETUP_PASSED++))
else
    echo "❌ Configuration is invalid"
    ((SETUP_FAILED++))
fi

# Test module loading
MODULE_COUNT=$($BINARY --test-config -c "$CONFIG" 2>/dev/null | grep -o "Number of available modules: [0-9]*" | grep -o "[0-9]*")
EXPECTED_MODULES=27
if [ "$MODULE_COUNT" = "$EXPECTED_MODULES" ]; then
    echo "✅ Module loading test: PASSED ($MODULE_COUNT/$EXPECTED_MODULES modules loaded)"
    ((SETUP_PASSED++))
else
    echo "❌ Module loading test: FAILED ($MODULE_COUNT/$EXPECTED_MODULES modules loaded)"
    ((SETUP_FAILED++))
fi

# Test ALL positive cases
echo
echo "📧 Testing ALL positive cases..."
pos_count=0
pos_passed=0
for email in tests/positive/*.eml; do
    [ ! -f "$email" ] && continue
    
    echo -n "Testing $(basename "$email"): "
    if timeout 60s $BINARY --test-email "$email" -c "$CONFIG" --disable-same-server 2>/dev/null | grep -qE "Result: (TAG AS SPAM|REJECT)"; then
        echo "✅ CAUGHT"
        ((EMAIL_PASSED++))
        ((pos_passed++))
    else
        echo "❌ MISSED"
        ((EMAIL_FAILED++))
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
    if timeout 60s $BINARY --test-email "$email" -c "$CONFIG" --disable-same-server 2>/dev/null | grep -qE "Result: ACCEPT"; then
        echo "✅ PASSED"
        ((EMAIL_PASSED++))
        ((neg_passed++))
    else
        echo "❌ BLOCKED"
        ((EMAIL_FAILED++))
    fi
    ((neg_count++))
done

# Results
echo
echo "📊 FULL Test Results:"
echo "✅ Passed: $EMAIL_PASSED"
echo "❌ Failed: $EMAIL_FAILED"
echo "📈 Success Rate: $(( EMAIL_PASSED * 100 / (EMAIL_PASSED + EMAIL_FAILED) ))%"
echo
echo "📧 Email Test Breakdown:"
echo "  Positive cases: $pos_passed/$pos_count passed"
echo "  Negative cases: $neg_passed/$neg_count passed"
echo "  Total emails tested: $((pos_count + neg_count))"

if [ $EMAIL_FAILED -eq 0 ]; then
    echo "🎉 All tests passed!"
    exit 0
else
    echo "❌ Some tests failed"
    exit 1
fi
