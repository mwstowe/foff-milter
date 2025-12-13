#!/bin/bash
# FOFF Milter Fast Test Suite - Performance Optimized

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

echo "🧪 FOFF Milter Fast Test Suite"
echo "=============================="
echo "Using binary: $BINARY"

# Quick config validation with timeout
echo "🔧 Testing configuration..."
if timeout 10s $BINARY --test-config -c "$CONFIG" >/dev/null 2>&1; then
    echo "✅ Configuration is valid"
    ((PASSED++))
else
    echo "❌ Configuration is invalid or timed out"
    ((FAILED++))
fi

# Module loading test with timeout
EXPECTED_MODULES=34
MODULE_COUNT=$(timeout 10s $BINARY --test-config -c $CONFIG 2>/dev/null | grep "Number of available modules:" | grep -o '[0-9]\+$' || echo "0")

if [ "$MODULE_COUNT" -eq "$EXPECTED_MODULES" ]; then
    echo "✅ Module loading test: PASSED ($MODULE_COUNT/$EXPECTED_MODULES modules loaded)"
    ((PASSED++))
else
    echo "❌ Module loading test: FAILED ($MODULE_COUNT/$EXPECTED_MODULES modules loaded)"
    ((FAILED++))
fi

# Test limited set of emails to prevent hanging
echo
echo "📧 Testing positive cases (first 20)..."
count=0
for email in tests/positive/*.eml; do
    [ $count -ge 20 ] && break
    [ ! -f "$email" ] && continue
    
    echo -n "Testing $(basename "$email"): "
    if timeout 30s $BINARY --test-email "$email" -c "$CONFIG" 2>/dev/null | grep -qE "(TAG AS SPAM|REJECT)"; then
        echo "✅ CAUGHT"
        ((PASSED++))
    else
        echo "❌ MISSED"
        ((FAILED++))
    fi
    ((count++))
done

echo
echo "📧 Testing negative cases (first 20)..."
count=0
for email in tests/negative/*.eml; do
    [ $count -ge 20 ] && break
    [ ! -f "$email" ] && continue
    
    echo -n "Testing $(basename "$email"): "
    if timeout 10s $BINARY --test-email "$email" -c "$CONFIG" 2>/dev/null | grep -q "Result: ACCEPT"; then
        echo "✅ PASSED"
        ((PASSED++))
    else
        echo "❌ BLOCKED"
        ((FAILED++))
    fi
    ((count++))
done

echo
echo "📊 Test Results (Limited Set):"
echo "✅ Passed: $PASSED"
echo "❌ Failed: $FAILED"

if [ $((PASSED + FAILED)) -gt 0 ]; then
    echo "📈 Success Rate: $(( PASSED * 100 / (PASSED + FAILED) ))%"
fi

echo
echo "⚠️  NOTE: This is a limited test set (42 tests max) for fast execution."
echo "   Full test suite has 266+ tests but was taking 30+ minutes."
echo "   This fast version completes in under 2 minutes."

if [ $FAILED -eq 0 ]; then
    echo "🎉 All tested cases passed!"
    exit 0
else
    echo "💥 Some tests failed!"
    exit 1
fi
