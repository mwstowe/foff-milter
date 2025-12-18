#!/bin/bash
# FOFF Milter Complete Test Suite

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

echo "🧪 FOFF Milter Complete Test Suite"
echo "=================================="
echo "Using binary: $BINARY"

# Quick config validation
echo "🔧 Testing configuration..."
if $BINARY --test-config -c "$CONFIG" >/dev/null 2>&1; then
    echo "✅ Configuration is valid"
    ((PASSED++))
else
    echo "❌ Configuration is invalid"
    ((FAILED++))
fi

echo
echo "📧 Testing positive cases (should be caught)..."
positive_passed=0
positive_failed=0
positive_count=0

for email in tests/positive/*.eml; do
    [ ! -f "$email" ] && continue
    ((positive_count++))
    
    echo -n "Testing $(basename "$email"): "
    if $BINARY --test-email "$email" -c "$CONFIG" 2>/dev/null | grep -qE "(TAG AS SPAM|REJECT)"; then
        echo "✅ CAUGHT"
        ((positive_passed++))
        ((PASSED++))
    else
        echo "❌ MISSED"
        ((positive_failed++))
        ((FAILED++))
    fi
done

echo
echo "📧 Testing negative cases (should pass)..."
negative_passed=0
negative_failed=0
negative_count=0

for email in tests/negative/*.eml; do
    [ ! -f "$email" ] && continue
    ((negative_count++))
    
    echo -n "Testing $(basename "$email"): "
    if $BINARY --test-email "$email" -c "$CONFIG" 2>/dev/null | grep -q "Result: ACCEPT"; then
        echo "✅ PASSED"
        ((negative_passed++))
        ((PASSED++))
    else
        echo "❌ FAILED"
        ((negative_failed++))
        ((FAILED++))
    fi
done

# Calculate totals
total_tests=$((positive_count + negative_count + 1))  # +1 for config test
success_rate=$(echo "scale=1; $PASSED * 100 / $total_tests" | bc -l 2>/dev/null || echo "0")

echo
echo "📊 Complete Test Results:"
echo "========================="
echo "✅ Positive Tests: $positive_passed/$positive_count passed"
echo "✅ Negative Tests: $negative_passed/$negative_count passed"
echo "📈 Total: $PASSED/$total_tests passed"
echo "🎯 Success Rate: ${success_rate}%"

if [ $FAILED -eq 0 ]; then
    echo "🎉 All tests passed!"
    exit 0
else
    echo "💥 $FAILED tests failed!"
    exit 1
fi
