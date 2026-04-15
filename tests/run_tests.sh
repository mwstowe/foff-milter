#!/bin/bash
# FOFF Milter Complete Test Suite (Parallel)

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
if [ "$GITHUB_ACTIONS" = "true" ]; then
    CONFIG="./foff-milter-ci.toml"
fi

# Parallelism: use nproc or default to 8
JOBS=${FOFF_TEST_JOBS:-$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 8)}

echo "🧪 FOFF Milter Complete Test Suite"
echo "=================================="
echo "Using binary: $BINARY"
echo "Parallel jobs: $JOBS"

# Config validation
echo "🔧 Testing configuration..."
if $BINARY --test-config -c "$CONFIG" >/dev/null 2>&1; then
    echo "✅ Configuration is valid"
    CONFIG_PASS=1
else
    echo "❌ Configuration is invalid"
    CONFIG_PASS=0
fi

TMPDIR=$(mktemp -d)
trap "rm -rf $TMPDIR" EXIT

# Test a single email, write result to temp file
test_email() {
    local email="$1"
    local expect="$2"  # "spam" or "clean"
    local binary="$3"
    local config="$4"
    local tmpdir="$5"
    local base=$(basename "$email")
    local result

    result=$($binary --test-email "$email" -c "$config" 2>/dev/null)

    if [ "$expect" = "spam" ]; then
        if echo "$result" | grep -qE "(TAG AS SPAM|REJECT)"; then
            echo "PASS" > "$tmpdir/result_${base}"
        else
            echo "FAIL" > "$tmpdir/result_${base}"
            echo "  ❌ MISSED: $base" >&2
        fi
    else
        if echo "$result" | grep -q "Result: ACCEPT"; then
            echo "PASS" > "$tmpdir/result_${base}"
        else
            echo "FAIL" > "$tmpdir/result_${base}"
            echo "  ❌ FALSE POSITIVE: $base" >&2
        fi
    fi
}
export -f test_email

echo
echo "📧 Running positive tests (should be caught)..."
positive_count=$(find tests/positive -name "*.eml" | wc -l)

find tests/positive -name "*.eml" -print0 | \
    xargs -0 -P "$JOBS" -I{} bash -c 'test_email "$@"' _ {} spam "$BINARY" "$CONFIG" "$TMPDIR"

positive_passed=$(grep -rl "PASS" "$TMPDIR"/result_* 2>/dev/null | wc -l)
positive_failed=$((positive_count - positive_passed))

echo "✅ Positive: $positive_passed/$positive_count"

# Clear results for negative tests
rm -f "$TMPDIR"/result_*

echo
echo "📧 Running negative tests (should pass)..."
negative_count=$(find tests/negative -name "*.eml" | wc -l)

find tests/negative -name "*.eml" -print0 | \
    xargs -0 -P "$JOBS" -I{} bash -c 'test_email "$@"' _ {} clean "$BINARY" "$CONFIG" "$TMPDIR"

negative_passed=$(grep -rl "PASS" "$TMPDIR"/result_* 2>/dev/null | wc -l)
negative_failed=$((negative_count - negative_passed))

echo "✅ Negative: $negative_passed/$negative_count"

# Totals
total_tests=$((positive_count + negative_count + 1))
total_passed=$((positive_passed + negative_passed + CONFIG_PASS))
total_failed=$((total_tests - total_passed))
success_rate=$(echo "scale=1; $total_passed * 100 / $total_tests" | bc -l 2>/dev/null || echo "0")

echo
echo "📈 Total: $total_passed/$total_tests passed"
echo "🎯 Success Rate: ${success_rate}%"

if [ $total_failed -eq 0 ]; then
    echo "🎉 All tests passed!"
    exit 0
else
    echo "💥 $total_failed tests failed!"
    exit 1
fi
