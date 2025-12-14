#!/bin/bash

EMAIL="tests/positive/fam_investment_scam.eml"
CONFIG="./foff-milter.toml"
BINARY="./target/release/foff-milter"

echo "=== PROFILING fam_investment_scam.eml ==="
echo

# First, let's see the email content to understand what we're dealing with
echo "=== EMAIL CONTENT ANALYSIS ==="
echo "File size: $(wc -c < "$EMAIL") bytes"
echo "Line count: $(wc -l < "$EMAIL") lines"
echo "Character count: $(wc -m < "$EMAIL") characters"
echo

echo "Content structure:"
grep -E "^(From:|To:|Subject:|Content-Type:|Content-Transfer-Encoding:)" "$EMAIL" | head -10
echo

echo "=== TIMING BREAKDOWN ==="

# Test with different verbosity levels to see where time is spent
echo "1. Testing with minimal output..."
time $BINARY --test-email "$EMAIL" -c $CONFIG >/dev/null 2>&1

echo
echo "2. Testing with normal output..."
time $BINARY --test-email "$EMAIL" -c $CONFIG 2>/dev/null >/dev/null

echo
echo "3. Testing with verbose output (first 20 lines)..."
time $BINARY --test-email "$EMAIL" -c $CONFIG -v 2>&1 | head -20 >/dev/null

echo
echo "=== SYSTEM RESOURCE USAGE ==="
echo "Testing with detailed system monitoring..."
/usr/bin/time -v $BINARY --test-email "$EMAIL" -c $CONFIG >/dev/null 2>&1

echo
echo "=== RULE ANALYSIS ==="
echo "Rules that match this email:"
$BINARY --test-email "$EMAIL" -c $CONFIG 2>&1 | grep "X-FOFF-Rule-Matched" | sed 's/.*X-FOFF-Rule-Matched: //' | sort

echo
echo "=== FEATURE ANALYSIS ==="
echo "Features detected:"
$BINARY --test-email "$EMAIL" -c $CONFIG 2>&1 | grep "X-FOFF-Feature-Evidence" | sed 's/.*X-FOFF-Feature-Evidence: //' | sort

echo
echo "=== CONTENT COMPLEXITY ANALYSIS ==="
echo "Checking for performance-heavy patterns..."

# Check for patterns that might cause regex backtracking
echo "Long lines (>200 chars): $(awk 'length > 200' "$EMAIL" | wc -l)"
echo "HTML content: $(grep -c "<[^>]*>" "$EMAIL" || echo "0")"
echo "URLs: $(grep -oE 'https?://[^[:space:]]+' "$EMAIL" | wc -l)"
echo "Email addresses: $(grep -oE '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' "$EMAIL" | wc -l)"
echo "Base64-like strings: $(grep -oE '[A-Za-z0-9+/]{20,}' "$EMAIL" | wc -l)"

echo
echo "=== REGEX COMPLEXITY TEST ==="
echo "Testing individual rule modules..."

# Test if we can isolate which module is slow
temp_dir=$(mktemp -d)
cp -r rulesets "$temp_dir/"

# Test with minimal rules first
echo "Testing with only one rule module..."
mkdir -p "$temp_dir/minimal_rules"
cp rulesets/financial-services.yaml "$temp_dir/minimal_rules/"

# Create minimal config
cat > "$temp_dir/minimal.toml" << EOF
[rulesets]
enabled = true
config_dir = "$temp_dir/minimal_rules"

[heuristics]
reject_threshold = 350
spam_threshold = 50
accept_threshold = 0
EOF

echo "Time with only financial-services rules:"
time $BINARY --test-email "$EMAIL" -c "$temp_dir/minimal.toml" >/dev/null 2>&1

rm -rf "$temp_dir"
