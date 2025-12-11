#!/bin/bash

BINARY="./target/release/foff-milter"
CONFIG="./foff-milter.toml"

echo "🕐 Analyzing timeout issues in test suite"
echo "========================================"

# Test 1: Check if any emails consistently take longer than 30s
echo ""
echo "📊 Testing execution times for all positive emails..."
echo "Email,Time(s),Result" > timeout_analysis.csv

slow_emails=()
for email in tests/positive/*.eml; do
    [ ! -f "$email" ] && continue
    
    email_name=$(basename "$email")
    echo -n "Testing $email_name: "
    
    start_time=$(date +%s.%N)
    
    if timeout 60s $BINARY --test-email "$email" -c "$CONFIG" --disable-same-server 2>/dev/null | grep -qE "Result: (TAG AS SPAM|REJECT)"; then
        result="CAUGHT"
    else
        result="MISSED"
    fi
    
    end_time=$(date +%s.%N)
    duration=$(echo "$end_time - $start_time" | bc -l)
    
    printf "%.3fs %s\n" "$duration" "$result"
    echo "$email_name,$duration,$result" >> timeout_analysis.csv
    
    # Flag emails taking longer than 5 seconds
    if (( $(echo "$duration > 5.0" | bc -l) )); then
        slow_emails+=("$email_name:$duration")
    fi
done

echo ""
echo "🐌 Slow emails (>5s):"
if [ ${#slow_emails[@]} -eq 0 ]; then
    echo "  None found"
else
    for slow in "${slow_emails[@]}"; do
        echo "  $slow"
    done
fi

# Test 2: Run the same email multiple times with different timeouts
echo ""
echo "⏱️  Testing timeout sensitivity with fam_investment_scam.eml..."
test_email="tests/positive/fam_investment_scam.eml"

for timeout_val in 5 10 15 20 30 45 60; do
    echo ""
    echo "Testing with ${timeout_val}s timeout:"
    
    success_count=0
    total_time=0
    
    for i in {1..10}; do
        start_time=$(date +%s.%N)
        
        if timeout ${timeout_val}s $BINARY --test-email "$test_email" -c "$CONFIG" --disable-same-server 2>/dev/null | grep -qE "Result: (TAG AS SPAM|REJECT)"; then
            ((success_count++))
            result="✅"
        else
            result="❌"
        fi
        
        end_time=$(date +%s.%N)
        duration=$(echo "$end_time - $start_time" | bc -l)
        total_time=$(echo "$total_time + $duration" | bc -l)
        
        printf "  Test %2d: %s (%.3fs)\n" $i "$result" "$duration"
    done
    
    avg_time=$(echo "scale=3; $total_time / 10" | bc -l)
    echo "  Success rate: $success_count/10 (${success_count}0%)"
    echo "  Average time: ${avg_time}s"
done

# Test 3: Check system load impact
echo ""
echo "💻 Testing under different system loads..."

echo "Normal load test (sequential):"
success_count=0
for i in {1..5}; do
    if timeout 30s $BINARY --test-email "$test_email" -c "$CONFIG" --disable-same-server 2>/dev/null | grep -qE "Result: (TAG AS SPAM|REJECT)"; then
        ((success_count++))
        echo "  Test $i: ✅"
    else
        echo "  Test $i: ❌"
    fi
done
echo "  Sequential success rate: $success_count/5"

echo ""
echo "High load test (parallel):"
# Run 5 tests in parallel
for i in {1..5}; do
    (
        if timeout 30s $BINARY --test-email "$test_email" -c "$CONFIG" --disable-same-server 2>/dev/null | grep -qE "Result: (TAG AS SPAM|REJECT)"; then
            echo "  Parallel test $i: ✅"
        else
            echo "  Parallel test $i: ❌"
        fi
    ) &
done
wait

echo ""
echo "📁 Detailed timing data saved to: timeout_analysis.csv"
echo "🔍 To find slowest emails: sort -t, -k2 -n timeout_analysis.csv | tail -10"
