#!/bin/bash

BINARY="./target/release/foff-milter"
CONFIG="./foff-milter.toml"
RESULTS_DIR="test_analysis_results"

mkdir -p "$RESULTS_DIR"

echo "🔍 Analyzing intermittent test failure..."
echo "Running multiple test iterations to capture both success and failure cases"

for i in {1..10}; do
    echo ""
    echo "=== Test Run $i ==="
    
    # Run full test suite and capture detailed output
    timeout 1800 ./tests/run_tests_full.sh > "$RESULTS_DIR/run_${i}_full.log" 2>&1
    
    # Extract summary
    tail -10 "$RESULTS_DIR/run_${i}_full.log" > "$RESULTS_DIR/run_${i}_summary.txt"
    
    # Check if this run failed
    if grep -q "❌ Failed: 1" "$RESULTS_DIR/run_${i}_summary.txt"; then
        echo "❌ Run $i FAILED - capturing detailed failure info"
        
        # Find which test failed
        grep "❌\|MISSED" "$RESULTS_DIR/run_${i}_full.log" > "$RESULTS_DIR/run_${i}_failures.txt"
        
        # Test each positive case individually to find the problematic one
        echo "Testing individual positive cases for run $i..."
        pos_failed=0
        for email in tests/positive/*.eml; do
            [ ! -f "$email" ] && continue
            
            email_name=$(basename "$email")
            echo -n "  Testing $email_name: "
            
            if timeout 30s $BINARY --test-email "$email" -c "$CONFIG" --disable-same-server 2>/dev/null | grep -qE "Result: (TAG AS SPAM|REJECT)"; then
                echo "✅ CAUGHT"
            else
                echo "❌ MISSED"
                echo "$email_name" >> "$RESULTS_DIR/run_${i}_missed_emails.txt"
                ((pos_failed++))
            fi
        done
        
        echo "Run $i: $pos_failed positive cases failed" >> "$RESULTS_DIR/failure_summary.txt"
        
    elif grep -q "❌ Failed: 0" "$RESULTS_DIR/run_${i}_summary.txt"; then
        echo "✅ Run $i PASSED - capturing success info"
        echo "Run $i: SUCCESS (all tests passed)" >> "$RESULTS_DIR/success_summary.txt"
    else
        echo "⚠️  Run $i had unexpected output"
        echo "Run $i: UNEXPECTED" >> "$RESULTS_DIR/unexpected_summary.txt"
    fi
    
    # Brief pause between runs
    sleep 2
done

echo ""
echo "📊 Analysis Results:"
echo ""

if [ -f "$RESULTS_DIR/failure_summary.txt" ]; then
    echo "❌ Failure cases found:"
    cat "$RESULTS_DIR/failure_summary.txt"
    echo ""
    
    if [ -f "$RESULTS_DIR/run_*_missed_emails.txt" ]; then
        echo "📧 Emails that failed:"
        cat "$RESULTS_DIR"/run_*_missed_emails.txt | sort | uniq -c | sort -nr
        echo ""
    fi
fi

if [ -f "$RESULTS_DIR/success_summary.txt" ]; then
    echo "✅ Success cases:"
    wc -l < "$RESULTS_DIR/success_summary.txt"
    echo ""
fi

echo "📁 Detailed logs saved in: $RESULTS_DIR/"
echo "🔍 To analyze specific failure: grep -A5 -B5 'MISSED' $RESULTS_DIR/run_*_full.log"
