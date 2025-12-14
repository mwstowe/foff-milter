#!/bin/bash

echo "=== TIMING EMAIL TESTS ==="
echo "Testing all emails to find the slowest..."

BINARY="./target/release/foff-milter"
CONFIG="./foff-milter.toml"

# Function to time a single email
time_email() {
    local email="$1"
    local start_time=$(date +%s.%N)
    $BINARY --test-email "$email" -c $CONFIG >/dev/null 2>&1
    local end_time=$(date +%s.%N)
    local duration=$(echo "$end_time - $start_time" | bc -l)
    printf "%.3f %s\n" "$duration" "$(basename "$email")"
}

# Test all emails and collect timing data
temp_file=$(mktemp)

echo "Testing positive cases..."
for email in tests/positive/*.eml; do
    time_email "$email" >> "$temp_file"
done

echo "Testing negative cases..."
for email in tests/negative/*.eml; do
    time_email "$email" >> "$temp_file"
done

echo
echo "=== TOP 10 SLOWEST EMAILS ==="
sort -nr "$temp_file" | head -10 | while read duration filename; do
    printf "%8.3fs  %s\n" "$duration" "$filename"
done

echo
echo "=== TOP 10 FASTEST EMAILS ==="
sort -n "$temp_file" | head -10 | while read duration filename; do
    printf "%8.3fs  %s\n" "$duration" "$filename"
done

echo
echo "=== STATISTICS ==="
total_count=$(wc -l < "$temp_file")
avg_time=$(awk '{sum+=$1} END {print sum/NR}' "$temp_file")
max_time=$(sort -nr "$temp_file" | head -1 | awk '{print $1}')
min_time=$(sort -n "$temp_file" | head -1 | awk '{print $1}')

printf "Total emails tested: %d\n" "$total_count"
printf "Average time: %.3fs\n" "$avg_time"
printf "Slowest: %.3fs\n" "$max_time"
printf "Fastest: %.3fs\n" "$min_time"

# Get the slowest email for detailed analysis
slowest_email=$(sort -nr "$temp_file" | head -1 | awk '{print $2}')
echo
echo "=== SLOWEST EMAIL ANALYSIS ==="
echo "Slowest email: $slowest_email"

# Find the full path
if [ -f "tests/positive/$slowest_email" ]; then
    slowest_path="tests/positive/$slowest_email"
elif [ -f "tests/negative/$slowest_email" ]; then
    slowest_path="tests/negative/$slowest_email"
fi

if [ -n "$slowest_path" ]; then
    echo "File size: $(wc -c < "$slowest_path") bytes"
    echo "Line count: $(wc -l < "$slowest_path") lines"
    echo "Content type: $(grep -i "content-type:" "$slowest_path" | head -1 || echo "Not found")"
    echo
    echo "Running detailed analysis..."
    time $BINARY --test-email "$slowest_path" -c $CONFIG -v 2>&1 | tail -10
fi

rm "$temp_file"
