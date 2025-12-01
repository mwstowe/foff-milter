#!/bin/bash

# Anonymization script for test emails
# Usage: ./anonymize_emails.sh input.eml output.eml

input="$1"
output="$2"

if [ -z "$input" ] || [ -z "$output" ]; then
    echo "Usage: $0 input.eml output.eml"
    exit 1
fi

# Copy input to output
cp "$input" "$output"

# Replace baddomain.com references
sed -i 's/baddomain\.com/example\.com/g' "$output"

# Replace recipient emails (keep domain if not baddomain.com)
sed -i 's/marcystowe+caf_=marcy=/testuser+test=/g' "$output"
sed -i 's/marcystowe/testuser/g' "$output"

# Replace personal references
sed -i 's/Marcy/TestUser/g' "$output"
sed -i 's/MARCY/TESTUSER/g' "$output"

echo "Anonymized $input -> $output"
