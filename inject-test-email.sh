#!/bin/bash

# Simple email injection test
# This simulates what sendmail would do

EMAIL="$1"
if [ -z "$EMAIL" ]; then
    echo "Usage: $0 <email-file>"
    exit 1
fi

echo "Testing email: $EMAIL"
echo

# Use swaks (Swiss Army Knife for SMTP) if available
if command -v swaks &> /dev/null; then
    echo "Using swaks to inject email..."
    swaks --to test@example.com \
          --from sender@example.com \
          --server localhost \
          --data "$EMAIL"
else
    echo "swaks not found. Install with: apt-get install swaks"
    echo
    echo "Alternative: Use sendmail directly"
    echo "  cat '$EMAIL' | sendmail -v test@example.com"
fi
