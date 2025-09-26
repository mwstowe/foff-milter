#!/bin/bash

# Analyze foff-milter logs for debugging header processing issues

if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <server> [email_pattern]"
    echo "Example: $0 hotel.example.com AAA"
    echo "Example: $0 juliett.example.com 'go-au.net'"
    exit 1
fi

SERVER=$1
PATTERN=${2:-"DEBUG"}

echo "🔍 Analyzing foff-milter logs on $SERVER for pattern: $PATTERN"
echo "=================================================="

ssh root@$SERVER << EOF
echo "📊 Recent foff-milter log entries with '$PATTERN':"
journalctl -u foff-milter --since "1 hour ago" | grep -i "$PATTERN" | tail -20

echo ""
echo "📊 Authentication-results header processing:"
journalctl -u foff-milter --since "1 hour ago" | grep "authentication-results" | tail -10

echo ""
echo "📊 AAA brand impersonation rule evaluations:"
journalctl -u foff-milter --since "1 hour ago" | grep "AAA brand" | tail -10

echo ""
echo "📊 Recent email processing results:"
journalctl -u foff-milter --since "1 hour ago" | grep -E "(ACCEPT|REJECT|TAG)" | tail -10
EOF
