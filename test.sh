#!/bin/bash

# Quick test runner for development
# Usage: ./test.sh [config]

CONFIG="${1:-hotel.yaml}"

echo "🧪 Running FOFF Milter tests with $CONFIG"
echo ""

cd tests && ./run_tests.sh "../$CONFIG"
