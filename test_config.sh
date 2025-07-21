#!/bin/bash

# Test script for FOFF milter configuration

echo "Building FOFF milter..."
cargo build --release

if [ $? -ne 0 ]; then
    echo "Build failed!"
    exit 1
fi

echo "Testing configuration..."
./target/release/foff-milter --test-config -c config.yaml

if [ $? -eq 0 ]; then
    echo "Configuration test passed!"
else
    echo "Configuration test failed!"
    exit 1
fi

echo "Running unit tests..."
cargo test

if [ $? -eq 0 ]; then
    echo "All tests passed!"
else
    echo "Some tests failed!"
    exit 1
fi

echo "All checks completed successfully!"
