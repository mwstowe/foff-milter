#!/bin/bash

echo "Building FOFF milter..."
cargo build --release

if [ $? -eq 0 ]; then
    echo "Build successful!"
    echo "Binary location: ./target/release/foff-milter"
    echo ""
    echo "Usage examples:"
    echo "  Generate config: ./target/release/foff-milter --generate-config /etc/foff-milter.yaml"
    echo "  Test config:     ./target/release/foff-milter --test-config -c /etc/foff-milter.yaml"
    echo "  Run milter:      sudo ./target/release/foff-milter -c /etc/foff-milter.yaml"
    echo "  Verbose mode:    sudo ./target/release/foff-milter -v -c /etc/foff-milter.yaml"
else
    echo "Build failed!"
    exit 1
fi
