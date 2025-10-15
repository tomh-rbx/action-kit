#!/bin/bash

# Docker-based eBPF build script for DNS Error Injection
# This builds the eBPF object in a Linux container with proper toolchain

set -euo pipefail

echo "🐳 Building DNS Error Injection eBPF using Docker..."

# Check if Docker is available
if ! command -v docker &> /dev/null; then
    echo "❌ Error: Docker is required but not installed"
    echo "Please install Docker and try again"
    exit 1
fi

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "📁 Working directory: $SCRIPT_DIR"

# Check if source file exists
if [ ! -f "dns_error_injection.c" ]; then
    echo "❌ Error: dns_error_injection.c not found in $SCRIPT_DIR"
    exit 1
fi

# Build the Docker image
echo "🔨 Building Docker image..."
docker build -t dns-error-injection-builder .

# Run the container to build the eBPF object
echo "🚀 Building eBPF object in container..."
docker run --rm \
    -v "$SCRIPT_DIR:/output" \
    dns-error-injection-builder \
    sh -c "cp dns_error_injection.o /output/ && ls -la /output/dns_error_injection.o"

# Verify the output
if [ -f "dns_error_injection.o" ]; then
    echo "✅ Successfully built dns_error_injection.o"
    echo "📁 File size: $(ls -lh dns_error_injection.o | awk '{print $5}')"
    echo "📋 File type: $(file dns_error_injection.o)"
    
    if command -v readelf &> /dev/null; then
        echo "📋 ELF header info:"
        readelf -h dns_error_injection.o
    fi
    
    echo "🎉 DNS Error Injection eBPF build completed successfully!"
else
    echo "❌ Error: dns_error_injection.o was not created"
    exit 1
fi
