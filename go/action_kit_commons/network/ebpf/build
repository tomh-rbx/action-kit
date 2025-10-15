#!/bin/bash
set -euo pipefail

echo "Building DNS Error Injection eBPF object (CO-RE)..."

[ -f dns_error_injection.c ] || { echo "dns_error_injection.c missing"; exit 1; }

# Build flags - with proper include paths
CLANG_FLAGS=(
    -O2
    -g
    -Wall
    -Wno-unused-value
    -Wno-pointer-sign
    -Wno-compare-distinct-pointer-types
    -Wno-gnu-variable-sized-type-not-at-end
    -Wno-address-of-packed-member
    -Wno-tautological-compare
    -I.
    -I/usr/include
    -I/usr/include/aarch64-linux-gnu
    -D__BPF_CO_RE__
    -target bpf
    -c dns_error_injection.c
    -o dns_error_injection.o
)

echo "Compiling with clang..."
clang "${CLANG_FLAGS[@]}"

if [ -f dns_error_injection.o ]; then
    echo "✅ dns_error_injection.o created: $(ls -lh dns_error_injection.o | awk '{print $5}')"
else
    echo "❌ Compilation failed"
    exit 1
fi

echo "MD5SUM: $(md5sum dns_error_injection.o)"

echo "🎉 Build completed successfully"
