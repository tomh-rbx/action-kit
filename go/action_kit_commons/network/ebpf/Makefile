# Makefile for building eBPF objects

CLANG ?= clang
LLC ?= llc
GO ?= go

# Target architecture
ARCH ?= x86

# Output directory
OUTPUT_DIR := .

# eBPF object file
EBPF_OBJECT := dns_error_injection.o

# Source files
C_SOURCES := dns_error_injection.c

# Build flags
CLANG_FLAGS := -O2 -g -Wall -Wno-unused-value -Wno-pointer-sign \
	-Wno-compare-distinct-pointer-types \
	-Wno-gnu-variable-sized-type-not-at-end \
	-Wno-address-of-packed-member -Wno-tautological-compare \
	-Wno-unknown-warning-option \
	-I. \
	-I/usr/include/x86_64-linux-gnu \
	-D__TARGET_ARCH_$(ARCH)

.PHONY: all clean build-ebpf build-script build-docker

all: build-ebpf

build-ebpf: $(EBPF_OBJECT)

$(EBPF_OBJECT): $(C_SOURCES)
	@echo "Building eBPF object: $@"
	$(CLANG) $(CLANG_FLAGS) -target bpf -c $< -o $@

clean:
	rm -f $(EBPF_OBJECT)

# Build using Docker for consistent Linux environment (requires proper eBPF toolchain)
build-docker:
	@echo "Building DNS Error Injection eBPF using Docker..."
	@chmod +x build-docker.sh
	@./build-docker.sh

# Build using the build script (recommended)
build-script:
	@echo "Building DNS Error Injection eBPF using build script..."
	chmod +x build.sh
	./build.sh

# Test the build
test-build: build-ebpf
	@echo "Testing eBPF object..."
	file $(EBPF_OBJECT)
	readelf -h $(EBPF_OBJECT) || true
