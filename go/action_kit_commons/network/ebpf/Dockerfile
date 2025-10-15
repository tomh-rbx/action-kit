# Dockerfile for building DNS Error Injection eBPF object (cross-compiled for target Linux)

FROM ubuntu:24.04

# Avoid interactive prompts
ARG DEBIAN_FRONTEND=noninteractive
ENV TZ=UTC

# Install build dependencies and kernel headers
RUN apt-get update && apt-get install -y \
    clang \
    llvm \
    make \
    linux-headers-generic \
    linux-tools-generic \
    build-essential \
    libbpf-dev \
    pkg-config \
    file \
    binutils \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /src

# Copy eBPF source and build scripts
COPY . .

# Make build script executable
RUN chmod +x build.sh

# Build the eBPF object
RUN ./build.sh

# Verify the built object
RUN file dns_error_injection.o && \
    readelf -h dns_error_injection.o

# Default command shows the built object
CMD ["ls", "-la", "dns_error_injection.o"]
