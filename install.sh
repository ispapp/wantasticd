#!/bin/sh
set -e

# Wantasticd Installation Script
# https://wanatsticd.wantastic.app

GITHUB_REPO="wantasticd"
BASE_URL="https://wanatsticd.wantastic.app"

# Detect OS
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"

case "$ARCH" in
    x86_64) ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64" ;;
    armv7*) ARCH="arm" ;;
    i386|i686) ARCH="386" ;;
    mips64) ARCH="mips64" ;;
    riscv64) ARCH="riscv64" ;;
    ppc64le) ARCH="ppc64le" ;;
    *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
esac

if [ "$OS" != "linux" ]; then
    echo "Currently, only Linux is supported for direct installation via this script."
    exit 1
fi

echo "Installing Wantasticd for $OS-$ARCH..."

# Create temp directory
TMP_DIR=$(mktemp -d)
cd "$TMP_DIR"

# Download the tarball from the 'latest' folder in R2
# Note: We assume the R2 structure has latest/wantasticd-<arch>.tar.gz
BINARY_URL="${BASE_URL}/latest/wantasticd-${ARCH}.tar.gz"

echo "Downloading from $BINARY_URL..."
curl -L -o wantasticd.tar.gz "$BINARY_URL"

# Extract
tar -xzf wantasticd.tar.gz

# Find the binary
BINARY_NAME="wantasticd-${ARCH}"
if [ ! -f "$BINARY_NAME" ]; then
    echo "Error: Binary $BINARY_NAME not found in package."
    exit 1
fi

# Install
echo "Installing to /usr/local/bin/wantasticd..."
sudo mv "$BINARY_NAME" /usr/local/bin/wantasticd
sudo chmod +x /usr/local/bin/wantasticd

# Cleanup
cd /
rm -rf "$TMP_DIR"

echo "Wantasticd installed successfully!"
echo "Run 'wantasticd --help' to get started."
