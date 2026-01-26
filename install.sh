#!/bin/sh
set -e

# Wantasticd Installation Script
# https://wantastic.app

BASE_URL="https://get.wantastic.app"

# Detect OS
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"

# Normalize Arch
case "$ARCH" in
    x86_64) ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64" ;;
    armv7*) ARCH="arm" ;;
    i386|i686) ARCH="386" ;;
    mips64) ARCH="mips64" ;;
    riscv64) ARCH="riscv64" ;;
    ppc64le) ARCH="ppc64le" ;;
    *) 
    echo "Architecture $ARCH is not directly supported by this script."
    echo "Please download the binary manually from GitHub releases."
    exit 1 
    ;;
esac

# Check for curl
if ! command -v curl >/dev/null 2>&1; then
    echo "Error: curl is required to install wantasticd."
    exit 1
fi

echo "Detected Platform: $OS-$ARCH"

# 1. Fetch Latest Version
echo "checking for latest version..."
VERSION=$(curl -sSL "${BASE_URL}/latest")

if [ -z "$VERSION" ]; then
    echo "Error: Could not determine latest version from ${BASE_URL}/latest"
    exit 1
fi

echo "Latest version: $VERSION"

# 2. Construct Download URL
# Structure: https://get.wantastic.app/<version>/wantasticd-<os>-<arch>.tar.gz
BINARY_URL="${BASE_URL}/${VERSION}/wantasticd-${OS}-${ARCH}.tar.gz"

# Create temp directory
TMP_DIR=$(mktemp -d)
cd "$TMP_DIR"

echo "Downloading ${BINARY_URL}..."
http_code=$(curl -sSL -w "%{http_code}" -o wantasticd.tar.gz "$BINARY_URL")

if [ "$http_code" != "200" ]; then
    echo "Error: Failed to download release (HTTP $http_code)"
    echo "Url: $BINARY_URL"
    rm -rf "$TMP_DIR"
    exit 1
fi

# 3. Extract
echo "Extracting..."
tar -xzf wantasticd.tar.gz

# Find the binary inside the extracted folder
# The tarball might contain ./wantasticd-<arch> or just the binary. 
# Based on existing build: BINARY_NAME="wantasticd-${GOARCH}"
# But we are renaming it to strictly 'wantasticd' for installation.
EXTRACTED_BIN="wantasticd-${ARCH}"

if [ ! -f "$EXTRACTED_BIN" ]; then
    # Fallback to check if it's just named 'wantasticd' or in a subdir
    if [ -f "wantasticd" ]; then
        EXTRACTED_BIN="wantasticd"
    else
        echo "Error: Could not find binary in archive."
        ls -la
        exit 1
    fi
fi

# 4. Install
INSTALL_PATH="/usr/local/bin/wantasticd"
echo "Installing to $INSTALL_PATH..."

if [ "$(id -u)" -ne 0 ]; then
    sudo mv "$EXTRACTED_BIN" "$INSTALL_PATH"
    sudo chmod +x "$INSTALL_PATH"
else
    mv "$EXTRACTED_BIN" "$INSTALL_PATH"
    chmod +x "$INSTALL_PATH"
fi

# Cleanup
cd /
rm -rf "$TMP_DIR"

echo "Success! Wantasticd ($VERSION) installed to $INSTALL_PATH"
echo "Run 'wantasticd --help' to get started."
