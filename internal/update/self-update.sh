#!/bin/sh
set -e

# Wantasticd Self-Update Script
# Usage: ./self-update.sh [version]

# Configuration
BASE_URL="https://get.wantastic.app"
LATEST_VERSION_URL="${BASE_URL}/latest"

# Detect OS
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH_RAW="$(uname -m)"

# Normalize Arch
case "$ARCH_RAW" in
    x86_64) ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64" ;;
    armv7*) ARCH="arm" ;;
    i386|i686) ARCH="386" ;;
    mips64) ARCH="mips64" ;;
    riscv64) ARCH="riscv64" ;;
    ppc64le) ARCH="ppc64le" ;;
    *) 
    echo "Architecture $ARCH_RAW is not directly supported by this script."
    exit 1 
    ;;
esac

# Find current binary path
BINARY_PATH=$(command -v wantasticd || echo "/usr/local/bin/wantasticd")

# Main update logic
main() {
    # Get target version
    if [ -n "$1" ]; then
        VERSION="$1"
    else
        echo "Fetching latest version from ${LATEST_VERSION_URL}..."
        VERSION=$(curl -sSL "${LATEST_VERSION_URL}" | tr -d '[:space:]')
    fi

    if [ -z "$VERSION" ]; then
        echo "Error: Could not determine latest version"
        exit 1
    fi

    echo "Target version: ${VERSION}"
    echo "Platform: ${OS}-${ARCH}"

    # Construct Download URL
    DOWNLOAD_URL="${BASE_URL}/${VERSION}/wantasticd-${OS}-${ARCH}.tar.gz"
    echo "Downloading from ${DOWNLOAD_URL}..."

    # Create temp directory
    TMP_DIR=$(mktemp -d)
    trap 'rm -rf "$TMP_DIR"' EXIT

    # Download and extract
    http_code=$(curl -sSL -w "%{http_code}" -o "${TMP_DIR}/package.tar.gz" "${DOWNLOAD_URL}")

    if [ "$http_code" != "200" ]; then
        echo "Error: Failed to download release (HTTP $http_code)"
        exit 1
    fi

    tar -xzf "${TMP_DIR}/package.tar.gz" -C "${TMP_DIR}"

    # Find the binary in the extracted files
    # The tarball is expected to contain a binary named wantasticd-${ARCH} or just wantasticd
    NEW_BINARY=$(find "${TMP_DIR}" -name "wantasticd*" -type f -executable | head -n 1)

    if [ -z "$NEW_BINARY" ]; then
        echo "Error: Could not find executable binary in the downloaded package"
        ls -la "${TMP_DIR}"
        exit 1
    fi

    echo "Applying update to ${BINARY_PATH}..."
    
    # Needs sudo if not writeable by current user
    if [ ! -w "$(dirname "${BINARY_PATH}")" ] || ([ -f "${BINARY_PATH}" ] && [ ! -w "${BINARY_PATH}" ]); then
        echo "Elevation required for installation..."
        sudo mv "${NEW_BINARY}" "${BINARY_PATH}"
        sudo chmod +x "${BINARY_PATH}"
    else
        mv "${NEW_BINARY}" "${BINARY_PATH}"
        chmod +x "${BINARY_PATH}"
    fi

    echo "Successfully updated to ${VERSION}!"
    
    # Restart service if running (Linux systemd)
    if [ "$OS" = "linux" ] && command -v systemctl >/dev/null 2>&1 && systemctl is-active wantasticd >/dev/null 2>&1; then
        echo "Restarting service..."
        sudo systemctl restart wantasticd
    fi
}

main "$@"
