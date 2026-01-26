#!/bin/sh
set -e

# Wantasticd Self-Update Script
# Usage: ./self-update.sh [version]

# Configuration
BASE_URL="https://get.wantastic.app"
LATEST_VERSION_URL="${BASE_URL}/latest"

# Detect OS
UNAME_S="$(uname -s)"
case "$UNAME_S" in
    Linux*)     OS="linux" ;;
    Darwin*)    OS="darwin" ;;
    *)          echo "Unsupported Operating System: $UNAME_S"; exit 1 ;;
esac
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
# Find current binary path
if command -v wantasticd >/dev/null 2>&1; then
    BINARY_PATH=$(command -v wantasticd)
else
    # Fallback if not found in PATH
    if [ -d "/usr/local/bin" ]; then
        BINARY_PATH="/usr/local/bin/wantasticd"
    elif [ -d "/bin" ]; then
        BINARY_PATH="/bin/wantasticd"
    else
        BINARY_PATH="/usr/bin/wantasticd"
    fi
fi

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
    # Structure: https://get.wantastic.app/latest/wantasticd-<os>-<arch>.tar.gz
    DOWNLOAD_URL="${BASE_URL}/latest/wantasticd-${OS}-${ARCH}.tar.gz"
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
    
    # Determine if we need elevated permissions for the TARGET directory
    TARGET_DIR=$(dirname "${BINARY_PATH}")
    
    if [ -w "${TARGET_DIR}" ] && ( [ ! -f "${BINARY_PATH}" ] || [ -w "${BINARY_PATH}" ] ); then
        mv "${NEW_BINARY}" "${BINARY_PATH}"
        chmod +x "${BINARY_PATH}"
    else
        echo "Elevation required for installation..."
        if ! command -v sudo >/dev/null 2>&1; then
             echo "Error: ${TARGET_DIR} is not writable and 'sudo' is not available."
             exit 1
        fi
        sudo mv "${NEW_BINARY}" "${BINARY_PATH}"
        sudo chmod +x "${BINARY_PATH}"
    fi

    echo "Successfully updated to ${VERSION}!"
    
    # Restart service if running (Linux systemd)
    if [ "$OS" = "linux" ] && command -v systemctl >/dev/null 2>&1 && systemctl is-active wantasticd >/dev/null 2>&1; then
        echo "Restarting service..."
        sudo systemctl restart wantasticd
    fi
}

main "$@"
