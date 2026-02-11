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
# Main update logic
main() {
    VERSION="$1"
    TARGET_BIN="$2"

    # Get target version
    if [ -z "$VERSION" ]; then
        echo "Fetching latest version from ${LATEST_VERSION_URL}..."
        VERSION=$(curl -sSL "${LATEST_VERSION_URL}" | tr -d '[:space:]')
    fi

    if [ -z "$VERSION" ]; then
        echo "Error: Could not determine latest version"
        exit 1
    fi

    # Determine Binary Path
    if [ -z "$TARGET_BIN" ]; then
        if command -v wantasticd >/dev/null 2>&1; then
            TARGET_BIN=$(command -v wantasticd)
        elif [ -f "/usr/local/bin/wantasticd" ]; then
            TARGET_BIN="/usr/local/bin/wantasticd"
        elif [ -f "/usr/bin/wantasticd" ]; then
            TARGET_BIN="/usr/bin/wantasticd"
        elif [ -f "/bin/wantasticd" ]; then
            TARGET_BIN="/bin/wantasticd"
        else
            echo "Error: Could not find existing wantasticd binary to update."
            exit 1
        fi
    fi

    echo "Target version: ${VERSION}"
    echo "Target binary: ${TARGET_BIN}"
    echo "Platform: ${OS}-${ARCH}"

    # Construct Download URL
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
    NEW_BINARY=$(find "${TMP_DIR}" -name "wantasticd*" -type f -executable | head -n 1)

    if [ -z "$NEW_BINARY" ]; then
        echo "Error: Could not find executable binary in the downloaded package"
        ls -la "${TMP_DIR}"
        exit 1
    fi

    echo "Replacing ${TARGET_BIN}..."
    
    # Check writability
    if [ ! -w "$(dirname "$TARGET_BIN")" ] && [ "$(id -u)" != "0" ]; then
        echo "Warning: Directory $(dirname "$TARGET_BIN") is not writable and we are not root."
        # Attempt anyway, might fail
    fi

    # Move new binary into place (Atomic replacement on Linux usually)
    if mv -f "${NEW_BINARY}" "${TARGET_BIN}"; then
        chmod +x "${TARGET_BIN}"
        echo "Successfully updated to ${VERSION}!"
    else
        echo "Error: Failed to replace binary. Check permissions."
        exit 1
    fi
}

main "$@"
