#!/bin/sh
set -e

# Wantasticd Self-Update Script
# Usage: ./self-update.sh [version]

# Configuration
BINARY_PATH="/bin/wantasticd"
BASE_URL="https://get.wantastic.app"
LATEST_VERSION_URL="${BASE_URL}/latest"
CURRENT_VERSION_URL="$(/bin/wantasticd version | cut -d ' ' -f 2)"
# Detect architecture
detect_arch() {
    local arch_raw=$(uname -m)
    case "$arch_raw" in
        x86_64)  ARCH="amd64" ;;
        i386|i686) ARCH="386" ;;
        arm64|aarch64) ARCH="arm64" ;;
        armv7*) ARCH="arm" ;;
        mips) ARCH="mips" ;;
        mips64) ARCH="mips64" ;;
        mips64el) ARCH="mips64le" ;;
        mipsel) ARCH="mipsle" ;;
        ppc64) ARCH="ppc64" ;;
        ppc64le) ARCH="ppc64le" ;;
        riscv64) ARCH="riscv64" ;;
        s390x) ARCH="s390x" ;;
        loongarch64) ARCH="loong64" ;;
        *)
            echo "Error: Unsupported architecture $arch_raw"
            exit 1
            ;;
    esac
}

# Main update logic
main() {
    detect_arch
    
    # Get target version
    if [ -n "$1" ]; then
        VERSION="$1"
    else
        echo "Fetching latest version from ${LATEST_VERSION_URL}..."
        VERSION=$(curl -sSL "${LATEST_VERSION_URL}" | tr -d '[:space:]')
        # Compare versions to decide if we going to update or not
        if [ "$VERSION" = "$CURRENT_VERSION_URL" ]; then
            echo "Already on latest version: $VERSION"
            exit 0
        fi
        if [ -z "$VERSION" ]; then
            echo "Error: Could not determine latest version"
            exit 1
        fi
    fi

    echo "Target version: ${VERSION}"
    echo "Detected architecture: ${ARCH}"

    DOWNLOAD_URL="${BASE_URL}/${VERSION}/wantasticd-${ARCH}.tar.gz"
    echo "Downloading from ${DOWNLOAD_URL}..."

    # Create temp directory
    TMP_DIR=$(mktemp -d)
    trap 'rm -rf "$TMP_DIR"' EXIT

    # Download and extract
    curl -sSL "${DOWNLOAD_URL}" -o "${TMP_DIR}/package.tar.gz"
    tar -xzf "${TMP_DIR}/package.tar.gz" -C "${TMP_DIR}"

    # Find the binary in the extracted files
    # The tarball is expected to contain a binary named wantasticd-${ARCH} or just wantasticd
    NEW_BINARY=$(find "${TMP_DIR}" -name "wantasticd*" -type f -executable | head -n 1)

    if [ -z "$NEW_BINARY" ]; then
        echo "Error: Could not find executable binary in the downloaded package"
        exit 1
    fi

    echo "Applying update to ${BINARY_PATH}..."
    
    # Backup current binary
    if [ -f "${BINARY_PATH}" ]; then
        mv "${BINARY_PATH}" "${BINARY_PATH}.old"
    fi

    # Install new binary
    mv "${NEW_BINARY}" "${BINARY_PATH}"
    chmod +x "${BINARY_PATH}"

    # Clean up backup
    rm -f "${BINARY_PATH}.old"

    echo "Successfully updated to ${VERSION}!"
    
    # Restart service if running (optional, depending on the system)
    if command -v systemctl >/dev/null 2>&1 && systemctl is-active wantasticd >/dev/null 2>&1; then
        echo "Restarting service..."
        systemctl restart wantasticd
    fi
}

main "$@"
