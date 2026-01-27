#!/bin/sh
set -e

# Wantasticd Installation Script
# https://wantastic.app

BASE_URL="https://get.wantastic.app"

# Detect OS
# Use case statement instead of tr to avoid potential locale/environment issues (fixing "Linlx")
UNAME_S="$(uname -s)"
case "$UNAME_S" in
    Linux*)     OS="linux" ;;
    Darwin*)    OS="darwin" ;;
    *)          echo "Unsupported Operating System: $UNAME_S"; exit 1 ;;
esac

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
echo "Checking for latest version..."
VERSION=$(curl -sSL "${BASE_URL}/latest")

if [ -z "$VERSION" ]; then
    echo "Error: Could not determine latest version from ${BASE_URL}/latest"
    exit 1
fi

echo "Latest version: $VERSION"

# 2. Construct Download URL
# Structure: https://get.wantastic.app/latest/wantasticd-<os>-<arch>.tar.gz
# We use 'latest' path directly as requested
BINARY_URL="${BASE_URL}/latest/wantasticd-${OS}-${ARCH}.tar.gz"

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
# The archive should contain a binary named 'wantasticd' (renamed during packaging)
# But we iterate to be safe if it's in a subdir
EXTRACTED_BIN=$(find . -type f -name "wantasticd" | head -n 1)

if [ -z "$EXTRACTED_BIN" ]; then
    echo "Error: Could not find 'wantasticd' binary in archive."
    ls -la
    exit 1
fi

# 4. Install
# Determine install directory
# Priority: /usr/local/bin -> /bin -> /usr/bin
if [ -d "/usr/local/bin" ] && echo "$PATH" | grep -q "/usr/local/bin"; then
    INSTALL_DIR="/usr/local/bin"
elif [ -d "/bin" ]; then
    INSTALL_DIR="/bin"
elif [ -d "/usr/bin" ]; then
    INSTALL_DIR="/usr/bin"
else
    echo "Error: Could not find a suitable installation directory in PATH."
    exit 1
fi

INSTALL_PATH="${INSTALL_DIR}/wantasticd"
echo "Installing to $INSTALL_PATH..."

# Move binary
if [ -w "$INSTALL_DIR" ]; then
    mv "$EXTRACTED_BIN" "$INSTALL_PATH"
    chmod +x "$INSTALL_PATH"
else
    echo "Elevation required..."
    if ! command -v sudo >/dev/null 2>&1; then
        echo "Error: Directory $INSTALL_DIR is not writable and 'sudo' is not available."
        exit 1
    fi
    sudo mv "$EXTRACTED_BIN" "$INSTALL_PATH"
    sudo chmod +x "$INSTALL_PATH"
fi

# Cleanup
cd /
rm -rf "$TMP_DIR"

echo "Success! Wantasticd ($VERSION) installed to $INSTALL_PATH"

# 5. Login & Connect Flow
echo ""
echo "=== Initialization ==="
TOKEN="$1"

if [ -n "$TOKEN" ]; then
    echo "Token provided. Attempting instant login and connection..."
    # Run login with token. This command will authenticate, save config, AND start the agent (blocking).
    "$INSTALL_PATH" login -token "$TOKEN"
else
    echo "No token provided."
    echo "Starting interactive login..."
    # Run interactive login. 
    # If it fails (e.g. no internet, firewall, embedded device issues), fall back to manual config guidance
    if ! "$INSTALL_PATH" login; then
        echo ""
        echo "Interactive login failed or timed out."
        echo "This is common on embedded devices or restricted networks."
        echo "Switching to manual configuration setup..."

        # Define config location
        CONF_DIR="/etc/wantasticd"
        CONF_FILE="${CONF_DIR}/config.conf"

        # Create Config Directory
        if [ ! -d "$CONF_DIR" ]; then
            echo "Creating config directory: $CONF_DIR"
            if ! sudo mkdir -p "$CONF_DIR"; then
                 echo "Warning: Failed to create $CONF_DIR. Falling back to current directory."
                 CONF_DIR="$(pwd)"
                 CONF_FILE="${CONF_DIR}/wantastic_demo.conf"
            fi
        fi

        # Write Demo Config
        # We use tee to handle permission escalation if needed
        # This is a template based on standard WireGuard config
        cat <<EOF | sudo tee "$CONF_FILE" > /dev/null
[Interface]
# Replace with your Private Key
PrivateKey = <YOUR_PRIVATE_KEY>
# Replace with your assigned IP address
Address = 10.x.x.x/32

[Peer]
# Server Public Key
PublicKey = O9l0CxzEiIPTI2g40feX+Wo8ZQE9P9ndft+UxfEAEEM=
# Server Endpoint
Endpoint = wg.wantastic.app:51820
# Allowed IPs for the overlay network
AllowedIPs = 10.0.0.0/8
PersistentKeepalive = 25
EOF

        echo ""
        echo "--------------------------------------------------------"
        echo "Manual Configuration Required"
        echo "--------------------------------------------------------"
        echo "A demo configuration file has been created at:"
        echo "  $CONF_FILE"
        echo ""
        echo "1. Edit this file with your actual credentials:"
        echo "   sudo nano $CONF_FILE"
        echo ""
        echo "2. Connect manually:"
        echo "   wantasticd connect -config $CONF_FILE &"
        echo "--------------------------------------------------------"
    fi
fi

