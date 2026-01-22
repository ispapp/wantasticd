#!/bin/bash

# Wantastic IoT Device Installer
# Automatically detects device architecture and installs the appropriate binary

set -e

VERSION="${VERSION:-latest}"
REPO="wantastic/wantasticd"
BINARY_NAME="wantastic-wgclient"
INSTALL_DIR="/usr/local/bin"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Log functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Detect architecture
detect_arch() {
    local arch="$(uname -m)"
    local os="$(uname -s | tr '[:upper:]' '[:lower:]')"
    
    case "$arch" in
        x86_64|amd64)
            ARCH="amd64"
            ;;
        i686|i386)
            ARCH="386"
            ;;
        armv6*|armv7*)
            ARCH="arm"
            ;;
        aarch64|armv8*|arm64)
            ARCH="arm64"
            ;;
        *)
            log_error "Unsupported architecture: $arch"
            exit 1
            ;;
    esac
    
    case "$os" in
        linux|darwin|freebsd|openbsd)
            OS="$os"
            ;;
        *)
            log_error "Unsupported OS: $os"
            exit 1
            ;;
    esac
    
    log_info "Detected architecture: $OS-$ARCH"
}

# Download and install
download_and_install() {
    local download_url=""
    
    if [ "$VERSION" = "latest" ]; then
        download_url="https://github.com/$REPO/releases/latest/download/$BINARY_NAME-$OS-$ARCH.tar.gz"
    else
        download_url="https://github.com/$REPO/releases/download/$VERSION/$BINARY_NAME-$OS-$ARCH.tar.gz"
    fi
    
    log_info "Downloading $BINARY_NAME $VERSION for $OS-$ARCH..."
    
    # Create temp directory
    TEMP_DIR="$(mktemp -d)"
    trap 'rm -rf "$TEMP_DIR"' EXIT
    
    # Download and extract
    if command -v curl >/dev/null 2>&1; then
        curl -sSL "$download_url" -o "$TEMP_DIR/$BINARY_NAME.tar.gz"
    elif command -v wget >/dev/null 2>&1; then
        wget -q "$download_url" -O "$TEMP_DIR/$BINARY_NAME.tar.gz"
    else
        log_error "Neither curl nor wget found. Please install one of them."
        exit 1
    fi
    
    if [ ! -s "$TEMP_DIR/$BINARY_NAME.tar.gz" ]; then
        log_error "Download failed or file is empty"
        exit 1
    fi
    
    # Extract
    tar -xzf "$TEMP_DIR/$BINARY_NAME.tar.gz" -C "$TEMP_DIR"
    
    # Install
    if [ ! -f "$TEMP_DIR/$BINARY_NAME" ]; then
        log_error "Binary not found in archive"
        exit 1
    fi
    
    # Check if install directory exists and is writable
    if [ ! -w "$INSTALL_DIR" ]; then
        log_warning "$INSTALL_DIR is not writable. Trying with sudo..."
        sudo mkdir -p "$INSTALL_DIR" 2>/dev/null || true
        if [ ! -w "$INSTALL_DIR" ]; then
            log_error "Cannot write to $INSTALL_DIR"
            exit 1
        fi
    fi
    
    # Move binary
    mv "$TEMP_DIR/$BINARY_NAME" "$INSTALL_DIR/"
    chmod +x "$INSTALL_DIR/$BINARY_NAME"
    
    log_success "Installed $BINARY_NAME to $INSTALL_DIR/"
}

# Create systemd service for IoT devices
create_systemd_service() {
    if [ "$OS" != "linux" ]; then
        return 0
    fi
    
    if ! command -v systemctl >/dev/null 2>&1; then
        log_warning "systemctl not found - skipping service creation"
        return 0
    fi
    
    local service_file="/etc/systemd/system/wantasticd.service"
    
    if [ -f "$service_file" ]; then
        log_info "Service file already exists: $service_file"
        return 0
    fi
    
    log_info "Creating systemd service..."
    
    cat > "$TEMP_DIR/wantasticd.service" << EOF
[Unit]
Description=Wantastic IoT VPN Client
After=network.target

[Service]
Type=simple
ExecStart=$INSTALL_DIR/$BINARY_NAME connect -config /etc/wantasticd/config.json
Restart=always
RestartSec=5
User=root
Group=root
Environment=HOME=/root

# Security hardening
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes

[Install]
WantedBy=multi-user.target
EOF
    
    if [ ! -w "/etc/systemd/system" ]; then
        sudo mv "$TEMP_DIR/wantasticd.service" "$service_file"
        sudo systemctl daemon-reload
        log_success "Systemd service created. Enable with: systemctl enable wantasticd"
    else
        mv "$TEMP_DIR/wantasticd.service" "$service_file"
        systemctl daemon-reload
        log_success "Systemd service created. Enable with: systemctl enable wantasticd"
    fi
}

# Create config directory
create_config_dir() {
    if [ "$OS" != "linux" ]; then
        return 0
    fi
    
    local config_dir="/etc/wantasticd"
    
    if [ ! -d "$config_dir" ]; then
        log_info "Creating config directory: $config_dir"
        if [ ! -w "/etc" ]; then
            sudo mkdir -p "$config_dir"
            sudo chmod 755 "$config_dir"
        else
            mkdir -p "$config_dir"
            chmod 755 "$config_dir"
        fi
    fi
    
    # Create sample config if it doesn't exist
    local sample_config="$config_dir/config.json.sample"
    if [ ! -f "$sample_config" ]; then
        cat > "$TEMP_DIR/config.json.sample" << 'EOF'
{
  "device_id": "your-device-id",
  "tenant_id": "your-tenant-id", 
  "private_key": "your-private-key",
  "public_key": "your-public-key",
  "server": {
    "endpoint": "vpn.wantastic.com:443",
    "public_key": "server-public-key"
  },
  "interface": {
    "addresses": ["10.8.0.2/32"],
    "dns": ["1.1.1.1", "8.8.8.8"],
    "mtu": 1420
  },
  "auth": {
    "token": "your-auth-token"
  },
  "verbose": false
}
EOF
        
        if [ ! -w "$config_dir" ]; then
            sudo mv "$TEMP_DIR/config.json.sample" "$sample_config"
            sudo chmod 644 "$sample_config"
        else
            mv "$TEMP_DIR/config.json.sample" "$sample_config"
            chmod 644 "$sample_config"
        fi
        
        log_info "Sample config created: $sample_config"
    fi
}

# Main installation function
main() {
    log_info "Wantastic IoT Device Installer"
    log_info "================================"
    
    # Detect architecture
    detect_arch
    
    # Download and install
    download_and_install
    
    # Additional setup for Linux IoT devices
    if [ "$OS" = "linux" ]; then
        create_config_dir
        create_systemd_service
        
        log_info ""
        log_info "Next steps:"
        log_info "1. Edit /etc/wantasticd/config.json with your configuration"
        log_info "2. Start the service: systemctl start wantasticd"
        log_info "3. Enable auto-start: systemctl enable wantasticd"
    fi
    
    log_success "Installation completed successfully!"
    log_info "Run: $INSTALL_DIR/$BINARY_NAME --help for usage information"
}

# Handle command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -v|--version)
            VERSION="$2"
            shift 2
            ;;
        -d|--directory)
            INSTALL_DIR="$2"
            shift 2
            ;;
        -h|--help)
            echo "Usage: $0 [options]"
            echo "Options:"
            echo "  -v, --version VERSION  Install specific version (default: latest)"
            echo "  -d, --directory DIR    Installation directory (default: /usr/local/bin)"
            echo "  -h, --help             Show this help message"
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            exit 1
            ;;
    esac

done

# Run main function
main "$@"