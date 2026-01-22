# Wantastic IoT VPN Client - Release Notes

## Version: v1.0.0

### Overview
Wantastic IoT VPN Client provides secure VPN connectivity for IoT devices with automatic architecture detection, system service management, and comprehensive monitoring capabilities.

### Supported Architectures
- **amd64**: x86_64 systems (servers, modern IoT gateways)
- **arm64**: ARMv8/AArch64 (Raspberry Pi 3/4/5, modern ARM devices)
- **arm**: ARMv6/ARMv7 (older Raspberry Pi, IoT boards, embedded devices)
- **386**: i386 (legacy industrial systems, older embedded devices)

### Installation Methods

#### 1. Automatic Installation Script (Recommended)

The easiest way to install on any Linux-based IoT device:

```bash
# Download and run the install script
curl -sSL https://github.com/wantastic/wantasticd/releases/latest/download/install.sh | sudo bash

# Or with specific version
curl -sSL https://github.com/wantastic/wantasticd/releases/download/v1.0.0/install.sh | sudo bash -s -- -v v1.0.0
```

The script will:
- Auto-detect your device architecture
- Download the appropriate binary
- Install to `/usr/local/bin/wantasticd`
- Create systemd service for automatic startup
- Set up config directory at `/etc/wantasticd/`

#### 2. Manual Installation

Download the appropriate package for your architecture:

```bash
# For ARMv6/v7 devices (Raspberry Pi, IoT boards)
wget https://github.com/wantastic/wantasticd/releases/download/v1.0.0/wantasticd-linux-arm.tar.gz
tar -xzf wantasticd-linux-arm.tar.gz
sudo mv wantasticd /usr/local/bin/
sudo chmod +x /usr/local/bin/wantasticd

# For ARM64 devices (Raspberry Pi 3/4/5)
wget https://github.com/wantastic/wantasticd/releases/download/v1.0.0/wantasticd-linux-arm64.tar.gz
tar -xzf wantasticd-linux-arm64.tar.gz
sudo mv wantasticd /usr/local/bin/
sudo chmod +x /usr/local/bin/wantasticd

# For x86_64 systems
wget https://github.com/wantastic/wantasticd/releases/download/v1.0.0/wantasticd-linux-amd64.tar.gz
tar -xzf wantasticd-linux-amd64.tar.gz
sudo mv wantasticd /usr/local/bin/
sudo chmod +x /usr/local/bin/wantasticd
```

### OpenWRT Specific Installation

#### Method 1: Using opkg Package Manager

For OpenWRT devices with sufficient storage:

```bash
# First, download the appropriate IPK package for your architecture
wget https://github.com/wantastic/wantasticd/releases/download/v1.0.0/wantasticd_1.0.0_<arch>.ipk

# Install using opkg
opkg install wantasticd_1.0.0_<arch>.ipk

# Configure the service
/etc/init.d/wantasticd enable
/etc/init.d/wantasticd start
```

#### Method 2: Manual Installation on OpenWRT

```bash
# Download binary
wget -O /usr/sbin/wantasticd https://github.com/wantastic/wantasticd/releases/download/v1.0.0/wantasticd-linux-<arch>
chmod +x /usr/sbin/wantasticd

# Create init script
cat > /etc/init.d/wantasticd << 'EOF'
#!/bin/sh /etc/rc.common
START=99
STOP=10

start() {
    /usr/sbin/wantasticd connect -config /etc/wantasticd/config.json &
}

stop() {
    killall wantasticd
}
EOF

chmod +x /etc/init.d/wantasticd
/etc/init.d/wantasticd enable
/etc/init.d/wantasticd start
```

### System Service Setup

#### Systemd (Most Linux Distributions)

```bash
# Enable and start the service
sudo systemctl enable wantasticd
sudo systemctl start wantasticd

# Check status
sudo systemctl status wantasticd

# View logs
sudo journalctl -u wantasticd -f
```

#### Init.d (Older Systems, BusyBox)

```bash
# Create init script
sudo cp wantasticd-init.sh /etc/init.d/wantasticd
sudo chmod +x /etc/init.d/wantasticd

# Enable on boot (Debian/Ubuntu)
sudo update-rc.d wantasticd defaults

# Enable on boot (RedHat/CentOS)
sudo chkconfig --add wantasticd
sudo chkconfig wantasticd on

# Start service
sudo service wantasticd start
```

### Configuration

Create your configuration file at `/etc/wantasticd/config.json`:

```json
{
  "server": "vpn.wantastic.com",
  "port": 51820,
  "private_key": "your_private_key_here",
  "public_key": "server_public_key_here",
  "allowed_ips": "0.0.0.0/0,::/0",
  "endpoint": "vpn.wantastic.com:51820",
  "persistent_keepalive": 25
}
```

### Monitoring and Statistics

The client includes a built-in stats server on port 9000:

```bash
# View stats via HTTP
curl http://localhost:9000/stats

# Or view in browser
# http://<device-ip>:9000/
```

Available metrics include:
- CPU and memory usage
- Network traffic statistics
- WiFi and Ethernet interface details
- Connection status and uptime
- Throughput and latency metrics

### Security Features

- **Automatic restarts** on failure
- **Security hardening** with systemd
- **Resource isolation** with cgroups
- **Minimal privileges** with NoNewPrivileges
- **Protected system** directories
- **Private temporary** files

### Troubleshooting

#### Common Issues

1. **Permission denied** on binary:
   ```bash
   sudo chmod +x /usr/local/bin/wantasticd
   ```

2. **Service won't start**:
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl restart wantasticd
   ```

3. **Check connectivity**:
   ```bash
   # Test basic connectivity
   wantasticd status
   
   # Check logs
   sudo journalctl -u wantasticd -n 50
   ```

#### OpenWRT Specific Issues

1. **Insufficient storage**:
   ```bash
   # Check available space
   df -h
   
   # Clean up packages
   opkg remove some-package
   ```

2. **Init script permissions**:
   ```bash
   chmod +x /etc/init.d/wantasticd
   ```

### Uninstallation

```bash
# Stop and disable service
sudo systemctl stop wantasticd
sudo systemctl disable wantasticd

# Remove binary
sudo rm /usr/local/bin/wantasticd

# Remove config directory (optional)
sudo rm -rf /etc/wantasticd/

# Remove systemd service
sudo rm /etc/systemd/system/wantasticd.service
sudo systemctl daemon-reload
```

### Support

- **Documentation**: https://github.com/wantastic/wantasticd/wiki
- **Issues**: https://github.com/wantastic/wantasticd/issues
- **Community**: Discord/Forum links

### Changelog

#### v1.0.0
- Initial release with IoT focus
- Automatic architecture detection
- Systemd service integration
- OpenWRT support
- Built-in stats server on port 9000
- Security hardening features
- Cross-platform compatibility

### License

MIT License - See LICENSE file for details.