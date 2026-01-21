# Wantastic Agent - WireGuard Userspace Implementation

## Overview

The Wantastic Agent is a userspace WireGuard implementation designed for embedded systems that cannot load kernel modules (`wireguard.ko`). It provides secure network tunneling similar to Tailscale's approach, using GRPC for authentication and configuration management.

## Architecture

### Core Components

1. **Agent** (`internal/agent/`)
   - Main orchestrator managing device lifecycle
   - Handles GRPC authentication and health monitoring
   - Coordinates between WireGuard device and netstack

2. **Device** (`internal/device/`)
   - Userspace WireGuard implementation using netstack
   - Manages cryptographic keys and peer connections
   - Handles packet encryption/decryption

3. **Netstack** (`internal/netstack/`)
   - Virtual network stack for packet routing
   - Exit node functionality for traffic forwarding
   - DNS resolution and route management

4. **GRPC Client** (`internal/grpc/`)
   - Authentication with auth.wantastic.app
   - Device registration and token refresh
   - Configuration retrieval and updates

## Key Features

### Userspace WireGuard
- No kernel module dependency
- Works on embedded systems with limited kernel access
- Complete control over network stack

### Authentication Flow
1. Device generates WireGuard keypair
2. Device registers with auth server via GRPC
3. Server returns configuration and server public key
4. Device establishes secure tunnel

### Exit Node Support
- Optional traffic forwarding capability
- Configurable routes and DNS servers
- LAN access controls for security

## Integration Guide

### Backend Implementation Requirements

#### 1. GRPC Service Definition
```protobuf
service AuthService {
    rpc RegisterDevice(RegisterDeviceRequest) returns (RegisterDeviceResponse);
    rpc RefreshToken(RefreshTokenRequest) returns (RefreshTokenResponse);
    rpc GetConfiguration(GetConfigurationRequest) returns (GetConfigurationResponse);
}

message RegisterDeviceRequest {
    string device_id = 1;
    string public_key = 2;
    string tenant_id = 3;
}

message RegisterDeviceResponse {
    bool success = 1;
    string token = 2;
    string server_key = 3;
    string endpoint = 4;
}
```

#### 2. Authentication Flow
1. **Device Registration**
   - Device sends public key and device ID
   - Server validates tenant and device
   - Server returns WireGuard server configuration
   - Server provides authentication token

2. **Token Refresh**
   - Device requests token refresh before expiry
   - Server validates existing token
   - Server returns new token with extended validity

3. **Configuration Updates**
   - Device polls for configuration changes
   - Server provides updated peer information
   - Device applies new configuration without restart

#### 3. WireGuard Server Setup
```bash
# Generate server keypair
wg genkey | tee server_private.key | wg pubkey > server_public.key

# Configure WireGuard interface
ip link add wg0 type wireguard
ip address add 10.0.0.1/24 dev wg0
wg set wg0 private-key server_private.key listen-port 51820

# Add peer (client device)
wg set wg0 peer <CLIENT_PUBLIC_KEY> allowed-ips 10.0.0.2/32
```

### Agent Deployment

#### Configuration File Format
```json
{
    "device_id": "unique-device-id",
    "tenant_id": "tenant-uuid",
    "private_key": "client-private-key",
    "public_key": "client-public-key",
    "server": {
        "endpoint": "wg.wantastic.app",
        "port": 51820,
        "public_key": "server-public-key"
    },
    "interface": {
        "addresses": ["10.0.0.2/32"],
        "listen_port": 51820,
        "mtu": 1420
    },
    "exit_node": {
        "enabled": false,
        "routes": ["0.0.0.0/0"],
        "dns": ["8.8.8.8", "1.1.1.1"],
        "allow_lan": false
    },
    "auth": {
        "server_url": "auth.wantastic.app:443",
        "token": "authentication-token",
        "refresh_time": "24h"
    }
}
```

#### Command Line Usage
```bash
# Using configuration file
wantasticd -config /etc/wantastic/config.json

# Using authentication URL
wantasticd -auth-url https://wantastic.app/auth/device

# Using direct token
wantasticd -token "your-auth-token"

# Enable exit node functionality
wantasticd -config /etc/wantastic/config.json -exit-node
```

### Network Integration

#### Traffic Flow
1. **Outbound Traffic**
   - Application sends packet to virtual interface
   - Netstack captures and encrypts packet
   - Encrypted packet sent to WireGuard server
   - Server decrypts and forwards to destination

2. **Inbound Traffic**
   - Server receives response from destination
   - Server encrypts and sends to client
   - Client decrypts and delivers to application

#### DNS Resolution
- Agent can use custom DNS servers
- DNS queries tunneled through WireGuard
- Supports split-horizon DNS for internal domains

### Security Considerations

#### Key Management
- Device generates unique keypair on first run
- Private key never leaves device
- Keys rotated periodically for forward secrecy

#### Network Isolation
- Exit node can restrict LAN access
- Configurable allowed/denied IP ranges
- Traffic filtering at netstack level

#### Authentication Security
- Tokens have limited validity period
- Refresh mechanism prevents service interruption
- Device certificates for mutual authentication

### Monitoring and Debugging

#### Health Checks
- Device connectivity monitoring
- Tunnel status reporting
- Automatic reconnection on failure

#### Logging
- Structured logging with levels
- Packet flow tracing (debug mode)
- Authentication event tracking

#### Metrics
- Bandwidth usage statistics
- Connection establishment time
- Error rates and types

### Performance Optimization

#### Memory Management
- Zero-copy packet processing where possible
- Buffer pooling for high throughput
- Minimal allocations in hot paths

#### CPU Usage
- Efficient crypto implementations
- Goroutine pooling for connection handling
- Batch processing for multiple packets

#### Network Efficiency
- Path MTU discovery
- Packet compression for small payloads
- Connection keepalive optimization

## Development Roadmap

### Phase 1: Core Functionality
- [x] Userspace WireGuard implementation
- [x] GRPC authentication client
- [x] Basic netstack integration
- [ ] Configuration management
- [ ] Health monitoring

### Phase 2: Advanced Features
- [ ] Exit node functionality
- [ ] Dynamic route updates
- [ ] DNS integration
- [ ] Peer discovery

### Phase 3: Production Ready
- [ ] Comprehensive testing
- [ ] Performance optimization
- [ ] Security audit
- [ ] Documentation completion

## Troubleshooting

### Common Issues

1. **Device Registration Fails**
   - Check GRPC server connectivity
   - Verify device ID uniqueness
   - Validate authentication credentials

2. **Tunnel Not Establishing**
   - Confirm WireGuard server configuration
   - Check firewall rules for UDP port
   - Verify keypair generation

3. **Exit Node Not Working**
   - Ensure proper route configuration
   - Check DNS server accessibility
   - Validate IP forwarding settings

### Debug Mode
```bash
# Enable verbose logging
wantasticd -config config.json -v

# Packet capture
tcpdump -i wg0 -w capture.pcap

# Check tunnel status
wantasticd -status
```

This architecture provides a solid foundation for building a Tailscale-like agent that works on embedded systems without kernel module support. The modular design allows for easy extension and maintenance while providing secure, reliable network tunneling.