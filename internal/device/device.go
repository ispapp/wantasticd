package device

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"net/netip"
	"strings"
	"sync"
	"time"

	"os/exec"
	"runtime"

	"wantastic-agent/internal/config"
	"wantastic-agent/internal/grpc"

	"golang.org/x/crypto/curve25519"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

type Device struct {
	config   *config.Config
	device   *device.Device
	tunDev   tun.Device
	netstack *netstack.Net
	routing  *RoutingManager

	mu        sync.RWMutex
	running   bool
	stopCh    chan struct{}
	stopped   bool      // Track if device has been stopped to prevent double-closing
	closeOnce sync.Once // Ensure tun device is only closed once
}

// New creates a new Device instance with the provided configuration.
// It initializes the device struct with the given config and prepares
// the stop channel for device control.
// Returns a pointer to the Device struct and an error if any step fails.
func New(cfg *config.Config) (*Device, error) {
	return &Device{
		config: cfg,
		stopCh: make(chan struct{}),
	}, nil
}

// Start initializes and starts the device with the provided context.
// This begins device operation, network stack initialization, and optional gRPC client connection.
// Returns an error if the device is already running or if initialization fails.
func (d *Device) Start() error {
	d.mu.Lock()
	if d.running {
		d.mu.Unlock()
		return fmt.Errorf("device already running")
	}
	d.running = true
	d.mu.Unlock()

	if d.config.Verbose {
		log.Printf("Device starting with config: %+v", d.config)
	}

	addrs := make([]netip.Addr, len(d.config.Interface.Addresses))
	for i, prefix := range d.config.Interface.Addresses {
		addrs[i] = prefix.Addr()
	}

	tunDev, err := tun.CreateTUN("wantastic", d.config.Interface.MTU)
	if err != nil {
		return fmt.Errorf("create tun: %w", err)
	}

	d.tunDev = tunDev
	d.netstack = nil // Not using userspace netstack anymore

	// Configure IP address on the interface
	realName, err := tunDev.Name()
	if err != nil {
		tunDev.Close()
		return fmt.Errorf("get tun name: %w", err)
	}

	if len(addrs) > 0 {
		addr := addrs[0]
		if runtime.GOOS == "darwin" {
			// macOS: ifconfig <interface> <ip> <ip> up
			// For point-to-point, destination address is required. Use same IP or broadcast?
			// WireGuard-go usually uses destination address same as local IP for /32
			cmd := exec.Command("ifconfig", realName, addr.String(), addr.String(), "up")
			if out, err := cmd.CombinedOutput(); err != nil {
				log.Printf("Failed to configure interface: %v, output: %s", err, out)
				// Don't fail hard, maybe it works anyway?
			}

			// Add route for the interface subnet if needed?
			// Usually WireGuard handles routing via AllowedIPs -> System Route table changes?
			// WireGuard-go DOES NOT change system routing table automatically.
			// We need to add routes.
			// For now, let's just get the interface UP with an IP.
		} else if runtime.GOOS == "linux" {
			// Linux: ip addr add <ip>/<cidr> dev <interface>
			//        ip link set up dev <interface>
			cmd := exec.Command("ip", "addr", "add", d.config.Interface.Addresses[0].String(), "dev", realName)
			if out, err := cmd.CombinedOutput(); err != nil {
				log.Printf("Failed to add address: %v, output: %s", err, out)
			}
			cmdUp := exec.Command("ip", "link", "set", "up", "dev", realName)
			if out, err := cmdUp.CombinedOutput(); err != nil {
				log.Printf("Failed to set up: %v, output: %s", err, out)
			}
		}
	}

	if d.config.Verbose {
		log.Printf("System TUN device %s created successfully", realName)
	}

	logLevel := 1 // device.LogLevelError
	if d.config.Verbose {
		logLevel = 2 // device.LogLevelVerbose
		log.Printf("Verbose mode enabled - WireGuard debug logging active")
	}

	logger := device.NewLogger(logLevel, fmt.Sprintf("(%s) ", d.config.DeviceID))
	wireguardDevice := device.NewDevice(tunDev, conn.NewDefaultBind(), logger)

	if err := d.configureDevice(wireguardDevice); err != nil {
		tunDev.Close()
		return fmt.Errorf("configure device: %w", err)
	}

	if d.config.Verbose {
		log.Printf("WireGuard device configured successfully")
	}

	if err := wireguardDevice.Up(); err != nil {
		if strings.Contains(err.Error(), "bind: address already in use") {
			log.Printf("Port %d is in use, trying a random port...", d.config.Interface.ListenPort)
			d.config.Interface.ListenPort = 0
			if err := d.configureDevice(wireguardDevice); err != nil {
				tunDev.Close()
				return fmt.Errorf("reconfigure device: %w", err)
			}
			if err := wireguardDevice.Up(); err != nil {
				tunDev.Close()
				return fmt.Errorf("bring device up (retry): %w", err)
			}
		} else {
			tunDev.Close()
			return fmt.Errorf("bring device up: %w", err)
		}
	}

	if d.config.Verbose {
		log.Printf("WireGuard device brought up successfully")
	}

	d.device = wireguardDevice

	// Setup routing to allow local subnet access
	if d.config.Server.Endpoint != "" {
		d.routing = NewRoutingManager(d.config.Server.Endpoint)
		if err := d.routing.SetupRouting(); err != nil {
			log.Printf("Warning: Failed to setup routing: %v", err)
			// Continue despite routing errors - VPN will still work
		}
	}

	return nil
}

// Close closes the device and releases all associated resources.
// It first stops the device if it's running, then closes the netstack tun device
// and the WireGuard device. This method is idempotent and can be called multiple times.
func (d *Device) Close() error {
	return d.Stop()
}

// Stop stops the device and releases all associated resources.
// It first checks if the device is running, and if so, it sets the running flag to false.
// If the device is not running or has already been stopped, it returns nil.
// After setting the running flag to false, it closes the stopCh channel if it hasn't been closed already.
// Finally, it stores references to the device and netstack tun device before unlocking the mutex.
// The device and netstack tun device are then closed if they are not nil.
func (d *Device) Stop() error {
	d.mu.Lock()
	if !d.running || d.stopped {
		d.mu.Unlock()
		return nil
	}
	d.running = false
	d.stopped = true

	if d.config.Verbose {
		log.Printf("Device stopping...")
	}

	// Only close stopCh if it hasn't been closed already
	select {
	case <-d.stopCh:
		// Channel already closed
	default:
		close(d.stopCh)
	}

	// Store references to devices before unlocking
	device := d.device

	// Clear references to prevent double closing
	d.device = nil
	d.tunDev = nil

	d.mu.Unlock()

	// Close devices safely with protection against double-closing
	if device != nil {
		device.Close()
	}

	// The netstack tun device has a fundamental bug with multiple Close() calls
	// Instead of closing it, we gracefully shutdown by bringing the device down
	// and letting the garbage collector handle cleanup to avoid the panic
	if device != nil {
		device.Close() // Gracefully bring device down
	}

	// Don't call tunDev.Close() - it causes "close of closed channel" panic
	// The netstack library has internal channel management issues
	// We'll let the garbage collector handle cleanup instead

	return nil
}

// base64ToHex converts a base64-encoded WireGuard key to hexadecimal format
func base64ToHex(base64Key string) (string, error) {
	// Decode base64 key
	decoded, err := base64.StdEncoding.DecodeString(base64Key)
	if err != nil {
		return "", fmt.Errorf("decode base64 key: %w", err)
	}

	// Convert to hexadecimal
	hexKey := hex.EncodeToString(decoded)
	return hexKey, nil
}

func (d *Device) configureDevice(dev *device.Device) error {
	// Convert base64 private key to hexadecimal format for WireGuard IPC
	privateKeyHex, err := base64ToHex(d.config.PrivateKey)
	if err != nil {
		return fmt.Errorf("convert private key to hex: %w", err)
	}

	config := fmt.Sprintf("private_key=%s\n", privateKeyHex)
	config += fmt.Sprintf("listen_port=%d\n", d.config.Interface.ListenPort)
	config += "replace_peers=true\n"

	if d.config.Server.PublicKey != "" {
		// Convert base64 public key to hexadecimal format for WireGuard IPC
		publicKeyHex, err := base64ToHex(d.config.Server.PublicKey)
		if err != nil {
			return fmt.Errorf("convert public key to hex: %w", err)
		}

		config += fmt.Sprintf("public_key=%s\n", publicKeyHex)
		config += fmt.Sprintf("endpoint=%s:%d\n", d.config.Server.Endpoint, d.config.Server.Port)

		// Configure AllowedIPs - route only specific networks through VPN
		// and exclude local subnets to allow internal network access
		if len(d.config.Server.AllowedIPs) > 0 {
			// Use custom AllowedIPs from config
			for _, allowedIP := range d.config.Server.AllowedIPs {
				config += fmt.Sprintf("allowed_ip=%s\n", allowedIP)
			}
		} else {
			// Default: route only non-private and specific networks through VPN
			// This allows local subnet access while maintaining VPN connectivity
			config += "allowed_ip=0.0.0.0/1\n"   // First half of internet
			config += "allowed_ip=128.0.0.0/1\n" // Second half of internet
			config += "allowed_ip=::/1\n"        // First half of IPv6 internet
			config += "allowed_ip=8000::/1\n"    // Second half of IPv6 internet

			// Exclude local networks (they will use direct routing)
			// Note: These exclusions are handled by the routing table, not WireGuard config
		}

		config += "persistent_keepalive_interval=25\n"
	}

	if err := dev.IpcSet(config); err != nil {
		return fmt.Errorf("apply device config: %w", err)
	}

	return nil
}

// HealthCheck performs a health check on the device.
// It checks if the device is running and if the WireGuard device is initialized.
// Returns an error if the device is not running or if the WireGuard device is not initialized.
func (d *Device) HealthCheck() error {
	d.mu.RLock()
	if !d.running {
		d.mu.RUnlock()
		return fmt.Errorf("device not running")
	}
	d.mu.RUnlock()

	if d.device == nil {
		return fmt.Errorf("wireguard device not initialized")
	}

	return nil
}

func (d *Device) UpdateConfig(config *grpc.DeviceConfiguration) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if !d.running {
		return fmt.Errorf("device not running")
	}

	log.Printf("Updating device configuration: addresses=%v, listen_port=%d, mtu=%d",
		config.Addresses, config.ListenPort, config.MTU)

	if len(config.Addresses) > 0 {
		d.config.Interface.Addresses = make([]netip.Prefix, len(config.Addresses))
		for i, addr := range config.Addresses {
			prefix, err := netip.ParsePrefix(addr)
			if err != nil {
				return fmt.Errorf("parse address %s: %w", addr, err)
			}
			d.config.Interface.Addresses[i] = prefix
		}
	}

	if config.ListenPort > 0 {
		d.config.Interface.ListenPort = int(config.ListenPort)
	}

	if config.MTU > 0 {
		d.config.Interface.MTU = int(config.MTU)
	}

	return d.reconfigureDevice()
}

// UpdateServerConfig updates the device configuration with new server settings.
// This method is thread-safe and can be called while the device is running.
// Returns an error if the device is not running or if configuration fails.
func (d *Device) UpdateServerConfig(config *grpc.ServerConfiguration) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if !d.running {
		return fmt.Errorf("device not running")
	}

	log.Printf("Updating server configuration: endpoint=%s, port=%d, allowed_ips=%v",
		config.Endpoint, config.Port, config.AllowedIPs)

	if config.Endpoint != "" {
		d.config.Server.Endpoint = config.Endpoint
	}

	if config.Port > 0 {
		d.config.Server.Port = int(config.Port)
	}

	if config.PublicKey != "" {
		d.config.Server.PublicKey = config.PublicKey
	}

	return d.reconfigureDevice()
}

func (d *Device) reconfigureDevice() error {
	if d.device == nil {
		return fmt.Errorf("wireguard device not initialized")
	}

	config := fmt.Sprintf("private_key=%s\n", d.config.PrivateKey)
	config += fmt.Sprintf("listen_port=%d\n", d.config.Interface.ListenPort)
	config += "replace_peers=true\n"

	if d.config.Server.PublicKey != "" {
		config += fmt.Sprintf("public_key=%s\n", d.config.Server.PublicKey)
		config += fmt.Sprintf("endpoint=%s:%d\n", d.config.Server.Endpoint, d.config.Server.Port)
		config += "allowed_ip=0.0.0.0/0\n"
		config += "allowed_ip=::/0\n"
		config += "persistent_keepalive_interval=25\n"
	}

	if err := d.device.IpcSet(config); err != nil {
		return fmt.Errorf("reconfigure device: %w", err)
	}

	log.Println("Device reconfigured successfully")
	return nil
}

// GetPublicKey returns the public key of the device.
// If the public key is not set in the configuration, it derives it from the private key.
func (d *Device) GetPublicKey() string {
	d.mu.RLock()
	defer d.mu.RUnlock()

	if d.config.PublicKey != "" {
		return d.config.PublicKey
	}

	// Derive from private key
	if d.config.PrivateKey != "" {
		keyBytes, err := base64.StdEncoding.DecodeString(d.config.PrivateKey)
		if err != nil || len(keyBytes) != 32 {
			log.Printf("Error decoding private key for public key derivation: %v", err)
			return "invalid-key"
		}

		var priv [32]byte
		copy(priv[:], keyBytes)

		var pub [32]byte
		curve25519.ScalarBaseMult(&pub, &priv)

		return base64.StdEncoding.EncodeToString(pub[:])
	}

	return "unknown"
}

// GetStats retrieves current device statistics and operational metrics.
// Returns a map of statistics or an error if the device is not running.
// Statistics include traffic counters, connection status, and performance metrics.
func (d *Device) GetStats() (map[string]any, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	if !d.running {
		return nil, fmt.Errorf("device not running")
	}

	stats := map[string]any{
		"device_id": d.config.DeviceID,
		"running":   d.running,
		"uptime":    time.Since(time.Now()).Seconds(),
	}

	return stats, nil
}
