package device

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"net/netip"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

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
	socks     *http.Server // We'll use a simple proxy for now
	stopped   bool         // Track if device has been stopped to prevent double-closing
	closeOnce sync.Once    // Ensure tun device is only closed once

	// System TUN cleanup info
	tunName    string // Name of the system TUN interface (e.g., utun5)
	addedRoute string // Route that was added to the system
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

	var tunDev tun.Device
	var netstackInst *netstack.Net
	var err error

	// 1. Try to create a system TUN first for better OS integration (allows ping/ifconfig)
	if runtime.GOOS == "darwin" {
		// On macOS, we must use utunX. We try to find an available one.
		for i := 0; i < 64; i++ {
			name := fmt.Sprintf("utun%d", i)
			tunDev, err = tun.CreateTUN(name, d.config.Interface.MTU)
			if err == nil {
				break
			}
		}
	} else {
		// On Linux/Others, we can try a specific name or let the system assign
		tunDev, err = tun.CreateTUN("wantastic", d.config.Interface.MTU)
	}

	if err != nil {
		log.Printf("Warning: Failed to create system TUN (%v), falling back to userspace netstack", err)
		// Fallback to pure userspace netstack
		tunDev, netstackInst, err = netstack.CreateNetTUN(addrs, nil, d.config.Interface.MTU)
		if err != nil {
			return fmt.Errorf("create netstack tun: %w", err)
		}
		d.netstack = netstackInst
		log.Printf("MODE: Userspace Netstack (Rootless). Some system tools may not work.")
	} else {
		// System TUN created successfully, configure the IP address so the OS can see it
		realName, _ := tunDev.Name()
		log.Printf("MODE: System TUN (%s). Standard OS networking enabled.", realName)

		if len(addrs) > 0 {
			addr := addrs[0]
			// We need the full prefix for masking etc.
			prefix := d.config.Interface.Addresses[0]

			switch runtime.GOOS {
			case "darwin":
				// macOS: ifconfig <interface> inet <local> <remote> netmask 255.255.255.255 up
				// For PTP interfaces like TUN, we use netmask 255.255.255.255 and local==remote
				cmdStr := fmt.Sprintf("ifconfig %s inet %s %s netmask 255.255.255.255 up", realName, addr.String(), addr.String())
				log.Printf("Configuring interface: %s", cmdStr)
				cmd := exec.Command("sh", "-c", cmdStr)
				if out, err := cmd.CombinedOutput(); err != nil {
					log.Printf("Error: Failed to configure interface %s: %v (output: %s)", realName, err, out)
				}

				// Add route for the VPN subnet so other peers are reachable via this interface
				routeTarget := prefix.Masked().Addr().String()
				maskBits := prefix.Bits()

				// Tailscale/WireGuard logic: if we are /32, use AllowedIPs to find the real subnet
				if maskBits == 32 && len(d.config.Server.AllowedIPs) > 0 {
					// Use the first AllowedIP as the subnet route (e.g. 10.255.255.224/27)
					routeTarget = d.config.Server.AllowedIPs[0]
					log.Printf("Host is /32, adding route for AllowedIPs subnet: %s", routeTarget)
				} else {
					routeTarget = prefix.Masked().String()
				}

				routeCmd := fmt.Sprintf("route -n add -net %s -interface %s", routeTarget, realName)
				log.Printf("Adding system route: %s", routeCmd)
				exec.Command("sh", "-c", routeCmd).Run()

				// Store for cleanup
				d.tunName = realName
				d.addedRoute = routeTarget
			case "linux":
				exec.Command("ip", "addr", "add", prefix.String(), "dev", realName).Run()
				exec.Command("ip", "link", "set", "up", "dev", realName).Run()
			}
		}
	}

	d.tunDev = tunDev

	if d.config.Verbose && d.netstack != nil {
		log.Printf("Netstack (fallback) initialized with %d addresses", len(addrs))
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

	log.Printf("Device stopping...")

	// Only close stopCh if it hasn't been closed already
	select {
	case <-d.stopCh:
		// Channel already closed
	default:
		close(d.stopCh)
	}

	// Store references to devices before unlocking
	wgDevice := d.device
	tunDevice := d.tunDev
	tunName := d.tunName
	addedRoute := d.addedRoute

	// Clear references to prevent double closing
	d.device = nil
	d.tunDev = nil
	d.tunName = ""
	d.addedRoute = ""

	d.mu.Unlock()

	// Cleanup system routes on macOS
	if runtime.GOOS == "darwin" && addedRoute != "" {
		routeCmd := fmt.Sprintf("route -n delete -net %s", addedRoute)
		log.Printf("Removing system route: %s", routeCmd)
		exec.Command("sh", "-c", routeCmd).Run()
	}

	// Close WireGuard device (this also brings down the interface)
	if wgDevice != nil {
		wgDevice.Close()
	}

	// Close TUN device
	if tunDevice != nil {
		tunDevice.Close()
	}

	log.Printf("Device stopped and cleaned up (interface: %s)", tunName)

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

	var config strings.Builder
	config.WriteString(fmt.Sprintf("private_key=%s\n", privateKeyHex))
	config.WriteString(fmt.Sprintf("listen_port=%d\n", d.config.Interface.ListenPort))
	config.WriteString("replace_peers=true\n")

	if d.config.Server.PublicKey != "" {
		// Convert base64 public key to hexadecimal format for WireGuard IPC
		publicKeyHex, err := base64ToHex(d.config.Server.PublicKey)
		if err != nil {
			return fmt.Errorf("convert public key to hex: %w", err)
		}

		config.WriteString(fmt.Sprintf("public_key=%s\n", publicKeyHex))
		config.WriteString(fmt.Sprintf("endpoint=%s:%d\n", d.config.Server.Endpoint, d.config.Server.Port))

		// Configure AllowedIPs - route only specific networks through VPN
		// and exclude local subnets to allow internal network access
		if len(d.config.Server.AllowedIPs) > 0 {
			// Use custom AllowedIPs from config
			for _, allowedIP := range d.config.Server.AllowedIPs {
				config.WriteString(fmt.Sprintf("allowed_ip=%s\n", allowedIP))
			}
		} else {
			// Default: route all traffic through VPN using the userspace netstack
			config.WriteString("allowed_ip=0.0.0.0/0\n")
			config.WriteString("allowed_ip=::/0\n")
		}

		config.WriteString("persistent_keepalive_interval=25\n")
	}

	if err := dev.IpcSet(config.String()); err != nil {
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

// GetNetstack returns the userspace netstack instance
func (d *Device) GetNetstack() *netstack.Net {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.netstack
}
