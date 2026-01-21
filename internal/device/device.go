package device

import (
	"fmt"
	"log"
	"net/netip"
	"sync"
	"time"

	"wantastic-agent/internal/config"
	"wantastic-agent/internal/grpc"

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

	mu      sync.RWMutex
	running bool
	stopCh  chan struct{}
}

func New(cfg *config.Config) (*Device, error) {
	return &Device{
		config: cfg,
		stopCh: make(chan struct{}),
	}, nil
}

func (d *Device) Start() error {
	d.mu.Lock()
	if d.running {
		d.mu.Unlock()
		return fmt.Errorf("device already running")
	}
	d.running = true
	d.mu.Unlock()

	addrs := make([]netip.Addr, len(d.config.Interface.Addresses))
	for i, prefix := range d.config.Interface.Addresses {
		addrs[i] = prefix.Addr()
	}

	tunDev, netstack, err := netstack.CreateNetTUN(addrs, nil, d.config.Interface.MTU)
	if err != nil {
		return fmt.Errorf("create netstack tun: %w", err)
	}

	d.tunDev = tunDev
	d.netstack = netstack

	logger := device.NewLogger(device.LogLevelError, fmt.Sprintf("(%s) ", d.config.DeviceID))
	wireguardDevice := device.NewDevice(tunDev, conn.NewDefaultBind(), logger)

	if err := d.configureDevice(wireguardDevice); err != nil {
		tunDev.Close()
		return fmt.Errorf("configure device: %w", err)
	}

	if err := wireguardDevice.Up(); err != nil {
		tunDev.Close()
		return fmt.Errorf("bring device up: %w", err)
	}

	d.device = wireguardDevice
	return nil
}

func (d *Device) Close() error {
	return d.Stop()
}

func (d *Device) Stop() error {
	d.mu.Lock()
	if !d.running {
		d.mu.Unlock()
		return nil
	}
	d.running = false
	close(d.stopCh)
	d.mu.Unlock()

	if d.device != nil {
		d.device.Close()
	}

	if d.tunDev != nil {
		d.tunDev.Close()
	}

	return nil
}

func (d *Device) configureDevice(dev *device.Device) error {
	config := fmt.Sprintf("private_key=%s\n", d.config.PrivateKey)
	config += fmt.Sprintf("listen_port=%d\n", d.config.Interface.ListenPort)
	config += "replace_peers=true\n"

	if d.config.Server.PublicKey != "" {
		config += fmt.Sprintf("public_key=%s\n", d.config.Server.PublicKey)
		config += fmt.Sprintf("endpoint=%s:%d\n", d.config.Server.Endpoint, d.config.Server.Port)
		config += fmt.Sprintf("allowed_ip=0.0.0.0/0\n")
		config += fmt.Sprintf("allowed_ip=::/0\n")
		config += "persistent_keepalive_interval=25\n"
	}

	if err := dev.IpcSet(config); err != nil {
		return fmt.Errorf("apply device config: %w", err)
	}

	return nil
}

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
		config += fmt.Sprintf("allowed_ip=0.0.0.0/0\n")
		config += fmt.Sprintf("allowed_ip=::/0\n")
		config += "persistent_keepalive_interval=25\n"
	}

	if err := d.device.IpcSet(config); err != nil {
		return fmt.Errorf("reconfigure device: %w", err)
	}

	log.Println("Device reconfigured successfully")
	return nil
}

func (d *Device) GetStats() (map[string]interface{}, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	if !d.running {
		return nil, fmt.Errorf("device not running")
	}

	stats := map[string]interface{}{
		"device_id": d.config.DeviceID,
		"running":   d.running,
		"uptime":    time.Since(time.Now()).Seconds(),
	}

	return stats, nil
}
