package device

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"wantastic-agent/internal/config"
	pb "wantastic-agent/internal/grpc/proto"

	"golang.org/x/crypto/curve25519"
	"golang.zx2c4.com/wireguard/conn"
	wgdevice "golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	virtstack "golang.zx2c4.com/wireguard/tun/netstack"
)

type Device struct {
	config   *config.Config
	device   *wgdevice.Device
	tunDev   tun.Device
	netstack *virtstack.Net

	mu      sync.RWMutex
	running bool
	stopCh  chan struct{}

	tunName     string
	addedRoutes []string

	PortForwarder func(string, int) bool
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
		return nil
	}
	d.running = true
	d.mu.Unlock()

	var tunDev tun.Device
	var netstackInst *virtstack.Net
	var err error

	addrs := make([]netip.Addr, len(d.config.Interface.Addresses))
	for i, prefix := range d.config.Interface.Addresses {
		addrs[i] = prefix.Addr()
	}

	// Force Userspace Netstack
	// We no longer attempt to creating a real system TUN device.
	// This ensures "busybox" behavior where the application is entirely self-contained.
	log.Printf("Initializing userspace netstack...")
	tunDev, netstackInst, err = virtstack.CreateNetTUN(addrs, nil, d.config.Interface.MTU)
	if err != nil {
		return fmt.Errorf("create netstack tun: %w", err)
	}
	d.netstack = netstackInst
	d.tunName = "userspace-tun"
	d.tunDev = tunDev

	// Wrap TUN for JIT Port Forwarding
	tunDev = NewTunWrapper(tunDev, d.PortForwarder)

	// 4. Start WireGuard
	logger := wgdevice.NewLogger(wgdevice.LogLevelError, fmt.Sprintf("(%s) ", d.config.DeviceID))
	if d.config.Verbose {
		logger = wgdevice.NewLogger(wgdevice.LogLevelVerbose, fmt.Sprintf("(%s) ", d.config.DeviceID))
	}

	wd := wgdevice.NewDevice(tunDev, conn.NewDefaultBind(), logger)
	wd.DisableSomeRoamingForBrokenMobileSemantics()
	d.device = wd

	if err := d.applyConfig(); err != nil {
		return err
	}
	return wd.Up()
}

func (d *Device) Stop() error {
	d.mu.Lock()
	if !d.running {
		d.mu.Unlock()
		return nil
	}
	d.running = false

	wg := d.device
	td := d.tunDev
	d.mu.Unlock()

	// No system cleanup needed for userspace netstack

	if wg != nil {
		wg.Close()
	} else if td != nil {
		td.Close()
	}

	log.Printf("Stopped device")
	return nil
}

func (d *Device) Close() error { return d.Stop() }

func (d *Device) applyConfig() error {
	privHex, _ := base64ToHex(d.config.PrivateKey)

	// Helper to generate the configuration string for a given port
	genConfig := func(port int) string {
		var conf strings.Builder
		fmt.Fprintf(&conf, "private_key=%s\nlisten_port=%d\nreplace_peers=true\n", privHex, port)

		if d.config.Server.PublicKey != "" {
			pubHex, _ := base64ToHex(d.config.Server.PublicKey)
			fmt.Fprintf(&conf, "public_key=%s\nendpoint=%s:%d\n", pubHex, d.config.Server.Endpoint, d.config.Server.Port)
			if len(d.config.Server.AllowedIPs) > 0 {
				for _, ip := range d.config.Server.AllowedIPs {
					fmt.Fprintf(&conf, "allowed_ip=%s\n", ip)
				}
			} else {
				conf.WriteString("allowed_ip=0.0.0.0/0\nallowed_ip=::/0\n")
			}
			conf.WriteString("persistent_keepalive_interval=25\n")
		}
		return conf.String()
	}

	// Try with the configured port first
	err := d.device.IpcSet(genConfig(d.config.Interface.ListenPort))
	if err != nil && d.config.Interface.ListenPort != 0 {
		log.Printf("Warning: failed to set listen_port %d (%v), falling back to random port", d.config.Interface.ListenPort, err)
		d.config.Interface.ListenPort = 0
		return d.device.IpcSet(genConfig(0))
	}

	return err
}

func (d *Device) UpdateConfig(cfg *pb.DeviceConfiguration) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(cfg.Addresses) > 0 {
		d.config.Interface.Addresses = nil
		for _, a := range cfg.Addresses {
			p, _ := netip.ParsePrefix(a)
			d.config.Interface.Addresses = append(d.config.Interface.Addresses, p)
		}
	}
	if cfg.ListenPort > 0 {
		d.config.Interface.ListenPort = int(cfg.ListenPort)
	}
	return d.applyConfig()
}

func (d *Device) UpdateServerConfig(cfg *pb.ServerConfiguration) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.config.Server.Endpoint = cfg.Endpoint
	d.config.Server.Port = int(cfg.Port)
	if cfg.PublicKey != "" {
		d.config.Server.PublicKey = cfg.PublicKey
	}
	return d.applyConfig()
}

func (d *Device) HealthCheck() error {
	if d.device == nil {
		return fmt.Errorf("off")
	}
	return nil
}

func (d *Device) GetPublicKey() string {
	b, _ := base64.StdEncoding.DecodeString(d.config.PrivateKey)
	var priv [32]byte
	copy(priv[:], b)
	var pub [32]byte
	curve25519.ScalarBaseMult(&pub, &priv)
	return base64.StdEncoding.EncodeToString(pub[:])
}

func (d *Device) GetStats() (map[string]any, error) {
	return map[string]any{
		"id":        d.config.DeviceID,
		"connected": d.HasActiveHandshake(),
	}, nil
}

func (d *Device) HasActiveHandshake() bool {
	d.mu.RLock()
	wd := d.device
	d.mu.RUnlock()
	if wd == nil {
		return false
	}

	res, err := wd.IpcGet()
	if err != nil {
		return false
	}
	lines := strings.Split(res, "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "last_handshake_time_sec=") {
			parts := strings.Split(line, "=")
			if len(parts) == 2 {
				ts, _ := strconv.ParseInt(parts[1], 10, 64)
				if ts > 0 && time.Since(time.Unix(ts, 0)) < 3*time.Minute {
					return true
				}
			}
		}
	}
	return false
}

func (d *Device) GetTransferStats() (uint64, uint64, error) {
	d.mu.RLock()
	wd := d.device
	d.mu.RUnlock()
	if wd == nil {
		return 0, 0, fmt.Errorf("device not started")
	}

	res, err := wd.IpcGet()
	if err != nil {
		return 0, 0, err
	}

	var rx, tx uint64
	lines := strings.Split(res, "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "rx_bytes=") {
			parts := strings.Split(line, "=")
			if n, err := strconv.ParseUint(parts[1], 10, 64); err == nil {
				rx += n
			}
		}
		if strings.HasPrefix(line, "tx_bytes=") {
			parts := strings.Split(line, "=")
			if n, err := strconv.ParseUint(parts[1], 10, 64); err == nil {
				tx += n
			}
		}
	}
	return rx, tx, nil
}

func (d *Device) GetNetstack() *virtstack.Net { return d.netstack }

func base64ToHex(b64 string) (string, error) {
	db, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(db), nil
}
