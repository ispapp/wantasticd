package wgcontrol

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/ipc"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	cfgpkg "wantastic-wgclient/internal/config"
)

type Runner struct {
	DeviceName string
	Mode       string
	dev        *device.Device
	tunDev     tun.Device
	net        *netstack.Net
	uapi       io.Closer
}

func Start(ctx context.Context, cfg cfgpkg.Config, deviceName string, useNetstack bool) (*Runner, error) {
	var t tun.Device
	var n *netstack.Net
	var err error

	if useNetstack {
		addrs := make([]netip.Addr, len(cfg.Interface.Addresses))
		for i, prefix := range cfg.Interface.Addresses {
			addrs[i] = prefix.Addr()
		}
		t, n, err = netstack.CreateNetTUN(addrs, nil, 1420)
		if err != nil {
			return nil, fmt.Errorf("create netstack tun: %w", err)
		}
	} else {
		t, err = tun.CreateTUN(deviceName, 1420)
		if err != nil {
			return nil, fmt.Errorf("create tun: %w", err)
		}
	}

	logger := device.NewLogger(device.LogLevelError, fmt.Sprintf("(%s) ", deviceName))
	d := device.NewDevice(t, conn.NewDefaultBind(), logger)

	l, err := ipc.UAPIListen(deviceName, t.File())
	if err != nil {
		d.Close()
		t.Close()
		return nil, fmt.Errorf("uapi listen: %w", err)
	}

	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go d.IpcHandle(conn)
		}
	}()

	if err := applyConfig(d, cfg); err != nil {
		d.Close()
		t.Close()
		l.Close()
		return nil, err
	}
	if err := d.Up(); err != nil {
		d.Close()
		t.Close()
		l.Close()
		return nil, err
	}

	if err := writePID(deviceName); err != nil {
		log.Printf("warn: pidfile: %v", err)
	}

	r := &Runner{DeviceName: deviceName, Mode: mode(useNetstack), dev: d, tunDev: t, net: n, uapi: l}
	go func() {
		sigs := make(chan os.Signal, 1)
		signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
		select {
		case <-ctx.Done():
		case <-sigs:
		}
		r.Close()
	}()
	return r, nil
}

func mode(useNetstack bool) string {
	if useNetstack {
		return "netstack"
	}
	return "host"
}

func (r *Runner) Close() {
	if r.dev != nil {
		r.dev.Close()
	}
	if r.tunDev != nil {
		r.tunDev.Close()
	}
	if r.uapi != nil {
		r.uapi.Close()
	}
	removePID(r.DeviceName)
}

func applyConfig(d *device.Device, cfg cfgpkg.Config) error {
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "private_key=%s\n", cfg.Interface.PrivateKey)
	fmt.Fprintf(&buf, "listen_port=%d\n", cfg.Interface.ListenPort)
	fmt.Fprintf(&buf, "replace_peers=true\n")
	for _, p := range cfg.Peers {
		fmt.Fprintf(&buf, "public_key=%s\n", p.PublicKey)
		if p.PresharedKey != "" {
			fmt.Fprintf(&buf, "preshared_key=%s\n", p.PresharedKey)
		}
		if p.Endpoint != "" {
			fmt.Fprintf(&buf, "endpoint=%s\n", p.Endpoint)
		}
		for _, aip := range p.AllowedIPs {
			fmt.Fprintf(&buf, "allowed_ip=%s\n", aip.String())
		}
		if p.PersistentKeepalive > 0 {
			fmt.Fprintf(&buf, "persistent_keepalive_interval=%d\n", p.PersistentKeepalive)
		}
	}
	if err := d.IpcSet(buf.String()); err != nil {
		return err
	}
	return nil
}

var ErrAlreadyRunning = errors.New("device already running")

func pidFile(deviceName string) string {
	runtimeDir := os.Getenv("XDG_RUNTIME_DIR")
	if runtimeDir == "" {
		runtimeDir = os.TempDir()
	}
	return filepath.Join(runtimeDir, "wantastic-wgclient", fmt.Sprintf("%s.pid", deviceName))
}

func writePID(deviceName string) error {
	path := pidFile(deviceName)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(fmt.Sprintf("%d", os.Getpid())), 0o600)
}

func removePID(deviceName string) {
	path := pidFile(deviceName)
	os.Remove(path)
}

func Down(deviceName string) error {
	data, err := os.ReadFile(pidFile(deviceName))
	if err == nil {
		var pid int
		_, scanErr := fmt.Sscanf(string(bytes.TrimSpace(data)), "%d", &pid)
		if scanErr == nil && pid > 0 {
			if err := syscall.Kill(pid, syscall.SIGTERM); err == nil {
				return nil
			}
		}
	}
	c, err := wgctrl.New()
	if err != nil {
		return err
	}
	defer c.Close()
	dev, err := c.Device(deviceName)
	if err != nil {
		return err
	}
	if dev == nil {
		return errors.New("device not found")
	}
	// Attempt to remove peers to quiesce; actual tun removal may require root ip link.
	return c.ConfigureDevice(deviceName, wgtypes.Config{ReplacePeers: true, Peers: []wgtypes.PeerConfig{}})
}

func Status(deviceName string) (string, error) {
	c, err := wgctrl.New()
	if err != nil {
		return "", err
	}
	defer c.Close()
	dev, err := c.Device(deviceName)
	if err != nil {
		return "", err
	}
	if dev == nil {
		return "", errors.New("device not found")
	}
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "device %s (%s)\n", dev.Name, dev.Type)
	fmt.Fprintf(&buf, "listen_port: %d\n", dev.ListenPort)
	for _, p := range dev.Peers {
		fmt.Fprintf(&buf, "peer %s\n", p.PublicKey.String())
		fmt.Fprintf(&buf, "  endpoint: %v\n", p.Endpoint)
		fmt.Fprintf(&buf, "  latest_handshake: %s\n", p.LastHandshakeTime)
		fmt.Fprintf(&buf, "  tx: %d bytes  rx: %d bytes\n", p.TransmitBytes, p.ReceiveBytes)
		fmt.Fprintf(&buf, "  allowed_ips: ")
		for i, aip := range p.AllowedIPs {
			if i > 0 {
				buf.WriteString(",")
			}
			buf.WriteString(aip.String())
		}
		buf.WriteString("\n")
	}
	return buf.String(), nil
}

func Doctor() []string {
	var out []string
	if os.Geteuid() == 0 {
		out = append(out, "ok: running as root")
	} else {
		out = append(out, "warn: not running as root; ensure permission to create tun and write /etc/wireguard")
	}
	if _, err := os.Stat("/dev/net/tun"); err == nil {
		out = append(out, "ok: /dev/net/tun present")
	} else {
		out = append(out, fmt.Sprintf("warn: /dev/net/tun not available: %v", err))
	}
	return out
}
