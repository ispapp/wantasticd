package config

import (
	"bufio"
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
)

type Interface struct {
	PrivateKey string
	ListenPort int
	Addresses  []netip.Prefix
}

type Peer struct {
	PublicKey           string
	PresharedKey        string
	Endpoint            string
	AllowedIPs          []netip.Prefix
	PersistentKeepalive int
}

type Config struct {
	Interface Interface
	Peers     []Peer
	Raw       string
}

func Load(path string) (Config, error) {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return Config{}, err
	}
	cfg, err := Parse(string(data))
	if err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func Parse(s string) (Config, error) {
	var cfg Config
	var section string
	var current Peer

	scanner := bufio.NewScanner(strings.NewReader(s))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			if section == "Peer" {
				cfg.Peers = append(cfg.Peers, current)
				current = Peer{}
			}
			section = strings.Trim(line, "[]")
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			return Config{}, fmt.Errorf("invalid line: %q", line)
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])
		switch section {
		case "Interface":
			switch strings.ToLower(key) {
			case "privatekey":
				cfg.Interface.PrivateKey = val
			case "listenport":
				var p int
				_, err := fmt.Sscanf(val, "%d", &p)
				if err != nil {
					return Config{}, fmt.Errorf("invalid listen port: %w", err)
				}
				cfg.Interface.ListenPort = p
			case "address":
				addrs := splitCSV(val)
				for _, a := range addrs {
					prefix, err := netip.ParsePrefix(strings.TrimSpace(a))
					if err != nil {
						return Config{}, fmt.Errorf("invalid address %q: %w", a, err)
					}
					cfg.Interface.Addresses = append(cfg.Interface.Addresses, prefix)
				}
			}
		case "Peer":
			switch strings.ToLower(key) {
			case "publickey":
				current.PublicKey = val
			case "presharedkey":
				current.PresharedKey = val
			case "endpoint":
				current.Endpoint = val
			case "allowedips":
				ips := splitCSV(val)
				for _, ip := range ips {
					prefix, err := netip.ParsePrefix(strings.TrimSpace(ip))
					if err != nil {
						return Config{}, fmt.Errorf("invalid allowed ip %q: %w", ip, err)
					}
					current.AllowedIPs = append(current.AllowedIPs, prefix)
				}
			case "persistentkeepalive":
				var v int
				_, err := fmt.Sscanf(val, "%d", &v)
				if err != nil {
					return Config{}, fmt.Errorf("invalid persistent keepalive: %w", err)
				}
				current.PersistentKeepalive = v
			}
		default:
			return Config{}, fmt.Errorf("unexpected section %q", section)
		}
	}
	if section == "Peer" {
		cfg.Peers = append(cfg.Peers, current)
	}
	cfg.Raw = s
	if err := scanner.Err(); err != nil {
		return Config{}, err
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func splitCSV(s string) []string {
	fields := strings.Split(s, ",")
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		trimmed := strings.TrimSpace(f)
		if trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func (c Config) Validate() error {
	if c.Interface.PrivateKey == "" {
		return errors.New("interface private key required")
	}
	if err := validateKey(c.Interface.PrivateKey); err != nil {
		return fmt.Errorf("invalid interface private key: %w", err)
	}
	if c.Interface.ListenPort <= 0 || c.Interface.ListenPort > 65535 {
		return errors.New("listen port must be 1-65535")
	}
	if len(c.Interface.Addresses) == 0 {
		return errors.New("at least one interface address required")
	}
	if len(c.Peers) == 0 {
		return errors.New("at least one peer required")
	}
	for i, p := range c.Peers {
		if err := validateKey(p.PublicKey); err != nil {
			return fmt.Errorf("peer %d public key: %w", i, err)
		}
		if p.PresharedKey != "" {
			if err := validateKey(p.PresharedKey); err != nil {
				return fmt.Errorf("peer %d preshared key: %w", i, err)
			}
		}
		if len(p.AllowedIPs) == 0 {
			return fmt.Errorf("peer %d requires at least one allowed IP", i)
		}
	}
	return nil
}

func validateKey(s string) error {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return err
	}
	if len(b) != 32 {
		return fmt.Errorf("expected 32 bytes, got %d", len(b))
	}
	return nil
}
