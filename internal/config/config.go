package config

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"runtime"
	"strings"
	"time"
	"wantastic-agent/internal/grpc"
	pb "wantastic-agent/internal/grpc/proto"

	"github.com/denisbrodbeck/machineid"
	"github.com/google/uuid"
	"golang.org/x/crypto/chacha20poly1305"
)

// resolveEndpoint resolves a hostname to an IP address using Cloudflare DNS (1.1.1.1:53)
func resolveEndpoint(hostname string) (string, error) {
	// Check if it's already an IP address
	if ip := net.ParseIP(hostname); ip != nil {
		return hostname, nil
	}

	// Create a custom resolver using Cloudflare DNS
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{}
			return d.DialContext(ctx, "udp", "1.1.1.1:53")
		},
	}

	// Resolve the hostname
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ips, err := resolver.LookupIPAddr(ctx, hostname)
	if err != nil {
		return "", fmt.Errorf("resolve hostname %s: %w", hostname, err)
	}

	if len(ips) == 0 {
		return "", fmt.Errorf("no IP addresses found for hostname %s", hostname)
	}

	// Return the first IPv4 address if available, otherwise first IPv6
	for _, ip := range ips {
		if ip.IP.To4() != nil {
			return ip.IP.String(), nil
		}
	}

	// If no IPv4, return the first IPv6
	return ips[0].IP.String(), nil
}

type Config struct {
	DeviceID   string    `json:"device_id"`
	TenantID   string    `json:"tenant_id"`
	PrivateKey string    `json:"private_key"`
	PublicKey  string    `json:"public_key"`
	Server     Server    `json:"server"`
	Interface  Interface `json:"interface"`
	Auth       Auth      `json:"auth"`
	Verbose    bool      `json:"verbose"`
}

type Server struct {
	Endpoint            string   `json:"endpoint"`
	Port                int      `json:"port"`
	PublicKey           string   `json:"public_key"`
	AllowedIPs          []string `json:"allowed_ips"`
	PersistentKeepalive int      `json:"persistent_keepalive"`
}

type Interface struct {
	Addresses  []netip.Prefix `json:"addresses"`
	ListenPort int            `json:"listen_port"`
	MTU        int            `json:"mtu"`
	DNS        []string       `json:"dns"`
}

// Auth holds the authentication credentials for the agent.
type Auth struct {
	ServerURL   string        `json:"server_url"`
	Token       string        `json:"token"`
	RefreshTime time.Duration `json:"refresh_time"`
}

// LoadFromFile loads the configuration from a file.
// It first attempts to parse the file as JSON.
// If that fails, it tries to parse it as a traditional WireGuard configuration file.
// Returns a pointer to the Config struct if successful, or an error if any step fails.
func LoadFromFile(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config file: %w", err)
	}

	// Try to parse as JSON first
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err == nil {
		if err := cfg.Validate(); err != nil {
			return nil, fmt.Errorf("validate config: %w", err)
		}
		return &cfg, nil
	}

	// If JSON parsing fails, try to parse as traditional WireGuard config
	cfg, err = parseTraditionalWireGuardConfig(string(data))
	if err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("validate config: %w", err)
	}

	return &cfg, nil
}

// parseTraditionalWireGuardConfig parses traditional WireGuard INI-style configuration
func parseTraditionalWireGuardConfig(configData string) (Config, error) {
	var cfg Config
	scanner := bufio.NewScanner(strings.NewReader(configData))

	currentSection := ""
	peerPublicKey := ""
	peerEndpoint := ""
	peerAllowedIPs := []string{}

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip comments and empty lines
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Check for section headers
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			currentSection = strings.Trim(line, "[]")
			continue
		}

		// Parse key-value pairs
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		switch currentSection {
		case "Interface":
			switch key {
			case "PrivateKey":
				cfg.PrivateKey = value
			case "Address":
				// Convert CIDR address to netip.Prefix
				if prefix, err := netip.ParsePrefix(value); err == nil {
					cfg.Interface.Addresses = []netip.Prefix{prefix}
				}
			case "ListenPort":
				if port, err := fmt.Sscanf(value, "%d", &cfg.Interface.ListenPort); err == nil && port == 1 {
					// Port parsed successfully
				}
			case "MTU":
				if mtu, err := fmt.Sscanf(value, "%d", &cfg.Interface.MTU); err == nil && mtu == 1 {
					// MTU parsed successfully
				}
			case "DNS":
				// Parse DNS servers from traditional WireGuard config
				dnsServers := strings.Split(value, ",")
				for i := range dnsServers {
					dnsServers[i] = strings.TrimSpace(dnsServers[i])
				}
				// Store DNS servers in Interface configuration for netstack to use
				cfg.Interface.DNS = dnsServers
				log.Printf("Configured DNS servers: %v", dnsServers)
			}

		case "Peer":
			switch key {
			case "PublicKey":
				peerPublicKey = value
			case "Endpoint":
				peerEndpoint = value
			case "AllowedIPs":
				peerAllowedIPs = strings.Split(value, ",")
				for i := range peerAllowedIPs {
					peerAllowedIPs[i] = strings.TrimSpace(peerAllowedIPs[i])
				}
			case "PersistentKeepalive":
				if keepalive, err := fmt.Sscanf(value, "%d", &cfg.Server.PersistentKeepalive); err == nil && keepalive == 1 {
					// Keepalive parsed successfully
				}
			}
		}
	}

	// Extract server information from peer section
	if peerPublicKey != "" {
		cfg.Server.PublicKey = peerPublicKey
	}

	if peerEndpoint != "" {
		// Parse endpoint (format: host:port)
		if parts := strings.Split(peerEndpoint, ":"); len(parts) == 2 {
			cfg.Server.Endpoint = parts[0]
			if port, err := fmt.Sscanf(parts[1], "%d", &cfg.Server.Port); err == nil && port == 1 {
				// Port parsed successfully
			}
		} else {
			cfg.Server.Endpoint = peerEndpoint
			cfg.Server.Port = 51820 // Default WireGuard port
		}
	}

	if len(peerAllowedIPs) > 0 {
		cfg.Server.AllowedIPs = peerAllowedIPs
	}

	// Generate device ID if not set
	if cfg.DeviceID == "" {
		cfg.GenerateDeviceID()
	}

	return cfg, nil
}

func LoadFromDeviceFlow(ctx context.Context, serverURL string) (*Config, error) {
	client, err := grpc.New(serverURL, "", "")
	if err != nil {
		return nil, fmt.Errorf("create grpc client: %w", err)
	}
	defer client.Close()

	resp, err := client.StartDeviceFlow(ctx)
	if err != nil {
		return nil, fmt.Errorf("start device flow: %w", err)
	}

	// The updated StartDeviceFlow returns a RegisterDeviceResponse
	// We can use the SAME LOGIC as LoadFromToken to process it
	if !resp.Success {
		return nil, fmt.Errorf("registration failed")
	}

	// Fallback to raw fields (LoadFromToken also does this now)
	cfg := &Config{
		Server: Server{
			Endpoint:            resp.Endpoint,
			PublicKey:           resp.ServerKey,
			AllowedIPs:          resp.AllowedIps,
			PersistentKeepalive: int(resp.PersistentKeepalive),
		},
		Interface: Interface{
			MTU:        int(resp.Mtu),
			ListenPort: int(resp.ListenPort),
			DNS:        resp.DnsServers,
		},
	}
	cfg.Auth.ServerURL = serverURL
	// Use new token if provided, otherwise keep existing enrollment token
	if resp.Token != "" {
		cfg.Auth.Token = resp.Token
	}

	// Parse routes
	for _, route := range resp.Routes {
		if prefix, err := netip.ParsePrefix(route); err == nil {
			cfg.Interface.Addresses = append(cfg.Interface.Addresses, prefix)
		}
	}

	cfg.GenerateDeviceID()
	return cfg, nil
}

// LoadFromToken loads the configuration from a token.
func LoadFromToken(ctx context.Context, serverURL, token string) (*Config, error) {
	// Create gRPC client
	client, err := grpc.New(serverURL, "", token)
	if err != nil {
		return nil, fmt.Errorf("create grpc client: %w", err)
	}
	defer client.Close()

	// Gather system information (fingerprint)
	hostname, _ := os.Hostname()
	osInfo := runtime.GOOS
	arch := runtime.GOARCH

	// Generate a random int64 nonce
	var nonce int64
	if err := binary.Read(rand.Reader, binary.LittleEndian, &nonce); err != nil {
		// Fallback to time if rand fails (unlikely)
		nonce = time.Now().UnixNano()
	}

	resp, err := client.RegisterDevice(ctx, nonce, osInfo, arch, hostname)
	if err != nil {
		return nil, fmt.Errorf("register device: %w", err)
	}

	if !resp.Success {
		return nil, fmt.Errorf("registration failed")
	}

	// 3. Handle response (Prefer EncryptedConfig, fallback to raw fields)
	if len(resp.EncryptedConfig) > 0 {
		// Derive key from token: Key = SHA256(Token)
		hash := sha256.Sum256([]byte(token))
		key := hash[:]

		// Construct Nonce (12 bytes, first 8 from nonce)
		nonceBytes := make([]byte, 12)
		binary.LittleEndian.PutUint64(nonceBytes[:8], uint64(nonce))

		// Create Cipher
		aead, err := chacha20poly1305.New(key)
		if err != nil {
			return nil, fmt.Errorf("create cipher: %w", err)
		}

		// Decrypt
		decrypted, err := aead.Open(nil, nonceBytes, resp.EncryptedConfig, nil)
		if err != nil {
			return nil, fmt.Errorf("decrypt config: %w", err)
		}

		// Parse decrypted config
		cfgStruct, err := parseTraditionalWireGuardConfig(string(decrypted))
		if err != nil {
			return nil, fmt.Errorf("parse decrypted config: %w", err)
		}

		cfg := &cfgStruct
		cfg.Auth.ServerURL = serverURL
		cfg.Auth.Token = resp.Token
		cfg.GenerateDeviceID()
		return cfg, nil
	}

	// Fallback: Use raw fields from response
	log.Println("⚠️  No encrypted configuration received, using raw fields")
	cfg := &Config{
		Server: Server{
			Endpoint:            resp.Endpoint,
			PublicKey:           resp.ServerKey,
			AllowedIPs:          resp.AllowedIps,
			PersistentKeepalive: int(resp.PersistentKeepalive),
		},
		Interface: Interface{
			MTU:        int(resp.Mtu),
			ListenPort: int(resp.ListenPort),
			DNS:        resp.DnsServers,
		},
	}
	cfg.Auth.ServerURL = serverURL
	cfg.Auth.Token = resp.Token

	// Parse routes if available
	for _, route := range resp.Routes {
		if prefix, err := netip.ParsePrefix(route); err == nil {
			cfg.Interface.Addresses = append(cfg.Interface.Addresses, prefix)
		}
	}

	cfg.GenerateDeviceID()
	return cfg, nil
}

// Validate validates the configuration.
// It checks if the private key, server endpoint, and server port are set.
// If the server endpoint is not an IP address, it attempts to resolve it.
// If any validation fails, it returns an error with a descriptive message.
func (c *Config) Validate() error {
	if c.PrivateKey == "" {
		return fmt.Errorf("private key required")
	}
	if c.Server.Endpoint == "" {
		return fmt.Errorf("server endpoint required")
	}

	// Resolve hostname to IP address if it's not already an IP
	if net.ParseIP(c.Server.Endpoint) == nil {
		resolvedIP, err := resolveEndpoint(c.Server.Endpoint)
		if err != nil {
			return fmt.Errorf("failed to resolve endpoint %s: %w", c.Server.Endpoint, err)
		}
		c.Server.Endpoint = resolvedIP
	}

	if c.Server.Port == 0 {
		c.Server.Port = 51820
	}
	if c.Interface.MTU == 0 {
		c.Interface.MTU = 1420
	}
	if c.Interface.ListenPort == 0 {
		// Standard client behavior: use random port to avoid conflicts
		c.Interface.ListenPort = 0
	}
	if c.Auth.RefreshTime == 0 {
		c.Auth.RefreshTime = 24 * time.Hour
	}
	return nil
}

func (c *Config) GenerateDeviceID() {
	if c.DeviceID != "" {
		return
	}

	// Generate a stable, anonymous device ID.
	id, err := machineid.ProtectedID("wantastic")
	if err != nil {
		log.Printf("Warning: could not generate a stable device ID, falling back to a random one. This device may be re-registered if the configuration is lost. Error: %v", err)
		c.DeviceID = uuid.New().String()
		return
	}

	// Hash the ID to protect privacy.
	hash := sha256.Sum256([]byte(id))
	c.DeviceID = hex.EncodeToString(hash[:])
}

// SaveToFile saves the configuration to a file.
// It marshals the configuration to JSON with indentation and writes it to the specified path.
// The file is created with permissions 0600, which restricts access to the owner only.
// Returns an error if any step of the process fails.
func (c *Config) SaveToFile(path string) error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("write config file: %w", err)
	}

	return nil
}

// UpdateFromGRPC updates the configuration from a GRPC response.
// It populates the interface addresses, listen port, and MTU from the device config.
// It also populates the server endpoint, port, and public key from the server config.
// Returns an error if any step of the process fails.
func (c *Config) UpdateFromGRPC(resp *pb.GetConfigurationResponse) error {
	if resp.DeviceConfig != nil {
		for _, addr := range resp.DeviceConfig.Addresses {
			prefix, err := netip.ParsePrefix(addr)
			if err != nil {
				return fmt.Errorf("parse address %s: %w", addr, err)
			}
			c.Interface.Addresses = append(c.Interface.Addresses, prefix)
		}
		c.Interface.ListenPort = int(resp.DeviceConfig.ListenPort)
		c.Interface.MTU = int(resp.DeviceConfig.Mtu)
	}

	if resp.ServerConfig != nil {
		c.Server.Endpoint = resp.ServerConfig.Endpoint
		c.Server.Port = int(resp.ServerConfig.Port)
		c.Server.PublicKey = resp.ServerConfig.PublicKey
	}

	return nil
}
