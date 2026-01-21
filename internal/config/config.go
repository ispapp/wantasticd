package config

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/netip"
	"os"
	"time"
	"wantastic-agent/internal/grpc"

	"github.com/denisbrodbeck/machineid"
	"github.com/google/uuid"
)

type Config struct {
	DeviceID   string    `json:"device_id"`
	TenantID   string    `json:"tenant_id"`
	PrivateKey string    `json:"private_key"`
	PublicKey  string    `json:"public_key"`
	Server     Server    `json:"server"`
	Interface  Interface `json:"interface"`
	ExitNode   ExitNode  `json:"exit_node"`
	Auth       Auth      `json:"auth"`
}

type Server struct {
	Endpoint  string `json:"endpoint"`
	Port      int    `json:"port"`
	PublicKey string `json:"public_key"`
}

type Interface struct {
	Addresses  []netip.Prefix `json:"addresses"`
	ListenPort int            `json:"listen_port"`
	MTU        int            `json:"mtu"`
}

type ExitNode struct {
	Enabled  bool     `json:"enabled"`
	Routes   []string `json:"routes"`
	DNS      []string `json:"dns"`
	AllowLAN bool     `json:"allow_lan"`
}

type Auth struct {
	ServerURL   string        `json:"server_url"`
	Token       string        `json:"token"`
	RefreshTime time.Duration `json:"refresh_time"`
}

func LoadFromFile(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config file: %w", err)
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("validate config: %w", err)
	}

	return &cfg, nil
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

	cfg := &Config{}
	if err := cfg.UpdateFromGRPC(resp); err != nil {
		return nil, fmt.Errorf("update config from grpc: %w", err)
	}

	return cfg, nil
}

func LoadFromToken(ctx context.Context, token string) (*Config, error) {
	return nil, fmt.Errorf("token loading not implemented yet")
}

func (c *Config) Validate() error {
	if c.PrivateKey == "" {
		return fmt.Errorf("private key required")
	}
	if c.Server.Endpoint == "" {
		return fmt.Errorf("server endpoint required")
	}
	if c.Server.Port == 0 {
		c.Server.Port = 51820
	}
	if c.Interface.MTU == 0 {
		c.Interface.MTU = 1420
	}
	if c.Interface.ListenPort == 0 {
		c.Interface.ListenPort = 51820
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

func (c *Config) UpdateFromGRPC(resp *grpc.GetConfigurationResponse) error {
	if resp.DeviceConfig != nil {
		for _, addr := range resp.DeviceConfig.Addresses {
			prefix, err := netip.ParsePrefix(addr)
			if err != nil {
				return fmt.Errorf("parse address %s: %w", addr, err)
			}
			c.Interface.Addresses = append(c.Interface.Addresses, prefix)
		}
		c.Interface.ListenPort = int(resp.DeviceConfig.ListenPort)
		c.Interface.MTU = int(resp.DeviceConfig.MTU)
		c.ExitNode.DNS = resp.DeviceConfig.DNS
	}

	if resp.ServerConfig != nil {
		c.Server.Endpoint = resp.ServerConfig.Endpoint
		c.Server.Port = int(resp.ServerConfig.Port)
		c.Server.PublicKey = resp.ServerConfig.PublicKey
	}

	if resp.NetworkConfig != nil {
		c.ExitNode.Routes = resp.NetworkConfig.Routes
	}

	if resp.ExitNodeConfig != nil {
		c.ExitNode.Enabled = resp.ExitNodeConfig.Enabled
		c.ExitNode.Routes = append(c.ExitNode.Routes, resp.ExitNodeConfig.ExitRoutes...)
		c.ExitNode.DNS = append(c.ExitNode.DNS, resp.ExitNodeConfig.ExitDNS...)
		c.ExitNode.AllowLAN = resp.ExitNodeConfig.AllowLAN
	}

	return nil
}
