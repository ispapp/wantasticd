package grpc

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"runtime"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"

	"wantastic-agent/internal/cipher"
	pb "wantastic-agent/internal/grpc/proto"
)

// resolveServerURL resolves the hostname in a server URL (host:port) to an IP address
// using Cloudflare DNS (1.1.1.1:53). This is necessary because grpc.NewClient's
// internal DNS resolver can fail on minimal Linux environments (e.g. Alpine/musl)
// where /etc/resolv.conf may be missing or misconfigured.
func resolveServerURL(serverURL string) (string, error) {
	host, port, err := net.SplitHostPort(serverURL)
	if err != nil {
		// No port — treat entire string as host
		host = serverURL
		port = ""
	}

	// If it's already an IP, return as-is
	if ip := net.ParseIP(host); ip != nil {
		return serverURL, nil
	}

	// Use Cloudflare DNS to resolve the hostname
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: 5 * time.Second}
			return d.DialContext(ctx, "udp", "1.1.1.1:53")
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	ips, err := resolver.LookupIPAddr(ctx, host)
	if err != nil {
		return "", fmt.Errorf("resolve auth server %s via Cloudflare DNS: %w", host, err)
	}

	if len(ips) == 0 {
		return "", fmt.Errorf("no IP addresses found for auth server %s", host)
	}

	// Prefer IPv4
	resolved := ips[0].IP.String()
	for _, ip := range ips {
		if ip.IP.To4() != nil {
			resolved = ip.IP.String()
			break
		}
	}

	if port != "" {
		return net.JoinHostPort(resolved, port), nil
	}
	return resolved, nil
}

type Client struct {
	serverURL string
	deviceID  string
	token     string

	conn   *grpc.ClientConn
	client pb.AuthServiceClient

	mu        sync.RWMutex
	connected bool
}

func New(serverURL, deviceID, token string) (*Client, error) {
	client := &Client{
		serverURL: serverURL,
		deviceID:  deviceID,
		token:     token,
	}

	if err := client.connect(); err != nil {
		return nil, fmt.Errorf("connect to auth server: %w", err)
	}

	return client, nil
}

func (c *Client) connect() error {
	c.mu.Lock()

	if c.connected {
		c.mu.Unlock()
		return nil
	}
	c.mu.Unlock()

	// Resolve hostname to IP using Cloudflare DNS (1.1.1.1)
	// This ensures DNS works on minimal Alpine/musl systems where
	// grpc.NewClient's internal DNS resolver may fail.
	serverAddr, err := resolveServerURL(c.serverURL)
	if err != nil {
		return fmt.Errorf("resolve server URL: %w", err)
	}

	if serverAddr != c.serverURL {
		// Extract just the hostname for logging
		origHost := c.serverURL
		if h, _, splitErr := net.SplitHostPort(c.serverURL); splitErr == nil {
			origHost = h
		}
		resolvedHost := serverAddr
		if h, _, splitErr := net.SplitHostPort(serverAddr); splitErr == nil {
			resolvedHost = h
		}
		log.Printf("Resolved %s -> %s", origHost, resolvedHost)
	}

	// Use insecure credentials for transport (plaintext)
	// We rely on "cipher" credentials for per-RPC auth/security if needed.
	transportCreds := insecure.NewCredentials()

	// Add Cipher Credentials (HMAC Signature)
	cipherCreds := cipher.NewCredentials()

	conn, err := grpc.NewClient(serverAddr,
		grpc.WithTransportCredentials(transportCreds),
		grpc.WithPerRPCCredentials(cipherCreds),
	)
	if err != nil {
		return fmt.Errorf("dial auth server: %w", err)
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	c.conn = conn
	c.client = pb.NewAuthServiceClient(conn)
	c.connected = true

	log.Printf("Connected to auth server: %s", serverAddr)
	return nil
}

func (c *Client) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn != nil {
		c.conn.Close()
		c.connected = false
	}
}

func (c *Client) RegisterDevice(ctx context.Context, nonce int64, osInfo, arch, hostname string) (*pb.RegisterDeviceResponse, error) {
	c.mu.RLock()
	// Connection check removed as we might be connecting for the first time with a token
	if c.client == nil {
		c.mu.RUnlock()
		return nil, fmt.Errorf("client not initialized")
	}
	token := c.token
	c.mu.RUnlock()

	req := &pb.RegisterDeviceRequest{
		Token:    token,
		Nonce:    nonce,
		Os:       osInfo,
		Arch:     arch,
		Hostname: hostname,
	}

	md := metadata.Pairs("authorization", fmt.Sprintf("Bearer %s", c.token))
	ctx = metadata.NewOutgoingContext(ctx, md)

	resp, err := c.client.RegisterDevice(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("register device: %w", err)
	}

	if resp.Success {
		c.mu.Lock()
		c.token = resp.Token
		c.mu.Unlock()
	}

	return resp, nil
}

func (c *Client) RefreshAuth(ctx context.Context) error {
	c.mu.RLock()
	token := c.token
	c.mu.RUnlock()

	req := &pb.RefreshTokenRequest{
		Token: token,
	}

	md := metadata.Pairs("authorization", fmt.Sprintf("Bearer %s", token))
	ctx = metadata.NewOutgoingContext(ctx, md)

	resp, err := c.client.RefreshToken(ctx, req)
	if err != nil {
		return fmt.Errorf("refresh token: %w", err)
	}

	if resp.Success {
		c.mu.Lock()
		c.token = resp.Token
		c.mu.Unlock()
		log.Println("Token refreshed successfully")
	}

	return nil
}

func (c *Client) GetConfiguration(ctx context.Context) (*pb.GetConfigurationResponse, error) {
	c.mu.RLock()
	token := c.token
	c.mu.RUnlock()

	req := &pb.GetConfigurationRequest{
		Token: token,
	}

	md := metadata.Pairs("authorization", fmt.Sprintf("Bearer %s", token))
	ctx = metadata.NewOutgoingContext(ctx, md)

	resp, err := c.client.GetConfiguration(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("get configuration: %w", err)
	}

	return resp, nil
}

func (c *Client) StartDeviceFlow(ctx context.Context) (*pb.RegisterDeviceResponse, error) {
	c.mu.RLock()
	client := c.client
	c.mu.RUnlock()

	if client == nil {
		return nil, fmt.Errorf("not connected to auth server")
	}

	req := &pb.StartDeviceFlowRequest{
		DeviceId: c.deviceID,
	}

	resp, err := client.StartDeviceFlow(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("start device flow: %w", err)
	}

	fmt.Printf("\n🚀 Device Authorization Required\n")
	fmt.Printf("-------------------------------\n")
	fmt.Printf("1. Open: %s\n", resp.VerificationUri)
	fmt.Printf("2. Enter Code: %s\n\n", resp.UserCode)
	log.Println("Waiting for authorization...")

	ticker := time.NewTicker(time.Duration(resp.Interval) * time.Second)
	defer ticker.Stop()

	timeout := time.After(time.Duration(resp.ExpiresIn) * time.Second)

	for {
		select {
		case <-ticker.C:
			pollReq := &pb.PollDeviceFlowRequest{
				DeviceCode: resp.DeviceCode,
			}
			pollResp, err := client.PollDeviceFlow(ctx, pollReq)
			if err != nil {
				continue
			}
			if pollResp.Success {
				c.mu.Lock()
				c.token = pollResp.Token
				c.mu.Unlock()

				log.Println("✅ Authorization successful! Registering device...")

				// Gather system information for registration
				hostname, _ := os.Hostname()
				return c.RegisterDevice(ctx, time.Now().UnixNano(), runtime.GOOS, runtime.GOARCH, hostname)
			}
		case <-timeout:
			return nil, fmt.Errorf("device flow timed out")
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}
