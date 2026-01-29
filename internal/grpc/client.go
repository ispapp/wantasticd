package grpc

import (
	"context"
	"fmt"
	"log"
	"os"
	"runtime"
	"sync"
	"time"
	"wantastic-agent/internal/certs"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	pb "wantastic-agent/internal/grpc/proto"
)

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

	// Load mTLS credentials
	creds, err := certs.LoadClientTLSCredentials()
	if err != nil {
		return fmt.Errorf("load tls credentials: %w", err)
	}

	conn, err := grpc.NewClient(c.serverURL,
		grpc.WithTransportCredentials(creds))
	if err != nil {
		return fmt.Errorf("dial auth server: %w", err)
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	c.conn = conn
	c.client = pb.NewAuthServiceClient(conn)
	c.connected = true

	log.Printf("Connected to auth server: %s", c.serverURL)
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
