package grpc

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

type Client struct {
	serverURL string
	deviceID  string
	token     string

	conn   *grpc.ClientConn
	client AuthServiceClient

	mu        sync.RWMutex
	connected bool
}

type AuthServiceClient interface {
	RegisterDevice(ctx context.Context, in *RegisterDeviceRequest, opts ...grpc.CallOption) (*RegisterDeviceResponse, error)
	RefreshToken(ctx context.Context, in *RefreshTokenRequest, opts ...grpc.CallOption) (*RefreshTokenResponse, error)
	GetConfiguration(ctx context.Context, in *GetConfigurationRequest, opts ...grpc.CallOption) (*GetConfigurationResponse, error)
	StartDeviceFlow(ctx context.Context, in *StartDeviceFlowRequest, opts ...grpc.CallOption) (*StartDeviceFlowResponse, error)
	PollDeviceFlow(ctx context.Context, in *PollDeviceFlowRequest, opts ...grpc.CallOption) (*PollDeviceFlowResponse, error)
}

type authServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewAuthServiceClient(cc grpc.ClientConnInterface) AuthServiceClient {
	return &authServiceClient{cc}
}

func (c *authServiceClient) RegisterDevice(ctx context.Context, in *RegisterDeviceRequest, opts ...grpc.CallOption) (*RegisterDeviceResponse, error) {
	out := new(RegisterDeviceResponse)
	err := c.cc.Invoke(ctx, "/grpc.AuthService/RegisterDevice", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *authServiceClient) RefreshToken(ctx context.Context, in *RefreshTokenRequest, opts ...grpc.CallOption) (*RefreshTokenResponse, error) {
	out := new(RefreshTokenResponse)
	err := c.cc.Invoke(ctx, "/grpc.AuthService/RefreshToken", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *authServiceClient) GetConfiguration(ctx context.Context, in *GetConfigurationRequest, opts ...grpc.CallOption) (*GetConfigurationResponse, error) {
	out := new(GetConfigurationResponse)
	err := c.cc.Invoke(ctx, "/grpc.AuthService/GetConfiguration", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *authServiceClient) StartDeviceFlow(ctx context.Context, in *StartDeviceFlowRequest, opts ...grpc.CallOption) (*StartDeviceFlowResponse, error) {
	out := new(StartDeviceFlowResponse)
	err := c.cc.Invoke(ctx, "/grpc.AuthService/StartDeviceFlow", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *authServiceClient) PollDeviceFlow(ctx context.Context, in *PollDeviceFlowRequest, opts ...grpc.CallOption) (*PollDeviceFlowResponse, error) {
	out := new(PollDeviceFlowResponse)
	err := c.cc.Invoke(ctx, "/grpc.AuthService/PollDeviceFlow", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

type StartDeviceFlowRequest struct {
	DeviceID string `protobuf:"bytes,1,opt,name=device_id,json=deviceId,proto3" json:"device_id,omitempty"`
}

type StartDeviceFlowResponse struct {
	DeviceCode      string `protobuf:"bytes,1,opt,name=device_code,json=deviceCode,proto3" json:"device_code,omitempty"`
	UserCode        string `protobuf:"bytes,2,opt,name=user_code,json=userCode,proto3" json:"user_code,omitempty"`
	VerificationURI string `protobuf:"bytes,3,opt,name=verification_uri,json=verificationUri,proto3" json:"verification_uri,omitempty"`
	ExpiresIn       int32  `protobuf:"varint,4,opt,name=expires_in,json=expiresIn,proto3" json:"expires_in,omitempty"`
	Interval        int32  `protobuf:"varint,5,opt,name=interval,proto3" json:"interval,omitempty"`
}

type PollDeviceFlowRequest struct {
	DeviceCode string `protobuf:"bytes,1,opt,name=device_code,json=deviceCode,proto3" json:"device_code,omitempty"`
}

type PollDeviceFlowResponse struct {
	Success bool `protobuf:"varint,1,opt,name=success,proto3" json:"success,omitempty"`
}

type RegisterDeviceRequest struct {
	DeviceID  string `protobuf:"bytes,1,opt,name=device_id,json=deviceId,proto3" json:"device_id,omitempty"`
	PublicKey string `protobuf:"bytes,2,opt,name=public_key,json=publicKey,proto3" json:"public_key,omitempty"`
	TenantID  string `protobuf:"bytes,3,opt,name=tenant_id,json=tenantId,proto3" json:"tenant_id,omitempty"`
}

type RegisterDeviceResponse struct {
	Success             bool     `protobuf:"varint,1,opt,name=success,proto3" json:"success,omitempty"`
	Token               string   `protobuf:"bytes,2,opt,name=token,proto3" json:"token,omitempty"`
	ServerKey           string   `protobuf:"bytes,3,opt,name=server_key,json=serverKey,proto3" json:"server_key,omitempty"`
	Endpoint            string   `protobuf:"bytes,4,opt,name=endpoint,proto3" json:"endpoint,omitempty"`
	AllowedIPs          []string `protobuf:"bytes,5,rep,name=allowed_ips,json=allowedIps,proto3" json:"allowed_ips,omitempty"`
	PersistentKeepalive int32    `protobuf:"varint,6,opt,name=persistent_keepalive,json=persistentKeepalive,proto3" json:"persistent_keepalive,omitempty"`
	DNSServers          []string `protobuf:"bytes,7,rep,name=dns_servers,json=dnsServers,proto3" json:"dns_servers,omitempty"`
	ForwardingRules     []string `protobuf:"bytes,8,rep,name=forwarding_rules,json=forwardingRules,proto3" json:"forwarding_rules,omitempty"`
	Routes              []string `protobuf:"bytes,9,rep,name=routes,proto3" json:"routes,omitempty"`
	MTU                 int32    `protobuf:"varint,10,opt,name=mtu,proto3" json:"mtu,omitempty"`
	ListenPort          int32    `protobuf:"varint,11,opt,name=listen_port,json=listenPort,proto3" json:"listen_port,omitempty"`
}

type RefreshTokenRequest struct {
	DeviceID string `protobuf:"bytes,1,opt,name=device_id,json=deviceId,proto3" json:"device_id,omitempty"`
	Token    string `protobuf:"bytes,2,opt,name=token,proto3" json:"token,omitempty"`
}

type RefreshTokenResponse struct {
	Success bool   `protobuf:"varint,1,opt,name=success,proto3" json:"success,omitempty"`
	Token   string `protobuf:"bytes,2,opt,name=token,proto3" json:"token,omitempty"`
}

type GetConfigurationRequest struct {
	DeviceID string `protobuf:"bytes,1,opt,name=device_id,json=deviceId,proto3" json:"device_id,omitempty"`
	Token    string `protobuf:"bytes,2,opt,name=token,proto3" json:"token,omitempty"`
}

type GetConfigurationResponse struct {
	DeviceConfig    *DeviceConfiguration   `protobuf:"bytes,1,opt,name=device_config,json=deviceConfig,proto3" json:"device_config,omitempty"`
	ServerConfig    *ServerConfiguration   `protobuf:"bytes,2,opt,name=server_config,json=serverConfig,proto3" json:"server_config,omitempty"`
	NetworkConfig   *NetworkConfiguration  `protobuf:"bytes,3,opt,name=network_config,json=networkConfig,proto3" json:"network_config,omitempty"`
	ExitNodeConfig  *ExitNodeConfiguration `protobuf:"bytes,4,opt,name=exit_node_config,json=exitNodeConfig,proto3" json:"exit_node_config,omitempty"`
	UpdateAvailable bool                   `protobuf:"varint,5,opt,name=update_available,json=updateAvailable,proto3" json:"update_available,omitempty"`
	UpdateVersion   string                 `protobuf:"bytes,6,opt,name=update_version,json=updateVersion,proto3" json:"update_version,omitempty"`
	UpdateURL       string                 `protobuf:"bytes,7,opt,name=update_url,json=updateUrl,proto3" json:"update_url,omitempty"`
}

type DeviceConfiguration struct {
	Addresses  []string `protobuf:"bytes,1,rep,name=addresses,proto3" json:"addresses,omitempty"`
	ListenPort int32    `protobuf:"varint,2,opt,name=listen_port,json=listenPort,proto3" json:"listen_port,omitempty"`
	MTU        int32    `protobuf:"varint,3,opt,name=mtu,proto3" json:"mtu,omitempty"`
	DNS        []string `protobuf:"bytes,4,rep,name=dns,proto3" json:"dns,omitempty"`
}

type ServerConfiguration struct {
	Endpoint            string   `protobuf:"bytes,1,opt,name=endpoint,proto3" json:"endpoint,omitempty"`
	Port                int32    `protobuf:"varint,2,opt,name=port,proto3" json:"port,omitempty"`
	PublicKey           string   `protobuf:"bytes,3,opt,name=public_key,json=publicKey,proto3" json:"public_key,omitempty"`
	AllowedIPs          []string `protobuf:"bytes,4,rep,name=allowed_ips,json=allowedIps,proto3" json:"allowed_ips,omitempty"`
	PersistentKeepalive int32    `protobuf:"varint,5,opt,name=persistent_keepalive,json=persistentKeepalive,proto3" json:"persistent_keepalive,omitempty"`
}

type NetworkConfiguration struct {
	Routes          []string `protobuf:"bytes,1,rep,name=routes,proto3" json:"routes,omitempty"`
	ForwardingRules []string `protobuf:"bytes,2,rep,name=forwarding_rules,json=forwardingRules,proto3" json:"forwarding_rules,omitempty"`
	FirewallRules   []string `protobuf:"bytes,3,rep,name=firewall_rules,json=firewallRules,proto3" json:"firewall_rules,omitempty"`
}

type ExitNodeConfiguration struct {
	Enabled    bool     `protobuf:"varint,1,opt,name=enabled,proto3" json:"enabled,omitempty"`
	ExitRoutes []string `protobuf:"bytes,2,rep,name=exit_routes,json=exitRoutes,proto3" json:"exit_routes,omitempty"`
	ExitDNS    []string `protobuf:"bytes,3,rep,name=exit_dns,json=exitDns,proto3" json:"exit_dns,omitempty"`
	AllowLAN   bool     `protobuf:"varint,4,opt,name=allow_lan,json=allowLan,proto3" json:"allow_lan,omitempty"`
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

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := grpc.DialContext(ctx, c.serverURL,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock())
	if err != nil {
		return fmt.Errorf("dial auth server: %w", err)
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	c.conn = conn
	c.client = NewAuthServiceClient(conn)
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

func (c *Client) RegisterDevice(ctx context.Context, publicKey string) (*RegisterDeviceResponse, error) {
	c.mu.RLock()
	if !c.connected {
		c.mu.RUnlock()
		return nil, fmt.Errorf("not connected to auth server")
	}
	c.mu.RUnlock()

	req := &RegisterDeviceRequest{
		DeviceID:  c.deviceID,
		PublicKey: publicKey,
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

	req := &RefreshTokenRequest{
		DeviceID: c.deviceID,
		Token:    token,
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

func (c *Client) GetConfiguration(ctx context.Context) (*GetConfigurationResponse, error) {
	c.mu.RLock()
	token := c.token
	c.mu.RUnlock()

	req := &GetConfigurationRequest{
		DeviceID: c.deviceID,
		Token:    token,
	}

	md := metadata.Pairs("authorization", fmt.Sprintf("Bearer %s", token))
	ctx = metadata.NewOutgoingContext(ctx, md)

	resp, err := c.client.GetConfiguration(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("get configuration: %w", err)
	}

	return resp, nil
}

func (c *Client) StartDeviceFlow(ctx context.Context) (*GetConfigurationResponse, error) {
	c.mu.RLock()
	if !c.connected {
		c.mu.RUnlock()
		return nil, fmt.Errorf("not connected to auth server")
	}
	c.mu.RUnlock()

	req := &StartDeviceFlowRequest{
		DeviceID: c.deviceID,
	}

	resp, err := c.client.StartDeviceFlow(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("start device flow: %w", err)
	}

	fmt.Printf("Please go to %s and enter the code: %s\n", resp.VerificationURI, resp.UserCode)

	ticker := time.NewTicker(time.Duration(resp.Interval) * time.Second)
	defer ticker.Stop()

	timeout := time.After(time.Duration(resp.ExpiresIn) * time.Second)

	for {
		select {
		case <-ticker.C:
			pollReq := &PollDeviceFlowRequest{
				DeviceCode: resp.DeviceCode,
			}
			pollResp, err := c.client.PollDeviceFlow(ctx, pollReq)
			if err != nil {
				// TODO: Handle transient errors
				continue
			}
			if pollResp.Success {
				return c.GetConfiguration(ctx)
			}
		case <-timeout:
			return nil, fmt.Errorf("device flow timed out")
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}
