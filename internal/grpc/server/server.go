package server

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	grpc "wantastic-agent/internal/grpc/proto"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// DemoServer implements the AuthService for testing and demo purposes
type DemoServer struct {
	grpc.UnimplementedAuthServiceServer

	// In-memory storage for demo purposes
	devices     map[string]*grpc.RegisterDeviceResponse
	tokens      map[string]string // token -> device_id
	deviceFlows map[string]*deviceFlowState
	mu          sync.RWMutex
}

// deviceFlowState tracks the state of device authorization flows
type deviceFlowState struct {
	deviceID     string
	userCode     string
	deviceCode   string
	created      time.Time
	expires      time.Time
	approved     bool
	pollInterval time.Duration
}

// NewDemoServer creates a new demo gRPC server instance
func NewDemoServer() *DemoServer {
	return &DemoServer{
		devices:     make(map[string]*grpc.RegisterDeviceResponse),
		tokens:      make(map[string]string),
		deviceFlows: make(map[string]*deviceFlowState),
	}
}

// RegisterDevice implements the device registration endpoint
func (s *DemoServer) RegisterDevice(ctx context.Context, req *grpc.RegisterDeviceRequest) (*grpc.RegisterDeviceResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check if device already exists
	if existing, exists := s.devices[req.DeviceId]; exists {
		return existing, nil
	}

	// Create mock response
	response := &grpc.RegisterDeviceResponse{
		Success:             true,
		Token:               fmt.Sprintf("demo-token-%s", req.DeviceId),
		ServerKey:           "demo-server-public-key",
		Endpoint:            "demo.wantastic.com:51820",
		AllowedIps:          []string{"0.0.0.0/0", "::/0"},
		PersistentKeepalive: 25,
		DnsServers:          []string{"1.1.1.1", "8.8.8.8"},
		ForwardingRules:     []string{},
		Routes:              []string{"10.0.0.0/8", "192.168.0.0/16"},
		Mtu:                 1420,
		ListenPort:          51820,
	}

	// Store device and token
	s.devices[req.DeviceId] = response
	s.tokens[response.Token] = req.DeviceId

	log.Printf("Registered device %s", req.DeviceId)
	return response, nil
}

// RefreshToken implements the token refresh endpoint
func (s *DemoServer) RefreshToken(ctx context.Context, req *grpc.RefreshTokenRequest) (*grpc.RefreshTokenResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Check if token exists and get device ID
	deviceID, exists := s.tokens[req.Token]
	if !exists {
		return nil, status.Errorf(codes.Unauthenticated, "Invalid token")
	}

	// Verify device exists
	if _, exists := s.devices[deviceID]; !exists {
		return nil, status.Errorf(codes.NotFound, "Device not found")
	}

	// For demo purposes, return the same token
	response := &grpc.RefreshTokenResponse{
		Success: true,
		Token:   req.Token,
	}

	log.Printf("Refreshed token for device %s", deviceID)
	return response, nil
}

// GetConfiguration implements the configuration retrieval endpoint
func (s *DemoServer) GetConfiguration(ctx context.Context, req *grpc.GetConfigurationRequest) (*grpc.GetConfigurationResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Verify token
	if _, exists := s.tokens[req.Token]; !exists {
		return nil, status.Error(codes.Unauthenticated, "invalid token")
	}

	// Create mock configuration
	response := &grpc.GetConfigurationResponse{
		DeviceConfig: &grpc.DeviceConfiguration{
			Addresses:  []string{"10.8.0.2/24", "fd42:42:42::2/64"},
			ListenPort: 51820,
			Mtu:        1420,
			Dns:        []string{"1.1.1.1", "8.8.8.8"},
		},
		ServerConfig: &grpc.ServerConfiguration{
			Endpoint:            "demo.wantastic.com",
			Port:                51820,
			PublicKey:           "demo-server-public-key",
			AllowedIps:          []string{"0.0.0.0/0", "::/0"},
			PersistentKeepalive: 25,
		},
		NetworkConfig: &grpc.NetworkConfiguration{
			Routes:          []string{"10.0.0.0/8", "192.168.0.0/16"},
			ForwardingRules: []string{},
			FirewallRules:   []string{},
		},
		ExitNodeConfig: &grpc.ExitNodeConfiguration{
			Enabled:    false,
			ExitRoutes: []string{},
			ExitDns:    []string{},
			AllowLan:   false,
		},
		UpdateUrl: "https://demo.wantastic.com/update",
	}

	log.Printf("Returning configuration for device %s", req.DeviceId)
	return response, nil
}

// StartDeviceFlow implements the device flow initiation endpoint
func (s *DemoServer) StartDeviceFlow(ctx context.Context, req *grpc.StartDeviceFlowRequest) (*grpc.StartDeviceFlowResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Generate device and user codes
	deviceCode := fmt.Sprintf("device_%s_%d", req.DeviceId, time.Now().Unix())
	userCode := fmt.Sprintf("%04d-%04d", time.Now().Unix()%10000, time.Now().UnixNano()%10000)

	// Create device flow state
	flow := &deviceFlowState{
		deviceID: req.DeviceId,
		userCode: userCode,
		approved: false,
		created:  time.Now(),
	}

	// Store device flow
	s.deviceFlows[deviceCode] = flow

	response := &grpc.StartDeviceFlowResponse{
		DeviceCode:      deviceCode,
		UserCode:        userCode,
		VerificationUri: "https://demo.wantastic.com/device",
		ExpiresIn:       600,
		Interval:        5,
	}

	log.Printf("Started device flow: device_code=%s, user_code=%s, verification_uri=%s",
		response.DeviceCode, response.UserCode, response.VerificationUri)

	return response, nil
}

// PollDeviceFlow implements the device flow polling endpoint
func (s *DemoServer) PollDeviceFlow(ctx context.Context, req *grpc.PollDeviceFlowRequest) (*grpc.PollDeviceFlowResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	flow, exists := s.deviceFlows[req.DeviceCode]
	if !exists {
		return nil, status.Error(codes.NotFound, "device flow not found")
	}

	// Check if expired
	if time.Now().After(flow.expires) {
		delete(s.deviceFlows, req.DeviceCode)
		return nil, status.Error(codes.DeadlineExceeded, "device flow expired")
	}

	// For demo purposes, auto-approve after 10 seconds
	if time.Since(flow.created) > 10*time.Second && !flow.approved {
		flow.approved = true
		log.Printf("Auto-approved device flow for device %s", flow.deviceID)
	}

	response := &grpc.PollDeviceFlowResponse{
		Success: flow.approved,
	}

	// Clean up if approved or expired
	if flow.approved {
		delete(s.deviceFlows, req.DeviceCode)
	}

	return response, nil
}

// GetService returns the gRPC service implementation
func (s *DemoServer) GetService() grpc.AuthServiceServer {
	return s
}
