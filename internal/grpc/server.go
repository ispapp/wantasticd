package grpc

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"wantastic-agent/internal/certs"
	pb "wantastic-agent/internal/grpc/proto"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type DeviceFlow struct {
	DeviceCode string
	UserCode   string
	Authorized bool
	ExpiresAt  time.Time
}

type Server struct {
	pb.UnimplementedAuthServiceServer
	flows map[string]*DeviceFlow
	mu    sync.RWMutex
}

func NewServer() *Server {
	return &Server{
		flows: make(map[string]*DeviceFlow),
	}
}

func (s *Server) StartDeviceFlow(ctx context.Context, req *pb.StartDeviceFlowRequest) (*pb.StartDeviceFlowResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	userCode := fmt.Sprintf("%X-%X", time.Now().UnixNano()%0xFFFF, time.Now().UnixNano()%0x0FFF)
	deviceCode := fmt.Sprintf("dc-%d", time.Now().UnixNano())

	flow := &DeviceFlow{
		DeviceCode: deviceCode,
		UserCode:   userCode,
		ExpiresAt:  time.Now().Add(10 * time.Minute),
	}

	s.flows[deviceCode] = flow

	// For demo purposes, we automatically authorize the flow after 5 seconds
	go func() {
		time.Sleep(5 * time.Second)
		s.mu.Lock()
		flow.Authorized = true
		s.mu.Unlock()
		log.Printf("Demo: Device flow %s authorized", userCode)
	}()

	return &pb.StartDeviceFlowResponse{
		DeviceCode:      deviceCode,
		UserCode:        userCode,
		VerificationUri: "http://localhost:52990/auth",
		ExpiresIn:       600,
		Interval:        2,
	}, nil
}

func (s *Server) PollDeviceFlow(ctx context.Context, req *pb.PollDeviceFlowRequest) (*pb.PollDeviceFlowResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	flow, ok := s.flows[req.DeviceCode]
	if !ok {
		return nil, status.Error(codes.NotFound, "flow not found")
	}

	if time.Now().After(flow.ExpiresAt) {
		return nil, status.Error(codes.DeadlineExceeded, "flow expired")
	}

	return &pb.PollDeviceFlowResponse{
		Success: flow.Authorized,
	}, nil
}

func (s *Server) RegisterDevice(ctx context.Context, req *pb.RegisterDeviceRequest) (*pb.RegisterDeviceResponse, error) {
	// Mock implementation returning some dummy data
	return &pb.RegisterDeviceResponse{
		Success: true,
		Token:   "demo-token-" + req.Hostname,
	}, nil
}

func (s *Server) GetConfiguration(ctx context.Context, req *pb.GetConfigurationRequest) (*pb.GetConfigurationResponse, error) {
	// Return a demo configuration
	return &pb.GetConfigurationResponse{
		DeviceConfig: &pb.DeviceConfiguration{
			Addresses:  []string{"10.8.0.2/24"},
			ListenPort: 51820,
			Mtu:        1420,
		},
		ServerConfig: &pb.ServerConfiguration{
			Endpoint:  "wg.wantastic.com",
			Port:      51820,
			PublicKey: "demo-server-public-key",
		},
	}, nil
}

func RunDemoServer(addr string) error {
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	creds, err := certs.LoadServerTLSCredentials()
	if err != nil {
		return fmt.Errorf("load tls credentials: %w", err)
	}

	s := grpc.NewServer(grpc.Creds(creds))
	pb.RegisterAuthServiceServer(s, NewServer())

	log.Printf("Demo Auth Server (TLS) listening on %s", addr)
	return s.Serve(lis)
}
