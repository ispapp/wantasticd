package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	grpcproto "wantastic-agent/internal/grpc/proto"
	"wantastic-agent/internal/grpc/server"

	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

func main() {
	// Default to port 50051 if no port is specified
	port := "50051"
	if len(os.Args) > 1 {
		port = os.Args[1]
	}

	// Create demo server
	demoServer := server.NewDemoServer()

	// Create gRPC server
	grpcServer := grpc.NewServer()

	// Register the demo server using the generated registration function
	grpcproto.RegisterAuthServiceServer(grpcServer, demoServer)

	// Enable reflection for testing with tools like grpcurl
	reflection.Register(grpcServer)

	// Start listening
	lis, err := net.Listen("tcp", fmt.Sprintf(":%s", port))
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}

	log.Printf("Demo gRPC server starting on port %s", port)
	log.Printf("Server is ready for testing - no online authentication required")
	log.Printf("Use CTRL+C to stop the server")

	// Start server in a goroutine
	go func() {
		if err := grpcServer.Serve(lis); err != nil {
			log.Fatalf("Failed to serve: %v", err)
		}
	}()

	// Wait for interrupt signal to gracefully shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Printf("Shutting down demo server...")

	// Graceful shutdown
	grpcServer.GracefulStop()
	log.Printf("Demo server stopped")
}
