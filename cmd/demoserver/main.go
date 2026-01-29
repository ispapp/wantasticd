package main

import (
	"log"
	"wantastic-agent/internal/grpc"
)

func main() {
	if err := grpc.RunDemoServer(":52990"); err != nil {
		log.Fatalf("Failed to run demo server: %v", err)
	}
}
