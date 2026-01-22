package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"wantastic-agent/internal/update"

	"wantastic-agent/internal/agent"
	"wantastic-agent/internal/config"
)

var (
	version = "1.0.0" // Build-time version injection
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "login":
		handleLogin()
	case "connect":
		handleConnect()
	case "version":
		printVersion()
	default:
		printUsage()
		os.Exit(1)
	}
}

func handleLogin() {
	loginCmd := flag.NewFlagSet("login", flag.ExitOnError)
	token := loginCmd.String("token", "", "Direct authentication token")
	serverURL := loginCmd.String("server-url", "auth.wantastic.com:443", "Authentication server URL")
	loginCmd.Parse(os.Args[2:])

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var cfg *config.Config
	var err error

	if *token != "" {
		cfg, err = config.LoadFromToken(ctx, *token)
	} else {
		cfg, err = config.LoadFromDeviceFlow(ctx, *serverURL)
	}

	if err != nil {
		log.Fatalf("Failed to configure agent: %v", err)
	}

	configPath := "wantasticd.json"
	if err := cfg.SaveToFile(configPath); err != nil {
		log.Printf("Warning: could not save configuration file: %v", err)
		log.Println("Running with in-memory configuration only.")
		runAgentWithConfig(cfg)
	} else {
		log.Println("Login successful. Configuration saved to", configPath)
		log.Println("Connecting...")
		runAgent(configPath, false)
	}
}

func runAgentWithConfig(cfg *config.Config) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	agt, err := agent.New(cfg)
	if err != nil {
		log.Fatalf("Failed to create agent: %v", err)
	}

	if err := agt.Start(ctx); err != nil {
		log.Fatalf("Failed to start agent: %v", err)
	}

	log.Printf("Wantastic agent started successfully")

	select {
	case <-sigCh:
		log.Println("Received shutdown signal")
	case <-ctx.Done():
		log.Println("Context cancelled")
	}

	if err := agt.Stop(); err != nil {
		log.Fatalf("Failed to stop agent: %v", err)
	}

	log.Println("Agent stopped successfully")
}

func handleConnect() {
	connectCmd := flag.NewFlagSet("connect", flag.ExitOnError)
	configPath := connectCmd.String("config", "", "Path to configuration file")
	verbose := connectCmd.Bool("v", false, "Enable verbose logging and debug output")
	connectCmd.Parse(os.Args[2:])

	if *configPath == "" {
		fmt.Fprintf(os.Stderr, "Usage: %s connect -config <path>\n", os.Args[0])
		connectCmd.PrintDefaults()
		os.Exit(1)
	}

	runAgent(*configPath, *verbose)
}

func runAgent(configPath string, verbose bool) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	cfg, err := config.LoadFromFile(configPath)
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	if verbose {
		cfg.Verbose = true
	}

	agt, err := agent.New(cfg)
	if err != nil {
		log.Fatalf("Failed to create agent: %v", err)
	}

	if err := agt.Start(ctx); err != nil {
		log.Fatalf("Failed to start agent: %v", err)
	}

	log.Printf("Wantastic agent started successfully")

	select {
	case <-sigCh:
		log.Println("Received shutdown signal")
	case <-ctx.Done():
		log.Println("Context cancelled")
	}

	if err := agt.Stop(); err != nil {
		log.Fatalf("Failed to stop agent: %v", err)
	}

	log.Println("Agent stopped successfully")
}

func printVersion() {
	fmt.Printf("Wantastic Agent %s\n", version)
	fmt.Printf("Platform: %s\n", update.GetPlatform())
}

func printUsage() {
	fmt.Fprintf(os.Stderr, "Usage: %s <command> [arguments]\n", os.Args[0])
	fmt.Fprintln(os.Stderr, "\nAvailable commands:")
	fmt.Fprintln(os.Stderr, "  login      Authenticate and configure the agent")
	fmt.Fprintln(os.Stderr, "  connect    Connect the agent using a configuration file")
	fmt.Fprintln(os.Stderr, "  version    Show version information")
}
