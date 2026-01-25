package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
	"wantastic-agent/internal/ipc"
	"wantastic-agent/internal/netagent/curl"
	"wantastic-agent/internal/netagent/ping"
	"wantastic-agent/internal/netagent/scanner"
	"wantastic-agent/internal/netagent/ssh"
	"wantastic-agent/internal/netagent/telnet"
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
	case "update":
		handleUpdate()
	case "peers":
		handlePeers()
	case "version":
		printVersion()
	case "ping":
		handlePing()
	case "curl":
		handleCurl()
	case "ssh":
		handleSSH()
	case "telnet":
		handleTelnet()
	case "bind":
		handleBind()
	case "neighbors":
		handleNeighbors()
	case "proxy":
		handleProxy()
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
	log.Println("Mode: Userspace Netstack (Passthrough active for common ports)")

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
	fmt.Printf("%s\n", version)
}

func handleUpdate() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	mgr := update.NewManager(version)
	latest, err := mgr.FetchLatestVersion(ctx)
	if err != nil {
		log.Fatalf("Failed to fetch latest version: %v", err)
	}

	if latest == version {
		fmt.Printf("Already running latest version: %s\n", version)
		return
	}

	fmt.Printf("Updating from %s to %s...\n", version, latest)
	if err := mgr.RunUpdateScript(ctx, latest); err != nil {
		log.Fatalf("Update failed: %v", err)
	}
}

func handlePeers() {
	resp, err := http.Get("http://127.0.0.1:9034/peers")
	if err != nil {
		log.Fatalf("Failed to reach daemon: %v", err)
	}
	defer resp.Body.Close()

	var data struct {
		Peers []struct {
			IP       string `json:"ip"`
			Hostname string `json:"hostname"`
			OS       string `json:"os"`
			Alive    bool   `json:"alive"`
		} `json:"peers"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		log.Fatalf("Failed to decode discovery results: %v", err)
	}

	fmt.Printf("%-18s %-20s %-25s\n", "IP ADDRESS", "HOSTNAME", "OS / DEVICE TYPE")
	fmt.Println(strings.Repeat("-", 65))
	for _, p := range data.Peers {
		hostname := p.Hostname
		if hostname == "" {
			hostname = "unknown"
		}
		osInfo := p.OS
		if osInfo == "" {
			osInfo = "unknown"
		}
		fmt.Printf("%-18s %-20s %-25s\n", p.IP, hostname, osInfo)
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, "Usage: %s <command> [arguments]\n", os.Args[0])
	fmt.Fprintln(os.Stderr, "\nAvailable commands:")
	fmt.Fprintln(os.Stderr, "  login      Authenticate and configure the agent")
	fmt.Fprintln(os.Stderr, "  connect    Connect the agent using a configuration file")
	fmt.Fprintln(os.Stderr, "  update     Self-update the agent to the latest version")
	fmt.Fprintln(os.Stderr, "  peers      List discovered peers in the subnet")
	fmt.Fprintln(os.Stderr, "  ping       Ping a host (TCP probe) via the agent network")
	fmt.Fprintln(os.Stderr, "  curl       Run curl via the agent network")
	fmt.Fprintln(os.Stderr, "  ssh        Run ssh via the agent network")
	fmt.Fprintln(os.Stderr, "  telnet     Run telnet via the agent network")
	fmt.Fprintln(os.Stderr, "  bind       Bind a local port to a remote endpoint via the agent network")
	fmt.Fprintln(os.Stderr, "  neighbors  Interact with neighbors (ls to list, sp to scan ports)")
	fmt.Fprintln(os.Stderr, "  version    Show version information")
}

// Session encapsulates a connection to the network, either via IPC or Ephemeral Agent
type Session struct {
	DialContext func(ctx context.Context, network, addr string) (net.Conn, error)
	Close       func()
}

func getSession(ctx context.Context) (*Session, error) {
	// 1. Try IPC (fast path, reuses existing tunnel)
	socketPath := ipc.GetSocketPath()

	// Probe if daemon is alive
	conn, err := net.DialTimeout("unix", socketPath, 1*time.Second)
	if err == nil {
		conn.Close()
		// Daemon is running
		return &Session{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return ipc.Dial(network, addr)
			},
			Close: func() {},
		}, nil
	}

	// 2. Fallback: Ephemeral Agent (if config exists)
	configPath := "wantasticd.json"
	if _, err := os.Stat(configPath); err == nil {
		cfg, err := config.LoadFromFile(configPath)
		if err == nil {
			cfg.Verbose = false
			agt, err := agent.New(cfg)
			if err == nil {
				if err := agt.Start(ctx); err == nil {
					// Wait briefly for handshake
					time.Sleep(2 * time.Second)
					return &Session{
						DialContext: agt.GetNetstack().DialContext,
						Close:       func() { agt.Stop() },
					}, nil
				}
			}
		}
	}

	return nil, fmt.Errorf("daemon not running at %s and no %s found for ephemeral session", socketPath, configPath)
}

func handleProxy() {
	if len(os.Args) < 4 {
		os.Exit(1)
	}
	targetHost := os.Args[2]
	targetPort := os.Args[3]
	target := net.JoinHostPort(targetHost, targetPort)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sess, err := getSession(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	defer sess.Close()

	conn, err := sess.DialContext(ctx, "tcp", target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Proxy connection failed: %v", err)
		os.Exit(1)
	}
	defer conn.Close()

	// Pipe io
	go io.Copy(os.Stdout, conn)
	io.Copy(conn, os.Stdin)
}

func handleNeighbors() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: wantasticd neighbors <ls|sp> [args]")
		os.Exit(1)
	}
	command := os.Args[2]

	switch command {
	case "ls":
		handlePeers()
	case "sp":
		if len(os.Args) < 4 {
			fmt.Println("Usage: wantasticd neighbors sp <ip>")
			os.Exit(1)
		}
		targetIP := os.Args[3]
		ctx := context.Background()
		sess, err := getSession(ctx)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}
		defer sess.Close()
		scanner.RunPortScan(ctx, sess.DialContext, targetIP)
	default:
		fmt.Println("Unknown neighbor command")
	}
}

func handleCurl() {
	curlCmd := flag.NewFlagSet("curl", flag.ExitOnError)
	method := curlCmd.String("X", "GET", "HTTP method")
	data := curlCmd.String("d", "", "HTTP data")
	verbose := curlCmd.Bool("v", false, "Verbose")
	var headers []string
	curlCmd.Func("H", "Header", func(s string) error {
		headers = append(headers, s)
		return nil
	})
	curlCmd.Parse(os.Args[2:])

	if len(curlCmd.Args()) < 1 {
		fmt.Println("Usage: wantasticd curl [options] <url>")
		os.Exit(1)
	}
	u := curlCmd.Args()[0]

	ctx := context.Background()
	sess, err := getSession(ctx)
	if err != nil {
		log.Fatalf("Error: %v", err)
	}
	defer sess.Close()

	if err := curl.Run(ctx, sess.DialContext, *method, u, *data, headers, *verbose); err != nil {
		log.Fatalf("Curl failed: %v", err)
	}
}
func handleSSH() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: wantasticd ssh <user@host>")
		os.Exit(1)
	}
	target := os.Args[2]
	user := "root"
	host := target
	if strings.Contains(target, "@") {
		parts := strings.SplitN(target, "@", 2)
		user = parts[0]
		host = parts[1]
	}

	sshPort := "22"
	if strings.Contains(host, ":") {
		h, p, err := net.SplitHostPort(host)
		if err == nil {
			host = h
			sshPort = p
		}
	}

	ctx := context.Background()
	sess, err := getSession(ctx)
	if err != nil {
		log.Fatalf("Error: %v", err)
	}
	defer sess.Close()

	if err := ssh.Run(ctx, sess.DialContext, user, host, sshPort); err != nil {
		log.Fatalf("SSH session failed: %v", err)
	}
}

func handleTelnet() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: wantasticd telnet <host> [port]")
		os.Exit(1)
	}
	host := os.Args[2]
	port := "23"
	if len(os.Args) > 3 {
		port = os.Args[3]
	}

	ctx := context.Background()
	sess, err := getSession(ctx)
	if err != nil {
		log.Fatalf("Error: %v", err)
	}
	defer sess.Close()

	if err := telnet.Run(ctx, sess.DialContext, host, port); err != nil {
		log.Fatalf("Telnet failed: %v", err)
	}
}

func handleBind() {
	bindCmd := flag.NewFlagSet("bind", flag.ExitOnError)
	verbose := bindCmd.Bool("v", false, "Log connections")
	bindCmd.Parse(os.Args[2:])

	args := bindCmd.Args()
	if len(args) < 2 {
		fmt.Println("Usage: wantasticd bind [-v] <local-port> <remote-host>:<remote-port>")
		os.Exit(1)
	}
	localPort := args[0]
	remoteTarget := args[1]

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sess, err := getSession(ctx)
	if err != nil {
		log.Fatalf("Error: %v", err)
	}
	defer sess.Close()

	l, err := net.Listen("tcp", ":"+localPort)
	if err != nil {
		log.Fatalf("Listen failed: %v", err)
	}
	log.Printf("Listening on :%s, forwarding to %s", localPort, remoteTarget)

	for {
		c, err := l.Accept()
		if err != nil {
			log.Printf("Accept error: %v", err)
			continue
		}
		go func(local net.Conn) {
			defer local.Close()
			if *verbose {
				log.Printf("New connection from %s", local.RemoteAddr())
			}

			remote, err := sess.DialContext(ctx, "tcp", remoteTarget)
			if err != nil {
				if *verbose {
					log.Printf("Dial failed to %s: %v", remoteTarget, err)
				}
				return
			}
			defer remote.Close()

			go io.Copy(local, remote)
			io.Copy(remote, local)

			if *verbose {
				log.Printf("Connection closed from %s", local.RemoteAddr())
			}
		}(c)
	}
}

func handlePing() {
	pingCmd := flag.NewFlagSet("ping", flag.ExitOnError)
	count := pingCmd.Int("c", -1, "Count")
	interval := pingCmd.Duration("i", time.Second, "Interval")
	pingCmd.Parse(os.Args[2:])

	if len(pingCmd.Args()) < 1 {
		fmt.Println("Usage: wantasticd ping [options] <host>")
		os.Exit(1)
	}
	host := pingCmd.Args()[0]

	ctx := context.Background()
	sess, err := getSession(ctx)
	if err != nil {
		log.Fatalf("Error: %v", err)
	}
	defer sess.Close()

	if err := ping.Run(ctx, sess.DialContext, host, *count, *interval); err != nil {
		log.Fatalf("Ping failed: %v", err)
	}
}
