package agent

import (
	"context"
	"fmt"
	"log"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"
	"wantastic-agent/internal/stats"
	"wantastic-agent/internal/update"

	"wantastic-agent/internal/config"
	"wantastic-agent/internal/device"
	"wantastic-agent/internal/grpc"
	pb "wantastic-agent/internal/grpc/proto"
	"wantastic-agent/internal/ipc"
	"wantastic-agent/internal/netstack"
	"wantastic-agent/pkg/version"
)

// Agent represents the main agent that manages the WireGuard device, netstack, and gRPC communication
type Agent struct {
	config   *config.Config
	device   *device.Device
	client   *grpc.Client
	netstack *netstack.Netstack
	ipc      *ipc.Server
	updater  *update.Manager
	stats    *stats.Server

	mu      sync.RWMutex
	running bool
	stopCh  chan struct{}
	wg      sync.WaitGroup
}

// New creates a new Agent with the provided configuration
func New(cfg *config.Config) (*Agent, error) {
	return NewWithClient(cfg, nil)
}

// NewWithClient creates a new Agent with the provided configuration and optional gRPC client
// If client is nil, the agent will create one automatically based on the configuration
func NewWithClient(cfg *config.Config, client *grpc.Client) (*Agent, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	cfg.GenerateDeviceID()

	dev, err := device.New(cfg)
	if err != nil {
		return nil, fmt.Errorf("create device: %w", err)
	}

	ns, err := netstack.New(cfg)
	if err != nil {
		dev.Close()
		return nil, fmt.Errorf("create netstack: %w", err)
	}

	// Hook up JIT Port Forwarding
	dev.PortForwarder = ns.EnsurePortForward

	updater := update.NewManager(version.Version)

	// Initialize stats server
	statsServer := stats.NewServer(dev, ns, version.Version)

	ipcServer := ipc.NewServer(ns)

	return &Agent{
		config:   cfg,
		device:   dev,
		netstack: ns,
		ipc:      ipcServer,
		updater:  updater,
		stats:    statsServer,
		client:   client, // Store the pre-configured client
		stopCh:   make(chan struct{}),
	}, nil
}

// Start starts the agent and its components.
// It first checks if the agent is already running, and if so, returns an error.
// Start initializes and starts the agent with the provided context.
// This begins device operation, network stack initialization, and optional gRPC client connection.
// Returns an error if the agent is already running or if initialization fails.
func (a *Agent) Start(ctx context.Context) error {
	a.mu.Lock()
	if a.running {
		a.mu.Unlock()
		return fmt.Errorf("agent already running")
	}
	a.running = true
	a.mu.Unlock()

	// Use pre-configured client if available, otherwise create one if authentication credentials are provided
	if a.client == nil {
		if a.config.Auth.ServerURL != "" && a.config.Auth.Token != "" {
			client, err := grpc.New(a.config.Auth.ServerURL, a.config.DeviceID, a.config.Auth.Token)
			if err != nil {
				log.Printf("Warning: could not create gRPC client, running with local configuration only: %v", err)
			} else {
				a.client = client
				if err := a.runOnce(ctx); err != nil {
					log.Printf("Warning: initial configuration fetch failed, running with local configuration: %v", err)
				}
			}
		} else {
			log.Printf("Running with local configuration only (no gRPC authentication required)")
		}
	} else {
		// Use the pre-configured client
		if err := a.runOnce(ctx); err != nil {
			log.Printf("Warning: initial configuration fetch failed with pre-configured client: %v", err)
		}
	}

	if err := a.device.Start(); err != nil {
		return fmt.Errorf("start device: %w", err)
	}
	// Link the userspace netstack from the device to the netstack manager
	a.netstack.SetNet(a.device.GetNetstack())
	// Start stats server
	if err := a.stats.Start(); err != nil {
		log.Printf("Warning: failed to start stats server: %v", err)
	}
	if err := a.netstack.Start(); err != nil {
		a.device.Stop()
		return fmt.Errorf("start netstack: %w", err)
	}

	// Start IPC server for subcommands
	if err := a.ipc.Start(); err != nil {
		log.Printf("Warning: failed to start IPC server: %v", err)
	}

	// Start background workers
	// We always run HealthCheck and DNSCheck (Linux)
	workerCount := 2
	if a.client != nil {
		workerCount += 2 // GRPC + ConfigMonitor
	}
	a.wg.Add(workerCount)

	go a.runHealthCheck(ctx)
	go a.runDNSCheck(ctx)

	if a.client != nil {
		go a.runGRPCClient(ctx)
		go a.runConfigMonitor(ctx)
	}

	return nil
}

func (a *Agent) runOnce(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	if err := a.checkForConfigUpdates(ctx); err != nil {
		return err
	}
	return nil
}

// Stop stops the agent and its components.
// It first checks if the agent is already stopped, and if so, returns nil.
// If not, it sets the running flag to false and unlocks the mutex.
// Then, it closes the stopCh channel if it hasn't been closed already.
// After that, it waits for all goroutines to finish.
// If a gRPC client is available, it closes it.
// Finally, it stops the netstack and device components.
// Returns an error if any component fails to stop.
func (a *Agent) Stop() error {
	a.mu.Lock()
	if !a.running {
		a.mu.Unlock()
		return nil
	}
	a.running = false

	// Only close stopCh if it hasn't been closed already
	select {
	case <-a.stopCh:
		// Channel already closed
	default:
		close(a.stopCh)
	}
	a.mu.Unlock()

	a.wg.Wait()

	if a.ipc != nil {
		a.ipc.Stop()
	}

	if err := a.netstack.Stop(); err != nil {
		log.Printf("Error stopping netstack: %v", err)
	}

	if err := a.device.Stop(); err != nil {
		log.Printf("Error stopping device: %v", err)
	}

	if a.client != nil {
		a.client.Close()
	}

	return nil
}

func (a *Agent) runGRPCClient(ctx context.Context) {
	defer a.wg.Done()

	ticker := time.NewTicker(a.config.Auth.RefreshTime)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-a.stopCh:
			return
		case <-ticker.C:
			if err := a.client.RefreshAuth(ctx); err != nil {
				log.Printf("Auth refresh failed: %v", err)
			}
		}
	}
}

func (a *Agent) runHealthCheck(ctx context.Context) {
	defer a.wg.Done()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-a.stopCh:
			return
		case <-ticker.C:
			if err := a.device.HealthCheck(); err != nil {
				log.Printf("Device health check failed: %v", err)
			}
		}
	}
}

func (a *Agent) runConfigMonitor(ctx context.Context) {
	defer a.wg.Done()

	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-a.stopCh:
			return
		case <-ticker.C:
			if err := a.checkForConfigUpdates(ctx); err != nil {
				log.Printf("Config update check failed: %v", err)
			}
		}
	}
}

func (a *Agent) runDNSCheck(ctx context.Context) {
	defer a.wg.Done()

	// Only run on Linux
	if runtime.GOOS != "linux" {
		return
	}

	checkDNS := func() {
		// Read /etc/resolv.conf
		content, err := os.ReadFile("/etc/resolv.conf")
		if err != nil {
			return
		}
		s := string(content)

		// Check if reliable DNS exists
		if !strings.Contains(s, "1.1.1.1") && !strings.Contains(s, "8.8.8.8") {
			// Append if running as root/privileged
			f, err := os.OpenFile("/etc/resolv.conf", os.O_APPEND|os.O_WRONLY, 0644)
			if err != nil {
				// Likely permission denied if not root; silent fail is okay as we can't do anything
				return
			}
			defer f.Close()

			log.Println("DNS Worker: Adding reliable nameservers (1.1.1.1, 8.8.8.8) to /etc/resolv.conf")
			if _, err := f.WriteString("\nnameserver 1.1.1.1\nnameserver 8.8.8.8\n"); err != nil {
				log.Printf("Warning: DNS worker failed to update resolv.conf: %v", err)
			}
		}
	}

	// Initial check
	checkDNS()

	ticker := time.NewTicker(30 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-a.stopCh:
			return
		case <-ticker.C:
			checkDNS()
		}
	}
}

func (a *Agent) checkForConfigUpdates(ctx context.Context) error {
	resp, err := a.client.GetConfiguration(ctx)
	if err != nil {
		return fmt.Errorf("get configuration: %w", err)
	}

	if resp.UpdateAvailable {
		log.Printf("Update available: %s -> %s", a.updater.GetCurrentVersion(), resp.UpdateVersion)
		updated, err := a.updater.CheckAndUpdate(ctx, resp.UpdateVersion)
		if err != nil {
			log.Printf("Self-update failed: %v", err)
		} else if updated {
			log.Println("Self-update completed successfully. Exiting to allow restart.")
			// Stop all components gracefully
			a.Stop()
			// Exit the process so supervisor (e.g. systemd) restarts it with new binary
			os.Exit(0)
		}
	}

	if err := a.applyConfiguration(resp); err != nil {
		return fmt.Errorf("apply configuration: %w", err)
	}

	return nil
}

func (a *Agent) applyConfiguration(resp *pb.GetConfigurationResponse) error {
	if resp.DeviceConfig != nil {
		if err := a.device.UpdateConfig(resp.DeviceConfig); err != nil {
			return fmt.Errorf("update device config: %w", err)
		}
	}

	if resp.ServerConfig != nil {
		if err := a.device.UpdateServerConfig(resp.ServerConfig); err != nil {
			return fmt.Errorf("update server config: %w", err)
		}
	}

	if resp.NetworkConfig != nil {
		if err := a.netstack.UpdateNetworkConfig(resp.NetworkConfig); err != nil {
			return fmt.Errorf("update network config: %w", err)
		}
	}

	return nil
}

// IsRunning returns true if the agent is running, false otherwise.
func (a *Agent) IsRunning() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.running
}

func (a *Agent) GetNetstack() *netstack.Netstack {
	return a.netstack
}
