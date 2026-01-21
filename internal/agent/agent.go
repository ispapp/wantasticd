package agent

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"
	"wantastic-agent/internal/update"

	"wantastic-agent/internal/config"
	"wantastic-agent/internal/device"
	"wantastic-agent/internal/grpc"
	"wantastic-agent/internal/netstack"
)

type Agent struct {
	config   *config.Config
	device   *device.Device
	client   *grpc.Client
	netstack *netstack.Netstack
	updater  *update.Manager

	mu      sync.RWMutex
	running bool
	stopCh  chan struct{}
	wg      sync.WaitGroup
}

func New(cfg *config.Config) (*Agent, error) {
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

	updater := update.NewManager("1.0.0") // TODO: Get version from build

	return &Agent{
		config:   cfg,
		device:   dev,
		netstack: ns,
		updater:  updater,
		stopCh:   make(chan struct{}),
	}, nil
}

func (a *Agent) Start(ctx context.Context) error {
	a.mu.Lock()
	if a.running {
		a.mu.Unlock()
		return fmt.Errorf("agent already running")
	}
	a.running = true
	a.mu.Unlock()

	client, err := grpc.New(a.config.Auth.ServerURL, a.config.DeviceID, a.config.Auth.Token)
	if err != nil {
		log.Printf("Warning: could not create gRPC client, running with local configuration only: %v", err)
	} else {
		a.client = client
		if err := a.runOnce(ctx); err != nil {
			log.Printf("Warning: initial configuration fetch failed, running with local configuration: %v", err)
		}
	}

	if err := a.device.Start(); err != nil {
		return fmt.Errorf("start device: %w", err)
	}

	if err := a.netstack.Start(); err != nil {
		a.device.Stop()
		return fmt.Errorf("start netstack: %w", err)
	}

	if a.client != nil {
		a.wg.Add(3)
		go a.runGRPCClient(ctx)
		go a.runHealthCheck(ctx)
		go a.runConfigMonitor(ctx)
	} else {
		a.wg.Add(1)
		go a.runHealthCheck(ctx)
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

func (a *Agent) Stop() error {
	a.mu.Lock()
	if !a.running {
		a.mu.Unlock()
		return nil
	}
	a.running = false
	close(a.stopCh)
	a.mu.Unlock()

	a.wg.Wait()

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

func (a *Agent) checkForConfigUpdates(ctx context.Context) error {
	resp, err := a.client.GetConfiguration(ctx)
	if err != nil {
		return fmt.Errorf("get configuration: %w", err)
	}

	if resp.UpdateAvailable {
		log.Printf("Update available: %s -> %s", a.updater.GetCurrentVersion(), resp.UpdateVersion)
		if err := a.updater.CheckAndUpdate(ctx, resp.UpdateURL, resp.UpdateVersion); err != nil {
			log.Printf("Self-update failed: %v", err)
		} else {
			log.Println("Self-update completed successfully")
		}
	}

	if err := a.applyConfiguration(resp); err != nil {
		return fmt.Errorf("apply configuration: %w", err)
	}

	return nil
}

func (a *Agent) applyConfiguration(resp *grpc.GetConfigurationResponse) error {
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

	if resp.ExitNodeConfig != nil {
		if err := a.netstack.UpdateExitNodeConfig(resp.ExitNodeConfig); err != nil {
			return fmt.Errorf("update exit node config: %w", err)
		}
	}

	return nil
}

func (a *Agent) IsRunning() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.running
}
