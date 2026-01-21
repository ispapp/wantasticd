package netstack

import (
	"fmt"
	"log"
	"net/netip"
	"sync"

	"wantastic-agent/internal/config"
	"wantastic-agent/internal/grpc"

	"golang.zx2c4.com/wireguard/tun/netstack"
)

type Netstack struct {
	config *config.Config
	net    *netstack.Net
	dns    *DNSResolver
	router *Router

	mu      sync.RWMutex
	running bool
}

type DNSResolver struct {
	servers []string
	mu      sync.RWMutex
}

type Router struct {
	routes map[string]netip.Prefix
	mu     sync.RWMutex
}

func New(cfg *config.Config) (*Netstack, error) {
	return &Netstack{
		config: cfg,
		dns: &DNSResolver{
			servers: cfg.ExitNode.DNS,
		},
		router: &Router{
			routes: make(map[string]netip.Prefix),
		},
	}, nil
}

func (ns *Netstack) Start() error {
	ns.mu.Lock()
	if ns.running {
		ns.mu.Unlock()
		return fmt.Errorf("netstack already running")
	}
	ns.running = true
	ns.mu.Unlock()

	if ns.config.ExitNode.Enabled {
		if err := ns.setupExitNode(); err != nil {
			return fmt.Errorf("setup exit node: %w", err)
		}
	}

	return nil
}

func (ns *Netstack) Stop() error {
	ns.mu.Lock()
	if !ns.running {
		ns.mu.Unlock()
		return nil
	}
	ns.running = false
	ns.mu.Unlock()

	// Note: netstack.Net doesn't have a Close() method
	// The cleanup happens automatically when the device is closed

	return nil
}

func (ns *Netstack) setupExitNode() error {
	log.Println("Setting up exit node functionality")

	for _, route := range ns.config.ExitNode.Routes {
		prefix, err := netip.ParsePrefix(route)
		if err != nil {
			return fmt.Errorf("parse route %s: %w", route, err)
		}
		ns.router.routes[route] = prefix
		log.Printf("Added exit route: %s", route)
	}

	if len(ns.config.ExitNode.DNS) > 0 {
		log.Printf("Configured DNS servers: %v", ns.config.ExitNode.DNS)
	}

	return nil
}

func (ns *Netstack) SetNet(net *netstack.Net) {
	ns.mu.Lock()
	defer ns.mu.Unlock()
	ns.net = net
}

func (ns *Netstack) IsExitNode() bool {
	ns.mu.RLock()
	defer ns.mu.RUnlock()
	return ns.config.ExitNode.Enabled
}

func (ns *Netstack) GetRoutes() []string {
	ns.router.mu.RLock()
	defer ns.router.mu.RUnlock()

	routes := make([]string, 0, len(ns.router.routes))
	for route := range ns.router.routes {
		routes = append(routes, route)
	}
	return routes
}

func (ns *Netstack) AddRoute(prefix netip.Prefix) error {
	ns.router.mu.Lock()
	defer ns.router.mu.Unlock()

	ns.router.routes[prefix.String()] = prefix
	log.Printf("Added route: %s", prefix.String())
	return nil
}

func (ns *Netstack) RemoveRoute(prefix netip.Prefix) error {
	ns.router.mu.Lock()
	defer ns.router.mu.Unlock()

	delete(ns.router.routes, prefix.String())
	log.Printf("Removed route: %s", prefix.String())
	return nil
}

func (ns *Netstack) UpdateNetworkConfig(config *grpc.NetworkConfiguration) error {
	ns.mu.Lock()
	defer ns.mu.Unlock()

	log.Printf("Updating network configuration: routes=%v, forwarding_rules=%v",
		config.Routes, config.ForwardingRules)

	ns.router.mu.Lock()
	ns.router.routes = make(map[string]netip.Prefix)
	for _, route := range config.Routes {
		prefix, err := netip.ParsePrefix(route)
		if err != nil {
			ns.router.mu.Unlock()
			return fmt.Errorf("parse route %s: %w", route, err)
		}
		ns.router.routes[prefix.String()] = prefix
	}
	ns.router.mu.Unlock()

	log.Println("Network configuration updated successfully")
	return nil
}

func (ns *Netstack) UpdateExitNodeConfig(config *grpc.ExitNodeConfiguration) error {
	ns.mu.Lock()
	defer ns.mu.Unlock()

	log.Printf("Updating exit node configuration: enabled=%v, exit_routes=%v, exit_dns=%v, allow_lan=%v",
		config.Enabled, config.ExitRoutes, config.ExitDNS, config.AllowLAN)

	ns.config.ExitNode.Enabled = config.Enabled
	ns.config.ExitNode.Routes = config.ExitRoutes
	ns.config.ExitNode.DNS = config.ExitDNS
	ns.config.ExitNode.AllowLAN = config.AllowLAN

	if config.Enabled {
		return ns.setupExitNode()
	}

	log.Println("Exit node configuration updated successfully")
	return nil
}
