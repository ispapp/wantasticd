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
			servers: cfg.Interface.DNS, // Use DNS servers from configuration
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

func (ns *Netstack) SetNet(net *netstack.Net) {
	ns.mu.Lock()
	defer ns.mu.Unlock()
	ns.net = net
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
