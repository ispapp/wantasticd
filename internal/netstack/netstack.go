package netstack

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

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
	stopCh  chan struct{}
	socks   net.Listener
	peers   []string // Discovered peers
}

func (ns *Netstack) DiscoverPeers() []string {
	ns.mu.RLock()
	defer ns.mu.RUnlock()
	return ns.peers
}

func (ns *Netstack) runDiscovery(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	// Initial scan
	ns.scanSubnet()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			ns.scanSubnet()
		}
	}
}

func (ns *Netstack) scanSubnet() {
	ns.mu.RLock()
	stack := ns.net
	ns.mu.RUnlock()

	var activePeers []string
	if len(ns.config.Interface.Addresses) > 0 {
		addr := ns.config.Interface.Addresses[0].Addr()
		base := addr.AsSlice()

		// Map of ports to check (stats and standard services)
		checkPorts := []int{9034, 22, 80, 443}

		for i := 128; i < 159; i++ {
			if byte(i) == base[3] {
				continue
			}
			target := net.IPv4(base[0], base[1], base[2], byte(i))

			for _, port := range checkPorts {
				var err error
				var conn net.Conn

				if stack != nil {
					// Use gVisor netstack in userspace mode
					conn, err = stack.DialTCP(&net.TCPAddr{IP: target, Port: port})
				} else {
					// Use OS network stack in System TUN mode
					conn, err = net.DialTimeout("tcp", net.JoinHostPort(target.String(), strconv.Itoa(port)), 500*time.Millisecond)
				}

				if err == nil {
					activePeers = append(activePeers, target.String())
					conn.Close()
					break
				}
			}
		}
	}

	ns.mu.Lock()
	ns.peers = activePeers
	ns.mu.Unlock()
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

func (ns *Netstack) SetNet(netInst *netstack.Net) {
	ns.mu.Lock()
	ns.net = netInst
	ns.mu.Unlock()

	if netInst == nil {
		log.Printf("Netstack: System TUN mode. Discovery and stats will use OS stack.")
	} else {
		log.Printf("Netstack: Userspace mode. Discovery and stats will use gVisor stack.")
		// Start SOCKS5 proxy to allow Host -> VPN connectivity
		go ns.startSOCKS5Proxy()
	}

	// Start internal mDNS responder for discovery
	go ns.startMDNSResponder()

	// Start background discovery scan
	go ns.runDiscovery(context.Background())
}

func (ns *Netstack) startMDNSResponder() {
	ns.mu.RLock()
	stack := ns.net
	ns.mu.RUnlock()

	// mDNS standard address: 224.0.0.251:5353
	addr := &net.UDPAddr{IP: net.IPv4(224, 0, 0, 251), Port: 5353}

	var conn net.PacketConn
	var err error

	if stack != nil {
		conn, err = stack.ListenUDP(addr)
	} else {
		// Use OS network stack (might fail if port 5353 is already taken by system mDNS)
		conn, err = net.ListenMulticastUDP("udp", nil, addr)
	}

	if err != nil {
		log.Printf("Netstack: mDNS discovery limited (could not bind 5353): %v", err)
		return
	}
	defer conn.Close()

	log.Printf("Netstack: mDNS discovery active.")

	buf := make([]byte, 2048)
	for {
		n, remoteAddr, err := conn.ReadFrom(buf)
		if err != nil {
			return
		}

		// Respond to incoming mDNS queries for "wantastic.local"
		// For robustness, we'll just track that someone is looking for us
		ns.handleMDNSQuery(conn, remoteAddr, buf[:n])
	}
}

func (ns *Netstack) handleMDNSQuery(conn net.PacketConn, remote net.Addr, data []byte) {
	// Simple mDNS handling: if we see a Query, we send an unsolicited response
	// notifying others of our existence.
	// In a real implementation this would follow RFC 6762.

	// Track the peer as discovered
	if udpAddr, ok := remote.(*net.UDPAddr); ok {
		ns.addPeer(udpAddr.IP.String())
	}
}

func (ns *Netstack) addPeer(ip string) {
	ns.mu.Lock()
	defer ns.mu.Unlock()

	for _, p := range ns.peers {
		if p == ip {
			return
		}
	}
	ns.peers = append(ns.peers, ip)
}

func (ns *Netstack) startSOCKS5Proxy() {
	// Tailscale typically uses port 1055 for its proxy
	l, err := net.Listen("tcp", "127.0.0.1:1055")
	if err != nil {
		log.Printf("Netstack: Failed to start SOCKS5 proxy on :1055: %v", err)
		return
	}

	ns.mu.Lock()
	ns.socks = l
	ns.mu.Unlock()

	log.Printf("Netstack: SOCKS5 proxy listening on 127.0.0.1:1055. Use this to reach peers from the host.")

	for {
		client, err := l.Accept()
		if err != nil {
			return
		}
		go ns.handleSOCKS5(client)
	}
}

func (ns *Netstack) handleSOCKS5(client net.Conn) {
	defer client.Close()

	// Simple SOCKS5 handshake (minimal implementation for robustness)
	buf := make([]byte, 256)
	if _, err := io.ReadFull(client, buf[:2]); err != nil || buf[0] != 0x05 {
		return
	}

	nMethods := int(buf[1])
	if _, err := io.ReadFull(client, buf[:nMethods]); err != nil {
		return
	}

	// No auth required
	client.Write([]byte{0x05, 0x00})

	// Request
	if _, err := io.ReadFull(client, buf[:4]); err != nil || buf[1] != 0x01 {
		return
	}

	var targetIP net.IP
	switch buf[3] {
	case 0x01: // IPv4
		if _, err := io.ReadFull(client, buf[:4]); err != nil {
			return
		}
		targetIP = net.IP(buf[:4])
	case 0x03: // Domain
		if _, err := io.ReadFull(client, buf[:1]); err != nil {
			return
		}
		len := int(buf[0])
		if _, err := io.ReadFull(client, buf[:len]); err != nil {
			return
		}
		// In a real implementation we'd resolve it, for now we assume IP
		return
	default:
		return
	}

	if _, err := io.ReadFull(client, buf[:2]); err != nil {
		return
	}
	port := int(buf[0])<<8 | int(buf[1])

	// Connect through netstack
	ns.mu.RLock()
	stack := ns.net
	ns.mu.RUnlock()

	if stack == nil {
		client.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	destAddr := &net.TCPAddr{IP: targetIP, Port: port}
	dest, err := stack.DialTCP(destAddr)
	if err != nil {
		client.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer dest.Close()

	client.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})

	done := make(chan struct{}, 2)
	go func() { io.Copy(dest, client); done <- struct{}{} }()
	go func() { io.Copy(client, dest); done <- struct{}{} }()
	<-done
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
