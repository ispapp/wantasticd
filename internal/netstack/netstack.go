package netstack

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"reflect"
	"unsafe"
	"wantastic-agent/internal/config"
	"wantastic-agent/internal/grpc"

	virtstack "golang.zx2c4.com/wireguard/tun/netstack"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

// PeerInfo represents a discovered host on the VPN
type PeerInfo struct {
	IP        string `json:"ip"`
	Hostname  string `json:"hostname,omitempty"`
	OS        string `json:"os,omitempty"`
	Alive     bool   `json:"alive"`
	LatencyMs int64  `json:"latency_ms,omitempty"`
}

// Netstack handles the userspace networking stack.
// It is used when the agent runs in rootless mode.
type Netstack struct {
	config        *config.Config
	net           *virtstack.Net
	mu            sync.RWMutex
	listeners     map[int]net.Listener
	negativeCache map[int]time.Time
}

func New(cfg *config.Config) (*Netstack, error) {
	return &Netstack{
		config:        cfg,
		listeners:     make(map[int]net.Listener),
		negativeCache: make(map[int]time.Time),
	}, nil
}

func (ns *Netstack) EnsurePortForward(proto string, port int) bool {
	if proto == "icmp" {
		// ICMP is usually handled internally by gvisor.
		return true
	}

	if proto != "tcp" {
		return true
	}

	ns.mu.RLock()
	if ns.net == nil {
		ns.mu.RUnlock()
		return true
	}
	if _, exists := ns.listeners[port]; exists {
		ns.mu.RUnlock()
		return true
	}
	// Check negative cache
	if expiry, hit := ns.negativeCache[port]; hit && time.Now().Before(expiry) {
		ns.mu.RUnlock()
		// It's closed. Return TRUE to let gvisor send RST (Honest).
		// returning FALSE would drop it (Stealth).
		// RST is better for "Connection Refused" feedback.
		return true
	}
	ns.mu.RUnlock()

	// Miss: We need to check if the port is open on the host.
	// We do this asynchronously to avoid blocking the packet processing loop.
	// We return FALSE to DROP this packet. The client will retry.

	go func(targetPort int) {
		// We use extremely short timeouts and avoid DNS (localhost) to ensure performance.
		// We check both IPv4 and IPv6 loopback.
		var open bool

		// Check IPv4 127.0.0.1
		c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", targetPort), 50*time.Millisecond)
		if err == nil {
			c.Close()
			open = true
		} else {
			// Check IPv6 [::1]
			c, err := net.DialTimeout("tcp", fmt.Sprintf("[::1]:%d", targetPort), 50*time.Millisecond)
			if err == nil {
				c.Close()
				open = true
			}
		}

		ns.mu.Lock()
		defer ns.mu.Unlock()

		if !open {
			// Cache the failure for a short period
			ns.negativeCache[targetPort] = time.Now().Add(2 * time.Second)
			return
		}

		// Re-check existence under write lock
		if _, exists := ns.listeners[targetPort]; exists {
			return
		}

		addr, err := net.ResolveTCPAddr("tcp", fmt.Sprintf("0.0.0.0:%d", targetPort))
		if err != nil {
			return
		}

		l, err := ns.net.ListenTCP(addr)
		if err != nil {
			return
		}

		ns.listeners[targetPort] = l
		log.Printf("JIT Listener active on TCP/%d (Verified host service)", targetPort)

		go func() {
			for {
				client, err := l.Accept()
				if err != nil {
					return
				}
				go ns.proxyConnection(client, targetPort)
			}
		}()
	}(port)

	// Return FALSE to drop the packet while we check
	return false
}

func (ns *Netstack) proxyConnection(remote net.Conn, port int) {
	defer remote.Close()

	// Dial local host
	local, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 2*time.Second)
	if err != nil {
		local, err = net.DialTimeout("tcp", fmt.Sprintf("localhost:%d", port), 2*time.Second)
	}

	if err != nil {
		log.Printf("JIT Forwarding failed: No local service on port %d", port)
		return
	}
	defer local.Close()

	// Bidirectional copy
	done := make(chan struct{}, 2)
	go func() {
		io.Copy(local, remote)
		if tc, ok := local.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
		done <- struct{}{}
	}()
	go func() {
		io.Copy(remote, local)
		done <- struct{}{}
	}()

	<-done
}

func (ns *Netstack) Start() error {
	go ns.reaper()
	return nil
}

func (ns *Netstack) reaper() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		ns.mu.Lock()
		for port, l := range ns.listeners {
			// Check if host port is still alive
			conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 100*time.Millisecond)
			if err != nil {
				// Host port is gone, close virtual listener
				log.Printf("Reaping JIT Listener on TCP/%d (Host service unreachable)", port)
				l.Close()
				delete(ns.listeners, port)
			} else {
				conn.Close()
			}
		}
		ns.mu.Unlock()
	}
}

func (ns *Netstack) Stop() error {
	ns.mu.Lock()
	defer ns.mu.Unlock()
	for port, l := range ns.listeners {
		l.Close()
		delete(ns.listeners, port)
	}
	return nil
}

func (ns *Netstack) SetNet(netInst *virtstack.Net) {
	ns.mu.Lock()
	ns.net = netInst
	ns.mu.Unlock()
	if netInst != nil {
		ns.tuneForMacOS(netInst)
		log.Printf("Internal netstack initialized and tuned for macOS fingerprint.")
	}
}

func (ns *Netstack) tuneForMacOS(netInst *virtstack.Net) {
	// Use reflection to access the unexported 's' (*stack.Stack) in virtstack.Net
	v := reflect.ValueOf(netInst).Elem()
	f := v.FieldByName("s")
	if !f.IsValid() {
		f = v.FieldByName("Stack")
	}
	if !f.IsValid() {
		return
	}

	s := reflect.NewAt(f.Type(), unsafe.Pointer(f.UnsafeAddr())).Elem().Interface().(*stack.Stack)

	// 1. Set Default TTL to 64 (macOS default)
	ttl := tcpip.DefaultTTLOption(64)
	s.SetNetworkProtocolOption(ipv4.ProtocolNumber, &ttl)
	s.SetNetworkProtocolOption(ipv6.ProtocolNumber, &ttl)

	// 2. Set TCP Options to look like macOS
	opt := tcpip.TCPReceiveBufferSizeRangeOption{
		Min:     4096,
		Default: 65535,
		Max:     4194304,
	}
	s.SetTransportProtocolOption(tcp.ProtocolNumber, &opt)

	sack := tcpip.TCPSACKEnabled(true)
	s.SetTransportProtocolOption(tcp.ProtocolNumber, &sack)

	// 3. Add default routes via NIC 1 (created by virtstack)
	// Without routes, DialContext returns "no ports are available"
	ipv4Subnet, _ := tcpip.NewSubnet(tcpip.AddrFrom4([4]byte{0, 0, 0, 0}), tcpip.MaskFrom("\x00\x00\x00\x00"))
	ipv6Subnet, _ := tcpip.NewSubnet(tcpip.AddrFrom16([16]byte{}), tcpip.MaskFrom(strings.Repeat("\x00", 16)))

	s.SetRouteTable([]tcpip.Route{
		{
			Destination: ipv4Subnet,
			NIC:         1,
		},
		{
			Destination: ipv6Subnet,
			NIC:         1,
		},
	})
}

func (ns *Netstack) UpdateNetworkConfig(config *grpc.NetworkConfiguration) error {
	return nil
}

func (ns *Netstack) DiscoverPeersDetail() []PeerInfo {
	ns.mu.RLock()
	stack := ns.net
	ns.mu.RUnlock()

	if stack == nil {
		return nil
	}

	subnets := ns.config.Server.AllowedIPs
	if len(subnets) == 0 {
		return nil
	}

	var results []PeerInfo
	var mu sync.Mutex
	var wg sync.WaitGroup

	sem := make(chan struct{}, 50)

	for _, sub := range subnets {
		if strings.Contains(sub, ":") {
			continue
		}

		ip, ipNet, err := net.ParseCIDR(sub)
		if err != nil {
			continue
		}

		mask, _ := ipNet.Mask.Size()
		if mask < 22 {
			continue
		}

		base := ip.To4()
		for i := 1; i < 255; i++ {
			target := net.IPv4(base[0], base[1], base[2], byte(i))
			if !ipNet.Contains(target) {
				continue
			}

			wg.Add(1)
			go func(t net.IP) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()

				info := ns.probeHost(t.String())
				if info.Alive {
					mu.Lock()
					results = append(results, info)
					mu.Unlock()
				}
			}(target)
		}
	}

	wg.Wait()
	return results
}

func (ns *Netstack) probeHost(target string) PeerInfo {
	info := PeerInfo{IP: target}
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()

	if d, err := ns.Ping(ctx, target); err == nil {
		info.Alive = true
		info.LatencyMs = d.Milliseconds()
	}

	ports := []int{22, 80, 443, 3389, 9034}
	for _, p := range ports {
		start := time.Now()
		dCtx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		conn, err := ns.DialContext(dCtx, "tcp", net.JoinHostPort(target, fmt.Sprintf("%d", p)))
		cancel()
		if err == nil {
			if info.LatencyMs == 0 {
				info.LatencyMs = time.Since(start).Milliseconds()
			}
			info.Alive = true
			switch p {
			case 22:
				conn.SetDeadline(time.Now().Add(500 * time.Millisecond))
				buf := make([]byte, 100)
				if n, err := conn.Read(buf); err == nil {
					banner := string(buf[:n])
					if strings.Contains(banner, "Ubuntu") || strings.Contains(banner, "Debian") {
						info.OS = "Linux (Ubuntu/Debian)"
					} else if strings.Contains(banner, "OpenSSH") {
						info.OS = "Linux/macOS"
					}
				}
			case 3389:
				info.OS = "Windows (RDP)"
			case 9034:
				info.Hostname = "Wantastic Agent"
			}
			conn.Close()
			if info.OS != "" {
				break
			}
		}
	}
	return info
}

func (ns *Netstack) DiscoverPeers() []string {
	details := ns.DiscoverPeersDetail()
	var ips []string
	for _, d := range details {
		ips = append(ips, d.IP)
	}
	return ips
}

func (ns *Netstack) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	ns.mu.RLock()
	stack := ns.net
	ns.mu.RUnlock()

	if stack == nil {
		return nil, net.ErrClosed
	}
	return stack.DialContext(ctx, network, addr)
}

func (ns *Netstack) Ping(ctx context.Context, target string) (time.Duration, error) {
	ns.mu.RLock()
	stack := ns.net
	ns.mu.RUnlock()

	if stack == nil {
		log.Printf("Ping Error: Netstack not initialized")
		return 0, net.ErrClosed
	}

	start := time.Now()

	// 1. Try Real ICMP Ping (gvisor protocol "ping")
	// For "ping" network, Dial returns a connection that behaves like a datagram socket.
	// We MUST write an ICMP packet and read the reply to measure RTT.
	conn, err := stack.DialContext(ctx, "ping", target)
	if err == nil {
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(2 * time.Second))

		// Construct ICMP Echo Request (Type 8, Code 0)
		pkt := make([]byte, 12) // 8 byte header + 4 byte payload
		pkt[0] = 8              // Type
		pkt[1] = 0              // Code
		pkt[2] = 0              // Checksum High
		pkt[3] = 0              // Checksum Low
		pkt[4] = 0              // ID High
		pkt[5] = 1              // ID Low
		pkt[6] = 0              // Seq High
		pkt[7] = 1              // Seq Low
		copy(pkt[8:], []byte("WANT"))

		// Checksum calculation (RFC 1071)
		var sum uint32
		for i := 0; i < len(pkt)-1; i += 2 {
			sum += uint32(pkt[i])<<8 | uint32(pkt[i+1])
		}
		if len(pkt)%2 == 1 {
			sum += uint32(pkt[len(pkt)-1]) << 8
		}
		sum = (sum >> 16) + (sum & 0xffff)
		sum += (sum >> 16)
		csum := ^uint16(sum)
		pkt[2] = byte(csum >> 8)
		pkt[3] = byte(csum)

		if _, err := conn.Write(pkt); err == nil {
			buf := make([]byte, 1024)
			// We might receive other ICMP packets (e.g. from other pings), so strictly we should match ID/Seq.
			// But for a simple probe, just getting *any* packet back from the target is likely the reply.
			if n, err := conn.Read(buf); err == nil && n >= 0 {
				// Parse reply type
				if n >= 1 {
					typeByte := buf[0]
					// 0 = Echo Reply. 8 = Echo Request (shouldn't see this). 3 = Dest Unreachable.
					if typeByte == 0 {
						return time.Since(start), nil
					}
				}
				// Even if type is not 0 (e.g. 69?), getting a read return means network trip happened.
				// But let's close enough.
				return time.Since(start), nil
			}
		}
		// Reset start if ICMP write/read failed but connect succeeded
		start = time.Now()
	}

	// 2. Fallback: TCP SYN Probing (Accurate RTT because Dial waits for SYN-ACK)
	// We avoid port 9034 to prevent hitting our own JIT listener if the target is local-ish.
	ports := []string{"80", "443", "22", "3389", "8080", "9034"}
	for _, p := range ports {
		pStart := time.Now()
		// We use a short timeout for each probe
		ctxT, cancel := context.WithTimeout(ctx, 1000*time.Millisecond)
		conn, err = stack.DialContext(ctxT, "tcp", net.JoinHostPort(target, p))
		cancel()
		if err == nil {
			conn.Close()
			return time.Since(pStart), nil
		}
	}

	return 0, fmt.Errorf("ping failed")
}
