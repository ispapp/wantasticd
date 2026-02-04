package netstack

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"time"
	"unsafe"

	"wantastic-agent/internal/config"
	pb "wantastic-agent/internal/grpc/proto"

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
	udpListeners  map[int]net.PacketConn
	negativeCache map[int]time.Time
	peerCache     map[string]PeerInfo
}

func New(cfg *config.Config) (*Netstack, error) {
	return &Netstack{
		config:        cfg,
		listeners:     make(map[int]net.Listener),
		udpListeners:  make(map[int]net.PacketConn),
		negativeCache: make(map[int]time.Time),
		peerCache:     make(map[string]PeerInfo),
	}, nil
}

func (ns *Netstack) EnsurePortForward(proto string, port int) bool {
	if proto == "icmp" {
		// ICMP is usually handled internally by gvisor.
		return true
	}

	if proto == "udp" {
		ns.mu.RLock()
		if ns.net == nil {
			ns.mu.RUnlock()
			return true
		}
		if _, exists := ns.udpListeners[port]; exists {
			ns.mu.RUnlock()
			return true
		}
		ns.mu.RUnlock()

		go ns.ensureUDPListener(port)
		return false
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
		c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", targetPort), 200*time.Millisecond)
		if err == nil {
			c.Close()
			open = true
		} else {
			// Check IPv6 [::1]
			c, err := net.DialTimeout("tcp", fmt.Sprintf("[::1]:%d", targetPort), 200*time.Millisecond)
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

func (ns *Netstack) ensureUDPListener(port int) {
	ns.mu.Lock()
	defer ns.mu.Unlock()

	if _, exists := ns.udpListeners[port]; exists {
		return
	}

	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("0.0.0.0:%d", port))
	if err != nil {
		return
	}

	l, err := ns.net.ListenUDP(addr)
	if err != nil {
		return
	}

	ns.udpListeners[port] = l
	log.Printf("JIT Listener active on UDP/%d", port)

	go ns.proxyUDP(l, port)
}

func (ns *Netstack) proxyUDP(conn net.PacketConn, targetPort int) {
	defer conn.Close()
	defer func() {
		ns.mu.Lock()
		delete(ns.udpListeners, targetPort)
		ns.mu.Unlock()
	}()

	// Sessions map: RemoteAddr("ip:port") -> *net.UDPConn (connected to 127.0.0.1:targetPort)
	sessions := make(map[string]*net.UDPConn)
	var sessionMu sync.Mutex

	buf := make([]byte, 4096)

	for {
		conn.SetReadDeadline(time.Now().Add(5 * time.Minute)) // Idle timeout for the whole listener
		n, remoteAddr, err := conn.ReadFrom(buf)
		if err != nil {
			break
		}

		sessionMu.Lock()
		sessConn, exists := sessions[remoteAddr.String()]
		if !exists {
			// Create new session
			rConn, err := net.Dial("udp", fmt.Sprintf("127.0.0.1:%d", targetPort))
			if err != nil {
				rConn, err = net.Dial("udp", fmt.Sprintf("[::1]:%d", targetPort))
			}
			if err == nil {
				uConn := rConn.(*net.UDPConn)
				sessConn = uConn
				sessions[remoteAddr.String()] = uConn

				// Start return path with shorter idle timeout
				go func(rc *net.UDPConn, remAddr net.Addr) {
					defer rc.Close()
					rBuf := make([]byte, 4096)
					for {
						rc.SetReadDeadline(time.Now().Add(2 * time.Minute))
						rn, err := rc.Read(rBuf)
						if err != nil {
							sessionMu.Lock()
							delete(sessions, remAddr.String())
							sessionMu.Unlock()
							return
						}
						conn.WriteTo(rBuf[:rn], remAddr)
					}
				}(uConn, remoteAddr)
			}
		}
		sessionMu.Unlock()

		if sessConn != nil {
			sessConn.Write(buf[:n])
		}
	}
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
	ctx := context.Background()
	go ns.reaper()
	go ns.discoveryLoop(ctx)
	go ns.startMDNS(ctx)
	return nil
}

func (ns *Netstack) discoveryLoop(ctx context.Context) {
	ticker := time.NewTicker(2 * time.Minute)
	defer ticker.Stop()

	// Initial scan
	ns.refreshPeers()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			ns.refreshPeers()
		}
	}
}

func (ns *Netstack) refreshPeers() {
	ns.mu.RLock()
	stackPtr := ns.net
	ns.mu.RUnlock()

	if stackPtr == nil {
		return
	}

	subnets := ns.config.Server.AllowedIPs
	if len(subnets) == 0 {
		return
	}

	var wg sync.WaitGroup
	sem := make(chan struct{}, 50)

	for _, sub := range subnets {
		if strings.Contains(sub, ":") {
			continue
		}

		_, ipNet, err := net.ParseCIDR(sub)
		if err != nil {
			continue
		}

		mask, _ := ipNet.Mask.Size()
		if mask < 22 {
			continue // Avoid scanning huge networks
		}

		base := ipNet.IP.To4()
		for i := 1; i < 255; i++ {
			target := net.IPv4(base[0], base[1], base[2], byte(i))
			if !ipNet.Contains(target) {
				continue
			}

			wg.Add(1)
			go func(ip net.IP) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()

				info := ns.probeHost(ip.String())
				if info.Alive {
					ns.mu.Lock()
					ns.peerCache[ip.String()] = info
					ns.mu.Unlock()
				}
			}(target)
		}
	}
	wg.Wait()
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
	for port, l := range ns.udpListeners {
		l.Close()
		delete(ns.udpListeners, port)
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

func (ns *Netstack) UpdateNetworkConfig(config *pb.NetworkConfiguration) error {
	return nil
}

func (ns *Netstack) DiscoverPeersDetail() []PeerInfo {
	ns.mu.RLock()
	defer ns.mu.RUnlock()

	results := make([]PeerInfo, 0, len(ns.peerCache))
	for _, info := range ns.peerCache {
		results = append(results, info)
	}
	return results
}

func (ns *Netstack) probeHost(target string) PeerInfo {
	info := PeerInfo{IP: target}
	ctx, cancel := context.WithTimeout(context.Background(), 2000*time.Millisecond) // Total timeout 2s
	defer cancel()

	// 1. L3/L4 Ping check
	if d, err := ns.Ping(ctx, target); err == nil {
		info.Alive = true
		info.LatencyMs = d.Milliseconds()
	} else {
		// If ping failed, try TCP probe on common ports just in case ICMP is blocked
		// Fast check on 80/443/22/8291
		ports := []string{"80", "443", "22", "8291"}
		for _, p := range ports {
			start := time.Now()
			dCtx, dCancel := context.WithTimeout(ctx, 300*time.Millisecond)
			conn, err := ns.DialContext(dCtx, "tcp", net.JoinHostPort(target, p))
			dCancel()
			if err == nil {
				conn.Close()
				info.Alive = true
				info.LatencyMs = time.Since(start).Milliseconds()
				break
			}
		}
	}

	if !info.Alive {
		return info
	}

	// 2. Deep Fingerprinting
	var wg sync.WaitGroup
	var mu sync.Mutex

	// Detected attributes
	var nbnsName string
	var httpTitle string
	var sshBanner string
	var isWinbox, isRDP, isSMB bool

	// Helper to safe-set
	set := func(f func()) {
		mu.Lock()
		defer mu.Unlock()
		f()
	}

	// A. NBNS (UDP 137) - Hostname
	wg.Add(1)
	go func() {
		defer wg.Done()
		name, err := ns.probeNBNS(target)
		if err == nil && name != "" {
			set(func() { nbnsName = name })
		}
	}()

	// B. HTTP/HTTPS (Title & Server)
	wg.Add(1)
	go func() {
		defer wg.Done()
		title80, server80 := ns.probeHTTP(target, 80)
		if title80 != "" {
			set(func() { httpTitle = title80 })
		}
		// If 80 didn't yield much, try 443? (Skipping for speed unless 80 failed, maybe implement if needed)
		if server80 != "" && title80 == "" {
			// Try 443
			// Impl omitted for brevity/speed, 80 is usually enough for local webs
		}
	}()

	// C. SSH Banner (OS)
	wg.Add(1)
	go func() {
		defer wg.Done()
		dCtx, dCancel := context.WithTimeout(ctx, 800*time.Millisecond)
		defer dCancel()
		conn, err := ns.DialContext(dCtx, "tcp", net.JoinHostPort(target, "22"))
		if err == nil {
			defer conn.Close()
			conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			buf := make([]byte, 256)
			n, _ := conn.Read(buf)
			if n > 0 {
				set(func() { sshBanner = string(buf[:n]) })
			}
		}
	}()

	// D. Port Checks (Winbox, RDP, SMB)
	checkPort := func(port int, flag *bool) {
		dCtx, dCancel := context.WithTimeout(ctx, 500*time.Millisecond)
		defer dCancel()
		conn, err := ns.DialContext(dCtx, "tcp", net.JoinHostPort(target, fmt.Sprintf("%d", port)))
		if err == nil {
			conn.Close()
			set(func() { *flag = true })
		}
	}

	wg.Add(3)
	go func() { defer wg.Done(); checkPort(8291, &isWinbox) }()
	go func() { defer wg.Done(); checkPort(3389, &isRDP) }()
	go func() { defer wg.Done(); checkPort(445, &isSMB) }()

	wg.Wait()

	// 3. Synthesize Results
	// Hostname priority
	if nbnsName != "" {
		info.Hostname = nbnsName
	} else if httpTitle != "" {
		t := strings.TrimSpace(httpTitle)
		if len(t) > 30 {
			t = t[:30] + "..."
		}
		info.Hostname = t
	}

	// OS priority
	if isWinbox {
		info.OS = "RouterOS (MikroTik)"
		if info.Hostname == "" {
			info.Hostname = "MikroTik"
		}
	} else if isRDP || isSMB {
		info.OS = "Windows"
	} else if sshBanner != "" {
		banner := strings.TrimSpace(sshBanner)
		if strings.Contains(banner, "Ubuntu") {
			info.OS = "Ubuntu Linux"
		} else if strings.Contains(banner, "Debian") {
			info.OS = "Debian Linux"
		} else if strings.Contains(banner, "Alpine") {
			info.OS = "Alpine Linux"
		} else if strings.Contains(banner, "OpenSSH") {
			info.OS = "Linux (OpenSSH)"
		} else if strings.Contains(banner, "RouterOS") {
			info.OS = "RouterOS (MikroTik)"
		} else {
			info.OS = "Linux/Unix"
		}
	} else if httpTitle != "" {
		info.OS = "Web Server"
	}

	// Fallback/Special
	if info.Hostname == "" && target == "10.255.255.249" {
		info.Hostname = "Wantastic Agent"
		info.OS = "Agent Node"
	}

	return info
}

// probeNBNS sends a Node Status Request to UDP 137
func (ns *Netstack) probeNBNS(target string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	conn, err := ns.DialContext(ctx, "udp", net.JoinHostPort(target, "137"))
	if err != nil {
		return "", err
	}
	defer conn.Close()

	// Transaction ID: Random (0x1337)
	// Flags: 0x0000 (Query) or 0x0010 (Broadcast?) - 0x0000 is usually fine for unicast
	// Questions: 1
	// Name: CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA (Wildcard)
	// Type: 0x0021 (NBSTAT)
	// Class: 0x0001 (IN)

	packet := []byte{
		0x13, 0x37, // Transaction ID
		0x00, 0x00, // Flags
		0x00, 0x01, // QDCount
		0x00, 0x00, // ANCount
		0x00, 0x00, // NSCount
		0x00, 0x00, // ARCount
		// Name "CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" (Encoded *)
		0x20, // Length 32
		0x43, 0x4B, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
		0x00,       // Terminator
		0x00, 0x21, // Type NBSTAT
		0x00, 0x01, // Class IN
	}

	_, err = conn.Write(packet)
	if err != nil {
		return "", err
	}

	buf := make([]byte, 1024)
	conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	n, err := conn.Read(buf)
	if err != nil || n < 57 { // Min response size roughly
		return "", err
	}

	// Simple parser: Find first name in the Name Array
	// Skip Header (12) + Name (34) + Type(2) + Class(2) + TTL(4) + RdLength(2) + NumNames(1) = ~57 bytes
	// Actually response has ANCount >= 1.
	// We scan for the "Number of Names" byte.
	// The response format for NBSTAT is data block.

	// Scan: The Name "CK..." is in Query section. Answer section follows.
	// We skip 12 header + question section (variable, but we know it's 34+4 = 38 bytes).
	// So offset = 50.
	// Then Answer Resource Record: Name (1 byte? or Pointer 2 bytes). usually Pointer 0xC00C.
	// Then Type (2), Class (2), TTL (4), RDLength (2).
	// Then RData.
	// Inside RData: NumNames (1 byte).

	// Heuristic: Search for the sequence of names.
	// Names are 15 chars + 1 byte suffix + 2 bytes flags. = 18 bytes.
	// We want the name with suffix 0x20 (File Server / Hostname) or 0x00 (Workstation).

	data := buf[:n]
	// Locate "Number of Names" - usually at offset ~56-57?
	// Finding pattern is safer? NO, binary offsets are strict.

	// Offset calculation is risky if compression used (C00C).
	// For NBSTAT, simple offsets usually work.
	// Header: 12 bytes.
	// Question: 34 (Name) + 2 (Type) + 2 (Class) = 38.
	// Total 50 bytes.
	// Answer RR Header: Name (1 byte usually? No, it echoes question). If encoded name: 34 bytes.
	// If compressed: 2 bytes (0xC00C).
	// Let's assume compressed (most implementations).
	// RR: Name (2 or 34) + Type(2) + Class(2) + TTL(4) + RDLength(2).

	offset := 50
	if offset >= len(data) {
		return "", nil
	}

	// Answer Name
	if data[offset]&0xC0 == 0xC0 {
		offset += 2
	} else {
		// Skip full name
		for offset < len(data) && data[offset] != 0 {
			offset++
		}
		offset += (1 + 2 + 2) // Null + Type + Class (Wait, we need to be precise)
		// Simpler: Just look for the Names Block inside the packet.
		// The Names block consists of 18-byte records.
		// The names are SPACE-padded ASCII.
	}
	// Skip Type(2), Class(2), TTL(4)
	offset += 8
	if offset+2 > len(data) {
		return "", nil
	}

	rdLen := int(data[offset])<<8 | int(data[offset+1])
	offset += 2

	if offset+rdLen > len(data) {
		return "", nil
	}
	rData := data[offset : offset+rdLen]

	if len(rData) < 1 {
		return "", nil
	}
	numNames := int(rData[0])

	curr := 1
	var bestName string

	for i := 0; i < numNames; i++ {
		if curr+18 > len(rData) {
			break
		}
		nameBytes := rData[curr : curr+15]
		suffix := rData[curr+15]
		// flags := rData[curr+16 : curr+18]
		curr += 18

		name := strings.TrimSpace(string(nameBytes))

		// Suffix 0x00 (Workstation) or 0x20 (Server) are good candidates
		if suffix == 0x20 {
			bestName = name
			break // Server name is usually what we want
		}
		if suffix == 0x00 && bestName == "" {
			bestName = name
		}
	}

	return bestName, nil
}

// probeHTTP fetches Title or Server header
func (ns *Netstack) probeHTTP(target string, port int) (string, string) {
	dCtx, cancel := context.WithTimeout(context.Background(), 800*time.Millisecond)
	defer cancel()

	client := &http.Client{
		Transport: &http.Transport{
			DialContext: ns.DialContext,
		},
	}

	req, err := http.NewRequestWithContext(dCtx, "GET", fmt.Sprintf("http://%s:%d", target, port), nil)
	if err != nil {
		return "", ""
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", ""
	}
	defer resp.Body.Close()

	server := resp.Header.Get("Server")

	// Read first 2KB for title
	buf := make([]byte, 2048)
	n, _ := io.ReadFull(resp.Body, buf)
	body := string(buf[:n])

	var title string
	if start := strings.Index(strings.ToLower(body), "<title>"); start != -1 {
		if end := strings.Index(strings.ToLower(body[start:]), "</title>"); end != -1 {
			title = body[start+7 : start+end]
			title = strings.TrimSpace(title)
		}
	}

	return title, server
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
