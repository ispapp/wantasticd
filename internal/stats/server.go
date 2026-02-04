package stats

import (
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"os"
	"runtime"
	"sync"
	"time"

	"wantastic-agent/internal/device"
	agent_netstack "wantastic-agent/internal/netstack"
	"wantastic-agent/pkg/version"

	"golang.org/x/sys/cpu"
)

//go:embed view.tmpl htmx.min.js dashboard.js
var viewsFS embed.FS

// Server provides metrics and statistics about the device
type Server struct {
	device    *device.Device
	netstack  *agent_netstack.Netstack
	server    *http.Server
	mu        sync.RWMutex
	startTime time.Time
	running   bool
}

// Metrics represents comprehensive device metrics
type Metrics struct {
	Timestamp time.Time `json:"timestamp"`
	Hostname  string    `json:"hostname"`
	Platform  string    `json:"platform"`

	// System metrics
	CPU struct {
		Cores int    `json:"cores"`
		Arch  string `json:"arch"`
		Usage string `json:"usage"` // Simplified usage percentage
	} `json:"cpu"`

	Memory struct {
		Allocated uint64 `json:"allocated"` // Current memory usage
		Total     uint64 `json:"total"`     // Total system memory
	} `json:"memory"`

	// Network metrics
	Network struct {
		Interfaces []InterfaceInfo `json:"interfaces"`
		Traffic    TrafficStats    `json:"traffic"`
	} `json:"network"`

	// WiFi metrics (collected from host device)
	WiFi struct {
		Interfaces []WiFiInterfaceInfo `json:"interfaces"`
		Connected  bool                `json:"connected"`
		Signal     int                 `json:"signal"`  // Signal strength in dBm
		Noise      int                 `json:"noise"`   // Noise level in dBm
		Bitrate    int                 `json:"bitrate"` // Current bitrate in Mbps
	} `json:"wifi"`

	// WireGuard device metrics
	WireGuard struct {
		Connected  bool                      `json:"connected"`
		PublicKey  string                    `json:"public_key"`
		Peers      int                       `json:"peers"`
		PeersList  []agent_netstack.PeerInfo `json:"peers_list"`
		Throughput struct {
			TxBytes uint64 `json:"tx_bytes"`
			RxBytes uint64 `json:"rx_bytes"`
		} `json:"throughput"`
	} `json:"wireguard"`

	// Agent metrics
	Agent struct {
		Uptime  string `json:"uptime"`
		Version string `json:"version"`
		Status  string `json:"status"`
	} `json:"agent"`

	// Modem metrics (for LTE/5G devices)
	Modem *ModemInfo `json:"modem,omitempty"`

	// GPS metrics
	GPS *GPSInfo `json:"gps,omitempty"`

	// Mesh metrics (for Linux embedded devices)
	Mesh *MeshInfo `json:"mesh,omitempty"`
}

// InterfaceInfo represents network interface details
type InterfaceInfo struct {
	Name    string   `json:"name"`
	MAC     string   `json:"mac"`
	IPs     []string `json:"ips"`
	TxBytes uint64   `json:"tx_bytes"`
	RxBytes uint64   `json:"rx_bytes"`
	Up      bool     `json:"up"`
}

// NearbyNetwork represents information about nearby WiFi networks
type NearbyNetwork struct {
	SSID     string `json:"ssid"`
	BSSID    string `json:"bssid"`
	Signal   int    `json:"signal"`
	Noise    int    `json:"noise"`
	Channel  int    `json:"channel"`
	Security string `json:"security"`
	PHYMode  string `json:"phy_mode"`
}

// WiFiInterfaceInfo represents WiFi interface details
type WiFiInterfaceInfo struct {
	Name      string          `json:"name"`
	MAC       string          `json:"mac"`
	SSID      string          `json:"ssid"`
	Connected bool            `json:"connected"`
	Signal    int             `json:"signal"`     // Signal strength in dBm
	Noise     int             `json:"noise"`      // Noise level in dBm
	Bitrate   int             `json:"bitrate"`    // Current bitrate in Mbps
	Frequency int             `json:"frequency"`  // Frequency in MHz
	Channel   int             `json:"channel"`    // Channel number
	PHYMode   string          `json:"phy_mode"`   // 802.11a/b/g/n/ac/ax
	Security  string          `json:"security"`   // WPA2, WPA3, etc
	SNR       int             `json:"snr"`        // Signal-to-noise ratio
	MCSIndex  int             `json:"mcs_index"`  // MCS Index (macOS)
	TxPower   int             `json:"tx_power"`   // Transmit power in dBm
	RxBytes   uint64          `json:"rx_bytes"`   // Received bytes
	TxBytes   uint64          `json:"tx_bytes"`   // Transmitted bytes
	RxPackets uint64          `json:"rx_packets"` // Received packets
	TxPackets uint64          `json:"tx_packets"` // Transmitted packets
	Nearby    []NearbyNetwork `json:"nearby"`     // Nearby networks seen by this interface
}

// TrafficStats represents network traffic statistics
type TrafficStats struct {
	TotalTx uint64 `json:"total_tx"`
	TotalRx uint64 `json:"total_rx"`
	TxRate  uint64 `json:"tx_rate"` // bytes per second
	RxRate  uint64 `json:"rx_rate"` // bytes per second
}

// MeshInfo represents mesh network information
type MeshInfo struct {
	Name     string    `json:"name,omitempty"`
	Protocol string    `json:"protocol"` // "easymesh", "openmesh", etc
	Role     string    `json:"role"`     // "controller", "agent", etc
	IsCenter bool      `json:"is_center"`
	Topology *MeshNode `json:"topology,omitempty"`
}

// MeshNode represents a node in the mesh topology
type MeshNode struct {
	Name     string      `json:"name"`
	MAC      string      `json:"mac"`
	IP       string      `json:"ip,omitempty"`
	Signal   int         `json:"signal,omitempty"`
	Role     string      `json:"role,omitempty"`
	Children []*MeshNode `json:"children,omitempty"`
}

// ModemInfo represents LTE/5G modem details
type ModemInfo struct {
	Model        string `json:"model"`
	IMEI         string `json:"imei"`
	IMSI         string `json:"imsi"`
	PhoneNumber  string `json:"phone_number"`
	SIMSlot      string `json:"sim_slot"`
	Signal       int    `json:"signal"`       // CSQ or dBm
	Registration string `json:"registration"` // e.g., "Home", "Roaming"
	Operator     string `json:"operator"`
	Tech         string `json:"tech"` // LTE, NR5G, etc.
}

// GPSInfo represents GNSS location details
type GPSInfo struct {
	Lat        float64   `json:"lat"`
	Lon        float64   `json:"lon"`
	Alt        float64   `json:"alt"`
	Speed      float64   `json:"speed"`
	Satellites int       `json:"satellites"`
	Fix        string    `json:"fix"` // "none", "2D", "3D"
	Timestamp  time.Time `json:"timestamp"`
}

// NewServer creates a new stats server instance
func NewServer(device *device.Device, ns *agent_netstack.Netstack, version string) *Server {
	s := &Server{
		device:    device,
		netstack:  ns,
		startTime: time.Now(),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", s.handleMetrics)
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/view", s.handleView)
	mux.HandleFunc("/events", s.handleEvents)
	mux.HandleFunc("/peers", s.handlePeers)
	mux.HandleFunc("/lib/htmx.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		data, _ := viewsFS.ReadFile("htmx.min.js")
		w.Write(data)
	})
	mux.HandleFunc("/lib/dashboard.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		data, _ := viewsFS.ReadFile("dashboard.js")
		w.Write(data)
	})
	mux.HandleFunc("/", s.handleView) // Main view at root

	s.server = &http.Server{
		Addr:    ":9034", // Listen on all interfaces
		Handler: mux,
	}

	return s
}

// Start begins the stats server
func (s *Server) Start() error {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return nil // Already running
	}
	s.running = true
	s.mu.Unlock()

	go func() {
		log.Printf("Stats server active on port 9034")
		if err := s.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("Stats server error: %v", err)
		}
		s.mu.Lock()
		s.running = false
		s.mu.Unlock()
	}()
	return nil
}

// Stop gracefully shuts down the stats server
func (s *Server) Stop() error {
	return s.server.Close()
}

// handleMetrics returns comprehensive device metrics in JSON format
func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	metrics := s.collectMetrics()

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	if err := json.NewEncoder(w).Encode(metrics); err != nil {
		http.Error(w, "Failed to encode metrics", http.StatusInternalServerError)
		return
	}
}

func (s *Server) handlePeers(w http.ResponseWriter, r *http.Request) {
	peers := s.netstack.DiscoverPeersDetail()

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	json.NewEncoder(w).Encode(map[string]any{
		"peers": peers,
		"count": len(peers),
	})
}

// handleHealth returns a simple health check response
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":    "healthy",
		"timestamp": time.Now().Format(time.RFC3339),
	})
}

// handleEvents streams device metrics via Server-Sent Events (SSE)
func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	// Set headers for SSE
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	// Create a channel to handle client disconnection
	clientGone := r.Context().Done()

	rc := http.NewResponseController(w)

	// Send initial data immediately
	metrics := s.collectMetrics()
	if data, err := json.Marshal(metrics); err == nil {
		fmt.Fprintf(w, "data: %s\n\n", data)
		rc.Flush()
	}

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-clientGone:
			return
		case <-ticker.C:
			metrics := s.collectMetrics()
			data, err := json.Marshal(metrics)
			if err != nil {
				continue
			}
			fmt.Fprintf(w, "data: %s\n\n", data)
			rc.Flush()
		}
	}
}

// handleView returns a beautiful HTML view of device statistics using Windows 11 design
func (s *Server) handleView(w http.ResponseWriter, r *http.Request) {
	// Parse and execute the template
	tmpl, err := template.New("view.tmpl").Funcs(template.FuncMap{
		"div": func(a, b any) float64 {
			toFloat := func(v any) float64 {
				switch val := v.(type) {
				case float64:
					return val
				case float32:
					return float64(val)
				case int:
					return float64(val)
				case int64:
					return float64(val)
				case uint64:
					return float64(val)
				case uint:
					return float64(val)
				default:
					return 0
				}
			}
			return toFloat(a) / toFloat(b)
		},
	}).ParseFS(viewsFS, "view.tmpl")
	if err != nil {
		log.Printf("Error parsing template: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Initial render
	metrics := s.collectMetrics()
	if err := tmpl.Execute(w, metrics); err != nil {
		log.Printf("Error executing template: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
}

// handleRoot returns a simple HTML landing page with a menu
func (s *Server) handleRoot(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `
<!DOCTYPE html>
<html>
<head>
    <title>Wantastic Agent Stats</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #f3f3f3;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
        }
        .menu {
            background: white;
            padding: 40px;
            border-radius: 12px;
            box-shadow: 0 4px 15px rgba(0,0,0,0.1);
            text-align: center;
        }
        h1 { color: #0078d4; margin-bottom: 30px; }
        .btn {
            display: block;
            width: 200px;
            margin: 15px auto;
            padding: 12px;
            background: #0078d4;
            color: white;
            text-decoration: none;
            border-radius: 6px;
            transition: background 0.2s;
            font-weight: 500;
        }
        .btn:hover { background: #005a9e; }
        .footer { margin-top: 20px; font-size: 0.8em; color: #666; }
    </style>
</head>
<body>
    <div class="menu">
        <h1>Wantastic Agent</h1>
        <a href="/metrics" class="btn">API (JSON)</a>
        <a href="/view" class="btn">View Dashboard</a>
        <a href="/health" class="btn">Health Status</a>
        <div class="footer">Version: %s</div>
    </div>
</body>
</html>
`, version.Version)
}

// collectMetrics gathers comprehensive device metrics
func (s *Server) collectMetrics() Metrics {
	var m Metrics
	m.Timestamp = time.Now()
	m.Hostname, _ = os.Hostname()
	m.Platform = runtime.GOOS

	// System metrics
	m.CPU.Cores = runtime.NumCPU()
	m.CPU.Arch = runtime.GOARCH
	m.CPU.Usage = collectCPUUsage()

	// Memory metrics (simplified)
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	m.Memory.Allocated = memStats.Alloc
	m.Memory.Total = collectMemoryTotal()

	// Network interfaces - collect from host device statistics
	m.Network.Interfaces = collectNetworkInterfaceStatistics()

	// WiFi statistics - collect from host device
	wifiInterfaces, wifiConnected := collectWiFiStatistics()
	m.WiFi.Interfaces = wifiInterfaces
	m.WiFi.Connected = wifiConnected

	// Calculate WiFi signal and bitrate averages if interfaces available
	if len(wifiInterfaces) > 0 {
		var totalSignal, totalBitrate int
		for _, wifiIface := range wifiInterfaces {
			totalSignal += wifiIface.Signal
			totalBitrate += wifiIface.Bitrate
		}
		m.WiFi.Signal = totalSignal / len(wifiInterfaces)
		m.WiFi.Bitrate = totalBitrate / len(wifiInterfaces)
	}

	// WireGuard metrics (would use actual device stats)
	m.WireGuard.Connected = s.device.HasActiveHandshake()
	m.WireGuard.PublicKey = s.device.GetPublicKey()

	// Try to get peers from netstack if available
	peers := s.netstack.DiscoverPeersDetail()
	m.WireGuard.Peers = len(peers)
	m.WireGuard.PeersList = peers

	rx, tx, _ := s.device.GetTransferStats()
	m.WireGuard.Throughput.RxBytes = rx
	m.WireGuard.Throughput.TxBytes = tx

	// Agent metrics
	// Agent metrics (Host Uptime)
	m.Agent.Uptime = formatUptimeDuration(getHostUptime())
	m.Agent.Version = version.Version
	m.Agent.Status = "running"

	// Mesh Statistics (Linux embedded only)
	m.Mesh = collectMeshStatistics()

	// Modem Statistics
	m.Modem = collectModemStatistics()

	// GPS Statistics
	m.GPS = collectGPSStatistics()

	return m
}

func formatUptimeDuration(seconds float64) string {
	d := time.Duration(seconds) * time.Second
	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	minutes := int(d.Minutes()) % 60

	if days > 0 {
		return fmt.Sprintf("%dd %dh %dm", days, hours, minutes)
	}
	if hours > 0 {
		return fmt.Sprintf("%dh %dm", hours, minutes)
	}
	return fmt.Sprintf("%dm", minutes)
}

// getCPUInfo returns basic CPU information
func getCPUInfo() string {
	if cpu.X86.HasAVX2 {
		return "x86 with AVX2"
	}
	if cpu.ARM.HasNEON {
		return "ARM with NEON"
	}
	return runtime.GOARCH
}

// getInterfaceIPs gets the IP addresses of a network interface
func getInterfaceIPs(ifaceName string) ([]string, error) {
	var ips []string

	// Get network interface
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, err
	}

	// Get addresses
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, err
	}

	for _, addr := range addrs {
		ips = append(ips, addr.String())
	}

	return ips, nil
}
