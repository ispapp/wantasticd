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

	"golang.org/x/sys/cpu"
)

//go:embed view.tmpl
var viewsFS embed.FS

// Server provides metrics and statistics about the device
type Server struct {
	device    *device.Device
	server    *http.Server
	mu        sync.RWMutex
	startTime time.Time
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
		Connected  bool   `json:"connected"`
		PublicKey  string `json:"public_key"`
		Peers      int    `json:"peers"`
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

// NewServer creates a new stats server instance
func NewServer(device *device.Device, version string) *Server {
	s := &Server{
		device:    device,
		startTime: time.Now(),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", s.handleMetrics)
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/view", s.handleView)
	mux.HandleFunc("/", s.handleRoot)

	s.server = &http.Server{
		Addr:    ":9034",
		Handler: mux,
	}

	return s
}

// Start begins the stats server
func (s *Server) Start() error {
	go func() {
		log.Printf("Stats server starting on port 9034")
		if err := s.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("Stats server error: %v", err)
		}
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

// handleHealth returns a simple health check response
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":    "healthy",
		"timestamp": time.Now().Format(time.RFC3339),
	})
}

// handleView returns a beautiful HTML view of device statistics using Windows 11 design
func (s *Server) handleView(w http.ResponseWriter, r *http.Request) {
	metrics := s.collectMetrics()

	w.Header().Set("Content-Type", "text/html; charset=utf-8")

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

	if err := tmpl.Execute(w, metrics); err != nil {
		log.Printf("Error executing template: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
}

// handleRoot returns API information
func (s *Server) handleRoot(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"api": "wantastic-agent stats server",
		"endpoints": map[string]string{
			"/metrics": "Device metrics and statistics",
			"/health":  "Health check endpoint",
			"/view":    "HTML statistics dashboard",
		},
		"version": "1.0.0",
	})
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
	m.CPU.Usage = "0%" // Simplified - would use proper monitoring in production

	// Memory metrics (simplified)
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	m.Memory.Allocated = memStats.Alloc
	m.Memory.Total = 1024 * 1024 * 1024 // 1GB default - would use proper system info

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
	m.WireGuard.Connected = true
	m.WireGuard.PublicKey = s.device.GetPublicKey()
	m.WireGuard.Peers = 1
	m.WireGuard.Throughput.TxBytes = 1024 * 1024     // 1MB
	m.WireGuard.Throughput.RxBytes = 2 * 1024 * 1024 // 2MB

	// Agent metrics
	m.Agent.Uptime = fmt.Sprintf("%.0fs", time.Since(s.startTime).Seconds())
	m.Agent.Version = "1.0.0"
	m.Agent.Status = "running"

	return m
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
