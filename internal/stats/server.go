package stats

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"runtime"
	"sync"
	"time"

	"wantastic-agent/internal/device"
	"golang.org/x/sys/cpu"
)

// Server provides metrics and statistics about the device
type Server struct {
	device   *device.Device
	server   *http.Server
	mu       sync.RWMutex
	startTime time.Time
}

// Metrics represents comprehensive device metrics
type Metrics struct {
	Timestamp time.Time `json:"timestamp"`
	
	// System metrics
	CPU struct {
		Cores     int    `json:"cores"`
		Arch      string `json:"arch"`
		Usage     string `json:"usage"` // Simplified usage percentage
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
		Uptime    string `json:"uptime"`
		Version   string `json:"version"`
		Status    string `json:"status"`
	} `json:"agent"`
}

// InterfaceInfo represents network interface details
type InterfaceInfo struct {
	Name      string   `json:"name"`
	MAC       string   `json:"mac"`
	IPs       []string `json:"ips"`
	TxBytes   uint64   `json:"tx_bytes"`
	RxBytes   uint64   `json:"rx_bytes"`
	Up        bool     `json:"up"`
}

// TrafficStats represents network traffic statistics
type TrafficStats struct {
	TotalTx uint64 `json:"total_tx"`
	TotalRx uint64 `json:"total_rx"`
	TxRate  uint64 `json:"tx_rate"`  // bytes per second
	RxRate  uint64 `json:"rx_rate"`  // bytes per second
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
	mux.HandleFunc("/", s.handleRoot)
	
	s.server = &http.Server{
		Addr:    ":9000",
		Handler: mux,
	}
	
	return s
}

// Start begins the stats server
func (s *Server) Start() error {
	go func() {
		log.Printf("Stats server starting on port 9000")
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

// handleRoot returns API information
func (s *Server) handleRoot(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"api": "wantastic-agent stats server",
		"endpoints": map[string]string{
			"/metrics": "Device metrics and statistics",
			"/health":  "Health check endpoint",
		},
		"version": "1.0.0",
	})
}

// collectMetrics gathers comprehensive device metrics
func (s *Server) collectMetrics() Metrics {
	var m Metrics
	m.Timestamp = time.Now()
	
	// System metrics
	m.CPU.Cores = runtime.NumCPU()
	m.CPU.Arch = runtime.GOARCH
	m.CPU.Usage = "0%" // Simplified - would use proper monitoring in production
	
	// Memory metrics (simplified)
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	m.Memory.Allocated = memStats.Alloc
	m.Memory.Total = 1024 * 1024 * 1024 // 1GB default - would use proper system info
	
	// Network interfaces (placeholder - would use proper network monitoring)
	m.Network.Interfaces = []InterfaceInfo{
		{
			Name: "eth0",
			MAC:  "00:11:22:33:44:55",
			IPs:  []string{"192.168.1.100"},
			Up:   true,
		},
	}
	
	// WireGuard metrics (would use actual device stats)
	m.WireGuard.Connected = true
	m.WireGuard.PublicKey = "demo-public-key"
	m.WireGuard.Peers = 1
	m.WireGuard.Throughput.TxBytes = 1024 * 1024  // 1MB
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