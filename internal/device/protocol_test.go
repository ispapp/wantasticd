package device_test

import (
	"bytes"
	"testing"
	"time"

	"wantastic-agent/internal/device"
	"wantastic-agent/internal/stats"

	"github.com/andybalholm/brotli"
)

// Helper to create a populated metrics struct
func createTestMetrics() *stats.Metrics {
	m := &stats.Metrics{}
	m.Timestamp = time.Now()
	m.Hostname = "benchmark-host"
	m.Platform = "linux"

	m.CPU.Cores = 8
	m.CPU.Arch = "amd64"
	m.CPU.Usage = "45.2%"

	m.Memory.Allocated = 8 * 1024 * 1024 * 1024
	m.Memory.Total = 16 * 1024 * 1024 * 1024

	// 5 Interfaces to simulate complex network
	for i := 0; i < 5; i++ {
		m.Network.Interfaces = append(m.Network.Interfaces, stats.InterfaceInfo{
			Name: "eth0", MAC: "00:11:22:33:44:55",
			IPs:     []string{"192.168.1.10", "fe80::1"},
			TxBytes: 100000, RxBytes: 200000, Up: true,
		})
	}

	// 10 WiFi networks to simulate scan results
	for i := 0; i < 10; i++ {
		m.WiFi.Interfaces = append(m.WiFi.Interfaces, stats.WiFiInterfaceInfo{
			Name: "wlan0", SSID: "Neighbor_AP", Connected: false,
			Signal: -80, Noise: -95, Bitrate: 0,
		})
	}
	m.WiFi.Connected = true
	m.WiFi.Signal = -60

	m.WireGuard.Connected = true
	m.WireGuard.PublicKey = "ZdR8/3+..."
	m.WireGuard.Peers = 20
	m.WireGuard.Throughput.TxBytes = 50000
	m.WireGuard.Throughput.RxBytes = 60000

	m.Agent.Uptime = "5d 10h"
	m.Agent.Version = "v1.0.0"
	m.Agent.Status = "running"

	return m
}

func TestProtocolRoundTrip(t *testing.T) {
	original := createTestMetrics()

	// 1. Serialize (Layer 1)
	layer1 := stats.SerializeMetrics(original)

	// 2. Compress (Layer 2)
	var b bytes.Buffer
	w := brotli.NewWriterLevel(&b, brotli.BestCompression)
	w.Write(layer1)
	w.Close()
	payload := b.Bytes()

	t.Logf("Original Size (struct): ~%d bytes (estimated)", 2000) // Approx JSON size
	t.Logf("Layer 1 Size: %d bytes", len(layer1))
	t.Logf("Layer 2 Size: %d bytes", len(payload))

	// 3. Decode (Receiver side)
	var decoded device.DeviceMetrics
	if err := decoded.UnmarshalBinary(payload); err != nil {
		t.Fatalf("UnmarshalBinary failed: %v", err)
	}

	// 4. Verify
	if decoded.Hostname != original.Hostname {
		t.Errorf("Hostname mismatch: got %s, want %s", decoded.Hostname, original.Hostname)
	}
	if decoded.CPU.Cores != original.CPU.Cores {
		t.Errorf("CPU mismatch: got %d, want %d", decoded.CPU.Cores, original.CPU.Cores)
	}
	if len(decoded.WiFi.Interfaces) != len(original.WiFi.Interfaces) {
		t.Errorf("WiFi count mismatch: got %d, want %d", len(decoded.WiFi.Interfaces), len(original.WiFi.Interfaces))
	}
	if decoded.WireGuard.Peers != original.WireGuard.Peers {
		t.Errorf("Peer count mismatch: got %d, want %d", decoded.WireGuard.Peers, original.WireGuard.Peers)
	}
}

func BenchmarkStatsSerialization(b *testing.B) {
	m := createTestMetrics()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		stats.SerializeMetrics(m)
	}
}

func BenchmarkStatsCompression(b *testing.B) {
	m := createTestMetrics()
	data := stats.SerializeMetrics(m)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var buf bytes.Buffer
		w := brotli.NewWriterLevel(&buf, brotli.BestCompression)
		w.Write(data)
		w.Close()
	}
}

func BenchmarkFullProtocol(b *testing.B) {
	m := createTestMetrics()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Layer 1
		data := stats.SerializeMetrics(m)

		// Layer 2
		var buf bytes.Buffer
		w := brotli.NewWriterLevel(&buf, brotli.BestCompression)
		w.Write(data)
		w.Close()

		compressed := buf.Bytes()

		// Decode
		var decoded device.DeviceMetrics
		decoded.UnmarshalBinary(compressed)
	}
}
