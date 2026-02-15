package device

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"log"

	"github.com/andybalholm/brotli"

	wgdevice "wantastic-agent/internal/device/wireguard-go/device"
)

// DeviceMetrics represents the decoded stats from a peer.
// This struct mirrors internal/stats.Metrics but is self-contained for the device package.
type DeviceMetrics struct {
	Timestamp int64
	Hostname  string
	Platform  string
	CPU       struct {
		Cores int
		Arch  string
		Usage string
	}
	Memory struct {
		Allocated uint64
		Total     uint64
	}
	Network struct {
		Interfaces []InterfaceInfo
		Traffic    TrafficStats
	}
	WiFi struct {
		Interfaces []WiFiInterfaceInfo
		Connected  bool
		Signal     int
		Noise      int
		Bitrate    int
	}
	WireGuard struct {
		Connected bool
		PublicKey string
		Peers     int
		TxBytes   uint64
		RxBytes   uint64
	}
	Agent struct {
		Uptime  string
		Version string
		Status  string
	}
	Modem *ModemInfo
	GPS   *GPSInfo
}

type InterfaceInfo struct {
	Name    string
	MAC     string
	IPs     []string
	TxBytes uint64
	RxBytes uint64
	Up      bool
}

type TrafficStats struct {
	TotalTx uint64
	TotalRx uint64
	TxRate  uint64
	RxRate  uint64
}

type WiFiInterfaceInfo struct {
	Name      string
	SSID      string
	Connected bool
	Signal    int
	Noise     int
	Bitrate   int
}

type ModemInfo struct {
	Model    string
	Operator string
	Tech     string
	Signal   int
}

type GPSInfo struct {
	Lat   float64
	Lon   float64
	Speed float64
}

// UnmarshalBinary decompress (Brotli) and decode (Custom Binary)
func (s *DeviceMetrics) UnmarshalBinary(data []byte) error {
	// 1. Layer 2: Decompress (Brotli)
	br := brotli.NewReader(bytes.NewReader(data))
	decompressed, err := io.ReadAll(br)
	if err != nil {
		return fmt.Errorf("brotli decompression failed: %w", err)
	}

	// 2. Layer 1: Decode Custom Binary Packing
	buf := bytes.NewBuffer(decompressed)

	// Helpers
	readUVarint := func(name string) uint64 {
		x, err := binary.ReadUvarint(buf)
		if err != nil {
			return 0
		}
		return x
	}

	readVarint := func(name string) int64 {
		x, err := binary.ReadVarint(buf)
		if err != nil {
			return 0
		}
		return x
	}

	readString := func(name string) string {
		len := readUVarint(name + ".len")
		if len == 0 {
			return ""
		}
		b := make([]byte, len)
		_, _ = buf.Read(b)
		return string(b)
	}

	// 1. Header
	s.Timestamp = readVarint("Timestamp")
	s.Hostname = readString("Hostname")
	s.Platform = readString("Platform")

	// 2. CPU
	s.CPU.Cores = int(readUVarint("CPU.Cores"))
	s.CPU.Arch = readString("CPU.Arch")
	s.CPU.Usage = readString("CPU.Usage")

	// 3. Memory
	s.Memory.Allocated = readUVarint("Memory.Allocated")
	s.Memory.Total = readUVarint("Memory.Total")

	// 4. Network Interfaces
	ifaceCount := readUVarint("ifaceCount")
	s.Network.Interfaces = make([]InterfaceInfo, ifaceCount)
	for i := 0; i < int(ifaceCount); i++ {
		s.Network.Interfaces[i].Name = readString("Iface.Name")
		s.Network.Interfaces[i].MAC = readString("Iface.MAC")
		ipCount := readUVarint("Iface.IPs.Count")
		s.Network.Interfaces[i].IPs = make([]string, ipCount)
		for j := 0; j < int(ipCount); j++ {
			s.Network.Interfaces[i].IPs[j] = readString("Iface.IP")
		}
		s.Network.Interfaces[i].TxBytes = readUVarint("Iface.Tx")
		s.Network.Interfaces[i].RxBytes = readUVarint("Iface.Rx")
		s.Network.Interfaces[i].Up = readUVarint("Iface.Up") == 1
	}

	// 5. Traffic
	s.Network.Traffic.TotalTx = readUVarint("Traffic.TotalTx")
	s.Network.Traffic.TotalRx = readUVarint("Traffic.TotalRx")
	s.Network.Traffic.TxRate = readUVarint("Traffic.TxRate")
	s.Network.Traffic.RxRate = readUVarint("Traffic.RxRate")

	// 6. WiFi
	wifiCount := readUVarint("wifiCount")
	s.WiFi.Interfaces = make([]WiFiInterfaceInfo, wifiCount)
	for i := 0; i < int(wifiCount); i++ {
		s.WiFi.Interfaces[i].Name = readString("WiFi.Name")
		s.WiFi.Interfaces[i].SSID = readString("WiFi.SSID")
		s.WiFi.Interfaces[i].Connected = readUVarint("WiFi.Connected") == 1
		s.WiFi.Interfaces[i].Signal = int(readVarint("WiFi.Signal"))
		s.WiFi.Interfaces[i].Noise = int(readVarint("WiFi.Noise"))
		s.WiFi.Interfaces[i].Bitrate = int(readUVarint("WiFi.Bitrate"))
	}
	s.WiFi.Connected = readUVarint("WiFi.Global.Connected") == 1
	s.WiFi.Signal = int(readVarint("WiFi.Global.Signal"))
	s.WiFi.Noise = int(readVarint("WiFi.Global.Noise"))
	s.WiFi.Bitrate = int(readUVarint("WiFi.Global.Bitrate"))

	// 7. WireGuard
	s.WireGuard.Connected = readUVarint("WG.Connected") == 1
	s.WireGuard.PublicKey = readString("WG.Pubkey")
	s.WireGuard.Peers = int(readUVarint("WG.Peers"))
	s.WireGuard.TxBytes = readUVarint("WG.Tx")
	s.WireGuard.RxBytes = readUVarint("WG.Rx")

	// 8. Agent
	s.Agent.Uptime = readString("Agent.Uptime")
	s.Agent.Version = readString("Agent.Version")
	s.Agent.Status = readString("Agent.Status")

	// 9. Modem
	if readUVarint("Modem.Present") == 1 {
		s.Modem = &ModemInfo{}
		s.Modem.Model = readString("Modem.Model")
		s.Modem.Operator = readString("Modem.Opt")
		s.Modem.Tech = readString("Modem.Tech")
		s.Modem.Signal = int(readVarint("Modem.Signal"))
	}

	// 10. GPS
	if readUVarint("GPS.Present") == 1 {
		s.GPS = &GPSInfo{}
		binary.Read(buf, binary.LittleEndian, &s.GPS.Lat)
		binary.Read(buf, binary.LittleEndian, &s.GPS.Lon)
		binary.Read(buf, binary.LittleEndian, &s.GPS.Speed)
	}

	return nil
}

func (d *Device) handleStats(peer *wgdevice.Peer, data []byte) {
	var metrics DeviceMetrics
	if err := metrics.UnmarshalBinary(data); err != nil {
		log.Printf("Failed to unmarshal Big Data stats from peer %v: %v", peer, err)
		return
	}

	// Log a summary
	log.Printf("STATS from %v: TS=%d, Host=%s, CPU=%s, Mem=%d/%d, WiFi=%v (%d dBm)",
		peer, metrics.Timestamp, metrics.Hostname, metrics.CPU.Usage,
		metrics.Memory.Allocated/1024/1024, metrics.Memory.Total/1024/1024,
		metrics.WiFi.Connected, metrics.WiFi.Signal)
}
