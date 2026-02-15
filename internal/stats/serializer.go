package stats

import (
	"bytes"
	"encoding/binary"
)

// SerializeMetrics compacts the Metrics struct into a custom binary format.
// This is "Layer 1" compression to reduce size before Brotli.
func SerializeMetrics(m *Metrics) []byte {
	buf := new(bytes.Buffer)

	// Helper to write unsigned varint
	putUvarint := func(x uint64) {
		b := make([]byte, binary.MaxVarintLen64)
		n := binary.PutUvarint(b, x)
		buf.Write(b[:n])
	}

	// Helper to write signed varint
	putVarint := func(x int64) {
		b := make([]byte, binary.MaxVarintLen64)
		n := binary.PutVarint(b, x)
		buf.Write(b[:n])
	}

	// Helper to write string (len + bytes)
	putString := func(s string) {
		putUvarint(uint64(len(s)))
		buf.WriteString(s)
	}

	// 1. Timestamp (int64) - Use Varint for timestamp!
	putVarint(m.Timestamp.UnixNano())
	putString(m.Hostname)
	putString(m.Platform)

	// 2. CPU
	putUvarint(uint64(m.CPU.Cores))
	putString(m.CPU.Arch)
	putString(m.CPU.Usage)

	// 3. Memory
	putUvarint(m.Memory.Allocated)
	putUvarint(m.Memory.Total)

	// 4. Network Interfaces
	putUvarint(uint64(len(m.Network.Interfaces)))
	for _, iface := range m.Network.Interfaces {
		putString(iface.Name)
		putString(iface.MAC)
		// IPs (List of strings)
		putUvarint(uint64(len(iface.IPs)))
		for _, ip := range iface.IPs {
			putString(ip)
		}
		putUvarint(iface.TxBytes)
		putUvarint(iface.RxBytes)
		if iface.Up {
			putUvarint(1)
		} else {
			putUvarint(0)
		}
	}

	// 5. Traffic
	putUvarint(m.Network.Traffic.TotalTx)
	putUvarint(m.Network.Traffic.TotalRx)
	putUvarint(m.Network.Traffic.TxRate)
	putUvarint(m.Network.Traffic.RxRate)

	// 6. WiFi
	putUvarint(uint64(len(m.WiFi.Interfaces)))
	for _, w := range m.WiFi.Interfaces {
		putString(w.Name)
		putString(w.SSID)
		if w.Connected {
			putUvarint(1)
		} else {
			putUvarint(0)
		}
		putVarint(int64(w.Signal))
		putVarint(int64(w.Noise))
		putUvarint(uint64(w.Bitrate))
	}
	if m.WiFi.Connected {
		putUvarint(1)
	} else {
		putUvarint(0)
	}
	putVarint(int64(m.WiFi.Signal))
	putVarint(int64(m.WiFi.Noise))
	putUvarint(uint64(m.WiFi.Bitrate))

	// 7. WireGuard
	if m.WireGuard.Connected {
		putUvarint(1)
	} else {
		putUvarint(0)
	}
	putString(m.WireGuard.PublicKey)
	putUvarint(uint64(m.WireGuard.Peers))
	putUvarint(m.WireGuard.Throughput.TxBytes)
	putUvarint(m.WireGuard.Throughput.RxBytes)

	// 8. Agent
	putString(m.Agent.Uptime)
	putString(m.Agent.Version)
	putString(m.Agent.Status)

	// 9. Modem (Optional)
	if m.Modem != nil {
		putUvarint(1) // Present
		putString(m.Modem.Model)
		putString(m.Modem.Operator)
		putString(m.Modem.Tech)
		putVarint(int64(m.Modem.Signal))
	} else {
		putUvarint(0) // Not Present
	}

	// 10. GPS (Optional)
	if m.GPS != nil {
		putUvarint(1)
		// Float64 is 8 bytes. write as LittleEndian
		binary.Write(buf, binary.LittleEndian, m.GPS.Lat)
		binary.Write(buf, binary.LittleEndian, m.GPS.Lon)
		binary.Write(buf, binary.LittleEndian, m.GPS.Speed)
	} else {
		putUvarint(0)
	}

	return buf.Bytes()
}

// GetSerializedMetrics collects and serializes metrics using the shared function
func (s *Server) GetSerializedMetrics() []byte {
	m := s.collectMetrics()
	return SerializeMetrics(&m)
}
