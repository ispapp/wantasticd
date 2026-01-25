package device

import (
	"encoding/binary"
	"os"

	"golang.zx2c4.com/wireguard/tun"
)

// TunWrapper wraps a real TUN device to inspect packet headers
// and trigger Just-In-Time port forwarding.
type TunWrapper struct {
	tun       tun.Device
	forwarder func(string, int)
}

func NewTunWrapper(dev tun.Device, cb func(string, int)) tun.Device {
	return &TunWrapper{
		tun:       dev,
		forwarder: cb,
	}
}

func (w *TunWrapper) File() *os.File {
	return w.tun.File()
}

func (w *TunWrapper) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	return w.tun.Read(bufs, sizes, offset)
}

func (w *TunWrapper) Write(bufs [][]byte, offset int) (int, error) {
	for _, buf := range bufs {
		if len(buf) > offset+20 { // Min IPv4 header length
			packet := buf[offset:]
			version := packet[0] >> 4
			if version == 4 {
				// IPv4
				// IHL is lower 4 bits of first byte * 4
				ihl := int(packet[0]&0x0F) * 4
				protocol := packet[9]

				if protocol == 6 { // TCP
					// Check dest port
					if len(packet) >= ihl+4 { // Header + Ports
						// Dst Port is at bytes 2,3 of TCP header (which starts at ihl)
						tcpHeader := packet[ihl:]
						dstPort := binary.BigEndian.Uint16(tcpHeader[2:4])

						// SYN flag is byte 13 (offset 13 from tcpHeader start)
						// Flags: CWR ECE URG ACK PSH RST SYN FIN
						// SYN is 0x02
						// Pure SYN check: SYN bit (0x02) set AND ACK bit (0x10) NOT set
						// This ensures we only trigger for incoming connection requests (initial SYN)
						// and ignore SYN-ACK responses to our own outgoing connections.
						isSYN := (tcpHeader[13] & 0x02) != 0
						isACK := (tcpHeader[13] & 0x10) != 0

						if isSYN && !isACK {
							if w.forwarder != nil {
								w.forwarder("tcp", int(dstPort))
							}
						}
					}
				}
				if protocol == 17 { // UDP
					if len(packet) >= ihl+4 {
						udpHeader := packet[ihl:]
						dstPort := binary.BigEndian.Uint16(udpHeader[2:4])
						if w.forwarder != nil {
							w.forwarder("udp", int(dstPort))
						}
					}
				}
				if protocol == 1 { // ICMP
					if w.forwarder != nil {
						w.forwarder("icmp", 0)
					}
				}
			}
		}
	}
	return w.tun.Write(bufs, offset)
}

func (w *TunWrapper) Name() (string, error) {
	return w.tun.Name()
}

func (w *TunWrapper) Events() <-chan tun.Event {
	return w.tun.Events()
}

func (w *TunWrapper) Close() error {
	return w.tun.Close()
}

func (w *TunWrapper) MTU() (int, error) {
	return w.tun.MTU()
}

func (w *TunWrapper) BatchSize() int {
	return w.tun.BatchSize()
}
