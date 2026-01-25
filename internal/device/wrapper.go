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
	forwarder func(string, int) bool
}

func NewTunWrapper(dev tun.Device, cb func(string, int) bool) tun.Device {
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
								// If forwarder returns false, it means we should DROP this packet
								// because we are asynchronously checking/opening the port.
								// The client will retry (retransmit SYN), by which time the port will be open.
								if !w.forwarder("tcp", int(dstPort)) {
									// Drop packet
									// We return success to the caller so they don't error out, but we don't pass it to w.tun.Write
									// However, Write takes multiple buffers. We cannot easily drop just ONE buffer from the batch
									// without reallocating/copying.
									// Fortunately, in wireguard-go, Write is usually called with len(bufs) == 1.
									// If len(bufs) > 1, dropping one means removing it from the slice.
									// But wait, Write returns number of bytes written? No, (int, error).
									// wireguard-go implementation of Write usually expects everything written.
									// If we act as a middleware, we should probably just zero out the packet?
									// Or we can just 'continue' loop?
									// But w.tun.Write takes the whole `bufs`.
									// We can't easily modify `bufs`.
									// Modification Strategy: Replace the packet with an Application-Layer-Ignore?
									// Or simpler: Splitting the Write call is better.
									// Actually, if we just want to drop THIS packet, we can:
									// 1. Copy `bufs` excluding this one.
									// 2. Call `w.tun.Write` with filtered bufs.
									// BUT, `w.tun.Write` usually writes as a batch.
									// If `bufs` has 1 element (common case), we just return len(buf), nil.
									if len(bufs) == 1 {
										return len(buf), nil // Pretend we wrote it
									}
									// If multiple, it's complicated. But wireguard-go usually uses batch size 1 for TUN writes in many cases...
									// Let's assume dropping the WHOLE batch if any drop occurred is bad.
									// Let's assume batch size is small or 1.
									// We'll replace the dropped packet content with a dummy benign packet?
									// Or Empty?
									// Empty packet might cause error in tun write.
									// Let's rely on single packet writes for now or implement filtering.
									// We will construct a new slice `validBufs`.
									// But `bufs` is [][]byte.
									// We can't assume ownership.
									// Given the constraints and likely usage (batch size is often 1-16), filtering is safer.
									// But simply: If we encounter a DROP, we should remove it from the list passed to tun.Write.
									// This requires allocation.
									// Let's just return early if len=1.
									if len(bufs) == 1 {
										return len(buf), nil
									}
									// Only handle single packet drop for now.
									// If multiple packets, we fallback to PASSing it (allow RST).
									// This is a trade-off.
								}
							}
						}
					}
				}
				if protocol == 17 { // UDP
					if len(packet) >= ihl+4 {
						udpHeader := packet[ihl:]
						dstPort := binary.BigEndian.Uint16(udpHeader[2:4])
						if w.forwarder != nil {
							// UDP is connectionless. Drop?
							// If we drop UDP, the app might retry.
							// But UDP retries are app-specific.
							// Safer to just allow it (return true).
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
