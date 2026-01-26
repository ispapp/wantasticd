package netstack

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

// MDNSPacket is a minimal mDNS packet builder
type MDNSPacket struct {
	buf bytes.Buffer
}

func NewMDNSResponse(anCount uint16) *MDNSPacket {
	p := &MDNSPacket{}
	// Header: ID(2), Flags(2), QDCount(2), ANCount(2), NSCount(2), ARCount(2)
	binary.Write(&p.buf, binary.BigEndian, uint16(0))      // ID
	binary.Write(&p.buf, binary.BigEndian, uint16(0x8400)) // Flags: Response, Authoritative
	binary.Write(&p.buf, binary.BigEndian, uint16(0))      // QDCount
	binary.Write(&p.buf, binary.BigEndian, anCount)        // ANCount
	binary.Write(&p.buf, binary.BigEndian, uint16(0))      // NSCount
	binary.Write(&p.buf, binary.BigEndian, uint16(0))      // ARCount
	return p
}

func (p *MDNSPacket) WriteName(name string) {
	parts := strings.Split(name, ".")
	for _, part := range parts {
		if part == "" {
			continue
		}
		p.buf.WriteByte(byte(len(part)))
		p.buf.WriteString(part)
	}
	p.buf.WriteByte(0)
}

func (p *MDNSPacket) AddPTR(service, target string) {
	p.WriteName(service)
	binary.Write(&p.buf, binary.BigEndian, uint16(12))  // Type PTR
	binary.Write(&p.buf, binary.BigEndian, uint16(1))   // Class IN
	binary.Write(&p.buf, binary.BigEndian, uint32(120)) // TTL

	var data bytes.Buffer
	dp := &MDNSPacket{buf: data}
	dp.WriteName(target)

	binary.Write(&p.buf, binary.BigEndian, uint16(len(dp.buf.Bytes())))
	p.buf.Write(dp.buf.Bytes())
}

func (p *MDNSPacket) AddSRV(name string, port uint16, target string) {
	p.WriteName(name)
	binary.Write(&p.buf, binary.BigEndian, uint16(33))  // Type SRV
	binary.Write(&p.buf, binary.BigEndian, uint16(1))   // Class IN
	binary.Write(&p.buf, binary.BigEndian, uint32(120)) // TTL

	var data bytes.Buffer
	binary.Write(&data, binary.BigEndian, uint16(0)) // Priority
	binary.Write(&data, binary.BigEndian, uint16(0)) // Weight
	binary.Write(&data, binary.BigEndian, port)      // Port
	dp := &MDNSPacket{buf: data}
	dp.WriteName(target)

	binary.Write(&p.buf, binary.BigEndian, uint16(len(dp.buf.Bytes())))
	p.buf.Write(dp.buf.Bytes())
}

func (p *MDNSPacket) AddA(name string, ip string) {
	p.WriteName(name)
	binary.Write(&p.buf, binary.BigEndian, uint16(1))   // Type A
	binary.Write(&p.buf, binary.BigEndian, uint16(1))   // Class IN
	binary.Write(&p.buf, binary.BigEndian, uint32(120)) // TTL

	parsed := net.ParseIP(ip).To4()
	if parsed == nil {
		return
	}
	binary.Write(&p.buf, binary.BigEndian, uint16(4))
	p.buf.Write(parsed)
}

func (p *MDNSPacket) AddTXT(name string, kv map[string]string) {
	p.WriteName(name)
	binary.Write(&p.buf, binary.BigEndian, uint16(16))  // Type TXT
	binary.Write(&p.buf, binary.BigEndian, uint16(1))   // Class IN
	binary.Write(&p.buf, binary.BigEndian, uint32(120)) // TTL

	var data bytes.Buffer
	for k, v := range kv {
		s := fmt.Sprintf("%s=%s", k, v)
		data.WriteByte(byte(len(s)))
		data.WriteString(s)
	}

	binary.Write(&p.buf, binary.BigEndian, uint16(len(data.Bytes())))
	p.buf.Write(data.Bytes())
}

func (ns *Netstack) startMDNS(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "wantastic-agent"
	}
	hostname = strings.ReplaceAll(hostname, ".", "-")

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			ns.mu.RLock()
			stackPtr := ns.net
			ns.mu.RUnlock()
			if stackPtr == nil {
				continue
			}
			ns.broadcastMDNS(hostname)
		}
	}
}

func (ns *Netstack) broadcastMDNS(hostname string) {
	addr := "224.0.0.251:5353"

	// We want to send 4 records: PTR, SRV, A, TXT
	p := NewMDNSResponse(4)

	serviceName := "_wantastic._tcp.local"
	instanceName := fmt.Sprintf("%s.%s", hostname, serviceName)
	domainName := fmt.Sprintf("%s.local", hostname)

	prefixes := ns.config.Interface.Addresses
	if len(prefixes) == 0 {
		return
	}
	var myIP string
	for _, pref := range prefixes {
		if pref.Addr().Is4() {
			myIP = pref.Addr().String()
			break
		}
	}
	if myIP == "" {
		return
	}

	p.AddPTR(serviceName, instanceName)
	p.AddSRV(instanceName, 9034, domainName)
	p.AddA(domainName, myIP)
	p.AddTXT(instanceName, map[string]string{
		"os":      "agent",
		"version": "1.0.0",
		"host":    hostname,
	})

	conn, err := ns.DialContext(context.Background(), "udp", addr)
	if err != nil {
		return
	}
	defer conn.Close()
	conn.Write(p.buf.Bytes())
}
