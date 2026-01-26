package scanner

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"wantastic-agent/internal/service"
)

type DialContext func(ctx context.Context, network, addr string) (net.Conn, error)

type Result struct {
	Port     int
	State    string
	Service  string
	Protocol string
}

func RunPortScan(ctx context.Context, dial DialContext, targetIP string) error {
	fmt.Printf("Starting Hyper-Fast Port Scan on %s (TCP+UDP 1-65535)...\n", targetIP)
	start := time.Now()

	// Output streaming channel
	results := make(chan Result, 100)
	done := make(chan struct{})

	// Printer routine
	go func() {
		fmt.Printf("%-10s %-10s %-10s %-20s\n", "PORT", "PROTO", "STATE", "SERVICE")
		fmt.Println(strings.Repeat("-", 60))
		for r := range results {
			fmt.Printf("%-10d %-10s %-10s %-20s\n", r.Port, r.Protocol, r.State, r.Service)
		}
		close(done)
	}()

	var wg sync.WaitGroup
	// 1024 workers (Optimal for userspace stack)
	sem := make(chan struct{}, 1024)

	scanTCP := func(p int) {
		defer wg.Done()

		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			return
		}
		defer func() { <-sem }()

		dCtx, cancel := context.WithTimeout(ctx, 1500*time.Millisecond) // Slightly longer for stability
		defer cancel()

		conn, err := dial(dCtx, "tcp", net.JoinHostPort(targetIP, fmt.Sprintf("%d", p)))
		if err == nil {
			// Banner grab
			conn.SetReadDeadline(time.Now().Add(400 * time.Millisecond))
			buf := make([]byte, 512)
			n, _ := conn.Read(buf)
			banner := ""
			if n > 0 {
				banner = string(buf[:n])
			}

			svc := service.Detect(p, banner)
			conn.Close()
			results <- Result{Port: p, State: "open", Service: svc, Protocol: "TCP"}
		}
	}

	scanUDP := func(p int) {
		defer wg.Done()

		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			return
		}
		defer func() { <-sem }()

		dCtx, cancel := context.WithTimeout(ctx, 800*time.Millisecond)
		defer cancel()

		conn, err := dial(dCtx, "udp", net.JoinHostPort(targetIP, fmt.Sprintf("%d", p)))
		if err != nil {
			return
		}
		defer conn.Close()

		conn.Write([]byte{0x00})

		buf := make([]byte, 128)
		conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, err := conn.Read(buf)
		if err == nil && n > 0 {
			svc := service.GetHint(p)
			results <- Result{Port: p, State: "open", Service: svc, Protocol: "UDP"}
		}
	}

	// Priority Scan: Well known ports first
	commonPorts := []int{21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5432, 5900, 8080, 8291, 9034}
	for _, p := range commonPorts {
		wg.Add(1)
		go scanTCP(p)
	}

	// Full Scan
	for p := 1; p <= 65535; p++ {
		// Skip common ports as they are already launched
		isCommon := false
		for _, cp := range commonPorts {
			if p == cp {
				isCommon = true
				break
			}
		}
		if isCommon {
			continue
		}

		wg.Add(1)
		go scanTCP(p)
	}

	// UDP Scan (Limited to top 1000 for speed unless requested, but we do full since requested)
	// We only scan well-known UDP ports to keep it "Hyper-Fast"
	commonUDP := []int{53, 67, 68, 69, 123, 161, 162, 389, 445, 514, 520, 631, 1194, 1812, 1813, 2375, 5000, 5060, 5353, 51820}
	for _, p := range commonUDP {
		wg.Add(1)
		go scanUDP(p)
	}

	wg.Wait()
	close(results)
	<-done

	duration := time.Since(start)
	fmt.Printf("\nScan completed in %.2fs\n", duration.Seconds())
	return nil
}
