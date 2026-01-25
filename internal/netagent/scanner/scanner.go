package scanner

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

type DialContext func(ctx context.Context, network, addr string) (net.Conn, error)

type Result struct {
	Port    int
	State   string
	Service string
}

func RunPortScan(ctx context.Context, dial DialContext, targetIP string) error {
	fmt.Printf("Starting advanced TCP Port Scan on %s (1-65535)...\n", targetIP)
	start := time.Now()

	results := make(chan Result)
	var wg sync.WaitGroup
	// Concurrency: 1024 workers
	sem := make(chan struct{}, 1024)

	// Scan 1 - 65535
	go func() {
		for p := 1; p <= 65535; p++ {
			wg.Add(1)
			go func(port int) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()

				// 800ms timeout - fast enough for LAN/VPN
				dCtx, cancel := context.WithTimeout(ctx, 800*time.Millisecond)
				defer cancel()
				conn, err := dial(dCtx, "tcp", net.JoinHostPort(targetIP, fmt.Sprintf("%d", port)))
				if err == nil {
					svc := GetServiceHint(port)
					results <- Result{Port: port, State: "open", Service: svc}
					conn.Close()
				}
			}(p)
		}
		wg.Wait()
		close(results)
	}()

	fmt.Printf("%-10s %-10s %-20s\n", "PORT", "STATE", "SERVICE")
	fmt.Println(strings.Repeat("-", 45))

	var found []Result
	for r := range results {
		found = append(found, r)
	}

	// Sort by port
	for i := 0; i < len(found); i++ {
		for j := i + 1; j < len(found); j++ {
			if found[i].Port > found[j].Port {
				found[i], found[j] = found[j], found[i]
			}
		}
	}

	if len(found) == 0 {
		fmt.Println("No open ports found (all 65535 scanned). Host might be down or fully filtered.")
	} else {
		for _, r := range found {
			fmt.Printf("%-10d %-10s %-20s\n", r.Port, r.State, r.Service)
		}
	}

	duration := time.Since(start)
	fmt.Printf("\nScan completed in %.2fs\n", duration.Seconds())
	return nil
}

func GetServiceHint(port int) string {
	switch port {
	case 21:
		return "ftp"
	case 22:
		return "ssh"
	case 23:
		return "telnet"
	case 25:
		return "smtp"
	case 53:
		return "dns"
	case 80:
		return "http"
	case 110:
		return "pop3"
	case 135:
		return "msrpc"
	case 139:
		return "netbios-ssn"
	case 143:
		return "imap"
	case 443:
		return "https"
	case 445:
		return "microsoft-ds"
	case 993:
		return "imaps"
	case 1055:
		return "wantastic-proxy"
	case 3000:
		return "hb-api"
	case 3306:
		return "mysql"
	case 3389:
		return "ms-wbt-server"
	case 5432:
		return "postgresql"
	case 5900:
		return "vnc"
	case 6379:
		return "redis"
	case 8080:
		return "http-proxy"
	case 8443:
		return "https-alt"
	case 9034:
		return "wantastic-agent"
	default:
		return "unknown"
	}
}
