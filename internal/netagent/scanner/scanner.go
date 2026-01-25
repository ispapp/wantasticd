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
	fmt.Printf("Starting professional port scan on %s via VPN...\n", targetIP)

	// High priority ports
	common := []int{21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 1055, 1723, 3000, 3306, 3389, 5432, 5900, 6379, 8000, 8080, 8443, 9034}

	uniquePorts := make(map[int]bool)
	for _, p := range common {
		uniquePorts[p] = true
	}
	for i := 1; i <= 1024; i++ {
		uniquePorts[i] = true
	}

	results := make(chan Result)
	var wg sync.WaitGroup
	sem := make(chan struct{}, 128)

	go func() {
		for port := range uniquePorts {
			wg.Add(1)
			go func(p int) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()

				dCtx, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
				conn, err := dial(dCtx, "tcp", net.JoinHostPort(targetIP, fmt.Sprintf("%d", p)))
				cancel()
				if err == nil {
					svc := GetServiceHint(p)
					results <- Result{Port: p, State: "open", Service: svc}
					conn.Close()
				}
			}(port)
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

	for _, r := range found {
		fmt.Printf("%-10d %-10s %-20s\n", r.Port, r.State, r.Service)
	}
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
