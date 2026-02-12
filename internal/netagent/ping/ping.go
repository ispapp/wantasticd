package ping

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"
)

type DialContext func(ctx context.Context, network, addr string) (net.Conn, error)

type Pinger interface {
	Ping(ctx context.Context, host string) (time.Duration, error)
}

type Stats struct {
	Sent     int
	Received int
	MinRTT   time.Duration
	MaxRTT   time.Duration
	TotalRTT time.Duration
}

func Run(ctx context.Context, dial DialContext, pinger Pinger, host string, count int, interval time.Duration) error {
	fmt.Printf("PING %s (%s): via wantasticd netstack\n", host, host)

	// Create cancellable context for immediate shutdown on signal
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	stats := &Stats{
		MinRTT: 1 * time.Hour,
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// Forward signals to context cancellation
	go func() {
		select {
		case <-sigCh:
			cancel()
		case <-ctx.Done():
		}
	}()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	probe := func(seq int) {
		stats.Sent++

		// Attempt ICMP via dialer (daemon should handle "ping" protocol)
		// Or fallback to TCP SYN if "ping" fails
		var rtt time.Duration
		err := tryPing(ctx, dial, pinger, host, &rtt)

		if err != nil {
			// Don't print timeout if cancelled
			if ctx.Err() == nil {
				fmt.Printf("Request timeout for seq %d\n", seq)
			}
		} else {
			stats.Received++
			stats.TotalRTT += rtt
			if rtt < stats.MinRTT {
				stats.MinRTT = rtt
			}
			if rtt > stats.MaxRTT {
				stats.MaxRTT = rtt
			}
			fmt.Printf("64 bytes from %s: icmp_seq=%d time=%.3f ms\n", host, seq, float64(rtt.Nanoseconds())/1e6)
		}
	}

	seq := 1
	for {
		// Check context before probing
		if ctx.Err() != nil {
			printStats(host, stats)
			return ctx.Err()
		}

		probe(seq)
		if count > 0 && seq >= count {
			break
		}
		seq++

		select {
		case <-ticker.C:
		case <-ctx.Done():
			printStats(host, stats)
			return ctx.Err()
		}
	}

	printStats(host, stats)
	return nil
}

func tryPing(ctx context.Context, dial DialContext, pinger Pinger, host string, rtt *time.Duration) error {
	start := time.Now()
	// 1. Try ICMP "ping" protocol
	// If Pinger interface is provided (e.g. IPC specialized ping), use it.
	if pinger != nil {
		d, err := pinger.Ping(ctx, host)
		if err == nil {
			*rtt = d
			return nil
		}
		// If specialized ping fails, fallback to stream ping (if implemented) or TCP
	} else {
		// Legacy / Stream Ping logic
		ctxPing, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()

		conn, err := dial(ctxPing, "ping", host)
		if err == nil {
			// Ensure closure on context cancel to unblock Read
			go func() {
				<-ctxPing.Done()
				conn.Close()
			}()
			defer conn.Close()

			conn.SetDeadline(time.Now().Add(2 * time.Second))
			msg := []byte("WANT")
			if _, err := conn.Write(msg); err == nil {
				buf := make([]byte, 64)
				if n, err := conn.Read(buf); err == nil && n >= 0 {
					*rtt = time.Since(start)
					return nil
				}
			}
		}
	}

	// 2. Fallback: TCP SYN on port 22
	// We use 22 because it's standard and likely to respond with RST or SYN-ACK
	ctxTCP, cancelTCP := context.WithTimeout(ctx, 1500*time.Millisecond)
	defer cancelTCP()

	conn, err := dial(ctxTCP, "tcp", net.JoinHostPort(host, "22"))
	if err == nil {
		conn.Close()
		*rtt = time.Since(start)
		return nil
	}

	return err
}

func printStats(host string, s *Stats) {
	fmt.Printf("\n--- %s ping statistics ---\n", host)
	loss := 0.0
	if s.Sent > 0 {
		loss = float64(s.Sent-s.Received) / float64(s.Sent) * 100
	}
	fmt.Printf("%d packets transmitted, %d packets received, %.1f%% packet loss\n", s.Sent, s.Received, loss)
	if s.Received > 0 {
		avg := s.TotalRTT / time.Duration(s.Received)
		fmt.Printf("round-trip min/avg/max = %.3f/%.3f/%.3f ms\n",
			float64(s.MinRTT.Nanoseconds())/1e6,
			float64(avg.Nanoseconds())/1e6,
			float64(s.MaxRTT.Nanoseconds())/1e6)
	}
}
