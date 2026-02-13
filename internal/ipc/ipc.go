package ipc

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
	"wantastic-agent/internal/device"
	"wantastic-agent/internal/netstack"
)

const SocketName = "wantasticd.sock"

func GetSocketPath() string {
	if path := os.Getenv("WANTASTIC_UNIX"); path != "" {
		return path
	}

	// 1. Check User Home (Default)
	home, _ := os.UserHomeDir()
	userPath := filepath.Join(home, ".wantastic", SocketName)
	if _, err := os.Stat(userPath); err == nil {
		return userPath
	}

	// 2. Check Global /var/run (for root daemon)
	if _, err := os.Stat("/var/run/" + SocketName); err == nil {
		return "/var/run/" + SocketName
	}

	// 3. Check /tmp (fallback)
	if _, err := os.Stat("/tmp/" + SocketName); err == nil {
		return "/tmp/" + SocketName
	}

	// Default to user path if nothing found (e.g. for creating new server)
	return userPath
}

// Server listens on a unix socket and proxies dial requests to the netstack
type Server struct {
	netstack *netstack.Netstack
	device   *device.Device
	listener net.Listener
	stopCh   chan struct{}
	wg       sync.WaitGroup
}

func NewServer(ns *netstack.Netstack, dev *device.Device) *Server {
	return &Server{
		netstack: ns,
		device:   dev,
		stopCh:   make(chan struct{}),
	}
}

func (s *Server) Start() error {
	socketPath := GetSocketPath()
	os.MkdirAll(filepath.Dir(socketPath), 0700)
	os.Remove(socketPath) // Cleanup previous

	l, err := net.Listen("unix", socketPath)
	if err != nil {
		return err
	}
	s.listener = l

	s.wg.Add(1)
	go s.serve()
	return nil
}

func (s *Server) serve() {
	defer s.wg.Done()
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-s.stopCh:
				return // Stopped
			default:
				log.Printf("IPC accept error: %v", err)
				continue
			}
		}
		go s.handleConnection(conn)
	}
}

func (s *Server) Stop() {
	close(s.stopCh)
	if s.listener != nil {
		s.listener.Close()
	}
	s.wg.Wait()
}

func (s *Server) handleConnection(c net.Conn) {
	defer c.Close()

	// Protocol:
	// Client sends: "CONNECT <host>:<port>\n"
	// Server responds: "OK\n" or "ERROR <msg>\n"
	// Then streams data

	r := bufio.NewReader(c)
	line, err := r.ReadString('\n')
	if err != nil {
		return
	}
	line = strings.TrimSpace(line)
	parts := strings.SplitN(line, " ", 2)
	if len(parts) < 2 {
		fmt.Fprintf(c, "ERROR invalid command\n")
		return
	}

	cmd := parts[0]
	target := parts[1]

	switch cmd {
	case "CONNECT":
		network := "tcp"
		addr := target

		// Check if target contains network hint or if we have 3 parts
		// Protocol: CONNECT <network> <addr> OR CONNECT <addr> (legacy)
		// Re-split line to be safe.
		parts := strings.Split(line, " ")
		if len(parts) >= 3 {
			network = parts[1]
			addr = parts[2]
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		targetConn, err := s.netstack.DialContext(ctx, network, addr)
		if err != nil {
			fmt.Fprintf(c, "ERROR dial failed: %v\n", err)
			return
		}
		defer targetConn.Close()

		fmt.Fprintf(c, "OK\n")

		// Handle potential buffered data from 'r'
		var clientReader io.Reader = c
		if r.Buffered() > 0 {
			clientReader = io.MultiReader(io.LimitReader(r, int64(r.Buffered())), c)
		}

		// Bidirectional copy
		go io.Copy(targetConn, clientReader)
		io.Copy(c, targetConn)

	case "PING":
		rtt, err := s.netstack.Ping(context.Background(), target)
		if err != nil {
			fmt.Fprintf(c, "ERROR ping failed: %v\n", err)
			return
		}
		fmt.Fprintf(c, "OK %d\n", rtt.Nanoseconds())

	case "STATUS":
		if s.device == nil {
			fmt.Fprintf(c, "ERROR device not available\n")
			return
		}
		stats, err := s.device.GetStats()
		if err != nil {
			fmt.Fprintf(c, "ERROR get stats: %v\n", err)
			return
		}

		// Also get data transfer stats
		rx, tx, _ := s.device.GetTransferStats()
		stats["rx_bytes"] = rx
		stats["tx_bytes"] = tx
		stats["public_key"] = s.device.GetPublicKey()

		// Serialize to JSON
		data, err := json.Marshal(stats)
		if err != nil {
			fmt.Fprintf(c, "ERROR marshal stats: %v\n", err)
			return
		}
		fmt.Fprintf(c, "OK %s\n", string(data))

	case "CURL":
		req, err := http.NewRequest("GET", target, nil)
		if err != nil {
			fmt.Fprintf(c, "ERROR curl req failed: %v\n", err)
			return
		}
		// Mimic macOS curl
		req.Header.Set("User-Agent", "curl/8.4.0")
		req.Header.Set("Accept", "*/*")

		client := &http.Client{
			Transport: &http.Transport{
				DialContext: s.netstack.DialContext,
			},
		}
		resp, err := client.Do(req)
		if err != nil {
			fmt.Fprintf(c, "ERROR curl failed: %v\n", err)
			return
		}
		defer resp.Body.Close()
		fmt.Fprintf(c, "OK %s\n", resp.Status)
		io.Copy(c, resp.Body)

	default:
		fmt.Fprintf(c, "ERROR unknown command\n")
	}
}

// Client helper
func Dial(network, target string) (net.Conn, error) {
	socketPath := GetSocketPath()
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		return nil, err
	}

	fmt.Fprintf(conn, "CONNECT %s %s\n", network, target)

	r := bufio.NewReader(conn)
	resp, err := r.ReadString('\n')
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("read ipc response: %w", err)
	}

	if strings.HasPrefix(resp, "OK") {
		// Return a wrapper that handles the already-read buffer if needed?
		// Actually bufio might have buffered legitimate data if the server sent data fast.
		// Wait, server sends OK, then waits for data or sends data.
		// If server sends data immediately after OK, 'r' has it.
		// We need to return a connection that reads from 'r' then 'conn'.
		return &bufferedConn{conn: conn, r: r}, nil
	}

	conn.Close()
	return nil, fmt.Errorf("ipc error: %s", strings.TrimSpace(resp))
}

// Ping performs an ICMP ping via the daemon
func Ping(ctx context.Context, target string) (time.Duration, error) {
	socketPath := GetSocketPath()
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", socketPath)
	if err != nil {
		return 0, err
	}

	// Ensure connection is closed on context cancellation to unblock ReadString
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			conn.Close()
		case <-done:
		}
	}()
	defer conn.Close()

	fmt.Fprintf(conn, "PING %s\n", target)

	r := bufio.NewReader(conn)
	resp, err := r.ReadString('\n')
	if err != nil {
		//Check context error first to return correct reason
		if ctx.Err() != nil {
			return 0, ctx.Err()
		}
		return 0, fmt.Errorf("read ipc response: %w", err)
	}

	if strings.HasPrefix(resp, "OK") {
		parts := strings.Split(strings.TrimSpace(resp), " ")
		if len(parts) < 2 {
			return 0, fmt.Errorf("invalid ping response")
		}
		ns, err := strconv.ParseInt(parts[1], 10, 64)
		if err != nil {
			return 0, fmt.Errorf("parse rtt: %w", err)
		}
		return time.Duration(ns), nil
	}

	return 0, fmt.Errorf("ipc error: %s", strings.TrimSpace(resp))
}

type bufferedConn struct {
	conn net.Conn
	r    *bufio.Reader
}

// Curl performs an HTTP GET via the daemon
func Curl(url string, stdout io.Writer, stderr io.Writer) error {
	socketPath := GetSocketPath()
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		return err
	}
	defer conn.Close()

	fmt.Fprintf(conn, "CURL %s\n", url)

	r := bufio.NewReader(conn)
	resp, err := r.ReadString('\n')
	if err != nil {
		return fmt.Errorf("read ipc response: %w", err)
	}

	if strings.HasPrefix(resp, "OK") {
		if stderr != nil {
			fmt.Fprintf(stderr, "< %s\n", strings.TrimSpace(resp[3:]))
		}
		_, err = io.Copy(stdout, r)
		return err
	}

	return fmt.Errorf("ipc error: %s", strings.TrimSpace(resp))
}

func (b *bufferedConn) Read(p []byte) (n int, err error) {
	return b.r.Read(p)
}
func (b *bufferedConn) Write(p []byte) (n int, err error) {
	return b.conn.Write(p)
}
func (b *bufferedConn) Close() error {
	return b.conn.Close()
}
func (b *bufferedConn) LocalAddr() net.Addr {
	return b.conn.LocalAddr()
}
func (b *bufferedConn) RemoteAddr() net.Addr {
	return b.conn.RemoteAddr()
}
func (b *bufferedConn) SetDeadline(t time.Time) error {
	return b.conn.SetDeadline(t)
}
func (b *bufferedConn) SetReadDeadline(t time.Time) error {
	return b.conn.SetReadDeadline(t)
}
func (b *bufferedConn) SetWriteDeadline(t time.Time) error {
	return b.conn.SetWriteDeadline(t)
}

// GetStatus retrieves the status from the daemon
func GetStatus() (map[string]any, error) {
	socketPath := GetSocketPath()
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	fmt.Fprintf(conn, "STATUS\n")

	r := bufio.NewReader(conn)
	resp, err := r.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("read ipc response: %w", err)
	}

	if strings.HasPrefix(resp, "OK") {
		jsonStr := strings.TrimSpace(resp[3:])
		var result map[string]any
		if err := json.Unmarshal([]byte(jsonStr), &result); err != nil {
			return nil, fmt.Errorf("unmarshal status: %w", err)
		}
		return result, nil
	}

	return nil, fmt.Errorf("ipc error: %s", strings.TrimSpace(resp))
}
