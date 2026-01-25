package ipc

import (
	"bufio"
	"context"
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
	"wantastic-agent/internal/netstack"
)

const SocketName = "wantasticd.sock"

func GetSocketPath() string {
	if path := os.Getenv("WANTASTIC_UNIX"); path != "" {
		return path
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".wantastic", SocketName)
}

// Server listens on a unix socket and proxies dial requests to the netstack
type Server struct {
	netstack *netstack.Netstack
	listener net.Listener
	stopCh   chan struct{}
	wg       sync.WaitGroup
}

func NewServer(ns *netstack.Netstack) *Server {
	return &Server{
		netstack: ns,
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
		// We already split by " " into 2 parts. If target has spaces, it might be the new format.
		// Re-split line to be safe.
		parts := strings.Split(line, " ")
		if len(parts) >= 3 {
			network = parts[1]
			addr = parts[2]
		}

		targetConn, err := s.netstack.DialContext(context.Background(), network, addr)
		if err != nil {
			fmt.Fprintf(c, "ERROR dial failed: %v\n", err)
			return
		}
		defer targetConn.Close()

		fmt.Fprintf(c, "OK\n")
		go io.Copy(targetConn, c)
		io.Copy(c, targetConn)

	case "PING":
		rtt, err := s.netstack.Ping(context.Background(), target)
		if err != nil {
			fmt.Fprintf(c, "ERROR ping failed: %v\n", err)
			return
		}
		fmt.Fprintf(c, "OK %d\n", rtt.Nanoseconds())

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
func Ping(target string) (time.Duration, error) {
	socketPath := GetSocketPath()
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		return 0, err
	}
	defer conn.Close()

	fmt.Fprintf(conn, "PING %s\n", target)

	r := bufio.NewReader(conn)
	resp, err := r.ReadString('\n')
	if err != nil {
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
