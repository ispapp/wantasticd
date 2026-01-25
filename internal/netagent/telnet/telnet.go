package telnet

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"

	"golang.org/x/term"
)

type DialContext func(ctx context.Context, network, addr string) (net.Conn, error)

func Run(ctx context.Context, dial DialContext, host, port string) error {
	target := net.JoinHostPort(host, port)
	fmt.Printf("Connecting to %s via wantasticd netstack...\n", target)

	conn, err := dial(ctx, "tcp", target)
	if err != nil {
		return fmt.Errorf("failed to connect: %w", err)
	}
	defer conn.Close()

	fmt.Printf("Connected to %s.\n", host)
	fmt.Println("Escape character is '^]'.")

	fd := int(os.Stdin.Fd())
	state, err := term.MakeRaw(fd)
	if err == nil {
		defer term.Restore(fd, state)
	}

	done := make(chan error, 2)

	go func() {
		_, err := io.Copy(conn, os.Stdin)
		done <- err
	}()

	go func() {
		_, err := io.Copy(os.Stdout, conn)
		done <- err
	}()

	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}
