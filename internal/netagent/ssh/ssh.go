package ssh

import (
	"context"
	"fmt"
	"net"
	"os"
	"time"

	"golang.org/x/crypto/ssh"
	ssh_agent "golang.org/x/crypto/ssh/agent"
	"golang.org/x/term"
)

type DialContext func(ctx context.Context, network, addr string) (net.Conn, error)

func Run(ctx context.Context, dial DialContext, user, host, port string) error {
	conn, err := dial(ctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		return fmt.Errorf("failed to dial: %w", err)
	}

	authMethods := []ssh.AuthMethod{}

	// 1. Try local SSH Agent
	if agentConn, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK")); err == nil {
		authMethods = append(authMethods, ssh.PublicKeysCallback(ssh_agent.NewClient(agentConn).Signers))
	}

	// 2. Try Keyboard-Interactive / Password by prompting
	passwordCallback := ssh.PasswordCallback(func() (string, error) {
		fmt.Printf("%s@%s's password: ", user, host)
		fd := int(os.Stdin.Fd())
		pass, err := term.ReadPassword(fd)
		fmt.Println()
		return string(pass), err
	})
	authMethods = append(authMethods, passwordCallback)

	sshConfig := &ssh.ClientConfig{
		User:            user,
		Auth:            authMethods,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}

	sshConn, chans, reqs, err := ssh.NewClientConn(conn, host, sshConfig)
	if err != nil {
		return fmt.Errorf("ssh handshake failed: %w", err)
	}
	client := ssh.NewClient(sshConn, chans, reqs)
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("failed to create session: %w", err)
	}
	defer session.Close()

	fd := int(os.Stdin.Fd())
	state, err := term.MakeRaw(fd)
	if err == nil {
		defer term.Restore(fd, state)
	}

	w, h, _ := term.GetSize(fd)
	if err := session.RequestPty("xterm-256color", h, w, ssh.TerminalModes{
		ssh.ECHO:          1,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}); err != nil {
		return fmt.Errorf("request for PTY failed: %w", err)
	}

	session.Stdout = os.Stdout
	session.Stderr = os.Stderr
	session.Stdin = os.Stdin

	if err := session.Shell(); err != nil {
		return fmt.Errorf("failed to start shell: %w", err)
	}

	return session.Wait()
}
