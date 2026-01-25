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

	// Shared password provider to avoid double prompting
	var cachedPassword string
	getPassword := func() (string, error) {
		if cachedPassword != "" {
			return cachedPassword, nil
		}
		fmt.Printf("%s@%s's password: ", user, host)
		pass, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		if err != nil {
			return "", err
		}
		cachedPassword = string(pass)
		return cachedPassword, nil
	}

	// 2. Try Keyboard-Interactive (common on some distros/devices)
	keyboardInteractive := ssh.KeyboardInteractive(func(name, instruction string, questions []string, echos []bool) (answers []string, err error) {
		if len(questions) == 0 {
			return nil, nil
		}
		if instruction != "" {
			fmt.Println(instruction)
		}
		for i, q := range questions {
			// If it looks like a password prompt and echo is off, try to use cached password or prompt
			if !echos[i] {
				// We don't print the question if we use cached, but for the first time we should probably just use our standard prompt?
				// Actually, K-I questions can be anything. We should respect them.
				// But if we want to "mock" the standard ssh behavior where users just type password...
				// Let's just prompt.
				// But if we already have a cached password?
				if cachedPassword != "" {
					answers = append(answers, cachedPassword)
					continue
				}

				fmt.Print(q)
				pass, err := term.ReadPassword(int(os.Stdin.Fd()))
				fmt.Println()
				if err != nil {
					return nil, err
				}
				cachedPassword = string(pass)
				answers = append(answers, cachedPassword)
			} else {
				fmt.Print(q)
				var ans string
				fmt.Scanln(&ans)
				answers = append(answers, ans)
			}
		}
		return answers, nil
	})
	authMethods = append(authMethods, keyboardInteractive)

	// 3. Try Password (legacy)
	passwordCallback := ssh.PasswordCallback(func() (string, error) {
		return getPassword()
	})
	authMethods = append(authMethods, passwordCallback)

	sshConfig := &ssh.ClientConfig{
		User:            user,
		Auth:            authMethods,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         30 * time.Second,
		// Enable legacy algorithms for compatibility
		HostKeyAlgorithms: []string{
			ssh.KeyAlgoRSA,
			ssh.KeyAlgoDSA,
			ssh.KeyAlgoECDSA256,
			ssh.KeyAlgoECDSA384,
			ssh.KeyAlgoECDSA521,
			ssh.KeyAlgoED25519,
		},
	}
	// Allow all ciphers/kex by default (Go's defaults are usually safe but restrictive)
	sshConfig.Config.SetDefaults()
	sshConfig.Ciphers = append(sshConfig.Ciphers, "aes128-cbc", "3des-cbc", "aes256-cbc", "aes128-ctr", "aes192-ctr", "aes256-ctr")

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
