package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"wantastic-wgclient/internal/config"
	"wantastic-wgclient/internal/store"
	"wantastic-wgclient/internal/wgcontrol"
	"wantastic-wgclient/internal/wss"
)

var version = "dev"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	cmd := os.Args[1]
	switch cmd {
	case "fetch":
		fetchCmd(os.Args[2:])
	case "up":
		upCmd(os.Args[2:])
	case "down":
		downCmd(os.Args[2:])
	case "status":
		statusCmd(os.Args[2:])
	case "doctor":
		doctorCmd(os.Args[2:])
	case "help", "-h", "--help":
		usage()
	case "version", "--version", "-v":
		fmt.Printf("wantastic-wgclient %s\n", version)
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", cmd)
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, "wantastic-wgclient %s\n", version)
	fmt.Fprintf(os.Stderr, "\nUsage:\n")
	fmt.Fprintf(os.Stderr, "  wantastic-wgclient <command> [flags]\n\n")
	fmt.Fprintf(os.Stderr, "Commands:\n")
	fmt.Fprintf(os.Stderr, "  fetch    Fetch config via wss and persist to /etc/wireguard/wg0.conf\n")
	fmt.Fprintf(os.Stderr, "  up       Bring up userspace WireGuard device\n")
	fmt.Fprintf(os.Stderr, "  down     Bring down userspace WireGuard device\n")
	fmt.Fprintf(os.Stderr, "  status   Show device and peer state\n")
	fmt.Fprintf(os.Stderr, "  doctor   Check environment and capabilities\n")
}

func fetchCmd(args []string) {
	fs := flag.NewFlagSet("fetch", flag.ExitOnError)
	token := fs.String("token", "", "token to use; if empty, request one via wss")
	output := fs.String("output", "/etc/wireguard/wg0.conf", "output config path")
	timeout := fs.Duration("timeout", 120*time.Second, "timeout waiting for config (default 120s)")
	jsonOut := fs.Bool("json", false, "emit machine-readable JSON")
	base := fs.String("base", "", "override websocket base (for testing)")
	fs.Parse(args)

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	client := &wss.Client{BaseURL: *base}

	tok := strings.TrimSpace(*token)
	link := ""
	if tok == "" {
		mac, err := wss.FirstMAC()
		if err != nil {
			fatal("failed to read mac address: %v", err)
		}
		req := wss.TokenRequest{Hostname: wss.Hostname(), MacAddr: mac}
		tok, link, err = client.RequestToken(ctx, req)
		if err != nil {
			fatal("request token: %v", err)
		}
		fmt.Fprintf(os.Stdout, "deploy_link=%s\n", link)
	}

	raw, err := client.WaitConfig(ctx, tok)
	if err != nil {
		fatal("waiting for config: %v", err)
	}
	cfg, err := config.Parse(string(raw))
	if err != nil {
		fatal("invalid config: %v", err)
	}
	if err := store.AtomicWrite(*output, []byte(cfg.Raw), 0o600); err != nil {
		fatal("write config: %v", err)
	}
	if *jsonOut {
		fmt.Fprintf(os.Stdout, "{\"status\":\"ok\",\"token\":\"%s\",\"link\":\"%s\",\"path\":\"%s\"}\n", tok, link, *output)
		return
	}
	fmt.Fprintf(os.Stdout, "config saved to %s\n", *output)
}

func upCmd(args []string) {
	fs := flag.NewFlagSet("up", flag.ExitOnError)
	configPath := fs.String("config", "/etc/wireguard/wg0.conf", "config path")
	installRoutes := fs.Bool("install-routes", false, "install routes from config (no iptables)")
	useNetstack := fs.Bool("netstack", true, "use userspace netstack (recommended)")
	fs.Parse(args)

	cfg, err := config.Load(*configPath)
	if err != nil {
		fatal("load config: %v", err)
	}
	if *installRoutes {
		fmt.Fprintln(os.Stderr, "note: route installation not yet implemented; skipping")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, err = wgcontrol.Start(ctx, cfg, "wg0", *useNetstack)
	if err != nil {
		fatal("start device: %v", err)
	}
	fmt.Println("device up (Ctrl+C to stop)")
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	<-sigs
	fmt.Println("shutting down")
}

func downCmd(args []string) {
	fs := flag.NewFlagSet("down", flag.ExitOnError)
	deviceName := fs.String("device", "wg0", "device name")
	fs.Parse(args)

	if err := wgcontrol.Down(*deviceName); err != nil {
		fatal("down: %v", err)
	}
	fmt.Println("device removed")
}

func statusCmd(args []string) {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	deviceName := fs.String("device", "wg0", "device name")
	fs.Parse(args)

	info, err := wgcontrol.Status(*deviceName)
	if err != nil {
		fatal("status: %v", err)
	}
	fmt.Print(info)
}

func doctorCmd(args []string) {
	fs := flag.NewFlagSet("doctor", flag.ExitOnError)
	fs.Parse(args)

	checks := wgcontrol.Doctor()
	for _, line := range checks {
		fmt.Println(line)
	}
}

func fatal(format string, a ...interface{}) {
	log.Fatalf(format, a...)
}
