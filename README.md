# wantastic-agent
wantastic custom userspace wireguard client

Planned CLI commands:
- fetch: Acquire WireGuard config over wss, validate, and write to /etc/wireguard/wg0.conf
- up: Bring up a userspace WireGuard device (wireguard-go) with optional route install
- down: Tear down the userspace WireGuard device
- status: Show device and peer state
- doctor: Check environment (capabilities, write perms, TUN availability)

Build notes:
- Pure Go (CGO_DISABLED=1) targeting broad GOOS/GOARCH matrix per go tool dist list.
- Uses golang.zx2c4.com/wireguard for userspace device support.
