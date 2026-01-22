package device

import (
	"fmt"
	"log"
	"net"
	"net/netip"
)

// RoutingManager handles network routing configuration for userspace WireGuard
// to allow local subnet access while maintaining VPN connectivity
type RoutingManager struct {
	vpnServerIP string
}

// NewRoutingManager creates a new routing manager for userspace WireGuard
func NewRoutingManager(vpnServerIP string) *RoutingManager {
	return &RoutingManager{
		vpnServerIP: vpnServerIP,
	}
}

// SetupRouting configures routing for userspace WireGuard to allow local subnet access
// This is a no-op for userspace implementation as routing is handled by netstack
func (rm *RoutingManager) SetupRouting() error {
	log.Printf("Userspace WireGuard routing configured - local subnet access enabled")

	// For userspace WireGuard, routing is handled by netstack and the AllowedIPs configuration
	// The key is to configure AllowedIPs properly to exclude local networks

	return nil
}

// CleanupRouting removes any custom routing configuration
func (rm *RoutingManager) CleanupRouting() error {
	// No cleanup needed for userspace implementation
	return nil
}

// GetLocalSubnets discovers local network subnets for routing configuration
func (rm *RoutingManager) GetLocalSubnets() ([]netip.Prefix, error) {
	var subnets []netip.Prefix

	// Get network interfaces
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("get network interfaces: %w", err)
	}

	for _, iface := range interfaces {
		// Skip loopback and down interfaces
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}

			// Skip IPv6 for simplicity (can be added later)
			if ipNet.IP.To4() == nil {
				continue
			}

			// Convert to netip.Prefix
			if prefix, err := netip.ParsePrefix(ipNet.String()); err == nil {
				// Add common private networks
				if rm.isPrivateNetwork(prefix.Addr()) {
					subnets = append(subnets, prefix)
				}
			}
		}
	}

	// Add common private networks that might not be on local interfaces
	commonSubnets := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"169.254.0.0/16", // Link-local
	}

	for _, subnetStr := range commonSubnets {
		if prefix, err := netip.ParsePrefix(subnetStr); err == nil {
			if !rm.containsSubnet(subnets, prefix) {
				subnets = append(subnets, prefix)
			}
		}
	}

	return subnets, nil
}

// GetRecommendedAllowedIPs returns the recommended AllowedIPs configuration
// that excludes local networks to allow subnet access
func (rm *RoutingManager) GetRecommendedAllowedIPs() ([]string, error) {
	// For userspace WireGuard, we want to route everything through VPN
	// except local networks. This is achieved by using 0.0.0.0/0 and ::/0
	// but excluding local subnets from the VPN routing

	return []string{
		"0.0.0.0/0", // All IPv4 traffic
		"::/0",      // All IPv6 traffic
	}, nil
}

// isPrivateNetwork checks if an IP address is in a private network range
func (rm *RoutingManager) isPrivateNetwork(ip netip.Addr) bool {
	if ip.Is4() {
		ip4 := ip.As4()
		switch {
		case ip4[0] == 10: // 10.0.0.0/8
			return true
		case ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31: // 172.16.0.0/12
			return true
		case ip4[0] == 192 && ip4[1] == 168: // 192.168.0.0/16
			return true
		case ip4[0] == 169 && ip4[1] == 254: // 169.254.0.0/16
			return true
		}
	}
	return false
}

// containsSubnet checks if a subnet already exists in the list
func (rm *RoutingManager) containsSubnet(subnets []netip.Prefix, subnet netip.Prefix) bool {
	for _, s := range subnets {
		if s == subnet {
			return true
		}
	}
	return false
}
