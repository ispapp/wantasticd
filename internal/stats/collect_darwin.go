//go:build darwin

package stats

import (
	"log"
	"net"
	"os/exec"
	"strconv"
	"strings"
)

// collectWiFiStatistics - implementation for macOS using system_profiler
func collectWiFiStatistics() ([]WiFiInterfaceInfo, bool) {
	out, err := exec.Command("system_profiler", "SPAirPortDataType").Output()
	if err != nil {
		log.Printf("Failed to execute system_profiler: %v", err)
		return []WiFiInterfaceInfo{}, false
	}

	output := string(out)
	var interfaces []WiFiInterfaceInfo
	var currentIface *WiFiInterfaceInfo

	lines := strings.Split(output, "\n")
	inInterfacesSection := false

	for i := 0; i < len(lines); i++ {
		line := lines[i]
		trimmed := strings.TrimSpace(line)

		if trimmed == "Interfaces:" {
			inInterfacesSection = true
			continue
		}

		if !inInterfacesSection {
			continue
		}

		// Check for a new interface (e.g., "        en0:")
		if strings.HasSuffix(line, ":") && strings.HasPrefix(line, "        ") && !strings.HasPrefix(line, "         ") {
			if currentIface != nil {
				interfaces = append(interfaces, *currentIface)
			}
			name := strings.TrimSpace(strings.TrimSuffix(line, ":"))
			currentIface = &WiFiInterfaceInfo{
				Name:      name,
				Connected: false,
			}
			continue
		}

		if currentIface == nil {
			continue
		}

		parts := strings.SplitN(trimmed, ":", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		switch key {
		case "MAC Address":
			currentIface.MAC = value
		case "Status":
			if value == "Connected" {
				currentIface.Connected = true
			}
		case "PHY Mode":
			currentIface.PHYMode = value
		case "Security":
			currentIface.Security = value
		case "Channel":
			// value is like "36 (5GHz, 80MHz)"
			valParts := strings.Fields(value)
			if len(valParts) > 0 {
				if ch, err := strconv.Atoi(valParts[0]); err == nil {
					currentIface.Channel = ch
				}
			}
		case "Signal / Noise":
			// value is like "-69 dBm / -91 dBm"
			valParts := strings.Split(value, " / ")
			if len(valParts) == 2 {
				sigStr := strings.TrimSuffix(valParts[0], " dBm")
				noiseStr := strings.TrimSuffix(valParts[1], " dBm")
				if s, err := strconv.Atoi(sigStr); err == nil {
					currentIface.Signal = s
				}
				if n, err := strconv.Atoi(noiseStr); err == nil {
					currentIface.Noise = n
				}
				if currentIface.Noise != 0 {
					currentIface.SNR = currentIface.Signal - currentIface.Noise
				}
			}
		case "Transmit Rate":
			if rate, err := strconv.Atoi(value); err == nil {
				currentIface.Bitrate = rate
			}
		case "MCS Index":
			if mcs, err := strconv.Atoi(value); err == nil {
				currentIface.MCSIndex = mcs
			}
		case "Current Network Information":
			// The next line is likely the SSID followed by a colon
			if i+1 < len(lines) {
				nextLine := lines[i+1]
				if strings.HasPrefix(nextLine, "            ") && strings.HasSuffix(strings.TrimSpace(nextLine), ":") {
					currentIface.SSID = strings.TrimSpace(strings.TrimSuffix(nextLine, ":"))
					i++ // Skip SSID line
				}
			}
		case "Other Local Wi-Fi Networks":
			// Parse nearby networks
			for j := i + 1; j < len(lines); j++ {
				line := lines[j]
				// Nearby networks SSIDs are at 12 spaces indentation
				if !strings.HasPrefix(line, "            ") || strings.HasPrefix(line, "             ") {
					if strings.TrimSpace(line) == "" {
						continue
					}
					// If we hit something less indented than 12 spaces, we're out of the section
					// But we must be careful about empty lines or sub-indents
					if !strings.HasPrefix(line, "            ") {
						i = j - 1 // Update main loop index
						break
					}
					continue
				}

				if strings.HasSuffix(strings.TrimSpace(line), ":") {
					nearby := NearbyNetwork{
						SSID: strings.TrimSpace(strings.TrimSuffix(line, ":")),
					}
					// Parse sub-fields of this nearby network
					for k := j + 1; k < len(lines); k++ {
						subLine := lines[k]
						if !strings.HasPrefix(subLine, "              ") {
							j = k - 1
							break
						}
						subTrimmed := strings.TrimSpace(subLine)
						subParts := strings.SplitN(subTrimmed, ":", 2)
						if len(subParts) == 2 {
							k := strings.TrimSpace(subParts[0])
							v := strings.TrimSpace(subParts[1])
							switch k {
							case "PHY Mode":
								nearby.PHYMode = v
							case "Security":
								nearby.Security = v
							case "Channel":
								parts := strings.Fields(v)
								if len(parts) > 0 {
									nearby.Channel, _ = strconv.Atoi(parts[0])
								}
							case "Signal / Noise":
								parts := strings.Split(v, " / ")
								if len(parts) == 2 {
									sig, _ := strconv.Atoi(strings.TrimSuffix(parts[0], " dBm"))
									noise, _ := strconv.Atoi(strings.TrimSuffix(parts[1], " dBm"))
									nearby.Signal = sig
									nearby.Noise = noise
								}
							}
						}
						j = k
					}
					currentIface.Nearby = append(currentIface.Nearby, nearby)
				}
				i = j
			}
		}
	}

	if currentIface != nil {
		interfaces = append(interfaces, *currentIface)
	}

	connected := false
	for _, iface := range interfaces {
		if iface.Connected {
			connected = true
			break
		}
	}

	return interfaces, connected
}

// collectNetworkInterfaceStatistics collects network interface statistics using net package and netstat
func collectNetworkInterfaceStatistics() []InterfaceInfo {
	var interfaces []InterfaceInfo

	netIfaces, err := net.Interfaces()
	if err != nil {
		log.Printf("Failed to get network interfaces: %v", err)
		return interfaces
	}

	for _, netIface := range netIfaces {
		if netIface.Flags&net.FlagLoopback != 0 {
			continue
		}

		// Basic info
		iface := InterfaceInfo{
			Name: netIface.Name,
			MAC:  netIface.HardwareAddr.String(),
			Up:   netIface.Flags&net.FlagUp != 0,
		}

		// IPs
		if ips, err := getInterfaceIPs(netIface.Name); err == nil {
			iface.IPs = ips
		}

		// Stats via netstat
		rx, tx, err := getInterfaceStats(netIface.Name)
		if err == nil {
			iface.RxBytes = rx
			iface.TxBytes = tx
		}

		interfaces = append(interfaces, iface)
	}

	return interfaces
}

func getInterfaceStats(name string) (uint64, uint64, error) {
	out, err := exec.Command("netstat", "-b", "-I", name).Output()
	if err != nil {
		return 0, 0, err
	}

	// Parse netstat output
	lines := strings.Split(string(out), "\n")
	if len(lines) < 2 {
		return 0, 0, nil
	}

	fields := strings.Fields(lines[1])
	// Typical output: Name Mtu Network Address Ipkts Ierrs Ibytes Opkts Oerrs Obytes Coll
	// Index:          0    1   2       3       4     5     6      7     8     9      10
	// Sometimes Address is missing if interface is down or special? But usually netstat -b -I shows it.

	if len(fields) >= 10 {
		rx, _ := strconv.ParseUint(fields[6], 10, 64)
		tx, _ := strconv.ParseUint(fields[9], 10, 64)
		return rx, tx, nil
	}

	return 0, 0, nil
}
