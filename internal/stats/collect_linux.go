//go:build linux

package stats

import (
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/mdlayher/wifi"
)

// collectWiFiStatistics collects WiFi statistics using github.com/mdlayher/wifi
// and other Linux-specific sources for better embedded device support.
func collectWiFiStatistics() ([]WiFiInterfaceInfo, bool) {
	var wifiInterfaces []WiFiInterfaceInfo
	var connected bool

	// Create WiFi client
	client, err := wifi.New()
	if err != nil {
		log.Printf("WiFi client creation failed: %v", err)
		return wifiInterfaces, false
	}
	defer client.Close()

	// Get all WiFi interfaces
	interfaces, err := client.Interfaces()
	if err != nil {
		log.Printf("Failed to get WiFi interfaces: %v", err)
		return wifiInterfaces, false
	}

	// Get noise levels from /proc/net/wireless
	noiseLevels := parseProcNetWireless()

	for _, iface := range interfaces {
		wifiInfo := WiFiInterfaceInfo{
			Name:      iface.Name,
			MAC:       iface.HardwareAddr.String(),
			Connected: false,
		}

		if noise, ok := noiseLevels[iface.Name]; ok {
			wifiInfo.Noise = noise
		}

		// Try to get BSS info for associated network
		if bss, err := client.BSS(iface); err == nil && bss != nil {
			wifiInfo.SSID = bss.SSID
			wifiInfo.Connected = (bss.Status == wifi.BSSStatusAssociated)
			wifiInfo.Frequency = bss.Frequency
			wifiInfo.Channel = frequencyToChannel(bss.Frequency)
			if wifiInfo.Connected {
				connected = true
			}
		}

		// Get detailed station info
		stationInfos, err := client.StationInfo(iface)
		if err == nil {
			for _, station := range stationInfos {
				wifiInfo.Signal = station.Signal
				if wifiInfo.Noise != 0 {
					wifiInfo.SNR = wifiInfo.Signal - wifiInfo.Noise
				}
				wifiInfo.Bitrate = station.TransmitBitrate / 1000000
				wifiInfo.RxBytes = uint64(station.ReceivedBytes)
				wifiInfo.TxBytes = uint64(station.TransmittedBytes)
				wifiInfo.RxPackets = uint64(station.ReceivedPackets)
				wifiInfo.TxPackets = uint64(station.TransmittedPackets)
				// Break after first station record for the interface
				break
			}
		}

		// Collect nearby networks via 'iw scan dump'
		// This uses the kernel scan cache and doesn't trigger an active scan
		if nearby, err := collectNearbyNetworks(iface.Name); err == nil {
			wifiInfo.Nearby = nearby
		}

		wifiInterfaces = append(wifiInterfaces, wifiInfo)
	}

	return wifiInterfaces, connected
}

func frequencyToChannel(freq int) int {
	if freq >= 2412 && freq <= 2484 {
		if freq == 2484 {
			return 14
		}
		return (freq-2412)/5 + 1
	} else if freq >= 5180 && freq <= 5825 {
		return (freq-5180)/5 + 36
	} else if freq >= 5945 && freq <= 7125 {
		return (freq-5945)/5 + 1
	}
	return 0
}

func parseProcNetWireless() map[string]int {
	noises := make(map[string]int)
	data, err := os.ReadFile("/proc/net/wireless")
	if err != nil {
		return noises
	}
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		if !strings.Contains(line, ":") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		iface := strings.TrimSpace(strings.Split(fields[0], ":")[0])
		// noise is field 4 (0-indexed)
		if noise, err := strconv.Atoi(strings.TrimSuffix(fields[4], ".")); err == nil {
			noises[iface] = noise
		}
	}
	return noises
}

func collectNearbyNetworks(iface string) ([]NearbyNetwork, error) {
	// Try 'iw dev <iface> scan dump'
	out, err := exec.Command("iw", "dev", iface, "scan", "dump").Output()
	if err != nil {
		return nil, err
	}

	var networks []NearbyNetwork
	var current *NearbyNetwork

	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "BSS ") {
			if current != nil && current.SSID != "" {
				networks = append(networks, *current)
			}
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				bssid := strings.Split(parts[1], "(")[0]
				current = &NearbyNetwork{BSSID: bssid}
			}
			continue
		}

		if current == nil {
			continue
		}

		if strings.HasPrefix(line, "SSID: ") {
			current.SSID = strings.TrimPrefix(line, "SSID: ")
		} else if strings.HasPrefix(line, "freq: ") {
			if freq, err := strconv.Atoi(strings.TrimPrefix(line, "freq: ")); err == nil {
				current.Channel = frequencyToChannel(freq)
			}
		} else if strings.HasPrefix(line, "signal: ") {
			// signal: -61.00 dBm
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				val := strings.TrimSuffix(fields[1], ".00")
				if sig, err := strconv.Atoi(val); err == nil {
					current.Signal = sig
				}
			}
		}
	}

	if current != nil && current.SSID != "" {
		networks = append(networks, *current)
	}

	return networks, nil
}

// collectNetworkInterfaceStatistics collects network interface statistics from /sys/class/net
func collectNetworkInterfaceStatistics() []InterfaceInfo {
	var interfaces []InterfaceInfo

	// Read network interfaces from /sys/class/net
	netDir := "/sys/class/net"
	entries, err := os.ReadDir(netDir)
	if err != nil {
		log.Printf("Failed to read network interfaces: %v", err)
		return interfaces
	}

	for _, entry := range entries {
		ifaceName := entry.Name()

		// Skip loopback and virtual interfaces
		if ifaceName == "lo" || strings.HasPrefix(ifaceName, "veth") ||
			strings.HasPrefix(ifaceName, "docker") || strings.HasPrefix(ifaceName, "br-") {
			continue
		}

		iface := InterfaceInfo{
			Name: ifaceName,
			Up:   isInterfaceUp(ifaceName),
		}

		// Get MAC address
		if mac, err := getInterfaceMAC(ifaceName); err == nil {
			iface.MAC = mac
		}

		// Get IP addresses
		if ips, err := getInterfaceIPs(ifaceName); err == nil {
			iface.IPs = ips
		}

		// Get interface statistics from /sys/class/net
		if rxBytes, err := readUint64FromFile(filepath.Join(netDir, ifaceName, "statistics", "rx_bytes")); err == nil {
			iface.RxBytes = rxBytes
		}

		if txBytes, err := readUint64FromFile(filepath.Join(netDir, ifaceName, "statistics", "tx_bytes")); err == nil {
			iface.TxBytes = txBytes
		}

		interfaces = append(interfaces, iface)
	}

	return interfaces
}

// isInterfaceUp checks if a network interface is up
func isInterfaceUp(ifaceName string) bool {
	operstateFile := filepath.Join("/sys/class/net", ifaceName, "operstate")
	data, err := os.ReadFile(operstateFile)
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(data)) == "up"
}

// getInterfaceMAC gets the MAC address of a network interface
func getInterfaceMAC(ifaceName string) (string, error) {
	macFile := filepath.Join("/sys/class/net", ifaceName, "address")
	data, err := os.ReadFile(macFile)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

// readUint64FromFile reads a uint64 value from a file
func readUint64FromFile(filePath string) (uint64, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return 0, err
	}

	str := strings.TrimSpace(string(data))
	return strconv.ParseUint(str, 10, 64)
}
