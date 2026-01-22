//go:build !darwin && !linux

package stats

// collectWiFiStatistics - stub for unsupported platforms
func collectWiFiStatistics() ([]WiFiInterfaceInfo, bool) {
	return []WiFiInterfaceInfo{}, false
}

// collectNetworkInterfaceStatistics - stub for unsupported platforms
func collectNetworkInterfaceStatistics() []InterfaceInfo {
	return []InterfaceInfo{}
}
