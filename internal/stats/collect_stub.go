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

// collectMeshStatistics - stub for unsupported platforms
func collectMeshStatistics() *MeshInfo {
	return nil
}

// getHostUptime returns 0 for unsupported platforms
func getHostUptime() float64 {
	return 0
}

func collectCPUUsage() string {
	return "0%"
}

func collectMemoryTotal() uint64 {
	return 1024 * 1024 * 1024
}
