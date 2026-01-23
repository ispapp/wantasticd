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
