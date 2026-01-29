package stats

import (
	"path/filepath"
)

// getSerialPorts returns a list of available serial port devices
func getSerialPorts() []string {
	var ports []string
	patterns := []string{
		"/dev/ttyUSB*",
		"/dev/ttyACM*",
		"/dev/ttyS*",
		"/dev/ttyAMA*",
	}

	for _, pattern := range patterns {
		matches, err := filepath.Glob(pattern)
		if err == nil {
			ports = append(ports, matches...)
		}
	}
	return ports
}
