package stats

import (
	"bufio"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"github.com/adrianmo/go-nmea"
)

// collectGPSStatistics tries to find and query a GPS module
func collectGPSStatistics() *GPSInfo {
	// Try common GPS ports/sockets
	paths := []struct {
		network string
		address string
	}{
		{"unix", "/tmp/gps-port"},
		{"unix", "/var/run/gpsd.sock"},
	}

	// Dynamic serial port scanning
	serialPorts := getSerialPorts()

	for _, p := range paths {
		if _, err := os.Stat(p.address); err == nil {
			if info := queryGPS(p.network, p.address); info != nil {
				return info
			}
		}
	}

	for _, p := range serialPorts {
		if _, err := os.Stat(p); err == nil {
			if info := queryGPSSerial(p); info != nil {
				return info
			}
		}
	}

	return nil
}

func queryGPS(network, address string) *GPSInfo {
	conn, err := net.DialTimeout(network, address, 2*time.Second)
	if err != nil {
		return nil
	}
	defer conn.Close()

	return parseNMEA(conn)
}

func queryGPSSerial(path string) *GPSInfo {
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return nil
	}
	defer f.Close()

	return parseNMEA(f)
}

func parseNMEA(r io.Reader) *GPSInfo {
	scanner := bufio.NewScanner(r)
	info := &GPSInfo{
		Fix: "none",
	}

	// Read for up to 2 seconds to gather enough sentences
	timeout := time.After(2 * time.Second)
	foundAny := false

	for {
		select {
		case <-timeout:
			if foundAny {
				return info
			}
			return nil
		default:
			if !scanner.Scan() {
				if foundAny {
					return info
				}
				return nil
			}
			line := strings.TrimSpace(scanner.Text())
			if !strings.HasPrefix(line, "$") {
				continue
			}

			foundAny = true
			s, err := nmea.Parse(line)
			if err != nil {
				continue
			}

			switch m := s.(type) {
			case nmea.GGA:
				info.Lat = m.Latitude
				info.Lon = m.Longitude
				info.Alt = m.Altitude
				info.Satellites = int(m.NumSatellites)
				if m.FixQuality != nmea.Invalid {
					info.Fix = "3D"
					if m.FixQuality == nmea.GPS {
						info.Fix = "2D"
					}
				}
				info.Timestamp = nmea.DateTime(0, nmea.Date{Valid: true, DD: time.Now().Day(), MM: int(time.Now().Month()), YY: time.Now().Year() % 100}, m.Time)
			case nmea.RMC:
				info.Lat = m.Latitude
				info.Lon = m.Longitude
				info.Speed = m.Speed
				if m.Validity == "A" {
					if info.Fix == "none" {
						info.Fix = "2D"
					}
				}
				info.Timestamp = nmea.DateTime(0, m.Date, m.Time)
			case nmea.GSA:
				if m.FixType == "3" {
					info.Fix = "3D"
				} else if m.FixType == "2" {
					info.Fix = "2D"
				}
			}
		}
	}
}
