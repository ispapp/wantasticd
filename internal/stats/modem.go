package stats

import (
	"bufio"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

// collectModemStatistics tries to find and query an LTE/5G modem
func collectModemStatistics() *ModemInfo {
	// Try common modem ports/sockets
	paths := []struct {
		network string
		address string
	}{
		{"unix", "/tmp/at-port"}, // Example embedded socket
		{"unix", "/var/run/quectel-at"},
		{"unix", "/dev/atport"},
	}

	for _, p := range paths {
		if _, err := os.Stat(p.address); err == nil {
			if info := queryModem(p.network, p.address); info != nil {
				return info
			}
		}
	}

	// Dynamic serial port scanning
	for _, p := range getSerialPorts() {
		if _, err := os.Stat(p); err == nil {
			if info := queryModemSerial(p); info != nil {
				return info
			}
		}
	}

	return nil
}

func queryModem(network, address string) *ModemInfo {
	conn, err := net.DialTimeout(network, address, 2*time.Second)
	if err != nil {
		return nil
	}
	defer conn.Close()

	return interactWithModem(conn)
}

func queryModemSerial(path string) *ModemInfo {
	// Open with O_RDWR | O_NOCTTY
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0666)
	if err != nil {
		return nil
	}
	defer f.Close()

	return interactWithModem(f)
}

func interactWithModem(rw interface{}) *ModemInfo {
	var scanner *bufio.Scanner
	var writer func(string) error

	if v, ok := rw.(net.Conn); ok {
		v.SetDeadline(time.Now().Add(5 * time.Second))
		scanner = bufio.NewScanner(v)
		writer = func(s string) error {
			_, err := v.Write([]byte(s + "\r\n"))
			return err
		}
	} else if v, ok := rw.(*os.File); ok {
		// Files (serial ports) don't support SetDeadline easily without extra syscalls
		// but scanner.Scan() will still respect the timeout channel below.
		scanner = bufio.NewScanner(v)
		writer = func(s string) error {
			_, err := v.Write([]byte(s + "\r\n"))
			return err
		}
	} else {
		return nil
	}

	info := &ModemInfo{}

	// Helper to send AT command and get response
	sendCmd := func(cmd string) []string {
		if err := writer(cmd); err != nil {
			return nil
		}
		var lines []string
		timeout := time.After(1 * time.Second) // 1s per command
		for {
			select {
			case <-timeout:
				return lines
			default:
				if scanner.Scan() {
					line := strings.TrimSpace(scanner.Text())
					if line == "OK" || line == "ERROR" {
						return lines
					}
					if line != "" && line != cmd {
						lines = append(lines, line)
					}
				} else {
					return lines
				}
			}
		}
	}

	// 1. Get Model (ATI)
	lines := sendCmd("ATI")
	if len(lines) > 0 {
		info.Model = strings.Join(lines, " ")
	}

	// 2. Get IMEI (AT+GSN)
	lines = sendCmd("AT+GSN")
	if len(lines) > 0 {
		info.IMEI = lines[0]
	}

	// 3. Get IMSI (AT+CIMI)
	lines = sendCmd("AT+CIMI")
	if len(lines) > 0 {
		info.IMSI = lines[0]
	}

	// 4. Get Signal Strength (AT+CSQ)
	lines = sendCmd("AT+CSQ")
	if len(lines) > 0 && strings.HasPrefix(lines[0], "+CSQ: ") {
		parts := strings.Split(strings.TrimPrefix(lines[0], "+CSQ: "), ",")
		if len(parts) > 0 {
			if csq, err := strconv.Atoi(parts[0]); err == nil && csq > 0 {
				// Convert CSQ (0-31) to dBm
				// CSQ 0 = -113 dBm, CSQ 31 = -51 dBm
				info.Signal = -113 + csq*2
			}
		}
	}

	// 5. Get Operator and Tech (AT+COPS?)
	lines = sendCmd("AT+COPS?")
	if len(lines) > 0 && strings.HasPrefix(lines[0], "+COPS: ") {
		parts := strings.Split(lines[0], ",")
		if len(parts) >= 3 {
			info.Operator = strings.Trim(parts[2], "\"")
		}
		if len(parts) >= 4 {
			tech := parts[3]
			switch tech {
			case "0":
				info.Tech = "GSM"
			case "2":
				info.Tech = "UMTS"
			case "7":
				info.Tech = "LTE"
			case "11":
				info.Tech = "NR5G"
			default:
				info.Tech = "Unknown"
			}
		}
	}

	// 6. Registration Status (AT+CREG?)
	lines = sendCmd("AT+CREG?")
	if len(lines) > 0 && strings.HasPrefix(lines[0], "+CREG: ") {
		parts := strings.Split(lines[0], ",")
		if len(parts) >= 2 {
			status := parts[1]
			switch status {
			case "1":
				info.Registration = "Home"
			case "5":
				info.Registration = "Roaming"
			default:
				info.Registration = "Not Registered"
			}
		}
	}

	// 7. SIM Slot (Quectel specific AT+QUIMSLOT?)
	lines = sendCmd("AT+QUIMSLOT?")
	if len(lines) > 0 && strings.HasPrefix(lines[0], "+QUIMSLOT: ") {
		info.SIMSlot = strings.TrimPrefix(lines[0], "+QUIMSLOT: ")
	}

	if info.IMEI == "" && info.Model == "" {
		return nil
	}

	return info
}
