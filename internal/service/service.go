package service

import (
	"regexp"
	"strings"
)

var serviceRegexps = []struct {
	name string
	re   *regexp.Regexp
}{
	// Core Protocols
	{"ssh", regexp.MustCompile(`(?i)^SSH-\d\.\d`)},
	{"http", regexp.MustCompile(`(?i)^(HTTP/1\.[01]|<html|<head|<body|HTTP/1\.[01] \d{3})`)},
	{"ftp", regexp.MustCompile(`(?i)^220.*FTP`)},
	{"smtp", regexp.MustCompile(`(?i)^220.*(SMTP|ESMTP)`)},
	{"telnet", regexp.MustCompile(`(?i)Telnet|Password:|login:`)},
	{"vnc", regexp.MustCompile(`(?i)^RFB \d{3}\.\d{3}`)},

	// Databases
	{"mysql", regexp.MustCompile(`(?i)MySQL.*[a-zA-Z0-9]`)},
	{"redis", regexp.MustCompile(`(?i)^-ERR unknown command|^\+PONG`)},
	{"mongodb", regexp.MustCompile(`(?i)mongo`)},
	{"postgres", regexp.MustCompile(`(?i)postgre|^\x45\x00\x00\x08`)},
	{"mssql", regexp.MustCompile(`(?i)^\x04\x01\x00\x1c`)},
	{"oracle", regexp.MustCompile(`(?i)TNSLSNR`)},
	{"elasticsearch", regexp.MustCompile(`(?i)"cluster_name"|"lucene_version"`)},
	{"cassandra", regexp.MustCompile(`(?i)Cassandra`)},
	{"influxdb", regexp.MustCompile(`(?i)InfluxDB`)},
	{"clickhouse", regexp.MustCompile(`(?i)ClickHouse`)},

	// Messaging & Infrastructure
	{"amqp", regexp.MustCompile(`(?i)^AMQP`)},
	{"imap", regexp.MustCompile(`(?i)^\* OK (IMAP|Ready)`)},
	{"pop3", regexp.MustCompile(`(?i)^\+OK`)},
	{"rsync", regexp.MustCompile(`(?i)^@RSYNCD:`)},
	{"memcached", regexp.MustCompile(`(?i)^ERROR\r\n`)},
	{"mqtt", regexp.MustCompile(`(?i)^\x20\x02\x00\x00`)},
	{"nats", regexp.MustCompile(`(?i)^INFO {`)},
	{"kafka", regexp.MustCompile(`(?i)kafka`)},

	// Windows & Enterprise
	{"smb", regexp.MustCompile(`(?i)^\xffSMB`)},
	{"rdp", regexp.MustCompile(`(?i)^\x03\x00\x00\x0b`)},
	{"ldap", regexp.MustCompile(`(?i)^\x30\x84|^\x30\x0c\x02\x01`)},
	{"kerberos", regexp.MustCompile(`(?i)^\x6a\x81`)},

	// VoIP & Media
	{"sip", regexp.MustCompile(`(?i)^SIP/2\.0`)},
	{"rtsp", regexp.MustCompile(`(?i)^RTSP/1\.0`)},
	{"rtp", regexp.MustCompile(`(?i)^\x80\x00`)},

	// Development & Tools
	{"git", regexp.MustCompile(`(?i)^git-upload-pack`)},
	{"docker", regexp.MustCompile(`(?i)Api-Version`)},
	{"kubernetes", regexp.MustCompile(`(?i)k8s|kubernetes`)},
	{"jenkins", regexp.MustCompile(`(?i)jenkins`)},
	{"prometheus", regexp.MustCompile(`(?i)prometheus`)},
	{"grafana", regexp.MustCompile(`(?i)grafana`)},
	{"cockpit", regexp.MustCompile(`(?i)cockpit`)},
	{"portainer", regexp.MustCompile(`(?i)portainer`)},

	// Security & Networking
	{"openvpn", regexp.MustCompile(`(?i)^\x00\x0e\x38`)},
	{"wireguard", regexp.MustCompile(`(?i)^\x01\x00\x00\x00`)},
	{"wantastic", regexp.MustCompile(`(?i)wantastic`)},
	{"mikrotik-api", regexp.MustCompile(`(?i)^\x21\x2f\x6c\x6f\x67\x69\x6e`)},
}

func Detect(port int, banner string) string {
	if banner != "" {
		for _, sr := range serviceRegexps {
			if sr.re.MatchString(banner) {
				return sr.name
			}
		}
	}

	hint := GetHint(port)
	if hint != "unknown" {
		return hint
	}

	if banner != "" {
		// Clean and use as raw service string if nothing else matched
		clean := strings.Map(func(r rune) rune {
			if r >= 32 && r <= 126 {
				return r
			}
			return -1
		}, banner)
		clean = strings.TrimSpace(clean)
		if len(clean) > 3 {
			if len(clean) > 40 {
				return clean[:40] + "..."
			}
			return clean
		}
	}

	return "unknown"
}

func GetHint(port int) string {
	switch port {
	case 7:
		return "echo"
	case 13:
		return "daytime"
	case 17:
		return "qotd"
	case 19:
		return "chargen"
	case 21:
		return "ftp"
	case 22:
		return "ssh"
	case 23:
		return "telnet"
	case 25:
		return "smtp"
	case 37:
		return "time"
	case 53:
		return "dns"
	case 67, 68:
		return "dhcp"
	case 69:
		return "tftp"
	case 79:
		return "finger"
	case 80, 81, 8000, 8080, 8081, 3000, 5000:
		return "http"
	case 88:
		return "kerberos"
	case 110:
		return "pop3"
	case 111:
		return "rpcbind"
	case 113:
		return "ident"
	case 119:
		return "nntp"
	case 123:
		return "ntp"
	case 135:
		return "msrpc"
	case 137, 138:
		return "netbios"
	case 139:
		return "netbios-ssn"
	case 143:
		return "imap"
	case 161, 162:
		return "snmp"
	case 179:
		return "bgp"
	case 194:
		return "irc"
	case 389:
		return "ldap"
	case 443, 8443:
		return "https"
	case 445:
		return "smb"
	case 465:
		return "smtps"
	case 512, 513, 514:
		return "r-services"
	case 515:
		return "printer"
	case 520:
		return "rip"
	case 543, 544:
		return "kerberos-remote"
	case 548:
		return "afp"
	case 554:
		return "rtsp"
	case 587:
		return "submission"
	case 631:
		return "ipp"
	case 636:
		return "ldaps"
	case 873:
		return "rsync"
	case 990:
		return "ftps"
	case 993:
		return "imaps"
	case 995:
		return "pop3s"
	case 1055, 1056:
		return "wantastic-proxy"
	case 1080:
		return "socks"
	case 1194:
		return "openvpn"
	case 1433, 1434:
		return "mssql"
	case 1521:
		return "oracle"
	case 1723:
		return "pptp"
	case 1812, 1813:
		return "radius"
	case 1883:
		return "mqtt"
	case 2049:
		return "nfs"
	case 2375, 2376:
		return "docker"
	case 3306:
		return "mysql"
	case 3389:
		return "rdp"
	case 3689:
		return "daap"
	case 4444:
		return "metasploit"
	case 5060, 5061:
		return "sip"
	case 5353:
		return "mdns"
	case 5432:
		return "postgresql"
	case 5672:
		return "rabbitmq"
	case 5900, 5901:
		return "vnc"
	case 6379:
		return "redis"
	case 6443:
		return "kubernetes"
	case 7000:
		return "cassandra"
	case 8001, 8002:
		return "unifi"
	case 8140:
		return "puppet"
	case 8200:
		return "hashicorp-vault"
	case 8291:
		return "mikrotik-winbox"
	case 8300, 8301, 8302:
		return "consul"
	case 8500:
		return "consul-http"
	case 9000:
		return "portainer"
	case 9034:
		return "wantastic-agent"
	case 9090:
		return "cockpit"
	case 9092:
		return "kafka"
	case 9100:
		return "prometheus-exporter"
	case 9200:
		return "elasticsearch"
	case 10000:
		return "webmin"
	case 11211:
		return "memcached"
	case 27017:
		return "mongodb"
	case 51820:
		return "wireguard"
	default:
		return "unknown"
	}
}
