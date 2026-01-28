package certs

import (
	"crypto/tls"
	"crypto/x509"
	"embed"
	"fmt"

	"google.golang.org/grpc/credentials"
)

//go:embed ca.crt client.crt client.key
var fs embed.FS

// LoadClientTLSCredentials loads the mTLS credentials from the embedded files.
func LoadClientTLSCredentials() (credentials.TransportCredentials, error) {
	// Load CA certificate
	caCert, err := fs.ReadFile("ca.crt")
	if err != nil {
		return nil, fmt.Errorf("read ca cert: %w", err)
	}

	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("failed to append ca cert")
	}

	// Load client certificate and key
	clientCert, err := fs.ReadFile("client.crt")
	if err != nil {
		return nil, fmt.Errorf("read client cert: %w", err)
	}

	clientKey, err := fs.ReadFile("client.key")
	if err != nil {
		return nil, fmt.Errorf("read client key: %w", err)
	}

	cert, err := tls.X509KeyPair(clientCert, clientKey)
	if err != nil {
		return nil, fmt.Errorf("load x509 key pair: %w", err)
	}

	// Create TLS configuration
	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caCertPool,
		MinVersion:   tls.VersionTLS12,
	}

	return credentials.NewTLS(config), nil
}
