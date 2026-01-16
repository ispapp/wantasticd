package wss

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/coder/websocket"
)

type Client struct {
	BaseURL string
	HTTP    *http.Client
}

type TokenResponse struct {
	Token string `json:"token"`
}

type TokenRequest struct {
	Hostname string `json:"hostname"`
	MacAddr  string `json:"macaddr"`
}

func (c *Client) defaultBase() string {
	if c.BaseURL != "" {
		return c.BaseURL
	}
	return "wss://console.wantastic.app/ws"
}

func (c *Client) httpClient() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}}}
}

// RequestToken opens the base websocket, sends TokenRequest, and returns the token and deploy link.
func (c *Client) RequestToken(ctx context.Context, req TokenRequest) (string, string, error) {
	base := c.defaultBase()
	conn, _, err := websocket.Dial(ctx, base, &websocket.DialOptions{HTTPClient: c.httpClient()})
	if err != nil {
		return "", "", err
	}
	defer conn.Close(websocket.StatusNormalClosure, "done")

	payload, err := json.Marshal(req)
	if err != nil {
		return "", "", err
	}
	if err := conn.Write(ctx, websocket.MessageText, payload); err != nil {
		return "", "", err
	}
	_, data, err := conn.Read(ctx)
	if err != nil {
		return "", "", err
	}
	var resp TokenResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return "", "", err
	}
	if resp.Token == "" {
		return "", "", errors.New("empty token")
	}
	link := fmt.Sprintf("https://console.wantastic.app/deploy/%s", resp.Token)
	return resp.Token, link, nil
}

// WaitConfig listens on /<token> and returns the raw config bytes.
func (c *Client) WaitConfig(ctx context.Context, token string) ([]byte, error) {
	if token == "" {
		return nil, errors.New("token required")
	}
	base, err := url.Parse(c.defaultBase())
	if err != nil {
		return nil, err
	}
	base.Path = strings.TrimSuffix(base.Path, "/") + "/" + token
	conn, _, err := websocket.Dial(ctx, base.String(), &websocket.DialOptions{HTTPClient: c.httpClient()})
	if err != nil {
		return nil, err
	}
	defer conn.Close(websocket.StatusNormalClosure, "done")

	_, data, err := conn.Read(ctx)
	if err != nil {
		return nil, err
	}
	return data, nil
}

// FirstMAC returns the first non-empty hardware address.
func FirstMAC() (string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	for _, iface := range ifaces {
		if len(iface.HardwareAddr) > 0 {
			return iface.HardwareAddr.String(), nil
		}
	}
	return "", errors.New("no mac address found")
}

func Hostname() string {
	h, err := osHostname()
	if err != nil || h == "" {
		return "unknown"
	}
	return h
}

var osHostname = func() (string, error) {
	return os.Hostname()
}

// SleepContext sleeps or returns early if context is done.
func SleepContext(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
