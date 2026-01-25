package curl

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
)

type DialContext func(ctx context.Context, network, addr string) (net.Conn, error)

func Run(ctx context.Context, dial DialContext, method, url, data string, headers []string, verbose bool) error {
	var body io.Reader
	if data != "" {
		body = strings.NewReader(data)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return fmt.Errorf("invalid request: %w", err)
	}

	// Add default User-Agent if not provided
	hasUA := false
	for _, h := range headers {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			val := strings.TrimSpace(parts[1])
			req.Header.Add(key, val)
			if strings.EqualFold(key, "User-Agent") {
				hasUA = true
			}
		}
	}

	if !hasUA {
		req.Header.Set("User-Agent", "curl/8.4.0")
	}

	client := &http.Client{
		Transport: &http.Transport{
			DialContext: dial,
		},
	}

	if verbose {
		fmt.Fprintf(os.Stderr, "> %s %s\n", req.Method, req.URL.String())
		for k, v := range req.Header {
			fmt.Fprintf(os.Stderr, "> %s: %s\n", k, strings.Join(v, ", "))
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if verbose {
		fmt.Fprintf(os.Stderr, "< %s\n", resp.Status)
		for k, v := range resp.Header {
			fmt.Fprintf(os.Stderr, "< %s: %s\n", k, strings.Join(v, ", "))
		}
	}

	_, err = io.Copy(os.Stdout, resp.Body)
	return err
}
