package wss

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/coder/websocket"
)

func TestRequestTokenAndWaitConfig(t *testing.T) {
	tokenValue := "tok123"
	configValue := []byte("[Interface]\nPrivateKey = gOP6u3AFeoJEBhDigw1VE3DybZ0SqnX+0Gooy2cwr+c=\nListenPort = 51820\nAddress = 10.0.0.2/32\n\n[Peer]\nPublicKey = qOP6u3AFeoJEBhDigw1VE3DybZ0SqnX+0Gooy2cwr+c=\nAllowedIPs = 0.0.0.0/0\n")

	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := websocket.Accept(w, r, nil)
		if err != nil {
			t.Fatalf("accept: %v", err)
		}
		defer c.Close(websocket.StatusNormalClosure, "done")
		if r.URL.Path == "/" {
			_, data, err := c.Read(context.Background())
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			if len(data) == 0 {
				t.Fatalf("expected data")
			}
			if err := c.Write(context.Background(), websocket.MessageText, []byte(`{"token":"`+tokenValue+`"}`)); err != nil {
				t.Fatalf("write token: %v", err)
			}
			return
		}
		if r.URL.Path == "/"+tokenValue {
			if err := c.Write(context.Background(), websocket.MessageText, configValue); err != nil {
				t.Fatalf("write cfg: %v", err)
			}
			return
		}
		http.Error(w, "bad", http.StatusBadRequest)
	}))
	t.Cleanup(s.Close)

	client := &Client{BaseURL: "ws" + s.URL[len("http"):], HTTP: s.Client()}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	tok, _, err := client.RequestToken(ctx, TokenRequest{Hostname: "h", MacAddr: "aa:bb"})
	if err != nil {
		t.Fatalf("RequestToken: %v", err)
	}
	if tok != tokenValue {
		t.Fatalf("unexpected token %q", tok)
	}

	cfg, err := client.WaitConfig(ctx, tok)
	if err != nil {
		t.Fatalf("WaitConfig: %v", err)
	}
	if string(cfg) != string(configValue) {
		t.Fatalf("config mismatch")
	}
}
