package config

import "testing"

const sampleConfig = `
[Interface]
PrivateKey = gOP6u3AFeoJEBhDigw1VE3DybZ0SqnX+0Gooy2cwr+c=
ListenPort = 51820
Address = 10.0.0.2/32, fd00::2/128

[Peer]
PublicKey = qOP6u3AFeoJEBhDigw1VE3DybZ0SqnX+0Gooy2cwr+c=
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = example.com:51820
PersistentKeepalive = 25
`

func TestParseValid(t *testing.T) {
	cfg, err := Parse(sampleConfig)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.Peers) != 1 {
		t.Fatalf("expected 1 peer, got %d", len(cfg.Peers))
	}
}

func TestParseInvalidKey(t *testing.T) {
	_, err := Parse("[Interface]\nPrivateKey = bad\nListenPort = 51820\nAddress = 10.0.0.2/32")
	if err == nil {
		t.Fatal("expected error for bad key")
	}
}
