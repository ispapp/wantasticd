package store

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAtomicWrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.conf")
	data := []byte("hello")
	if err := AtomicWrite(path, data, 0o600); err != nil {
		t.Fatalf("AtomicWrite error: %v", err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if string(b) != string(data) {
		t.Fatalf("data mismatch: %q", string(b))
	}
}
