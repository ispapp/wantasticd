package update

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

type Manager struct {
	currentVersion string
	httpClient     *http.Client
}

func NewManager(currentVersion string) *Manager {
	return &Manager{
		currentVersion: currentVersion,
		httpClient: &http.Client{
			Timeout: 5 * time.Minute,
		},
	}
}

func (m *Manager) GetCurrentVersion() string {
	return m.currentVersion
}

func (m *Manager) CheckAndUpdate(ctx context.Context, updateURL, targetVersion string) error {
	if !m.shouldUpdate(targetVersion) {
		log.Printf("Already running latest version: %s", m.currentVersion)
		return nil
	}

	log.Printf("Downloading update from %s", updateURL)
	
	binaryPath, err := m.downloadUpdate(ctx, updateURL)
	if err != nil {
		return fmt.Errorf("download update: %w", err)
	}
	defer os.Remove(binaryPath)

	if err := m.verifyUpdate(binaryPath); err != nil {
		return fmt.Errorf("verify update: %w", err)
	}

	if err := m.applyUpdate(binaryPath); err != nil {
		return fmt.Errorf("apply update: %w", err)
	}

	return nil
}

func (m *Manager) shouldUpdate(targetVersion string) bool {
	// Simple version comparison - in production, use proper semantic versioning
	return m.currentVersion != targetVersion
}

func (m *Manager) downloadUpdate(ctx context.Context, url string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", fmt.Errorf("create request: %w", err)
	}

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("download: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download failed: %s", resp.Status)
	}

	// Create temporary file
	tmpFile, err := os.CreateTemp("", "wantastic-update-*")
	if err != nil {
		return "", fmt.Errorf("create temp file: %w", err)
	}
	defer tmpFile.Close()

	// Download to temporary file
	if _, err := io.Copy(tmpFile, resp.Body); err != nil {
		return "", fmt.Errorf("copy: %w", err)
	}

	return tmpFile.Name(), nil
}

func (m *Manager) verifyUpdate(binaryPath string) error {
	// Make executable
	if err := os.Chmod(binaryPath, 0755); err != nil {
		return fmt.Errorf("chmod: %w", err)
	}

	// Basic verification - check if it's a valid binary
	cmd := exec.Command(binaryPath, "--version")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("verify binary: %w", err)
	}

	return nil
}

func (m *Manager) applyUpdate(binaryPath string) error {
	// Get current executable path
	currentPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("get executable path: %w", err)
	}

	// Create backup
	backupPath := currentPath + ".backup"
	if err := os.Rename(currentPath, backupPath); err != nil {
		return fmt.Errorf("backup current: %w", err)
	}

	// Move new binary to current location
	if err := os.Rename(binaryPath, currentPath); err != nil {
		// Restore backup on failure
		os.Rename(backupPath, currentPath)
		return fmt.Errorf("replace binary: %w", err)
	}

	// Remove backup after successful update
	os.Remove(backupPath)

	log.Println("Update applied successfully. Restarting...")
	
	// Restart the process
	return m.restart()
}

func (m *Manager) restart() error {
	// Get current executable path and arguments
	executable, err := os.Executable()
	if err != nil {
		return fmt.Errorf("get executable: %w", err)
	}

	args := os.Args[1:]
	
	// Start new process
	cmd := exec.Command(executable, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start new process: %w", err)
	}

	// Exit current process
	os.Exit(0)
	return nil
}

// GetPlatform returns the current platform identifier for update URLs
func GetPlatform() string {
	goos := runtime.GOOS
	goarch := runtime.GOARCH
	
	// Normalize architecture names
	switch goarch {
	case "amd64":
		goarch = "x86_64"
	case "386":
		goarch = "x86"
	}
	
	return fmt.Sprintf("%s-%s", goos, goarch)
}

// BuildUpdateURL constructs an update URL for the given version and platform
func BuildUpdateURL(baseURL, version, platform string) string {
	if strings.Contains(baseURL, "%s") {
		return fmt.Sprintf(baseURL, version, platform)
	}
	
	// Default URL pattern
	return fmt.Sprintf("%s/wantastic-agent-%s-%s", baseURL, version, platform)
}