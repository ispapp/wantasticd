package update

import (
	"context"
	"embed"
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

//go:embed self-update.sh
var updateScript embed.FS

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

// FetchLatestVersion gets the latest version as text from the /latest endpoint
func (m *Manager) FetchLatestVersion(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://get.wantastic.app/latest", nil)
	if err != nil {
		return "", err
	}

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to fetch latest version: %s", resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(string(body)), nil
}

// RunUpdateScript executes the embedded self-update.sh script
func (m *Manager) RunUpdateScript(ctx context.Context, targetVersion string) error {
	scriptContent, err := updateScript.ReadFile("self-update.sh")
	if err != nil {
		return fmt.Errorf("read embedded script: %w", err)
	}

	tmpFile, err := os.CreateTemp("", "self-update-*.sh")
	if err != nil {
		return fmt.Errorf("create temp script: %w", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.Write(scriptContent); err != nil {
		tmpFile.Close()
		return fmt.Errorf("write temp script: %w", err)
	}
	tmpFile.Close()

	if err := os.Chmod(tmpFile.Name(), 0755); err != nil {
		return fmt.Errorf("chmod temp script: %w", err)
	}

	log.Printf("Running update script for version %s...", targetVersion)
	cmd := exec.CommandContext(ctx, "/bin/sh", tmpFile.Name(), targetVersion)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("execute update script: %w", err)
	}

	return nil
}

func (m *Manager) shouldUpdate(targetVersion string) bool {
	return m.currentVersion != targetVersion
}

func (m *Manager) CheckAndUpdate(ctx context.Context, targetVersion string) error {
	if !m.shouldUpdate(targetVersion) {
		log.Printf("Already running latest version: %s", m.currentVersion)
		return nil
	}

	return m.RunUpdateScript(ctx, targetVersion)
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

// GetPlatform returns the current OS and architecture for update URLs
func GetPlatform() string {
	return fmt.Sprintf("%s-%s", runtime.GOOS, runtime.GOARCH)
}

// BuildUpdateURL constructs an update URL for the given version and platform
func BuildUpdateURL(baseURL, version, platform string) string {
	// Pattern: https://get.wantastic.app/latest/wantasticd-${platform}.tar.gz
	// We ignore the version in the URL path and use 'latest' directly
	return fmt.Sprintf("%s/latest/wantasticd-%s.tar.gz", baseURL, platform)
}
