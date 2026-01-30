package daemon

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/kardianos/service"
)

const (
	ServiceName = "wantasticd"
	ServiceDesc = "Wantastic Overlay Networking Daemon"
)

// emptyProgram is a stub because we only use the library for installation
type emptyProgram struct{}

func (p *emptyProgram) Start(s service.Service) error { return nil }
func (p *emptyProgram) Stop(s service.Service) error  { return nil }

// SetupService installs and starts the service
func SetupService(configPath string) error {
	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %w", err)
	}

	// Resolve any symlinks to ensure we point to the real binary
	exePath, err = filepath.EvalSymlinks(exePath)
	if err != nil {
		return fmt.Errorf("failed to resolve symlink for executable: %w", err)
	}

	// Ensure absolute path for config
	absConfigPath, err := filepath.Abs(configPath)
	if err != nil {
		return fmt.Errorf("failed to get absolute path for config: %w", err)
	}

	svcConfig := &service.Config{
		Name:        ServiceName,
		DisplayName: ServiceName,
		Description: ServiceDesc,
		Executable:  exePath,
		Arguments:   []string{"connect", "-config", absConfigPath},
	}

	prg := &emptyProgram{}
	s, err := service.New(prg, svcConfig)
	if err != nil {
		return fmt.Errorf("failed to create service definition: %w", err)
	}

	// Check if already running/installed
	status, err := s.Status()
	if err == nil && status == service.StatusRunning {
		log.Println("Service is currently running. Stopping it first...")
		if err := s.Stop(); err != nil {
			log.Printf("Warning: failed to stop existing service: %v", err)
		}
	}

	// Always attempt to uninstall first to update configuration/path if it changed
	_ = s.Uninstall()

	log.Println("Installing system service...")
	if err := s.Install(); err != nil {
		return fmt.Errorf("failed to install service (do you have root privileges?): %w", err)
	}

	log.Println("Starting system service...")
	if err := s.Start(); err != nil {
		return fmt.Errorf("failed to start service: %w", err)
	}

	return nil
}
