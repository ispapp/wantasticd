package version

var (
	// Version is the current version of the application.
	// It should be set at build time using -ldflags "-X wantastic-agent/pkg/version.Version=v1.2.3"
	Version = "dev"

	// Commit is the git commit hash at build time.
	Commit = "unknown"

	// BuildDate is the date the binary was built.
	BuildDate = "unknown"
)
