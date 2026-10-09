package version

// Set via -ldflags at build time (see Dockerfile / stagefreight image build).
var (
	Version   = "dev"
	Commit    = "unknown"
	BuildDate = "unknown"
)
