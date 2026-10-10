// Package main executes the CLI for gatecheck
package main

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"runtime"
	"time"

	"github.com/lmittmann/tint"

	"github.com/gatecheckdev/gatecheck/cmd"
	"github.com/gatecheckdev/gatecheck/pkg/gatecheck"
	"github.com/gatecheckdev/gatecheck/pkg/redact"
)

const (
	exitSystemFail     int = -1
	exitOk             int = 0
	exitValidationFail int = 1
	exitFileAccessFail int = 2
)

// GatecheckVersion see CHANGELOG.md
const GatecheckVersion = "[Not Provided]"

// all variables here are provided as build-time arguments, with clear default values
var (
	cliVersion     = "[Not Provided]"
	buildDate      = "[Not Provided]"
	gitCommit      = "[Not Provided]"
	gitDescription = "[Not Provided]"
)

func main() {
	os.Exit(run())
}

func run() int {
	cmd.ApplicationMetadata = gatecheck.ApplicationMetadata{
		CLIVersion:     cliVersion,
		GitCommit:      gitCommit,
		BuildDate:      buildDate,
		GitDescription: gitDescription,
		Platform:       fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH),
		GoVersion:      runtime.Version(),
		Compiler:       runtime.Compiler,
	}

	// Logs and errors pass through redaction, which is a no-op unless --redact-cve-ids is set
	stderr := redact.NewWriter(os.Stderr)
	defer stderr.Flush()

	// Colorized logging output for the CLI
	logHandler := tint.NewHandler(stderr, &tint.Options{Level: cmd.LogLeveler, TimeFormat: time.TimeOnly})
	slog.SetDefault(slog.New(logHandler))

	command := cmd.NewGatecheckCommand()
	command.SetErr(stderr)

	err := command.Execute()
	if errors.Is(err, gatecheck.ErrValidationFailure) {
		return exitValidationFail
	}
	if err != nil {
		return exitSystemFail
	}
	return exitOk
}
