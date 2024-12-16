package cmd

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/gatecheckdev/gatecheck/pkg/gatecheck"
	"github.com/spf13/cobra"
)

type Config struct {
	API struct {
		Endpoint   string
		SkipVerify bool
	}
}

var submitCmd = &cobra.Command{
	Use:   "submit [FILE]",
	Short: "submit bundle to configured API endpoint",
	Args:  cobra.ExactArgs(1),
	PreRunE: func(cmd *cobra.Command, args []string) error {
		configFilename := RuntimeConfig.ConfigFilename.Value().(string)

		RuntimeConfig.gatecheckConfig = gatecheck.NewDefaultConfig()
		if configFilename != "" {
			slog.Info("GATECHECK: using config file", "path", configFilename)
			err := gatecheck.NewConfigDecoder(configFilename).Decode(RuntimeConfig.gatecheckConfig)
			if err != nil {
				return err
			}
		} else {
			slog.Info("GATECHECK: no config file specified, using defaults")
		}

		// Check if API is enabled and configured
		if !RuntimeConfig.gatecheckConfig.API.Enabled {
			return fmt.Errorf("API submission is not enabled in config")
		}
		if RuntimeConfig.gatecheckConfig.API.Endpoint == "" {
			return fmt.Errorf("API endpoint is not configured")
		}

		// Check for JWT token in environment
		if os.Getenv("BELAY_JWT_TOKEN") == "" {
			return fmt.Errorf("BELAY_JWT_TOKEN environment variable is not set")
		}

		// Open the target file
		targetFilename := args[0]
		slog.Debug("open target file", "filename", targetFilename)
		var err error
		RuntimeConfig.targetFile, err = os.Open(targetFilename)
		if err != nil {
			return err
		}

		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		err := UploadBundle(
			args[0],
			RuntimeConfig.gatecheckConfig,
		)
		if err != nil {
			slog.Error("failed to submit bundle", "error", err)
			return err
		}
		slog.Info("bundle submitted successfully", "endpoint", RuntimeConfig.gatecheckConfig.API.Endpoint)
		return nil
	},
}

func newSubmitCommand() *cobra.Command {
	RuntimeConfig.ConfigFilename.SetupCobra(submitCmd)
	return submitCmd
}

func UploadBundle(filename string, config *gatecheck.Config) error {
	// Get JWT token from environment
	jwtToken := os.Getenv("BELAY_JWT_TOKEN")

	// Get git information
	gitCmd := exec.Command("git", "rev-parse", "HEAD")
	commitHash, err := gitCmd.Output()
	if err != nil {
		return fmt.Errorf("failed to get commit hash: %w", err)
	}

	gitCmd = exec.Command("git", "show", "-s", "--format=%cI", "HEAD")
	commitDate, err := gitCmd.Output()
	if err != nil {
		return fmt.Errorf("failed to get commit date: %w", err)
	}

	// Get git log (last commit message)
	gitCmd = exec.Command("git", "log", "-1", "--pretty=format:%s")
	gitLog, err := gitCmd.Output()
	if err != nil {
		return fmt.Errorf("failed to get git log: %w", err)
	}

	// Get git status
	gitCmd = exec.Command("git", "status", "--porcelain")
	gitStatus, err := gitCmd.Output()
	if err != nil {
		return fmt.Errorf("failed to get git status: %w", err)
	}

	// Get git branch name
	gitCmd = exec.Command("git", "rev-parse", "--abbrev-ref", "HEAD")
	branchName, err := gitCmd.Output()
	if err != nil {
		return fmt.Errorf("failed to get branch name: %w", err)
	}

	// Get repository information
	gitCmd = exec.Command("git", "config", "--get", "remote.origin.url")
	repoURL, err := gitCmd.Output()
	if err != nil {
		return fmt.Errorf("failed to get repository URL: %w", err)
	}

	// Extract owner and repository names from URL
	repoURLStr := strings.TrimSpace(string(repoURL))
	// Handle both HTTPS and SSH URLs
	var ownerName, repoName string
	if strings.HasPrefix(repoURLStr, "https://") {
		// https://github.com/owner/repo.git
		parts := strings.Split(strings.TrimSuffix(repoURLStr, ".git"), "/")
		if len(parts) >= 2 {
			ownerName = parts[len(parts)-2]
			repoName = parts[len(parts)-1]
		}
	} else {
		// git@github.com:owner/repo.git
		parts := strings.Split(strings.Split(repoURLStr, ":")[1], "/")
		if len(parts) >= 2 {
			ownerName = parts[0]
			repoName = strings.TrimSuffix(parts[1], ".git")
		}
	}

	if ownerName == "" || repoName == "" {
		return fmt.Errorf("failed to extract owner and repository names from URL: %s", repoURLStr)
	}

	// Open the file
	file, err := os.Open(filename)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	// Create a new multipart writer
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	// Add all required fields
	fields := map[string]string{
		"JwtToken":       jwtToken,
		"OwnerName":      ownerName,
		"RepositoryName": repoName,
		"CommitHash":     strings.TrimSpace(string(commitHash)),
		"CommitDate":     strings.TrimSpace(string(commitDate)),
		"GitLog":         strings.TrimSpace(string(gitLog)),
		"GitStatus":      string(gitStatus),
		"BranchName":     strings.TrimSpace(string(branchName)),
	}

	for key, value := range fields {
		if err := writer.WriteField(key, value); err != nil {
			return fmt.Errorf("failed to write field %s: %w", key, err)
		}
		slog.Debug("wrote field", "key", key)
	}

	// Create the file field
	part, err := writer.CreateFormFile("TarGzFile", filepath.Base(filename))
	if err != nil {
		return fmt.Errorf("failed to create form file: %w", err)
	}

	// Copy the file content
	if _, err := io.Copy(part, file); err != nil {
		return fmt.Errorf("failed to copy file content: %w", err)
	}

	// Close the multipart writer
	if err := writer.Close(); err != nil {
		return fmt.Errorf("failed to close writer: %w", err)
	}

	// Create the request
	req, err := http.NewRequest("POST", config.API.Endpoint, body)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Set the content type
	req.Header.Set("Content-Type", writer.FormDataContentType())

	// Create HTTP client
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: config.API.SkipVerify,
			},
		},
	}

	// Send the request
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	// Check response status
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("upload failed with status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}
