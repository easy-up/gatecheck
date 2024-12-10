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
	"path/filepath"

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

	// Open the file
	file, err := os.Open(filename)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()
	slog.Debug("opened file", "filename", filepath.Base(filename))

	// Create a new multipart writer
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	// Add the JWT token field with exact case matching
	if err := writer.WriteField("JwtToken", jwtToken); err != nil {
		return fmt.Errorf("failed to write JWT token: %w", err)
	}
	slog.Debug("wrote JWT token", "length", len(jwtToken))

	// Create the file field with exact case matching
	part, err := writer.CreateFormFile("TarGzFile", filepath.Base(filename))
	if err != nil {
		return fmt.Errorf("failed to create form file: %w", err)
	}
	slog.Debug("wrote file", "filename", filepath.Base(filename))

	// Add debug logging to verify the form fields
	slog.Debug("sending multipart request",
		"endpoint", config.API.Endpoint,
		"filename", filepath.Base(filename),
		"content_type", writer.FormDataContentType())

	// Copy the file content
	if _, err := io.Copy(part, file); err != nil {
		return fmt.Errorf("failed to copy file content: %w", err)
	}
	slog.Debug("copied file content", "filename", filepath.Base(filename))
	// Close the multipart writer
	if err := writer.Close(); err != nil {
		return fmt.Errorf("failed to close writer: %w", err)
	}

	// Create the request
	req, err := http.NewRequest("POST", config.API.Endpoint, body)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	slog.Debug("created request", "endpoint", config.API.Endpoint)

	// Set the content type
	req.Header.Set("Content-Type", writer.FormDataContentType())
	slog.Debug("set content type", "content_type", writer.FormDataContentType())
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
	slog.Debug("received response", "status", resp.Status)
	defer resp.Body.Close()

	// Check response status
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("upload failed with status %d: %s", resp.StatusCode, string(body))
	}
	slog.Debug("upload successful", "status", resp.Status)

	return nil
}
