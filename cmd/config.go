package cmd

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/gatecheckdev/gatecheck/pkg/gatecheck"
	"github.com/spf13/cobra"
)

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "manage the gatecheck configuration file",
}

var configInitCmd = &cobra.Command{
	Use:   "init",
	Short: "output an example configuration file",
	RunE: func(cmd *cobra.Command, args []string) error {
		output, _ := cmd.Flags().GetString("output")

		switch output {
		case "json", ".json":
			output = ".json"
		case "toml", ".toml":
			output = ".toml"
		case "yaml", "yml", ".yaml", ".yml":
			output = ".yaml"
		default:
			return errors.New("invalid --output format, must be json,toml,yaml, or yml")
		}

		return gatecheck.NewConfigEncoder(cmd.OutOrStdout(), output).Encode(gatecheck.NewDefaultConfig())
	},
}

var configConvertCmd = &cobra.Command{
	Use:   "convert",
	Short: "convert and existing configuration file into another format",
	PreRunE: func(cmd *cobra.Command, args []string) error {
		configFilename, _ := cmd.Flags().GetString("file")
		RuntimeConfig.gatecheckConfig = &gatecheck.Config{}
		err := gatecheck.NewConfigDecoder(configFilename).Decode(RuntimeConfig.gatecheckConfig)
		if err != nil {
			return err
		}

		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		output, _ := cmd.Flags().GetString("output")

		switch output {
		case "json", ".json":
			output = ".json"
		case "toml", ".toml":
			output = ".toml"
		case "yaml", "yml", ".yaml", ".yml":
			output = ".yaml"
		default:
			return errors.New("invalid --output format, must be json, toml, yaml, or yml")
		}

		return gatecheck.NewConfigEncoder(cmd.OutOrStdout(), output).Encode(RuntimeConfig.gatecheckConfig)
	},
}

var configFetchCmd = &cobra.Command{
	Use:   "fetch",
	Short: "download a configuration file from a URL and verify it before use",
	Long: `Download a gatecheck configuration file over HTTPS and verify it strictly decodes
before writing it out. Plain HTTP is only permitted for loopback hosts.

Any non-2xx response, empty body, unknown key or invalid document is an error and
nothing is written. The credential is read from the environment variable named by
--auth-env and is never accepted as a flag value, logged, or written to the output.`,
	Example: `  gatecheck config fetch --url https://policy.example.com/gatecheck.yml --auth-env POLICY_TOKEN -o .gatecheck.yml`,
	Args:    cobra.NoArgs,
	RunE:    runConfigFetch,
}

func runConfigFetch(cmd *cobra.Command, _ []string) error {
	fetchURL, _ := cmd.Flags().GetString("url")
	authEnv, _ := cmd.Flags().GetString("auth-env")
	output, _ := cmd.Flags().GetString("output")
	timeout, _ := cmd.Flags().GetDuration("timeout")

	if strings.TrimSpace(fetchURL) == "" {
		return errors.New("--url is required")
	}
	if timeout <= 0 {
		return errors.New("--timeout must be greater than 0")
	}

	authorization := ""
	if authEnv != "" {
		token, ok := os.LookupEnv(authEnv)
		if !ok || strings.TrimSpace(token) == "" {
			return fmt.Errorf("environment variable %s named by --auth-env is not set or empty", authEnv)
		}
		authorization = gatecheck.AuthorizationFromToken(token)
	}

	content, err := gatecheck.FetchConfig(cmd.Context(), gatecheck.FetchConfigOptions{
		URL:           fetchURL,
		Authorization: authorization,
		Timeout:       timeout,
	})
	if err != nil {
		return err
	}

	if output == "" || output == "-" {
		_, err = cmd.OutOrStdout().Write(content)
		return err
	}

	return writeFileAtomic(output, content)
}

// writeFileAtomic writes to a temporary file in the destination directory and renames it
// into place so an existing file is never left truncated or partially written
func writeFileAtomic(filename string, content []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(filename), "."+filepath.Base(filename)+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	if _, err := tmp.Write(content); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o644); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, filename)
}

func newConfigCommand() *cobra.Command {
	configConvertCmd.Flags().StringP("file", "f", "gatecheck.yaml", "gatecheck validation config file")
	configConvertCmd.Flags().StringP("output", "o", "yaml", "Format to convert into formats=[json yaml yml toml]")
	configInitCmd.Flags().StringP("output", "o", "yaml", "Format to convert into formats=[json yaml yml toml]")

	_ = configConvertCmd.MarkFlagFilename("file", "json", "yaml", "yml", "toml")
	_ = configInitCmd.MarkFlagFilename("file", "json", "yaml", "yml", "toml")

	configFetchCmd.Flags().String("url", "", "URL of the configuration file (https required, http only for loopback hosts)")
	configFetchCmd.Flags().String("auth-env", "", "name of the environment variable holding the credential sent in the Authorization header")
	configFetchCmd.Flags().StringP("output", "o", "", "file to write the configuration to (default STDOUT)")
	configFetchCmd.Flags().Duration("timeout", gatecheck.DefaultConfigFetchTimeout, "maximum time allowed for the request")
	_ = configFetchCmd.MarkFlagRequired("url")
	_ = configFetchCmd.MarkFlagFilename("output", "json", "yaml", "yml")

	configCmd.AddCommand(configInitCmd, configConvertCmd, configFetchCmd)
	return configCmd
}
