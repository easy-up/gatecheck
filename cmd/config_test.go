package cmd

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/spf13/cobra"
)

const cmdTestToken = "cmd-test-token-9f8e7d"

const cmdTestConfig = `# comment from the policy server
version: "1"
gitleaks:
  limitEnabled: true
`

var (
	testRootOnce sync.Once
	testRoot     *cobra.Command
)

// runGatecheck executes the CLI with args. Commands are package level vars,
// so the command tree can only be built once per test binary.
func runGatecheck(args ...string) (stdout string, stderr string, err error) {
	testRootOnce.Do(func() { testRoot = NewGatecheckCommand() })

	// flag values persist between executions
	for _, name := range []string{"url", "auth-env", "output"} {
		_ = configFetchCmd.Flags().Set(name, "")
	}
	_ = configFetchCmd.Flags().Set("timeout", "30s")

	outBuf, errBuf := new(bytes.Buffer), new(bytes.Buffer)
	testRoot.SetOut(outBuf)
	testRoot.SetErr(errBuf)
	testRoot.SetArgs(args)
	err = testRoot.Execute()
	return outBuf.String(), errBuf.String(), err
}

func newPolicyServer(t *testing.T, status int, body string) (*httptest.Server, *string) {
	t.Helper()
	gotAuth := new(string)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(server.Close)
	return server, gotAuth
}

func TestConfigFetch_WritesOutputFile(t *testing.T) {
	server, gotAuth := newPolicyServer(t, http.StatusOK, cmdTestConfig)
	t.Setenv("POLICY_TOKEN", cmdTestToken)
	output := filepath.Join(t.TempDir(), ".gatecheck.yml")

	stdout, stderr, err := runGatecheck("config", "fetch", "--url", server.URL+"/gatecheck?branch=main", "--auth-env", "POLICY_TOKEN", "-o", output)
	if err != nil {
		t.Fatal(err)
	}

	content, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != cmdTestConfig {
		t.Fatalf("want config written unmodified, got:\n%s", content)
	}
	if *gotAuth != "Bearer "+cmdTestToken {
		t.Fatalf("want bearer token header, got %q", *gotAuth)
	}
	if strings.Contains(stdout+stderr+string(content), cmdTestToken) {
		t.Fatal("token leaked to output")
	}
	leftovers, _ := filepath.Glob(filepath.Join(filepath.Dir(output), ".*.tmp-*"))
	if len(leftovers) != 0 {
		t.Fatalf("temporary files left behind: %v", leftovers)
	}
}

func TestConfigFetch_Stdout(t *testing.T) {
	server, gotAuth := newPolicyServer(t, http.StatusOK, cmdTestConfig)

	stdout, _, err := runGatecheck("config", "fetch", "--url", server.URL)
	if err != nil {
		t.Fatal(err)
	}
	if stdout != cmdTestConfig {
		t.Fatalf("want config on stdout, got %q", stdout)
	}
	if *gotAuth != "" {
		t.Fatalf("want no authorization header without --auth-env, got %q", *gotAuth)
	}
}

func TestConfigFetch_FailureKeepsExistingFile(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
	}{
		{name: "403", status: http.StatusForbidden, body: cmdTestConfig},
		{name: "invalid", status: http.StatusOK, body: "not: [valid"},
		{name: "empty", status: http.StatusOK, body: ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server, _ := newPolicyServer(t, tc.status, tc.body)
			t.Setenv("POLICY_TOKEN", cmdTestToken)
			output := filepath.Join(t.TempDir(), ".gatecheck.yml")
			if err := os.WriteFile(output, []byte("previous"), 0o644); err != nil {
				t.Fatal(err)
			}

			_, stderr, err := runGatecheck("config", "fetch", "--url", server.URL, "--auth-env", "POLICY_TOKEN", "-o", output)
			if err == nil {
				t.Fatal("want error")
			}
			if strings.Contains(stderr+err.Error(), cmdTestToken) {
				t.Fatal("token leaked in error output")
			}
			content, _ := os.ReadFile(output)
			if string(content) != "previous" {
				t.Fatalf("existing file was modified: %q", content)
			}
		})
	}
}

func TestConfigFetch_FailureCreatesNoFile(t *testing.T) {
	server, _ := newPolicyServer(t, http.StatusUnauthorized, "")
	output := filepath.Join(t.TempDir(), ".gatecheck.yml")

	if _, _, err := runGatecheck("config", "fetch", "--url", server.URL, "-o", output); err == nil {
		t.Fatal("want error")
	}
	if _, err := os.Stat(output); !os.IsNotExist(err) {
		t.Fatalf("want no output file, stat err: %v", err)
	}
}

func TestConfigFetch_AuthEnvMissing(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests++
		_, _ = w.Write([]byte(cmdTestConfig))
	}))
	defer server.Close()

	t.Setenv("POLICY_TOKEN_EMPTY", "")
	for _, envName := range []string{"POLICY_TOKEN_EMPTY", "POLICY_TOKEN_DEFINITELY_UNSET"} {
		_, _, err := runGatecheck("config", "fetch", "--url", server.URL, "--auth-env", envName)
		if err == nil || !strings.Contains(err.Error(), envName) {
			t.Fatalf("want error naming %s, got %v", envName, err)
		}
	}
	if requests != 0 {
		t.Fatalf("want no request when credential is missing, got %d", requests)
	}
}

func TestConfigFetch_RequiresURL(t *testing.T) {
	if _, _, err := runGatecheck("config", "fetch"); err == nil {
		t.Fatal("want error without --url")
	}
}

// Existing config subcommands must behave as before
func TestConfigInit_Unchanged(t *testing.T) {
	stdout, _, err := runGatecheck("config", "init")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout, "version: \"1\"") || !strings.Contains(stdout, "severityLimit:") {
		t.Fatalf("unexpected config init output:\n%s", stdout)
	}
}
