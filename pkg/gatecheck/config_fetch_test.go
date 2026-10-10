package gatecheck

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

const fetchTestToken = "s3cr3t-token-value"

const fetchTestConfig = `# Not expressible in gatecheck: grype negligible limit 0
# SBOM required
version: "1"
grype:
  severityLimit:
    critical:
      enabled: true
      limit: 0
    high:
      enabled: true
      limit: 3
`

func TestFetchConfig_Success(t *testing.T) {
	var gotAuth string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "text/yaml")
		_, _ = w.Write([]byte(fetchTestConfig))
	}))
	defer server.Close()

	content, err := FetchConfig(context.Background(), FetchConfigOptions{
		URL:           server.URL + "/policy/gatecheck?branch=main",
		Authorization: AuthorizationFromToken(fetchTestToken),
	})
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != fetchTestConfig {
		t.Fatalf("want body returned unmodified, got:\n%s", content)
	}
	if gotAuth != "Bearer "+fetchTestToken {
		t.Fatalf("want bearer authorization header, got %q", gotAuth)
	}
}

func TestFetchConfig_NoAuthorization(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := r.Header["Authorization"]; ok {
			t.Error("want no Authorization header")
		}
		_, _ = w.Write([]byte(fetchTestConfig))
	}))
	defer server.Close()

	if _, err := FetchConfig(context.Background(), FetchConfigOptions{URL: server.URL}); err != nil {
		t.Fatal(err)
	}
}

func TestFetchConfig_FailClosed(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
		want   string
	}{
		{name: "unauthorized", status: 401, body: fetchTestConfig, want: "status 401"},
		{name: "forbidden", status: 403, body: fetchTestConfig, want: "status 403"},
		{name: "not-found", status: 404, body: fetchTestConfig, want: "status 404"},
		{name: "server-error", status: 500, body: fetchTestConfig, want: "status 500"},
		{name: "redirect-not-followed-to-content", status: 304, body: "", want: "status 304"},
		{name: "empty", status: 200, body: "", want: "empty document"},
		{name: "whitespace", status: 200, body: "  \n\n", want: "empty document"},
		{name: "comments-only", status: 200, body: "# nothing here\n", want: "empty document"},
		{name: "invalid-yaml", status: 200, body: "version: [1\n", want: "not a valid gatecheck config"},
		{name: "html", status: 200, body: "<html><body>login</body></html>", want: "not a valid gatecheck config"},
		{name: "unknown-key", status: 200, body: "version: \"1\"\ngrype:\n  severityLimits: {}\n", want: "not found in type"},
		{name: "wrong-type", status: 200, body: "version: \"1\"\ngrype:\n  severityLimit:\n    high:\n      limit: lots\n", want: "not a valid gatecheck config"},
		{name: "missing-version", status: 200, body: "grype:\n  kevLimitEnabled: true\n", want: "missing required field 'version'"},
		{name: "multiple-documents", status: 200, body: "version: \"1\"\n---\nversion: \"1\"\n", want: "multiple documents"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer server.Close()

			content, err := FetchConfig(context.Background(), FetchConfigOptions{URL: server.URL})
			if err == nil {
				t.Fatalf("want error, got content %q", content)
			}
			if content != nil {
				t.Fatal("want no content on error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want error containing %q, got %v", tc.want, err)
			}
		})
	}
}

func TestFetchConfig_JSONBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"version":"1","gitleaks":{"limitEnabled":true}}`))
	}))
	defer server.Close()

	if _, err := FetchConfig(context.Background(), FetchConfigOptions{URL: server.URL}); err != nil {
		t.Fatal(err)
	}
}

func TestFetchConfig_TooLarge(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("version: \"1\"\n"))
		_, _ = w.Write(bytes.Repeat([]byte("#"), MaxFetchedConfigSize))
	}))
	defer server.Close()

	_, err := FetchConfig(context.Background(), FetchConfigOptions{URL: server.URL})
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("want size error, got %v", err)
	}
}

func TestFetchConfig_Timeout(t *testing.T) {
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer server.Close()
	defer close(release)

	start := time.Now()
	_, err := FetchConfig(context.Background(), FetchConfigOptions{URL: server.URL, Timeout: 100 * time.Millisecond})
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("want timeout error, got %v", err)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("timeout was not enforced")
	}
}

func TestFetchConfig_URLValidation(t *testing.T) {
	cases := []struct {
		url  string
		want string
	}{
		{url: "http://policy.example.com/gatecheck", want: "refusing plain http"},
		{url: "ftp://policy.example.com/gatecheck", want: "unsupported url scheme"},
		{url: "/just/a/path", want: "invalid url"},
		{url: "::not a url", want: "invalid url"},
	}
	for _, tc := range cases {
		_, err := FetchConfig(context.Background(), FetchConfigOptions{URL: tc.url})
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("url %q: want error containing %q, got %v", tc.url, tc.want, err)
		}
	}
}

func TestFetchConfig_HTTPS(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(fetchTestConfig))
	}))
	defer server.Close()

	if _, err := FetchConfig(context.Background(), FetchConfigOptions{URL: server.URL, Client: server.Client()}); err != nil {
		t.Fatal(err)
	}
}

func TestFetchConfig_SecretsNotLeaked(t *testing.T) {
	logBuf := new(bytes.Buffer)
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(logBuf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	defer slog.SetDefault(previous)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("token " + fetchTestToken + " belongs to another repository"))
	}))
	defer server.Close()

	// credentials in the URL itself must not be echoed either
	rawURL := strings.Replace(server.URL, "http://", "http://user:urlpass@", 1) + "/p?token=querysecret"
	_, err := FetchConfig(context.Background(), FetchConfigOptions{
		URL:           rawURL,
		Authorization: AuthorizationFromToken(fetchTestToken),
	})
	if err == nil {
		t.Fatal("want error")
	}

	for _, secret := range []string{fetchTestToken, "urlpass", "querysecret"} {
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("error leaked %q: %v", secret, err)
		}
		if strings.Contains(logBuf.String(), secret) {
			t.Fatalf("log leaked %q: %s", secret, logBuf.String())
		}
	}
}

func TestAuthorizationFromToken(t *testing.T) {
	cases := map[string]string{
		"":               "",
		"   ":            "",
		"abc":            "Bearer abc",
		" abc\n":         "Bearer abc",
		"Bearer abc":     "Bearer abc",
		"Basic dXNlcg==": "Basic dXNlcg==",
	}
	for in, want := range cases {
		if got := AuthorizationFromToken(in); got != want {
			t.Fatalf("AuthorizationFromToken(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRedactURL(t *testing.T) {
	got := RedactURL("https://user:pass@belay.example.com/Policy/o/r/gatecheck?branch=main&token=x#frag")
	want := "https://belay.example.com/Policy/o/r/gatecheck"
	if got != want {
		t.Fatalf("want %q, got %q", want, got)
	}
}

// Configs that real pipelines already use must pass the strict validator
func TestValidateConfigBytes_ExistingConfigs(t *testing.T) {
	for _, filename := range []string{"../../test/gatecheck.yaml"} {
		content, err := os.ReadFile(filename)
		if err != nil {
			t.Fatal(err)
		}
		if err := ValidateConfigBytes(content); err != nil {
			t.Fatalf("%s: %v", filename, err)
		}
	}

	buf := new(bytes.Buffer)
	if err := EncodeConfigTo(buf, NewDefaultConfig(), "yaml"); err != nil {
		t.Fatal(err)
	}
	if err := ValidateConfigBytes(buf.Bytes()); err != nil {
		t.Fatalf("default config: %v", err)
	}
}
