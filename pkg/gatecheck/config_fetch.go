package gatecheck

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// MaxFetchedConfigSize is the largest configuration body FetchConfig will accept
const MaxFetchedConfigSize = 1 << 20

// DefaultConfigFetchTimeout is used when FetchConfigOptions.Timeout is zero
const DefaultConfigFetchTimeout = 30 * time.Second

// FetchConfigOptions controls how a remote configuration file is retrieved
type FetchConfigOptions struct {
	// URL must use https, plain http is only permitted for loopback hosts
	URL string
	// Authorization is the full Authorization header value, "" sends no header
	Authorization string
	// Timeout bounds the entire request, 0 uses DefaultConfigFetchTimeout
	Timeout time.Duration
	// Client is optional, mainly for tests
	Client *http.Client
}

// AuthorizationFromToken builds an Authorization header value from a credential
//
// A bare token is sent as a Bearer token. A value that already carries a scheme
// (e.g. "Bearer abc" or "Basic abc") is used as-is.
func AuthorizationFromToken(token string) string {
	token = strings.TrimSpace(token)
	if token == "" {
		return ""
	}
	if strings.ContainsAny(token, " \t") {
		return token
	}
	return "Bearer " + token
}

// RedactURL returns scheme://host/path with any user info, query and fragment removed
//
// Safe to use in logs and error messages.
func RedactURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "<invalid url>"
	}
	redacted := url.URL{Scheme: u.Scheme, Host: u.Host, Path: u.Path}
	return redacted.String()
}

// FetchConfig downloads a configuration file and verifies it is a valid gatecheck config
//
// The function fails closed: a non-2xx response, an empty body, or a body that does not
// strictly decode into a Config is an error. On success the original response bytes are
// returned unmodified so comments in the source document are preserved.
func FetchConfig(ctx context.Context, opts FetchConfigOptions) ([]byte, error) {
	target, err := url.Parse(opts.URL)
	if err != nil || target.Host == "" {
		return nil, errors.New("config fetch: invalid url")
	}
	safeURL := RedactURL(opts.URL)

	switch target.Scheme {
	case "https":
	case "http":
		if !isLoopbackHost(target.Hostname()) {
			return nil, fmt.Errorf("config fetch: refusing plain http for non-loopback host, use https: %s", safeURL)
		}
	default:
		return nil, fmt.Errorf("config fetch: unsupported url scheme %q", target.Scheme)
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = DefaultConfigFetchTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("config fetch: cannot create request for %s", safeURL)
	}
	req.Header.Set("Accept", "application/yaml, text/yaml, application/json;q=0.9, */*;q=0.1")
	if opts.Authorization != "" {
		req.Header.Set("Authorization", opts.Authorization)
	}

	client := opts.Client
	if client == nil {
		client = &http.Client{}
	}

	slog.Debug("fetch config", "url", safeURL, "timeout", timeout.String(), "authorization", opts.Authorization != "")
	res, err := client.Do(req)
	if err != nil {
		// url.Error embeds the full request URL, only report the underlying cause
		var urlErr *url.Error
		if errors.As(err, &urlErr) {
			err = urlErr.Err
		}
		if errors.Is(err, context.DeadlineExceeded) {
			return nil, fmt.Errorf("config fetch: request to %s timed out after %s", safeURL, timeout)
		}
		return nil, fmt.Errorf("config fetch: request to %s failed: %w", safeURL, err)
	}
	defer res.Body.Close()

	if res.StatusCode < 200 || res.StatusCode > 299 {
		return nil, fmt.Errorf("config fetch: %s returned status %d", safeURL, res.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(res.Body, MaxFetchedConfigSize+1))
	if err != nil {
		return nil, fmt.Errorf("config fetch: reading response from %s failed: %w", safeURL, err)
	}
	if len(body) > MaxFetchedConfigSize {
		return nil, fmt.Errorf("config fetch: response from %s exceeds %d bytes", safeURL, MaxFetchedConfigSize)
	}

	if err := ValidateConfigBytes(body); err != nil {
		return nil, fmt.Errorf("config fetch: response from %s is not a valid gatecheck config: %w", safeURL, err)
	}

	slog.Debug("fetched config", "url", safeURL, "bytes", len(body))
	return body, nil
}

// ValidateConfigBytes strictly decodes a YAML or JSON document into a Config
//
// Empty documents, unknown keys, multiple documents and a missing version are errors.
func ValidateConfigBytes(content []byte) error {
	if len(bytes.TrimSpace(content)) == 0 {
		return errors.New("empty document")
	}

	decoder := yaml.NewDecoder(bytes.NewReader(content))
	decoder.KnownFields(true)

	config := new(Config)
	if err := decoder.Decode(config); err != nil {
		if errors.Is(err, io.EOF) {
			return errors.New("empty document")
		}
		return err
	}

	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("multiple documents are not supported")
	}

	if strings.TrimSpace(config.Version) == "" {
		return errors.New("missing required field 'version'")
	}

	return nil
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
