package gatecheck

import (
	"bytes"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/gatecheckdev/gatecheck/pkg/artifacts"
	"github.com/gatecheckdev/gatecheck/pkg/epss"
	"github.com/gatecheckdev/gatecheck/pkg/kev"
	"gopkg.in/yaml.v3"
)

func grypeMatches(severities ...string) []artifacts.GrypeMatch {
	matches := make([]artifacts.GrypeMatch, 0, len(severities))
	for i, severity := range severities {
		matches = append(matches, artifacts.GrypeMatch{Vulnerability: artifacts.GrypeVulnerability{
			ID:       "TEST-" + string(rune('A'+i)),
			Severity: severity,
		}})
	}
	return matches
}

func Test_ruleGrypeSeverityLimit_NegligibleUnknown(t *testing.T) {
	cases := []struct {
		name       string
		negligible configLimit
		unknown    configLimit
		severities []string
		want       bool
	}{
		{name: "disabled-ignores-counts", severities: []string{"Negligible", "Negligible", "Unknown"}, want: true},
		{name: "negligible-within-limit", negligible: configLimit{Enabled: true, Limit: 2}, severities: []string{"Negligible", "Negligible"}, want: true},
		{name: "negligible-over-limit", negligible: configLimit{Enabled: true, Limit: 1}, severities: []string{"Negligible", "negligible"}, want: false},
		{name: "unknown-limit-0", unknown: configLimit{Enabled: true, Limit: 0}, severities: []string{"Unknown"}, want: false},
		{name: "unknown-within-limit", unknown: configLimit{Enabled: true, Limit: 1}, severities: []string{"Unknown", "Negligible"}, want: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			config := NewDefaultConfig()
			config.Grype.SeverityLimit.Negligible = tc.negligible
			config.Grype.SeverityLimit.Unknown = tc.unknown
			report := &artifacts.GrypeReportMin{Matches: grypeMatches(tc.severities...)}

			if got := ruleGrypeSeverityLimit(config, report); got != tc.want {
				t.Fatalf("want %t, got %t", tc.want, got)
			}
		})
	}
}

func noEPSS() *epss.Data {
	return &epss.Data{CVEs: map[string]epss.CVE{}}
}

func Test_validateGrypeRules_NegligibleUnknown(t *testing.T) {
	t.Run("default-config-unchanged", func(t *testing.T) {
		// Without the new limits negligible and unknown findings are ignored, as before
		config := NewDefaultConfig()
		config.Grype.SeverityLimit.Critical = configLimit{Enabled: true, Limit: 0}
		report := &artifacts.GrypeReportMin{Matches: grypeMatches("Negligible", "Unknown", "Negligible")}

		if err := validateGrypeRules(config, report, nil, noEPSS()); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("negligible-limit-exceeded", func(t *testing.T) {
		config := NewDefaultConfig()
		config.Grype.SeverityLimit.Negligible = configLimit{Enabled: true, Limit: 0}
		report := &artifacts.GrypeReportMin{Matches: grypeMatches("Negligible")}

		err := validateGrypeRules(config, report, nil, noEPSS())
		if !errors.Is(err, ErrValidationFailure) {
			t.Fatalf("want validation failure, got %v", err)
		}
	})

	t.Run("unknown-limit-exceeded", func(t *testing.T) {
		config := NewDefaultConfig()
		config.Grype.SeverityLimit.Unknown = configLimit{Enabled: true, Limit: 1}
		report := &artifacts.GrypeReportMin{Matches: grypeMatches("Unknown", "Unknown", "High")}

		err := validateGrypeRules(config, report, nil, noEPSS())
		if !errors.Is(err, ErrValidationFailure) {
			t.Fatalf("want validation failure, got %v", err)
		}
	})

	catalog := &kev.Catalog{Vulnerabilities: []kev.Vulnerability{{CveID: "TEST-A"}}}

	t.Run("kev-negligible-ignored-by-default", func(t *testing.T) {
		config := NewDefaultConfig()
		config.Grype.KEVLimitEnabled = true
		report := &artifacts.GrypeReportMin{Matches: grypeMatches("Negligible")}

		if err := validateGrypeRules(config, report, catalog, noEPSS()); err != nil {
			t.Fatalf("existing behaviour: negligible findings are removed before the KEV check, got %v", err)
		}
	})

	t.Run("kev-negligible-checked-when-limit-enabled", func(t *testing.T) {
		config := NewDefaultConfig()
		config.Grype.KEVLimitEnabled = true
		config.Grype.SeverityLimit.Negligible = configLimit{Enabled: true, Limit: 100}
		report := &artifacts.GrypeReportMin{Matches: grypeMatches("Negligible")}

		err := validateGrypeRules(config, report, catalog, noEPSS())
		if !errors.Is(err, ErrValidationFailure) {
			t.Fatalf("want KEV failure once negligible findings are in scope, got %v", err)
		}
	})
}

// strictDecode decodes YAML into a default config, rejecting unknown keys
func strictDecode(content []byte) (*Config, error) {
	decoder := yaml.NewDecoder(bytes.NewReader(content))
	decoder.KnownFields(true)
	config := NewDefaultConfig()
	return config, decoder.Decode(config)
}

func TestConfig_GrypeNegligibleUnknownKeys(t *testing.T) {
	content := []byte(`version: "1"
grype:
  severityLimit:
    negligible:
      enabled: true
      limit: 10
    unknown:
      enabled: true
      limit: 0
`)
	config, err := strictDecode(content)
	if err != nil {
		t.Fatal(err)
	}
	if !config.Grype.SeverityLimit.Negligible.Enabled || config.Grype.SeverityLimit.Negligible.Limit != 10 ||
		!config.Grype.SeverityLimit.Unknown.Enabled {
		t.Fatalf("unexpected grype severity limits %+v", config.Grype.SeverityLimit)
	}

	// cyclonedx has no negligible severity, the key must not be silently accepted
	if _, err := strictDecode([]byte("version: \"1\"\ncyclonedx:\n  severityLimit:\n    negligible:\n      enabled: true\n")); err == nil {
		t.Fatal("want cyclonedx negligible key rejected")
	}

	// the default config advertises the new keys, disabled
	buf := new(bytes.Buffer)
	if err := EncodeConfigTo(buf, NewDefaultConfig(), "yaml"); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(buf.Bytes(), []byte("negligible:")) || !bytes.Contains(buf.Bytes(), []byte("unknown:")) {
		t.Fatalf("want negligible and unknown in default config:\n%s", buf.String())
	}
}

func Test_ruleGrypeEPSSAllow_LogsGrypeScore(t *testing.T) {
	logBuf := new(bytes.Buffer)
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(logBuf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	defer slog.SetDefault(previous)

	config := NewDefaultConfig()
	config.Grype.EPSSRiskAcceptance = configEPSSRiskAcceptance{Enabled: true, Score: 0.001}
	report := &artifacts.GrypeReportMin{Matches: grypeMatches("High")}

	ruleGrypeEPSSAllow(config, report, noEPSS())

	if !strings.Contains(logBuf.String(), "epss_risk_acceptance_score=0.001") {
		t.Fatalf("want the grype score logged:\n%s", logBuf.String())
	}
}
