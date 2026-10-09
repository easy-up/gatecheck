package cmd

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/gatecheckdev/gatecheck/pkg/gatecheck"
	"github.com/gatecheckdev/gatecheck/pkg/redact"
)

func TestRedactCVEIDsEnvValues(t *testing.T) {
	cases := map[string]bool{"true": true, "1": true, "TRUE": true, "false": false, "0": false, " false ": false, "yes-please": true}
	for value, want := range cases {
		if got := RuntimeConfig.RedactCVEIDs.EnvToValueFunc(value).(bool); got != want {
			t.Errorf("GATECHECK_REDACT_CVE_IDS=%q: want %t, got %t", value, want, got)
		}
	}
}

func TestListOutputRedaction(t *testing.T) {
	render := func(on bool) string {
		previous := redact.Enabled()
		redact.SetEnabled(on)
		defer redact.SetEnabled(previous)

		src, err := os.Open("../test/grype-report.json")
		if err != nil {
			t.Fatal(err)
		}
		defer src.Close()

		buf := new(bytes.Buffer)
		dst := redact.NewWriter(buf)
		if err := gatecheck.List(dst, src, "grype-report.json"); err != nil {
			t.Fatal(err)
		}
		_ = dst.Flush()
		return buf.String()
	}

	plain, redacted := render(false), render(true)
	if !strings.Contains(plain, "GHSA-") {
		t.Fatal("fixture should contain advisory IDs")
	}
	if strings.Contains(redacted, "GHSA-") || strings.Contains(redacted, "CVE-") {
		t.Fatal("IDs leaked in redacted list output")
	}
	if !strings.Contains(redacted, "[redacted]") || !strings.Contains(redacted, "vm2") {
		t.Fatal("want the table kept with IDs replaced")
	}
	plainLines, redactedLines := strings.Split(plain, "\n"), strings.Split(redacted, "\n")
	if len(plainLines) != len(redactedLines) {
		t.Fatalf("line count changed: %d vs %d", len(plainLines), len(redactedLines))
	}
	for i := range plainLines {
		if len(plainLines[i]) != len(redactedLines[i]) {
			t.Fatalf("line %d width changed, columns misaligned:\n%s\n%s", i, plainLines[i], redactedLines[i])
		}
	}
}
