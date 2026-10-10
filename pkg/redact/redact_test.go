package redact

import (
	"bytes"
	"strings"
	"testing"
)

func withRedaction(t *testing.T, on bool) {
	t.Helper()
	previous := Enabled()
	SetEnabled(on)
	t.Cleanup(func() { SetEnabled(previous) })
}

func TestString_Identifiers(t *testing.T) {
	ids := []string{
		"CVE-2023-12345", "cve-2021-44228", "GHSA-cchq-frgv-rjh5", "GO-2023-1234", "PYSEC-2021-19",
		"RUSTSEC-2022-0001", "ALAS2-2023-1234", "ALAS2023-2024-512", "RHSA-2023:1234", "ELSA-2023-12345",
		"DSA-5001-1", "DLA-3000-2", "USN-6000-1", "SUSE-SU-2023:1234-1", "GLSA-202301-01",
		"BIT-node-2023-1234", "MAL-2024-100",
	}
	for _, id := range ids {
		got := String("found " + id + " in package")
		if strings.Contains(got, id) || !strings.Contains(got, "[redacted]") {
			t.Errorf("%s not redacted: %q", id, got)
		}
		if len(got) != len("found "+id+" in package") {
			t.Errorf("%s: width changed: %q", id, got)
		}
	}
}

func TestString_LeavesOtherTextAlone(t *testing.T) {
	for _, s := range []string{
		"severity=Critical package=vm2 version=3.9.17",
		"limit exceeded: 3 critical (limit 0)",
		"https://github.com/advisories",
		"CVE-23-1",
		"sha256:0123abcd",
	} {
		if got := String(s); got != s {
			t.Errorf("unexpected change %q -> %q", s, got)
		}
	}
}

func TestString_ColorizedLogs(t *testing.T) {
	line := "\x1b[2mid=\x1b[0mCVE-2023-12345 \x1b[2mseverity=\x1b[0mHigh\n"
	got := String(line)
	if strings.Contains(got, "CVE-2023-12345") {
		t.Fatalf("not redacted after ANSI escape: %q", got)
	}
}

func TestString_ShortIdentifierKeepsWidth(t *testing.T) {
	if got := String("DSA-1-1"); got != "[redact" {
		t.Fatalf("want placeholder cut to width, got %q", got)
	}
}

func TestWriter_Disabled(t *testing.T) {
	withRedaction(t, false)
	buf := new(bytes.Buffer)
	w := NewWriter(buf)
	_, _ = w.Write([]byte("CVE-2023-12345 partial"))
	if buf.String() != "CVE-2023-12345 partial" {
		t.Fatalf("disabled writer must pass through immediately, got %q", buf.String())
	}
}

func TestWriter_SplitAcrossWrites(t *testing.T) {
	withRedaction(t, true)
	buf := new(bytes.Buffer)
	w := NewWriter(buf)
	for _, part := range []string{"id=CVE-20", "23-12345 sev=High\nnext GHSA-cchq", "-frgv-rjh5"} {
		if _, err := w.Write([]byte(part)); err != nil {
			t.Fatal(err)
		}
	}
	if strings.Contains(buf.String(), "next") {
		t.Fatalf("partial line written before newline or flush: %q", buf.String())
	}
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if strings.Contains(out, "CVE-") || strings.Contains(out, "GHSA-") {
		t.Fatalf("identifier split across writes leaked: %q", out)
	}
	if !strings.HasPrefix(out, "id=[redacted]     sev=High\n") {
		t.Fatalf("unexpected output %q", out)
	}
}

func TestWriter_WriteReportsInputLength(t *testing.T) {
	withRedaction(t, true)
	w := NewWriter(new(bytes.Buffer))
	n, err := w.Write([]byte("CVE-2023-12345\n"))
	if err != nil || n != len("CVE-2023-12345\n") {
		t.Fatalf("want n=%d, got n=%d err=%v", len("CVE-2023-12345\n"), n, err)
	}
}
