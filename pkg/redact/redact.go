// Package redact removes vulnerability identifiers from CLI output
//
// When enabled, output written through a Writer has CVE, GHSA and common
// ecosystem/distribution advisory IDs replaced with "[redacted]". Report
// files are never modified, only what is printed.
package redact

import (
	"bytes"
	"io"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
)

// Placeholder replaces each redacted identifier
const Placeholder = "[redacted]"

// idPattern matches vulnerability identifiers: CVE, GitHub (GHSA), OSV ecosystem
// databases, and common Linux distribution advisories
//
// There is no leading word boundary: colorized log output puts an ANSI escape
// ending in "m" directly before attribute values.
var idPattern = regexp.MustCompile(`(?i)(?:` + strings.Join([]string{
	`CVE-\d{4}-\d{4,}`,
	`GHSA(?:-[23456789cfghjmpqrvwx]{4}){3}`,
	`(?:GO|PYSEC|RUSTSEC|OSV|MAL|PSF|RSEC)-\d{4}-\d+`,
	`BIT-[a-z0-9]+(?:-[a-z0-9]+)*-\d{4}-\d+`,
	`(?:ALAS2023|ALAS2|ALAS|ALSA|RLSA|ELSA|RHSA|RHBA|RHEA|CESA|SUSE-SU|openSUSE-SU)-\d{4}[:-]\d+(?:-\d+)?`,
	`(?:DSA|DLA|USN)-\d+-\d+`,
	`GLSA-\d{6}-\d{2}`,
}, "|") + `)\b`)

var enabled atomic.Bool

// SetEnabled turns redaction on or off for every Writer
func SetEnabled(on bool) {
	enabled.Store(on)
}

// Enabled reports whether redaction is on
func Enabled() bool {
	return enabled.Load()
}

// String replaces each identifier in s with Placeholder padded or cut to the
// identifier's width, so fixed-width table columns stay aligned
func String(s string) string {
	return idPattern.ReplaceAllStringFunc(s, sameWidth)
}

func sameWidth(id string) string {
	if len(id) <= len(Placeholder) {
		return Placeholder[:len(id)]
	}
	return Placeholder + strings.Repeat(" ", len(id)-len(Placeholder))
}

// Writer redacts complete lines written to it while redaction is enabled
//
// Partial lines are held until a newline or Flush so identifiers split across
// writes are still matched. When redaction is disabled writes pass through.
type Writer struct {
	mu  sync.Mutex
	dst io.Writer
	buf []byte
}

// NewWriter wraps dst
func NewWriter(dst io.Writer) *Writer {
	return &Writer{dst: dst}
}

func (w *Writer) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if !Enabled() && len(w.buf) == 0 {
		return w.dst.Write(p)
	}

	w.buf = append(w.buf, p...)
	end := bytes.LastIndexByte(w.buf, '\n')
	if end < 0 {
		return len(p), nil
	}
	if err := w.writeRedacted(w.buf[:end+1]); err != nil {
		return 0, err
	}
	w.buf = append(w.buf[:0], w.buf[end+1:]...)
	return len(p), nil
}

// Flush writes any buffered partial line
func (w *Writer) Flush() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.buf) == 0 {
		return nil
	}
	err := w.writeRedacted(w.buf)
	w.buf = w.buf[:0]
	return err
}

func (w *Writer) writeRedacted(p []byte) error {
	out := p
	if Enabled() {
		out = []byte(String(string(p)))
	}
	_, err := w.dst.Write(out)
	return err
}
