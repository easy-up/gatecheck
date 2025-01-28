package gatecheck

import (
	"io"
	"log/slog"

	"github.com/gatecheckdev/gatecheck/pkg/archive"
)

// CreateBundle create a new bundle with a file
//
// If the bundle already exist, use CreateBundle.
// this function will completely overwrite an existing bundle
func CreateBundle(dstBundle io.Writer, src io.Reader, label string, tags []string) error {
	slog.Debug("creating new bundle")
	srcContent, err := io.ReadAll(src)
	if err != nil {
		slog.Error("failed to read source content", "error", err)
		return err
	}

	gitContext, err := archive.GetContext()
	if err != nil {
		slog.Error("failed to get git context", "error", err)
		return err
	}
	if gitContext == nil {
		slog.Warn("no git context available, bundle will not include git information")
	} else {
		slog.Info("git context for bundle",
			"commit", gitContext.CommitHash,
			"branch", gitContext.Branch,
			"date", gitContext.CommitDate,
			"message", gitContext.CommitMessage,
			"status_count", len(gitContext.Status))
	}

	bundle := archive.NewBundle()
	bundle.SetContext(gitContext)
	bundle.Add(srcContent, label, tags)

	slog.Debug("writing bundle to tar.gz")
	n, err := archive.TarGzipBundle(dstBundle, bundle)
	if err != nil {
		slog.Error("failed to write bundle", "error", err)
		return err
	}

	slog.Info("bundle write success",
		"bytes_written", n,
		"label", label,
		"tags", tags,
		"has_git_context", gitContext != nil)

	return nil
}

// AppendToBundle adds a file to an existing bundle
//
// If the bundle doesn't exist, use CreateBundle
func AppendToBundle(bundleRWS io.ReadWriteSeeker, src io.Reader, label string, tags []string) error {
	slog.Debug("load bundle")
	bundle := archive.NewBundle()
	if err := archive.UntarGzipBundle(bundleRWS, bundle); err != nil {
		return err
	}

	// Validate the GitContext in the bundle
	newContext, err := archive.GetContext()
	if !compareContext(newContext, bundle.Manifest().Context) {
		// The current context is different from the existing context. Clear all stale artifacts.
		slog.Info("the git context hash changed, clearing stale bundle contents")
		bundle.Clear()
	}
	bundle.SetContext(newContext)

	slog.Debug("load source file")
	srcContent, err := io.ReadAll(src)
	if err != nil {
		return err
	}

	slog.Debug("add to source file content to bundle", "label", label, "tags", tags)
	bundle.Add(srcContent, label, tags)

	// Seek errors are unlikely so just capture for edge cases
	_, seekErr := bundleRWS.Seek(0, io.SeekStart)

	slog.Debug("write bundle", "seek_err", seekErr)
	n, err := archive.TarGzipBundle(bundleRWS, bundle)
	if err != nil {
		return err
	}

	slog.Info("bundle write success", "bytes_written", n, "label", label, "tags", tags)

	return nil
}

// compareContext compares two GitContext objects for equivalence based on their CommitHash and Status slices.
// It is assumed that if the CommitHash fields are equal that other fields that would naturally change the CommitHash are also equal.
// Git branch is not considered because it is possible to change the git branch without changing the repository contents in any way.
// Returns true if both GitContext objects are identical; otherwise, it returns false.
func compareContext(context1 *archive.GitContext, context2 *archive.GitContext) bool {
	if context1 == nil || context2 == nil {
		return context1 == context2
	}
	if context1.CommitHash != context2.CommitHash {
		return false
	}
	if len(context1.Status) != len(context2.Status) {
		return false
	}

	for i, status := range context1.Status {
		// this assumes that file statuses are in a stable sort order
		if i >= len(context2.Status) || !statusEqual(status, context2.Status[i]) {
			return false
		}
	}

	return true
}

func statusEqual(status1 archive.GitFileStatus, status2 archive.GitFileStatus) bool {
	return status1.IndexStatus == status2.IndexStatus &&
		status1.WorkTreeStatus == status2.WorkTreeStatus &&
		status1.Path == status2.Path &&
		status1.OriginalPath == status2.OriginalPath &&
		status1.FileSha256 == status2.FileSha256
}

// RemoveFromBundle removes a file from an existing bundle
func RemoveFromBundle(bundleRWS io.ReadWriteSeeker, label string) error {
	slog.Debug("load bundle")
	bundle := archive.NewBundle()
	if err := archive.UntarGzipBundle(bundleRWS, bundle); err != nil {
		return err
	}
	bundle.Remove(label)
	// Seek errors are unlikely so just capture for edge cases
	_, seekErr := bundleRWS.Seek(0, io.SeekStart)

	slog.Debug("write bundle", "seek_err", seekErr)
	n, err := archive.TarGzipBundle(bundleRWS, bundle)
	if err != nil {
		return err
	}

	slog.Info("bundle write after remove success", "bytes_written", n, "label", label)
	return nil
}
