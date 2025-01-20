// Package archive provides the logic for Gatecheck Bundles
package archive

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/olekukonko/tablewriter"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"

	"github.com/dustin/go-humanize"
	"github.com/gatecheckdev/gatecheck/pkg/format"
)

// FileType in plain text
const FileType = "Gatecheck Bundle"

// BundleVersion the version support by this archive format
const BundleVersion = "1"

// ManifestFilename the file name to be used as a default
const ManifestFilename = "gatecheck-manifest.json"

// DefaultBundleFilename the bundle name to be used as a default
const DefaultBundleFilename = "gatecheck-bundle.tar.gz"

// Manifest is created and loaded into a bundle which contains information on the files
type Manifest struct {
	Created time.Time                 `json:"createdAt"`
	Version string                    `json:"version"`
	Files   map[string]fileDescriptor `json:"files"`
	Context *GitContext               `json:"context,omitempty"`
}

type GitContext struct {
	CommitHash    string          `json:"commitHash"`
	CommitDate    time.Time       `json:"commitDate"`
	CommitMessage string          `json:"commitMessage"`
	Status        []GitFileStatus `json:"status"`
	Branch        string          `json:"branch"`
}

type GitFileStatus struct {
	Path           string     `json:"path"`
	OriginalPath   string     `json:"originalPath"`
	IndexStatus    StatusFlag `json:"indexStatus"`
	WorkTreeStatus StatusFlag `json:"workTreeStatus"`
	FileSha256     string     `json:"fileSha256"`
}

type StatusFlag string

const (
	Unchanged   StatusFlag = " "
	TypeChanged StatusFlag = "T"
	Modified    StatusFlag = "M"
	Added       StatusFlag = "A"
	Deleted     StatusFlag = "D"
	Renamed     StatusFlag = "R"
	Copied      StatusFlag = "C"
	Unmerged    StatusFlag = "U"
	Untracked   StatusFlag = "?"
)

type fileDescriptor struct {
	Added time.Time `json:"addedAt"`
	// Deprecated: use tags instead of properties
	Properties map[string]string `json:"properties"`
	Tags       []string          `json:"tags"`
	// Deprecated: assume file label has the file type
	FileType string `json:"fileType"`
	Digest   string `json:"digest"`
}

// Bundle uses tar and gzip to collect reports and files into a single file
type Bundle struct {
	content  map[string][]byte
	manifest Manifest
}

// NewBundle ...
func NewBundle() *Bundle {
	return &Bundle{
		content:  make(map[string][]byte),
		manifest: Manifest{Created: time.Now(), Version: BundleVersion, Files: make(map[string]fileDescriptor), Context: nil},
	}
}

func GetContext() (*GitContext, error) {
	// Get git information
	gitCmd := exec.Command("git", "rev-parse", "HEAD")
	commitHash, err := gitCmd.Output()
	if err != nil {
		// If rev-parse fails either the git executable is missing or corrupt, or we are not in a git repo
		// If we're not in a git repo then Context should just be nil
		return nil, nil
	}

	gitCmd = exec.Command("git", "show", "-s", "--format=%cI%n%B", "HEAD")
	commitDateAndMessageBytes, err := gitCmd.Output()
	commitDateAndMessage := strings.SplitN(string(commitDateAndMessageBytes), "\n", 2)
	commitDate := commitDateAndMessage[0]
	commitMessage := ""
	if len(commitDateAndMessage) > 1 {
		commitMessage = commitDateAndMessage[1]
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get commit date: %w", err)
	}

	// Get git branch name
	gitCmd = exec.Command("git", "rev-parse", "--abbrev-ref", "HEAD")
	branchName, err := gitCmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to get branch name: %w", err)
	}

	// Get git status
	gitCmd = exec.Command("git", "status", "--porcelain")
	gitStatus, err := gitCmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to get git status: %w", err)
	}

	statusLines := strings.Split(string(gitStatus), "\n")

	var gitFileStatuses []GitFileStatus
	for _, line := range statusLines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		status, err := parseGitStatusLine(line)
		if err != nil {
			return nil, fmt.Errorf("failed to parse git status line: %w", err)
		}
		gitFileStatuses = append(gitFileStatuses, status)
	}

	commitDateParsed, err := time.Parse(time.RFC3339, strings.TrimSpace(commitDate))
	if err != nil {
		return nil, fmt.Errorf("failed to parse commit date: %w", err)
	}

	return &GitContext{
		CommitHash:    strings.TrimSpace(string(commitHash)),
		CommitDate:    commitDateParsed,
		CommitMessage: strings.TrimSpace(commitMessage),
		Status:        gitFileStatuses,
		Branch:        strings.TrimSpace(string(branchName)),
	}, nil
}

func parseGitStatusLine(line string) (GitFileStatus, error) {
	if len(line) < 3 {
		return GitFileStatus{}, fmt.Errorf("invalid git status line: %s", line)
	}

	// Extract the index and work tree status flags
	indexStatus := StatusFlag(line[0])
	workTreeStatus := StatusFlag(line[1])

	// Extract path and original path (for renames or copied files)
	line = strings.TrimSpace(line[3:])

	path, part2, err := splitGitStatusPaths(line)
	if err != nil {
		return GitFileStatus{}, fmt.Errorf("failed to parse git status path: %w", err)
	}

	originalPath := ""
	if part2 != "" {
		originalPath = path
		path = strings.TrimSpace(part2)
	}

	fileSha256 := ""
	computeHash := false
	if workTreeStatus == Deleted {
		computeHash = indexStatus != Unmerged
	} else if workTreeStatus == TypeChanged {
		computeHash = indexStatus != TypeChanged && indexStatus != Unchanged
	} else {
		// When indexStatus is Deleted, the workTreeStatus should only ever be unchanged.
		computeHash = indexStatus != Deleted && (workTreeStatus != Unchanged || indexStatus != TypeChanged)
	}

	if computeHash {
		file, err := os.Open(path)
		if err == nil {
			defer file.Close()

			hasher := sha256.New()
			if _, err := io.Copy(hasher, file); err != nil {
				return GitFileStatus{}, fmt.Errorf("failed to compute SHA256 hash for file '%s': %w", path, err)
			}
			fileSha256 = hex.EncodeToString(hasher.Sum([]byte{}))
			slog.Debug("file SHA256 hash computed", "path", path, "hash", fileSha256)
		} else {
			slog.Warn("Unable to open file to compute SHA256 hash", "path", path, "error", err)
		}
	}

	return GitFileStatus{
		Path:           path,
		OriginalPath:   originalPath,
		IndexStatus:    indexStatus,
		WorkTreeStatus: workTreeStatus,
		FileSha256:     fileSha256,
	}, nil
}

func splitGitStatusPaths(line string) (string, string, error) {
	var result []string
	var currentSegment []rune
	inQuotes := false
	escaped := false

	for i, char := range line {
		if escaped {
			// Handle escaped characters
			currentSegment = append(currentSegment, char)
			escaped = false
			continue
		}

		if char == '\\' {
			// Process escape sequences
			escaped = true
			continue
		}

		if char == '"' {
			// Toggle the in-quotes state
			inQuotes = !inQuotes
			continue
		}

		if !inQuotes && i+2 <= len(line) && line[i:i+2] == "->" {
			// Split when encountering an unquoted '->'
			result = append(result, string(currentSegment))
			currentSegment = []rune{}
			i++ // Skip the '>'
			continue
		}

		// Append regular characters
		currentSegment = append(currentSegment, char)
	}

	// Append the last segment
	if len(currentSegment) > 0 {
		result = append(result, string(currentSegment))
	}

	if len(result) > 2 || inQuotes || escaped {
		return "", "", fmt.Errorf("failed to parse the git status path")
	}

	if len(result) == 2 {
		return strings.TrimSpace(result[0]), strings.TrimSpace(result[1]), nil
	} else {
		return strings.TrimSpace(result[0]), "", nil
	}
}

func (b *Bundle) SetContext(context *GitContext) {
	b.manifest.Context = context
}

// Manifest generated by the bundle
func (b *Bundle) Manifest() Manifest {
	return b.manifest
}

// WriteFileTo Used to write files inside the bundle to a writer
func (b *Bundle) WriteFileTo(w io.Writer, fileLabel string) (int64, error) {
	fileBytes, ok := b.content[fileLabel]
	if !ok {
		return 0, fmt.Errorf("Gatecheck Bundle: Label '%s' not found in bundle", fileLabel)
	}
	return bytes.NewReader(fileBytes).WriteTo(w)
}

func (b *Bundle) FileBytes(fileLabel string) []byte {
	fileBytes, ok := b.content[fileLabel]
	if !ok {
		slog.Warn("file label not found in bundle", "file_label", fileLabel)
	}
	return fileBytes
}

// FileSize get the file size for a specific label
func (b *Bundle) FileSize(fileLabel string) int {
	fileBytes, ok := b.content[fileLabel]
	slog.Debug("bundle calculate file size", "label", fileLabel, "content_in_bundle", ok)
	if !ok {
		return 0
	}
	return len(fileBytes)
}

// AddFrom reads files into the bundle
func (b *Bundle) AddFrom(r io.Reader, label string, properties map[string]string) error {
	hasher := sha256.New()
	p, err := io.ReadAll(r)
	_, _ = bytes.NewReader(p).WriteTo(hasher)
	if err != nil {
		return err
	}
	digest := fmt.Sprintf("%x", hasher.Sum(nil))

	b.manifest.Files[label] = fileDescriptor{Added: time.Now(), Properties: properties, Digest: digest}

	b.content[label] = p
	return nil
}

func (b *Bundle) Add(content []byte, label string, tags []string) {
	hasher := sha256.New()
	n, hashErr := hasher.Write(content)
	slog.Debug("bundle add hash content", "error", hashErr, "bytes_hashed", n)
	digest := hex.EncodeToString(hasher.Sum(nil))

	b.manifest.Files[label] = fileDescriptor{
		Added:  time.Now(),
		Tags:   tags,
		Digest: digest,
	}

	b.content[label] = content
}

// Remove a file from the bundle and manifest by label
//
// If the file doesn't exist, it will log a warning
func (b *Bundle) Remove(label string) {
	if _, ok := b.content[label]; !ok {
		slog.Error("file does not exist", "label", label)
	}
	delete(b.content, label)
	delete(b.manifest.Files, label)
}

// Delete will remove files from the bundle by label
//
// Deprecated: use Remove
func (b *Bundle) Delete(label string) {
	delete(b.content, label)
	delete(b.manifest.Files, label)
}

func (b *Bundle) Clear() {
	b.content = make(map[string][]byte)
	b.manifest.Files = make(map[string]fileDescriptor)
}

func (b *Bundle) Content() string {
	matrix := format.NewSortableMatrix(make([][]string, 0), 0, format.AlphabeticLess)

	for label, descriptor := range b.Manifest().Files {
		fileSize := humanize.Bytes(uint64(b.FileSize(label)))
		tags := strings.Join(descriptor.Tags, ", ")
		row := []string{label, descriptor.Digest, tags, fileSize}
		matrix.Append(row)
	}

	sort.Sort(matrix)
	buf := new(bytes.Buffer)
	header := []string{"Label", "Digest", "Tags", "Size"}
	table := tablewriter.NewWriter(buf)
	table.SetHeader(header)
	matrix.Table(table)
	table.Render()
	return buf.String()
}

func TarGzipBundle(dst io.Writer, bundle *Bundle) (int64, error) {
	if bundle == nil {
		return 0, errors.New("cannot write nil bundle")
	}
	tarballBuffer := new(bytes.Buffer)
	tarWriter := tar.NewWriter(tarballBuffer)
	manifestBytes, _ := json.Marshal(bundle.manifest)
	_ = bundle.AddFrom(bytes.NewReader(manifestBytes), "gatecheck-manifest.json", nil)

	for label, data := range bundle.content {
		// Using bytes.Buffer so IO errors are unlikely
		_ = tarWriter.WriteHeader(&tar.Header{Name: label, Size: int64(len(data)), Mode: int64(os.FileMode(0o666))})
		_, _ = bytes.NewReader(data).WriteTo(tarWriter)
	}
	tarWriter.Close()

	gzipWriter := gzip.NewWriter(dst)
	n, _ := tarballBuffer.WriteTo(gzipWriter)
	gzipWriter.Close()

	return n, nil
}

func UntarGzipBundle(src io.Reader, bundle *Bundle) error {
	gzipReader, err := gzip.NewReader(src)
	if err != nil {
		slog.Error("failed to create new gzip reader")
		return err
	}
	tarReader := tar.NewReader(gzipReader)

	bundle.content = make(map[string][]byte)
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		if header.Typeflag != tar.TypeReg {
			return errors.New("Gatecheck Bundle only supports regular files in a flat directory structure")
		}
		fileBytes, _ := io.ReadAll(tarReader)
		bundle.content[header.Name] = fileBytes
	}
	manifest := new(Manifest)
	manifestBytes, ok := bundle.content[ManifestFilename]
	if !ok {
		return errors.New("Gatecheck Bundle manifest not found")
	}
	if err := json.Unmarshal(manifestBytes, manifest); err != nil {
		return fmt.Errorf("gatecheck manifest decoding: %w", err)
	}
	bundle.manifest = *manifest

	return nil
}
