package archive

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
)

func TestBundle_WriteFileTo(t *testing.T) {
	bundle := NewBundle()
	_ = bundle.AddFrom(strings.NewReader("ABCDEF"), "file-1.txt", nil)
	_ = bundle.AddFrom(strings.NewReader("GHIJKL"), "file-2.txt", nil)
	_ = bundle.AddFrom(strings.NewReader("MNOPQR"), "file-3.txt", nil)
	outputBuf := new(bytes.Buffer)
	_, err := bundle.WriteFileTo(outputBuf, "file-1.txt")
	if err != nil {
		t.Fatal(err)
	}
	if outputBuf.String() != "ABCDEF" {
		t.Fatalf("want: 'ABCDEF' got: '%s'", outputBuf.String())
	}
	if bundle.FileSize("file-1.txt") != outputBuf.Len() {
		t.Fatalf("%d is not equal to %d", bundle.FileSize("file-1.txt"), outputBuf.Len())
	}

	t.Run("not-found", func(t *testing.T) {
		_, err := bundle.WriteFileTo(outputBuf, "file-999.txt")
		t.Log(err)
		if err == nil {
			t.Fatal("want error got nil")
		}
		if bundle.FileSize("file-999.txt") != 0 {
			t.Fatal()
		}
	})

	t.Run("bad-writer", func(t *testing.T) {
		_, err := bundle.WriteFileTo(&badWriter{}, "file-1.txt")
		if err == nil {
			t.Fatal("want: badreader error got: nil")
		}
	})
}

func TestBundle_BuildContextInManifest(t *testing.T) {
	bundle := NewBundle()
	bundle.SetBuildContext(&BuildContext{
		BuildGroupID:    "build-123",
		ImageName:       "registry.example.com/team/api",
		BuildImageNames: []string{"registry.example.com/team/api", "registry.example.com/team/worker"},
	})

	manifestBytes, err := json.Marshal(bundle.Manifest())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(manifestBytes, []byte(`"buildImageNames"`)) {
		t.Fatalf("want buildImageNames in manifest: %s", manifestBytes)
	}

	var manifest Manifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.Build == nil {
		t.Fatal("want build context")
	}
	if manifest.Build.BuildGroupID != "build-123" {
		t.Fatalf("want group ID build-123, got %q", manifest.Build.BuildGroupID)
	}
	if manifest.Build.ImageName != "registry.example.com/team/api" {
		t.Fatalf("want image name registry.example.com/team/api, got %q", manifest.Build.ImageName)
	}
	if len(manifest.Build.BuildImageNames) != 2 {
		t.Fatalf("want 2 build image names, got %d", len(manifest.Build.BuildImageNames))
	}
}

type badWriter struct{}

func (r *badWriter) Write(_ []byte) (int, error) {
	return 0, errors.New("mock reader error")
}

func MustOpen(filename string, t *testing.T) *os.File {
	f, err := os.Open(filename)
	if err != nil {
		t.Fatal(err)
	}
	return f
}
