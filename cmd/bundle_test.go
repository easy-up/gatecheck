package cmd

import (
	"strings"
	"testing"

	"github.com/gatecheckdev/gatecheck/pkg/archive"
	"github.com/spf13/cobra"
)

func newBuildContextTestCommand(t *testing.T, args ...string) *cobra.Command {
	t.Helper()
	cmd := &cobra.Command{Use: "test"}
	setupBuildContextFlags(cmd)
	if err := cmd.ParseFlags(args); err != nil {
		t.Fatal(err)
	}
	return cmd
}

func TestBuildContextFromFlags_NoFlags(t *testing.T) {
	buildContext, err := buildContextFromFlags(newBuildContextTestCommand(t))
	if err != nil {
		t.Fatal(err)
	}
	if buildContext != nil {
		t.Fatalf("want nil build context without flags, got %+v", buildContext)
	}
}

func TestBuildContextFromFlags_GroupedOnlyUnchanged(t *testing.T) {
	buildContext, err := buildContextFromFlags(newBuildContextTestCommand(t,
		"--build-group-id", "build-1",
		"--image-name", "registry.example.com/team/api",
		"--build-image-name", "registry.example.com/team/api",
	))
	if err != nil {
		t.Fatal(err)
	}
	want := archive.BuildContext{
		BuildGroupID:    "build-1",
		ImageName:       "registry.example.com/team/api",
		BuildImageNames: []string{"registry.example.com/team/api"},
	}
	if buildContext.BuildGroupID != want.BuildGroupID || buildContext.ImageName != want.ImageName ||
		len(buildContext.BuildImageNames) != 1 || buildContext.PublishedImage != "" ||
		buildContext.ImageDigest != "" || buildContext.ImageVerification != "" {
		t.Fatalf("unexpected build context %+v", buildContext)
	}
}

func TestBuildContextFromFlags_PublishedImage(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	for _, verification := range []string{archive.ImageVerificationMatched, archive.ImageVerificationExistsOnly} {
		buildContext, err := buildContextFromFlags(newBuildContextTestCommand(t,
			"--build-published-image", "registry.example.com/team/api:abc1234",
			"--build-image-digest", digest,
			"--build-image-verification", verification,
		))
		if err != nil {
			t.Fatal(err)
		}
		if buildContext.PublishedImage != "registry.example.com/team/api:abc1234" ||
			buildContext.ImageDigest != digest || buildContext.ImageVerification != verification {
			t.Fatalf("unexpected build context %+v", buildContext)
		}
	}
}

func TestBuildContextFromFlags_Invalid(t *testing.T) {
	cases := [][]string{
		{"--build-image-verification", "trusted"},
		{"--build-image-digest", "md5:abc"},
	}
	for _, args := range cases {
		if _, err := buildContextFromFlags(newBuildContextTestCommand(t, args...)); err == nil {
			t.Fatalf("want error for %v", args)
		}
	}
}
