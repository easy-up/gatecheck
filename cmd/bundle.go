package cmd

import (
	"fmt"
	"log/slog"
	"os"
	"path"
	"strings"

	"github.com/gatecheckdev/gatecheck/pkg/archive"
	"github.com/gatecheckdev/gatecheck/pkg/gatecheck"
	"github.com/spf13/cobra"
)

var bundleCmd = &cobra.Command{
	Use:   "bundle",
	Short: "create and manage a gatecheck bundle",
}

var bundleCreateCmd = &cobra.Command{
	Use:     "create BUNDLE_FILE TARGET_FILE",
	Short:   "create a new bundle with a new file",
	Aliases: []string{"init"},
	Args:    cobra.ExactArgs(2),
	PreRunE: func(cmd *cobra.Command, args []string) error {
		if _, err := buildContextFromFlags(cmd); err != nil {
			return err
		}
		bundleFilename := args[0]
		targetFilename := args[1]

		bundleFile, err := os.OpenFile(bundleFilename, os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			return err
		}
		targetFile, err := os.Open(targetFilename)
		if err != nil {
			return err
		}

		RuntimeConfig.bundleFile = bundleFile
		RuntimeConfig.targetFile = targetFile
		RuntimeConfig.BundleTagValue = RuntimeConfig.BundleTag.Value().([]string)
		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		targetFilename := args[1]
		label := path.Base(targetFilename)
		bf, tf := RuntimeConfig.bundleFile, RuntimeConfig.targetFile
		tags := RuntimeConfig.BundleTagValue
		buildContext, err := buildContextFromFlags(cmd)
		if err != nil {
			return err
		}
		return gatecheck.CreateBundleWithBuildContext(bf, tf, label, tags, buildContext)
	},
}

var bundleAddCmd = &cobra.Command{
	Use:   "add BUNDLE_FILE TARGET_FILE",
	Short: "add a file to a bundle",
	Args:  cobra.ExactArgs(2),
	PreRunE: func(cmd *cobra.Command, args []string) error {
		if _, err := buildContextFromFlags(cmd); err != nil {
			return err
		}
		bundleFilename := args[0]
		targetFilename := args[1]

		bundleFile, err := os.OpenFile(bundleFilename, os.O_RDWR, 0o644)
		if err != nil {
			return err
		}
		targetFile, err := os.Open(targetFilename)
		if err != nil {
			return err
		}

		RuntimeConfig.bundleFile = bundleFile
		RuntimeConfig.targetFile = targetFile
		RuntimeConfig.BundleTagValue = RuntimeConfig.BundleTag.Value().([]string)
		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		targetFilename := args[1]
		slog.Info("bundle tag", "environment", os.Getenv("GATECHECK_BUNDLE_TAG"))
		label := path.Base(targetFilename)
		bf, tf := RuntimeConfig.bundleFile, RuntimeConfig.targetFile
		tags := RuntimeConfig.BundleTagValue
		buildContext, err := buildContextFromFlags(cmd)
		if err != nil {
			return err
		}
		return gatecheck.AppendToBundleWithBuildContext(bf, tf, label, tags, buildContext)
	},
}

var bundleRemoveCmd = &cobra.Command{
	Use:     "remove BUNDLE_FILE TARGET_FILE",
	Short:   "remove a file from a bundle by label",
	Aliases: []string{"rm"},
	Args:    cobra.ExactArgs(2),
	PreRunE: func(cmd *cobra.Command, args []string) error {
		bundleFilename := args[0]

		bundleFile, err := os.OpenFile(bundleFilename, os.O_RDWR, 0o644)
		if err != nil {
			return err
		}
		RuntimeConfig.bundleFile = bundleFile
		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		label := args[1]
		return gatecheck.RemoveFromBundle(RuntimeConfig.bundleFile, label)
	},
}

func newBundleCommand() *cobra.Command {
	RuntimeConfig.BundleTag.SetupCobra(bundleCreateCmd)
	RuntimeConfig.BundleTag.SetupCobra(bundleAddCmd)
	setupBuildContextFlags(bundleCreateCmd)
	setupBuildContextFlags(bundleAddCmd)

	bundleCmd.AddCommand(bundleCreateCmd, bundleAddCmd, bundleRemoveCmd)
	return bundleCmd
}

func setupBuildContextFlags(cmd *cobra.Command) {
	cmd.Flags().String("build-group-id", "", "identifier shared by all images in this build")
	cmd.Flags().String("image-name", "", "full registry image path without a tag or digest")
	cmd.Flags().StringSlice("build-image-name", nil, "image name belonging to this build; may be repeated")
	cmd.Flags().String("build-published-image", "", "registry reference confirmed to be published for this build")
	cmd.Flags().String("build-image-digest", "", "registry manifest digest (sha256:...) of the published image")
	cmd.Flags().String("build-image-verification", "", "how the published image was verified: matched or exists-only")
}

func buildContextFromFlags(cmd *cobra.Command) (*archive.BuildContext, error) {
	buildGroupID, _ := cmd.Flags().GetString("build-group-id")
	imageName, _ := cmd.Flags().GetString("image-name")
	buildImageNames, _ := cmd.Flags().GetStringSlice("build-image-name")
	publishedImage, _ := cmd.Flags().GetString("build-published-image")
	imageDigest, _ := cmd.Flags().GetString("build-image-digest")
	imageVerification, _ := cmd.Flags().GetString("build-image-verification")

	if !archive.ValidImageVerification(imageVerification) {
		return nil, fmt.Errorf("invalid --build-image-verification %q, must be %s or %s",
			imageVerification, archive.ImageVerificationMatched, archive.ImageVerificationExistsOnly)
	}
	if imageDigest != "" && !strings.HasPrefix(imageDigest, "sha256:") {
		return nil, fmt.Errorf("invalid --build-image-digest %q, must start with sha256:", imageDigest)
	}

	if buildGroupID == "" && imageName == "" && len(buildImageNames) == 0 &&
		publishedImage == "" && imageDigest == "" && imageVerification == "" {
		return nil, nil
	}

	return &archive.BuildContext{
		BuildGroupID:      buildGroupID,
		ImageName:         imageName,
		BuildImageNames:   buildImageNames,
		PublishedImage:    publishedImage,
		ImageDigest:       imageDigest,
		ImageVerification: imageVerification,
	}, nil
}
