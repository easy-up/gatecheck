# Gatecheck Bundle

Gatecheck bundles multiple security reports into a single .gcb file for easy sharing and attestation.

## Commands

- `gatecheck bundle new bundle.gcb`: Create a new bundle.
- `gatecheck bundle add bundle.gcb report.json --type grype`: Add a report.
- `gatecheck bundle list bundle.gcb`: List contents.

Bundles can include metadata and multiple report types.

## Build context

CI orchestrators may add an optional build context to each bundle:

- `buildGroupId` identifies one logical build shared by all image pipelines.
- `imageName` identifies the image represented by this bundle, using its stable registry path without a tag or digest.
- `buildImageNames` is the complete set of image names belonging to that logical build. Every bundle in the group carries the same set so a consumer can determine when the whole build has arrived.

For a build containing an API and worker image:

```shell
gatecheck bundle create gatecheck-bundle.tar.gz grype.json \
  --build-group-id pipeline-123 \
  --image-name registry.example.com/team/api \
  --build-image-name registry.example.com/team/api \
  --build-image-name registry.example.com/team/worker
```

The manifest stores these values without interpreting the image naming scheme:

```json
{
  "build": {
    "buildGroupId": "pipeline-123",
    "imageName": "registry.example.com/team/api",
    "buildImageNames": [
      "registry.example.com/team/api",
      "registry.example.com/team/worker"
    ]
  }
}
```
