# Gatecheck Bundle

Gatecheck bundles multiple security reports into a single .gcb file for easy sharing and attestation.

## Commands

- `gatecheck bundle new bundle.gcb`: Create a new bundle.
- `gatecheck bundle add bundle.gcb report.json --type grype`: Add a report.
- `gatecheck bundle list bundle.gcb`: List contents.

Bundles can include metadata and multiple report types.

## Build context

Gatecheck accepts optional logical-build context and writes it to the bundle manifest. Gatecheck does **not** generate `buildGroupId`, inspect CI environment variables, infer a group from an image tag, or discover sibling images. The CI orchestrator must generate one opaque ID once per logical build and supply the complete context to every image job. Portage and Gatecheck transport it without inference; Belay consumes it.

- `buildGroupId` identifies one logical build and is identical in every image bundle.
- `imageName` identifies the current bundle's image by stable registry path, without a tag or digest.
- `buildImageNames` is the complete set for the logical build. Every bundle carries the same list; it is not a progress list.

For a build containing four images, the API job can run:

```shell
gatecheck bundle create gatecheck-bundle.tar.gz grype.json \
  --build-group-id ci:project-42:build-781 \
  --image-name registry.example.com/team/api \
  --build-image-name registry.example.com/team/api \
  --build-image-name registry.example.com/team/web \
  --build-image-name registry.example.com/team/worker \
  --build-image-name registry.example.com/team/migrations
```

The manifest stores these values without interpreting the image naming scheme:

```json
{
  "build": {
    "buildGroupId": "ci:project-42:build-781",
    "imageName": "registry.example.com/team/api",
    "buildImageNames": [
      "registry.example.com/team/api",
      "registry.example.com/team/web",
      "registry.example.com/team/worker",
      "registry.example.com/team/migrations"
    ]
  }
}
```

The web, worker, and migrations jobs use their own `imageName` but repeat the exact group ID and complete four-image list. Grouped mode requires `buildGroupId`, `imageName`, and `buildImageNames` together. Supply all three for every image job, or omit all three for legacy ungrouped behavior. Partial context and partial image lists must not be used.

Group identity and retry policy remain the CI orchestrator's responsibility. A new grouped replacement must publish every expected image with a new shared ID. GitHub workflows commonly use `github:${{ github.repository_id }}:${{ github.run_id }}:${{ github.run_attempt }}` and rerun the full workflow. GitLab pipelines commonly use `gitlab:${CI_PROJECT_ID}:${CI_PIPELINE_ID}` and start a new full pipeline; an individual job retry keeps the same pipeline ID and, with Belay's current duplicate-artifact semantics, is not a new grouped replacement.

Parent/child pipeline users must create the root identity before triggering children and pass it explicitly to each child. Other CI providers can use any provider-qualified opaque run identity, provided every parallel job receives the same value.
