# CLI Reference

This section provides a detailed reference for all Gatecheck CLI commands, including subcommands, options, examples, and use cases.

## gatecheck

The root command. Displays help information.

**Usage:**
```
gatecheck [command]
```

**Use Case:** Entry point to access all functionalities. Run without arguments to see available commands.

## gatecheck bundle

Manage Gatecheck bundles (.gcb files) which aggregate multiple security reports.

### gatecheck bundle new

Create a new empty bundle file.

**Usage:**
```
gatecheck bundle new <bundle-file>
```

**Example:**
```
gatecheck bundle new myproject.gcb
```

**Use Case:** Initialize a new bundle before adding reports, useful for starting a new attestation or archive.

### gatecheck bundle add

Add a report to an existing bundle.

**Usage:**
```
gatecheck bundle add <bundle-file> <report-file> --type <report-type>
```

**Options:**
- `--type`: Specify report type (e.g., grype, cyclonedx, semgrep, gitleaks)

**Example:**
```
gatecheck bundle add myproject.gcb grype-report.json --type grype
```

**Use Case:** Aggregate reports from different tools into one file for easy sharing, auditing, or CI/CD integration.

### gatecheck bundle list

List the contents of a bundle.

**Usage:**
```
gatecheck bundle list <bundle-file>
```

**Example:**
```
gatecheck bundle list myproject.gcb
```

**Use Case:** Quickly inspect what reports are in a bundle without extracting them, helpful for verification.

## gatecheck config

Manage configuration files for validation.

### gatecheck config new

Generate a new default configuration file.

**Usage:**
```
gatecheck config new <config-file> [--format yaml|json|toml]
```

**Example:**
```
gatecheck config new gatecheck.yaml
```

**Use Case:** Create a starting point for defining validation rules, then customize thresholds for your project.

### gatecheck config fetch

Download a configuration file from a URL and verify it before writing it out.

**Usage:**
```
gatecheck config fetch --url <url> [--auth-env <ENV_VAR_NAME>] [-o <file>] [--timeout 30s]
```

**Flags:**
- `--url` (required): Location of the configuration file. Must be `https`; plain `http` is only accepted for loopback hosts (`localhost`, `127.0.0.1`, `::1`).
- `--auth-env`: Name of an environment variable holding the credential for the `Authorization` header. A bare token is sent as `Bearer <token>`; a value that already includes a scheme (e.g. `Basic ...`) is sent as-is. The credential itself is never accepted as a flag value. If the named variable is unset or empty, the command fails without making a request.
- `-o, --output`: File to write. Defaults to STDOUT.
- `--timeout`: Maximum time for the whole request (default `30s`).

**Behavior:**
- Fails closed. Any non-2xx response, an empty body, a body larger than 1 MiB, invalid YAML/JSON, an unknown key, multiple documents, or a missing `version` field is an error, and nothing is written.
- The output file is replaced atomically and only after the body validates, so an existing file is never left truncated or overwritten by a failed fetch.
- The response body is written exactly as received, so comments in the source are preserved.
- The credential is never logged, included in errors, or written to the output. URLs in logs and errors are reduced to `scheme://host/path` (no user info or query string).

**Example:**
```
export POLICY_TOKEN=...
gatecheck config fetch --url https://policy.example.com/repos/acme/api/gatecheck?branch=main --auth-env POLICY_TOKEN -o .gatecheck.yml
gatecheck validate --config .gatecheck.yml bundle.tar.gz
```

**Use Case:** Keep validation thresholds in a central policy service instead of each repository.

## gatecheck download

Download external datasets like EPSS or KEV.

**Usage:**
```
gatecheck download <type> <output-file>
```

**Types:** epss, kev

**Example:**
```
gatecheck download epss epss_scores.csv
```

**Use Case:** Fetch latest vulnerability scoring data for offline use in validation or analysis.

## gatecheck list

List contents of a report or bundle in a human-readable format.

**Usage:**
```
gatecheck list <file> [--input-type <type>]
```

**Example:**
```
gatecheck list grype-report.json
```

**Use Case:** Summarize lengthy JSON reports for quick review, e.g., checking vulnerability counts without parsing JSON manually.

## gatecheck validate

Validate reports against a configuration file.

**Usage:**
```
gatecheck validate <config-file> <target-file>
```

**Example:**
```
gatecheck validate gatecheck.yaml bundle.gcb
```

**Use Case:** Ensure security reports meet project thresholds before deployment, integrating into CI pipelines for automated checks.

## gatecheck version

Print the version information.

**Usage:**
```
gatecheck version
```

**Example:**
```
gatecheck version
```

**Use Case:** Verify the installed version for compatibility or reporting issues.