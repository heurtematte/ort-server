---
position: 2
title: CLI
---

# ORT Server CLI

The ORT Server Client CLI (`osc`) is a command-line interface designed to interact with the ORT Server. It provides essential functionality for managing ORT runs and retrieving results.

## Installation

The latest version of `osc` can be obtained from the [GitHub releases page](https://github.com/eclipse-apoapsis/ort-server/releases/latest).

### macOS

When using the CLI on macOS, Apple's Gatekeeper restrictions may prevent the application from running.
To bypass this, the quarantine attribute from the `osc` binary needs to be removed.
This can be done by running the following command:

```shell
xattr -d com.apple.quarantine /path/to/osc
```

## Usage in GitHub Actions

When using `osc` in a GitHub action, the [`setup-osc`](https://github.com/eclipse-apoapsis/actions/setup-osc) action can be used to install `osc` and authenticate with an ORT Server instance.

The following example demonstrates how to integrate `osc` in a GitHub Actions workflow to start an ORT run, retrieve the created reports, and store them as workflow artifacts:

```yaml
jobs:
  run-osc:
    runs-on: ubuntu-latest
    steps:
      - name: Setup OSC
        uses: eclipse-apoapsis/actions/setup-osc@main
        with:
          url: https://ort-server.example.com
          username: user
          password: ${{ secrets.ORT_SERVER_PASSWORD }}

      - name: Start ORT run
        run: |
          osc runs start --parameters '{
            "revision": "${{ github.head_ref || github.ref_name }}",
            "jobConfigs": {
              "analyzer": {},
              "advisor": {},
              "evaluator": {},
              "scanner": {},
              "reporter": {},
              "notifier": {}
            }
          }'
        env:
          OSC_REPOSITORY_ID: 42
          OSC_RUNS_START_WAIT: true # Block the runner until the ORT Server run is finished.

      - name: Download Reports
        run: |
          osc runs download reports
        env:
          OSC_DOWNLOAD_REPORTS_FILE_NAMES: 'scan-report-web-app.html'
          OSC_DOWNLOAD_REPORTS_OUTPUT_DIR: './reports'

      - name: Upload reports
        id: upload
        uses: actions/upload-artifact@v4
        with:
          name: reports
          path: reports/
```

All available settings for `setup-osc` can be found [in the Repository of the action](https://github.com/eclipse-apoapsis/actions).

## Usage

### Authentication

Most operations require authentication with your ORT Server instance.

Authenticate with username and password:

```shell
osc auth login \
    --url <ORT_SERVER_URL> \
    --username <USERNAME> \
    --password <PASSWORD>
```

Authenticate with an offline token (for example, generated in the UI under Profile -> CLI token):

```shell
osc auth login \
    --url <ORT_SERVER_URL> \
    --token <TOKEN>
```

### Basic Operations

#### Starting an ORT Run

A basic ORT run can be started using:

```shell
osc runs start --repository-id <REPOSITORY_ID> --parameters '{
  "jobConfigs": {},
  "revision": "main"
}'
```

#### Monitoring Run Status

To check the status of the previously started run:

```shell
osc runs info
```

#### Downloading Reports

To retrieve reports from a completed ORT run, execute:

```shell
osc runs download reports --file-names scan-report-web-app.html --output-dir /tmp
```

### Managing the SBOM of an SBOM Repository

For a [repository of type SBOM](concepts/sbom-repositories.md), the `sbom` commands manage the SBOM that the runs of the repository analyze.

To upload an SBOM, replacing the current one, execute:

```shell
osc sbom upload --repository-id <REPOSITORY_ID> --file bom.cdx.json
```

The format of the SBOM is detected from its content.
The server validates the SBOM before storing it: if the file is not a supported SBOM, or the repository is not of type SBOM, the command fails with the reason given by the server.
Otherwise, it prints information about the stored SBOM: its file name, format and version, the number of components, its size, its SHA-256 checksum, and warnings about problems that did not prevent it from being accepted.
With `--json`, this information is printed as JSON.
The file name stored with the SBOM is the name of the uploaded file, unless another one is given with `--file-name`.

To print information about the current SBOM, or to download it, execute:

```shell
osc sbom info --repository-id <REPOSITORY_ID>
osc sbom download --repository-id <REPOSITORY_ID> --output bom.cdx.json
```

Both commands fail if no SBOM has been uploaded for the repository.

In a CI pipeline, upload the SBOM produced by the build and start a run that analyzes it:

```shell
osc sbom upload --repository-id 42 --file build/bom.cdx.json && \
  osc runs start --repository-id 42 --wait --parameters '{
    "revision": "",
    "jobConfigs": {
      "analyzer": {},
      "advisor": {},
      "evaluator": {},
      "reporter": {}
    }
  }'
```

As `osc` exits with a non-zero code if the upload fails, no run is started for an invalid SBOM.
Both commands also read the repository ID from the `OSC_REPOSITORY_ID` environment variable, so that `--repository-id` can be omitted if it is set.
For an uploaded SBOM, the revision of a run is only a label: if it is empty, it is set to the version of the component that the SBOM describes.

### Environment Variables

For automated environments like CI/CD pipelines, all command-line arguments can be configured using environment variables.  
For example, to authenticate with username and password:

```shell
export OSC_ORT_SERVER_URL="<ORT_SERVER_URL>"
export OSC_ORT_SERVER_USERNAME="<USERNAME>"
export OSC_ORT_SERVER_PASSWORD="<PASSWORD>"

osc auth login
```

To authenticate with an offline token:

```shell
export OSC_ORT_SERVER_URL="<ORT_SERVER_URL>"
export OSC_ORT_SERVER_TOKEN="<TOKEN>"

osc auth login
```

## Command Documentation

For detailed information about available commands and their options:

```shell
osc --help
```

Each subcommand also provides specific help documentation when invoked with the `--help` flag.
