# SBOM Repositories

Besides source code repositories, ORT Server can analyze existing Software Bills of Materials (SBOMs).
This is useful for components whose source code is not available to ORT Server, such as container images, runtimes, or third-party software, and to check the components listed in SBOMs produced by other tools, for instance for vulnerabilities.

An SBOM is analyzed by a repository of type `SBOM`.
Runs of such a repository do not clone source code; instead, the analyzer converts the SBOM into projects and packages, and all later steps (advisor, evaluator, reporter, notifier) work on the result as usual.

## Supported Formats

| Format    | Serializations             | Tested versions |
| --------- | -------------------------- | --------------- |
| CycloneDX | JSON, XML                  | 1.0 to 1.7      |
| SPDX      | JSON, YAML, tag-value, XML | 2.0 to 2.3      |
| SPDX      | JSON-LD                    | 3.0.0, 3.0.1    |

Documents may be encoded in UTF-8, UTF-16, or UTF-32.
SPDX documents in RDF/XML format and CycloneDX documents in Protocol Buffers format are not supported; convert them to one of the formats above.

The format and the specification version do not have to be specified: every supported format identifies itself in its content (for instance with `bomFormat` and `specVersion` in CycloneDX JSON, the namespace in CycloneDX XML, `spdxVersion` in SPDX 2, or the JSON-LD context and the creation info in SPDX 3), so they are detected from the content of the SBOM, not from its file name.
The detected format and version are shown in the information about an uploaded SBOM.
Documents of versions that have not been tested, such as a future CycloneDX version, are accepted with a warning and interpreted like the closest tested version.

## Providing the SBOM

The SBOM of a repository is obtained from the first of the following sources that is available:

1. **An uploaded SBOM.**
   Upload it with `PUT /api/v1/repositories/{repositoryId}/sbom`, either as the raw request body or as the first file of a `multipart/form-data` request.
   The SBOM is validated before it is stored; uploading a new SBOM replaces the previous one.
   `GET /api/v1/repositories/{repositoryId}/sbom` returns information about the uploaded SBOM, `GET .../sbom/content` returns the SBOM itself, and `DELETE .../sbom` deletes it.
2. **The source of the repository URL**, identified when the repository was created:
   - **A Dependency-Track project**, if the URL is the URL of a project page of the Dependency-Track frontend, such as `https://sbom.eclipse.org/projects/<uuid>`: the analyzer exports the SBOM of the project from Dependency-Track.
   - **A sbomify component or product**, if the URL is the URL of a component or product page of a [sbomify](https://github.com/sbomify/sbomify) instance, such as `https://app.sbomify.com/component/<id>/` or `https://app.sbomify.com/public/product/<id>/`: the analyzer downloads the SBOM of the component, or the aggregated SBOM of the product.
   - **An SBOM document**, for any other URL: the analyzer downloads the document the URL points to.

### Identification of the source

The source of the SBOM is identified once, when the repository is created or its URL or type changes, and not guessed again at each run:

- The URL determines the candidate type of source, as the UUID of a Dependency-Track project or the ID of a sbomify component or product is part of it.
- The server must then confirm it through the public endpoints these platforms provide for this purpose, without credentials: `GET <frontend>/static/config.json` and `GET <api>/api/version` for Dependency-Track, `GET <base>/api/v1/openapi.json` for sbomify.
  The configuration of the Dependency-Track frontend also gives the URL of its API server, if the API is not served by the frontend.
- If the URL does not match a type of source, or the server is not of this type or cannot be reached, the repository is not created or changed: the request fails with status 400 and explains why.

The identified source is stored with the repository, and every run uses it as it is.
`GET /api/v1/repositories/{repositoryId}/sbom/source` returns it, and `PUT /api/v1/repositories/{repositoryId}/sbom/source` identifies it again, for instance after the server moved, optionally with an explicit `type` (`DEPENDENCY_TRACK`, `SBOMIFY`, or `DOCUMENT`) to treat a URL that looks like a Dependency-Track or sbomify page as a document.

The version of the server software is stored for information only: runs do not depend on it.
Upgrading Dependency-Track or sbomify does not affect the repositories, as long as the platforms keep their API version 1 (Dependency-Track 4 and 5 both provide the endpoints used here).

### Revision of a run

For a repository of type SBOM, the revision of a run does not select a branch, but the version of the source:

| Revision  | Dependency-Track project                                                          | sbomify component          | sbomify product, document          |
| --------- | --------------------------------------------------------------------------------- | -------------------------- | ---------------------------------- |
| empty     | the version of the project of the URL                                             | its latest SBOM            | the SBOM                           |
| `latest`  | the version flagged as latest, or the active version whose SBOM was imported last | its latest SBOM            | not supported (products: the SBOM) |
| a version | the version of the project with the same name                                     | its SBOM with this version | not supported                      |

A revision that does not exist fails the run with an explicit error, such as "The Dependency-Track project 'che-server' has no version 'main'".
The revision of a run that has no revision is set to the version of the project or component of the source, or of the component the SBOM describes, and the resolved revision is set to the SHA-256 checksum of the analyzed SBOM, so that it can be identified later.

### Credentials

For the sources, the analyzer uses the credentials of the [infrastructure service](external-services.md) whose URL is the longest prefix of the repository URL.
Credentials are only sent to the origin of the repository URL and, for Dependency-Track, to the API server its frontend designates; they are not sent to the target of a redirect to another origin.

For Dependency-Track, the password secret of the service must contain an API key; the username is ignored.
The team of the API key only needs the `VIEW_PORTFOLIO` permission, which covers reading the project, looking up its versions, and exporting its SBOM; permissions that modify the portfolio, such as `BOM_UPLOAD` or `PORTFOLIO_MANAGEMENT`, are not needed.
If portfolio access control is enabled in Dependency-Track, the projects to analyze must also be assigned to the team, including all versions selected by revisions; otherwise Dependency-Track answers with status 403.
For sbomify, the password secret must contain an access token; public components and products need no credentials.
For documents, the credentials are used for HTTP basic authentication.

### Failing fast

A run fails at once, before the ORT Analyzer is started, if:

- no SBOM was uploaded and the source of the repository has not been identified, or was identified for another URL;
- the revision cannot be used for the source, or does not exist;
- the source is a Dependency-Track project and no infrastructure service provides credentials for it, or the credentials of the matching infrastructure service cannot be resolved: Dependency-Track is never accessed anonymously;
- the source refuses the request, for instance with status 401 or 403, or does not provide an SBOM in a supported format.

### Name of the repository

If a repository of type SBOM has no name, the first successful run names it after the project, component, or product of its source, such as `che-server` for a Dependency-Track project.
A name given by a user is never changed.

Example of creating an SBOM repository and uploading an SBOM:

```shell
curl -X POST "$ORT_SERVER/api/v1/products/1/repositories" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"type": "SBOM", "url": "https://github.com/eclipse-jetty/jetty.project", "name": "jetty-home"}'

curl -X PUT "$ORT_SERVER/api/v1/repositories/42/sbom?fileName=jetty-home.cdx.json" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/vnd.cyclonedx+json" \
  --data-binary @jetty-home-12.0.21-cyclonedx.json
```

## How SBOMs Are Mapped

The conversion is done by the `SBOM` package manager plugin, which is provided by the [ORT SBOM Plugin](https://heurtematte.github.io/ort-sbom-plugin/):

- Each component the SBOM describes (the CycloneDX `metadata.component`, or the packages an SPDX document `DESCRIBES`) becomes a project of type `SBOM`.
  If the SBOM describes no component, a project named after the document is created.
- All other components become packages.
  If a component has a package URL, the identifier of the package is derived from it, using the same types as the package managers of ORT (for instance `Maven`, `NPM`, or `PyPI`), and the package URL is kept as is.
  This allows advisors such as OSV, package curations, and rules to work on these packages.
  Components without a package URL get identifiers of type `SBOM`.
- The dependency graph of the SBOM is preserved.
  Nested CycloneDX components and SPDX `CONTAINS` relationships are treated as dependencies.
  Components that are not reachable from a described component are attached as direct dependencies of the project.
- Scopes are taken from the CycloneDX component scope (`required`, `optional`, `excluded`) or from the type of SPDX relationships (for instance `test` for `TEST_DEPENDENCY_OF`); the default scope of SPDX dependencies is `dependencies`.
  Scope excludes and includes of a run apply to them.
- Declared licenses, copyrights, authors, hashes, download locations, and VCS information of components are mapped to the corresponding package properties.
- Colons in the coordinates of components, such as in container image digests or Debian versions with an epoch, are encoded as `%3A` in the identifiers, because ORT does not allow them there; the package URLs keep the original values.
- Invalid values that do not affect the analysis, such as a malformed timestamp of a CycloneDX BOM or a hash value of the wrong length, are ignored.

The plugin supports the following options, which can be set in the `packageManagerOptions` of the analyzer job configuration under the name `SBOM`:

| Option                         | Default    | Description                                                                                                                                                                                                   |
| ------------------------------ | ---------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `attachUnreferencedComponents` | `true`     | Whether components that are not reachable from a described component are added as direct dependencies of the project. If disabled, they are dropped with a warning.                                           |
| `concludedLicenseHandling`     | `DECLARED` | How licenses an SBOM marks as concluded are mapped: `DECLARED` uses them as declared licenses of packages without declared licenses, `CONCLUDED` maps them to the concluded license, and `IGNORE` drops them. |
| `definitionFilePatterns`       | see plugin | The file name patterns of SBOMs, see below.                                                                                                                                                                   |

The `SBOM` package manager can also be enabled for runs of source code repositories by adding it to the `enabledPackageManagers` of the analyzer job configuration.
It then analyzes all files matching `definitionFilePatterns` (such as `*.cdx.json`, `bom.xml`, or `*.spdx.json`) whose content is a supported SBOM.
Do not enable it together with the `SpdxDocumentFile` package manager, as both handle `*.spdx.json` and `*.spdx.yaml` files.

## Limitations

- An SBOM does not provide the source code of its projects, so the scanner cannot scan them.
  Packages are scanned if the SBOM provides a VCS or a source artifact location for them.
  For SBOM repositories, it is usually sufficient to run the analyzer, the advisor, the evaluator, and the reporter.
- Dependency-Track does not keep uploaded SBOMs, but generates a CycloneDX SBOM from its own model when it is exported.
- Repository configuration files (`.ort.yml`) are not available for SBOM repositories; use the resolutions and the run configuration of ORT Server instead.

## Synchronizing a Dependency-Track Instance

To analyze all SBOMs managed by a Dependency-Track instance, create an SBOM repository for each project, for instance with a script that runs periodically and uses the APIs of both systems:

- Map parent projects of Dependency-Track to products, projects to SBOM repositories whose URL is the URL of the project, and project versions to runs whose revision is the version.
- Trigger a run whenever the `lastBomImport` timestamp of a project version changes.

With SBOM repositories pointing to Dependency-Track, ORT Server fetches the SBOMs itself and needs an infrastructure service with a Dependency-Track API key.
Alternatively, the script can export the SBOMs from Dependency-Track and upload them to the repositories before triggering the runs, so that ORT Server needs no access to Dependency-Track.

## Administration

Uploaded SBOMs are kept in the storage configured in the `sbomStorage` section of the configuration of the core and the workers, which uses the [database storage](../../admin-guide/infrastructure/storage/database.md) with the namespace `sboms` by default.
Like the other storages, it can be configured with environment variables, here prefixed with `SBOM_STORAGE_`, for instance `SBOM_STORAGE_NAME=s3` and `SBOM_STORAGE_BUCKET_NAME`.
The SBOM of a repository is deleted together with the repository.
