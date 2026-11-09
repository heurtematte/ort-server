/*
 * Copyright (C) 2026 The ORT Server Authors (See <https://github.com/eclipse-apoapsis/ort-server/blob/main/NOTICE>)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 * License-Filename: LICENSE
 */

package org.eclipse.apoapsis.ortserver.workers.analyzer

import java.io.File
import java.io.IOException
import java.net.PasswordAuthentication
import java.net.URI
import java.nio.file.Files
import java.nio.file.StandardCopyOption

import kotlin.io.path.createTempDirectory

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

import org.eclipse.apoapsis.ortserver.components.sbom.SbomStorageService
import org.eclipse.apoapsis.ortserver.components.sbom.StoredSbomSource
import org.eclipse.apoapsis.ortserver.components.sbom.sha256
import org.eclipse.apoapsis.ortserver.model.Repository
import org.eclipse.apoapsis.ortserver.model.repositories.RepositoryRepository
import org.eclipse.apoapsis.ortserver.model.util.asPresent
import org.eclipse.apoapsis.sbom.parser.SbomParser
import org.eclipse.apoapsis.sbom.sources.CredentialsProvider
import org.eclipse.apoapsis.sbom.sources.SbomFetcher
import org.eclipse.apoapsis.sbom.sources.SbomSource

import org.slf4j.LoggerFactory

private val logger = LoggerFactory.getLogger(SbomDownloader::class.java)

/** The characters that the name of a repository must not contain. */
private val INVALID_NAME_CHARACTERS = Regex("""[<>%\\]""")

/** The credentials of an infrastructure service that are used to download an SBOM. */
data class SbomCredentials(val username: String, val password: String)

/**
 * A class to obtain the SBOM of a repository of type SBOM, in place of cloning a source code repository:
 *
 * 1. The SBOM uploaded for the repository, managed by the [SbomStorageService], if there is one.
 * 2. Otherwise, the SBOM of the source identified when the repository was created or its URL changed: a project of a
 *    Dependency-Track instance, a component or product of a sbomify instance, or an SBOM document. The source is used
 *    as it was identified, without guessing its type from the URL again.
 *
 * The SBOM is retrieved with the [SbomFetcher] of the ORT SBOM plugin, so that SBOM repositories and SBOM source files
 * behave the same. The revision of a run selects the version of a Dependency-Track project or sbomify component: a
 * version, `latest`, or, if it is empty, the version of the repository URL. For Dependency-Track, the password of the
 * credentials is the API key; without credentials, the run fails at once.
 *
 * The analysis fails fast: if the source was not identified, the revision does not apply to the source, the
 * credentials are missing, or the retrieval fails, an [IOException] is thrown before the ORT Analyzer is started.
 *
 * If the [repositoryRepository] is given and the repository has no name, it is named after the project, component, or
 * product of the source, such as `che-server` for a Dependency-Track project.
 */
class SbomDownloader(
    private val sbomStorageService: SbomStorageService,
    private val repositoryRepository: RepositoryRepository? = null,
    private val fetcherFactory: (CredentialsProvider) -> SbomFetcher = { SbomFetcher(it, identifyServers = false) }
) {
    /**
     * Obtain the SBOM of the given [repository] for the requested [revision], using the optional [credentials] to
     * access its source. Store it in a new download directory below the optional [targetDir] whose name is derived
     * from the given [runId], so that later phases can find it. The revision of the result is the requested one or,
     * if none was requested, the version of the project or component of the source, or of the component described by
     * the SBOM; the resolved revision is the SHA-256 checksum of the SBOM.
     */
    suspend fun download(
        repository: Repository,
        revision: String,
        credentials: SbomCredentials?,
        targetDir: File? = null,
        runId: Long? = null
    ): DownloadResult {
        val outputDir = createTempDirectory(targetDir?.toPath(), AnalyzerDownloader.downloadDirName(runId)).toFile()

        val uploaded = sbomStorageService.downloadTo(repository.id, outputDir)
        val (file, versionFromSource) = if (uploaded != null) {
            logger.info(
                "Using the SBOM '{}' uploaded for repository '{}' at {}.",
                uploaded.second.fileName,
                repository.id,
                uploaded.second.uploadedAt
            )

            uploaded.first to null
        } else {
            fetchFromSource(repository, revision, credentials, outputDir)
        }

        val document = SbomParser.parse(file)
        val rootVersion = document.roots.firstNotNullOfOrNull { document.components[it]?.version }
        val initRevision = revision.ifEmpty { versionFromSource ?: rootVersion.orEmpty() }
        val resolvedRevision = "sha256:${file.readBytes().sha256()}"

        logger.info(
            "Obtained {} {} SBOM with {} components for repository '{}' (revision '{}', {}).",
            document.format.displayName,
            document.specVersion,
            document.components.size,
            repository.id,
            initRevision,
            resolvedRevision
        )

        return DownloadResult(outputDir, initRevision, resolvedRevision)
    }

    /**
     * Retrieve the SBOM of the identified source of the given [repository] for the given [revision] into [outputDir].
     * Return the file and the version of the project or component of the source.
     */
    private suspend fun fetchFromSource(
        repository: Repository,
        revision: String,
        credentials: SbomCredentials?,
        outputDir: File
    ): Pair<File, String?> {
        val identified = sbomStorageService.getSource(repository.id)
            ?: throw IOException(
                "The source of the SBOM of repository '${repository.id}' has not been identified, and no SBOM was " +
                    "uploaded. Identify it with '${sourceEndpoint(repository)}', or upload an SBOM."
            )

        if (identified.url != repository.url.trim()) {
            throw IOException(
                "The source of the SBOM of repository '${repository.id}' was identified for the URL " +
                    "'${identified.url}', but the URL of the repository is '${repository.url}'. Identify it again " +
                    "with '${sourceEndpoint(repository)}'."
            )
        }

        val source = identified.sourceFor(repository, revision)
        val fetcher = fetcherFactory(credentials.toProvider(identified))

        logger.info("Retrieving the SBOM of repository '{}' from {}.", repository.id, source.description)

        val fetched = withContext(Dispatchers.IO) { fetcher.fetch(source, outputDir) }
        nameRepository(repository, fetched.name)

        // Use a stable file name, as it becomes the definition file path of the projects in the results.
        val file = outputDir.resolve("sbom.${fetched.format.fileExtension}")
        Files.move(fetched.file.toPath(), file.toPath(), StandardCopyOption.REPLACE_EXISTING)

        return file to fetched.version
    }

    /** Name the given [repository] after its source with the given [name] if the repository has no name yet. */
    private suspend fun nameRepository(repository: Repository, name: String?) {
        val repositories = repositoryRepository ?: return
        val repositoryName = name?.trim()?.takeUnless { it.isEmpty() || INVALID_NAME_CHARACTERS.containsMatchIn(it) }
        if (repository.name != null || repositoryName == null) return

        runCatching {
            repositories.update(repository.id, name = repositoryName.asPresent())
        }.onSuccess {
            logger.info("Named repository '{}' '{}' after its source.", repository.id, repositoryName)
        }.onFailure {
            logger.warn("Could not name repository '{}' '{}'.", repository.id, repositoryName, it)
        }
    }
}

/** Return the endpoint to identify the source of the given [repository] again. */
private fun sourceEndpoint(repository: Repository) = "PUT /api/v1/repositories/${repository.id}/sbom/source"

/**
 * Return the [SbomSource] of this identified source for the given [revision] of a run of the given [repository].
 * Throw an [IOException] if the revision cannot be used for this source.
 */
private fun StoredSbomSource.sourceFor(repository: Repository, revision: String): SbomSource =
    try {
        toSbomSource(revision)
    } catch (e: IllegalArgumentException) {
        throw IOException(
            "The revision '$revision' of the run cannot be used for repository '${repository.id}': ${e.message} For " +
                "an SBOM repository, the revision selects the version of a Dependency-Track project or sbomify " +
                "component; leave it empty for the version of the repository URL.",
            e
        )
    }

/**
 * Return a [CredentialsProvider] that provides these credentials only for the origins of the given [source]: the
 * origin of its URL and, for a Dependency-Track instance whose API is served elsewhere, the origin of its API.
 */
private fun SbomCredentials?.toProvider(source: StoredSbomSource): CredentialsProvider {
    if (this == null) return CredentialsProvider.NONE

    val origins = listOfNotNull(source.url, source.apiUrl).mapNotNull { it.origin() }.toSet()
    val authentication = PasswordAuthentication(username, password.toCharArray())

    return CredentialsProvider { url -> authentication.takeIf { url.toString().origin() in origins } }
}

/** Return the origin of this URL, consisting of the scheme, host, and port, or *null* if it is not a valid URL. */
private fun String.origin(): String? =
    runCatching {
        val uri = URI(this)
        val port = uri.port.takeIf { it != -1 } ?: if (uri.scheme.equals("https", ignoreCase = true)) 443 else 80
        "${uri.scheme.lowercase()}://${uri.host.lowercase()}:$port"
    }.getOrNull()
