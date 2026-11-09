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
import java.net.URI
import java.net.URLEncoder
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.time.Duration
import java.util.Base64

import kotlin.io.path.createTempDirectory

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

import org.eclipse.apoapsis.ortserver.components.sbom.SbomStorageService
import org.eclipse.apoapsis.ortserver.components.sbom.sha256
import org.eclipse.apoapsis.ortserver.model.Repository
import org.eclipse.apoapsis.sbom.parser.SbomParser

import org.slf4j.LoggerFactory

private val logger = LoggerFactory.getLogger(SbomDownloader::class.java)

/** The credentials of an infrastructure service that are used to download an SBOM. */
data class SbomCredentials(val username: String, val password: String)

/**
 * A reference to a project in a Dependency-Track instance with the given [baseUrl], as given by the URL of the project
 * page in the Dependency-Track frontend, such as `https://sbom.eclipse.org/projects/<uuid>`.
 */
internal data class DependencyTrackProject(val baseUrl: String, val uuid: String) {
    companion object {
        private const val UUID_PATTERN = "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"

        private val PROJECT_URL_REGEX = Regex("""^(https?://[^?#]+?)/projects/($UUID_PATTERN)/?(?:[?#].*)?$""")

        /** Return the [DependencyTrackProject] referenced by the given [url], or *null* if it is not a project URL. */
        fun parse(url: String): DependencyTrackProject? =
            PROJECT_URL_REGEX.matchEntire(url.trim())?.let { match ->
                DependencyTrackProject(match.groupValues[1], match.groupValues[2])
            }
    }
}

/**
 * A reference to a component or a product of a [sbomify](https://github.com/sbomify/sbomify) instance with the given
 * [baseUrl], as given by the URL of its page, such as `https://app.sbomify.com/component/<id>/` or
 * `https://app.sbomify.com/public/product/<id>/`.
 */
internal data class SbomifyReference(val baseUrl: String, val kind: Kind, val id: String) {
    enum class Kind { COMPONENT, PRODUCT }

    companion object {
        private val PAGE_URL_REGEX =
            Regex("""^(https?://[^?#]+?)/(?:public/)?(component|product)/([A-Za-z0-9_-]+)/?(?:[?#].*)?$""")

        /** Return the [SbomifyReference] for the given [url], or *null* if it is not a component or product URL. */
        fun parse(url: String): SbomifyReference? =
            PAGE_URL_REGEX.matchEntire(url.trim())?.let { match ->
                val kind = if (match.groupValues[2] == "product") Kind.PRODUCT else Kind.COMPONENT
                SbomifyReference(match.groupValues[1], kind, match.groupValues[3])
            }
    }
}

/**
 * A class to obtain the SBOM of a repository of type SBOM, in place of cloning a source code repository. The SBOM is
 * taken from the following sources, in this order:
 *
 * 1. The SBOM uploaded for the repository, managed by the [SbomStorageService].
 * 2. If the repository URL references a project of a Dependency-Track instance (such as
 *    `https://sbom.eclipse.org/projects/<uuid>`), the SBOM exported by Dependency-Track for this project. If a revision
 *    is requested, it selects the version of the project with the same name. The password of the credentials is used
 *    as the Dependency-Track API key.
 * 3. If the repository URL references a component or a product of a sbomify instance (such as
 *    `https://app.sbomify.com/component/<id>/`), the latest SBOM of the component, or the one whose version matches
 *    the requested revision, or the aggregated SBOM of the product. The password of the credentials is used as the
 *    sbomify access token; public components do not need one.
 * 4. Otherwise, the document the repository URL points to, using the credentials for basic authentication.
 */
class SbomDownloader(private val sbomStorageService: SbomStorageService) {
    companion object {
        private const val CONNECT_TIMEOUT_SECONDS = 30L
        private const val REQUEST_TIMEOUT_MINUTES = 10L

        private val json = Json { ignoreUnknownKeys = true }

        /** The headers that carry credentials, which must not be sent to the target of a redirect. */
        private val CREDENTIAL_HEADERS = setOf("Authorization", "X-Api-Key")
    }

    /** The client for anonymous requests, which follows redirects, for instance to download release assets. */
    private val anonymousClient = HttpClient.newBuilder()
        .followRedirects(HttpClient.Redirect.NORMAL)
        .connectTimeout(Duration.ofSeconds(CONNECT_TIMEOUT_SECONDS))
        .build()

    /** The client for requests with credentials, which does not follow redirects to avoid leaking credentials. */
    private val authenticatedClient = HttpClient.newBuilder()
        .followRedirects(HttpClient.Redirect.NEVER)
        .connectTimeout(Duration.ofSeconds(CONNECT_TIMEOUT_SECONDS))
        .build()

    /**
     * Obtain the SBOM of the given [repository] for the requested [revision], using the optional [credentials] to
     * access a remote source. Store it in a new download directory below the optional [targetDir] whose name is derived
     * from the given [runId], so that later phases can find it. The revision of the result is the requested one or,
     * if none was requested, the version of the component described by the SBOM; the resolved revision is the SHA-256
     * checksum of the SBOM.
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
            val dependencyTrackProject = DependencyTrackProject.parse(repository.url)
            val sbomifyReference = SbomifyReference.parse(repository.url)

            when {
                dependencyTrackProject != null ->
                    downloadFromDependencyTrack(dependencyTrackProject, revision, credentials, outputDir)

                sbomifyReference != null -> downloadFromSbomify(sbomifyReference, revision, credentials, outputDir)

                else -> downloadFromUrl(repository.url, credentials, outputDir) to null
            }
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
     * Download the SBOM of the given Dependency-Track [project] into [outputDir]. If a [revision] is given, look up the
     * version of the project with this name. Return the file and the version of the exported project.
     */
    private suspend fun downloadFromDependencyTrack(
        project: DependencyTrackProject,
        revision: String,
        credentials: SbomCredentials?,
        outputDir: File
    ): Pair<File, String?> {
        if (credentials == null) {
            logger.warn(
                "No infrastructure service with credentials matches the Dependency-Track URL '{}'; trying to access " +
                    "it anonymously.",
                project.baseUrl
            )
        }

        val headers = credentials?.let { mapOf("X-Api-Key" to it.password) }.orEmpty()
        val api = "${project.baseUrl}/api/v1"

        val requestedProject = getJson("$api/project/${project.uuid}", headers, DEPENDENCY_TRACK_PERMISSIONS_HINT)
        val name = requestedProject.string("name")
        val version = requestedProject.string("version")

        val uuid = if (revision.isEmpty() || revision == version) {
            project.uuid
        } else {
            val query = "name=${name.orEmpty().urlEncode()}&version=${revision.urlEncode()}"
            getJson("$api/project/lookup?$query", headers, DEPENDENCY_TRACK_PERMISSIONS_HINT).string("uuid")
                ?: throw IOException("Dependency-Track project '$name' has no version '$revision'.")
        }

        logger.info(
            "Exporting the SBOM of Dependency-Track project '{}' version '{}'.",
            name,
            revision.ifEmpty { version }
        )

        val file = outputDir.resolve("sbom.cdx.json")
        val response = send(
            "$api/bom/cyclonedx/project/$uuid?format=json&variant=inventory&download=true",
            headers + ("Accept" to "application/vnd.cyclonedx+json"),
            HttpResponse.BodyHandlers.ofFile(file.toPath())
        )
        response.requireSuccess(DEPENDENCY_TRACK_PERMISSIONS_HINT)

        return file to revision.ifEmpty { version }
    }

    /**
     * Download the SBOM of the given sbomify [reference] into [outputDir]. For a component, select the latest SBOM, or
     * the one with the given [revision] as version. Return the file and the version of the SBOM.
     */
    private suspend fun downloadFromSbomify(
        reference: SbomifyReference,
        revision: String,
        credentials: SbomCredentials?,
        outputDir: File
    ): Pair<File, String?> {
        val headers = credentials?.let { mapOf("Authorization" to "Bearer ${it.password}") }.orEmpty()
        val api = "${reference.baseUrl}/api/v1"

        val (downloadUrl, version) = when (reference.kind) {
            SbomifyReference.Kind.COMPONENT -> {
                val versionFilter = revision.takeUnless { it.isEmpty() }?.let { "&version=${it.urlEncode()}" }.orEmpty()
                val sboms = getJson("$api/components/${reference.id}/sboms?page=1&page_size=1$versionFilter", headers)
                val sbom = (sboms["items"] as? JsonArray)?.firstOrNull()?.jsonObject?.get("sbom")?.jsonObject
                    ?: throw IOException(
                        "The sbomify component '${reference.id}' has no SBOM" +
                            revision.takeUnless { it.isEmpty() }?.let { " with version '$it'" }.orEmpty() + "."
                    )

                val id = sbom.string("id") ?: throw IOException("Unexpected response from sbomify.")
                "$api/sboms/$id/download" to sbom.string("version")
            }

            SbomifyReference.Kind.PRODUCT -> {
                if (revision.isNotEmpty()) {
                    logger.warn(
                        "Ignoring revision '{}': sbomify products are exported in their latest state.",
                        revision
                    )
                }

                "$api/products/${reference.id}/download?format=cyclonedx" to null
            }
        }

        logger.info("Downloading the SBOM of sbomify {} '{}'.", reference.kind.name.lowercase(), reference.id)

        val response = send(downloadUrl, headers, HttpResponse.BodyHandlers.ofByteArray())
        response.requireSuccess()

        return response.body().writeAsSbom(outputDir, downloadUrl) to version
    }

    /** Download the SBOM from the given [url] into [outputDir] and return the file. */
    private suspend fun downloadFromUrl(url: String, credentials: SbomCredentials?, outputDir: File): File {
        logger.info("Downloading the SBOM from '{}'.", url)

        val headers = credentials?.let {
            val token = Base64.getEncoder().encodeToString("${it.username}:${it.password}".toByteArray())
            mapOf("Authorization" to "Basic $token")
        }.orEmpty()

        val response = send(url, headers, HttpResponse.BodyHandlers.ofByteArray())
        response.requireSuccess()

        return response.body().writeAsSbom(outputDir, url)
    }

    private suspend fun getJson(url: String, headers: Map<String, String>, permissionsHint: String = ""): JsonObject {
        val response = send(url, headers + ("Accept" to "application/json"), HttpResponse.BodyHandlers.ofString())
        response.requireSuccess(permissionsHint)
        return json.parseToJsonElement(response.body()) as? JsonObject
            ?: throw IOException("Unexpected response from '$url'.")
    }

    private suspend fun <T> send(
        url: String,
        headers: Map<String, String>,
        bodyHandler: HttpResponse.BodyHandler<T>
    ): HttpResponse<T> =
        withContext(Dispatchers.IO) {
            val request = HttpRequest.newBuilder(URI.create(url))
                .timeout(Duration.ofMinutes(REQUEST_TIMEOUT_MINUTES))
                .apply { headers.forEach { (name, value) -> header(name, value) } }
                .GET()
                .build()

            val client = if (headers.keys.any { it in CREDENTIAL_HEADERS }) authenticatedClient else anonymousClient
            client.send(request, bodyHandler)
        }
}

/** The hint for failed requests to Dependency-Track because of missing credentials or permissions. */
private const val DEPENDENCY_TRACK_PERMISSIONS_HINT = " The password of the service must be a Dependency-Track API " +
    "key whose team has the permission 'VIEW_PORTFOLIO' and, if portfolio access control is enabled, access to the " +
    "project."

private fun HttpResponse<*>.requireSuccess(permissionsHint: String = "") {
    if (statusCode() !in 200..299) {
        val hint = if (statusCode() == 401 || statusCode() == 403) {
            " Check the credentials of the infrastructure service matching the repository URL.$permissionsHint"
        } else {
            ""
        }

        throw IOException("Request to '${uri()}' failed with status ${statusCode()}.$hint")
    }
}

private fun JsonObject.string(key: String): String? = get(key)?.jsonPrimitive?.contentOrNull

/**
 * Write this content downloaded from the given [url] to a file in [outputDir] whose extension matches its SBOM format,
 * so that the SBOM package manager recognizes it. Throw an [IOException] if the content is not a supported SBOM.
 */
private fun ByteArray.writeAsSbom(outputDir: File, url: String): File {
    val format = SbomParser.detectFormat(this)
        ?: throw IOException("The document at '$url' is not an SBOM in a supported format.")

    return outputDir.resolve("sbom.${format.fileExtension}").also { it.writeBytes(this) }
}

private fun String.urlEncode(): String = URLEncoder.encode(this, Charsets.UTF_8)
