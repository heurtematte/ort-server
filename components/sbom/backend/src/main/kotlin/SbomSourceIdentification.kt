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

package org.eclipse.apoapsis.ortserver.components.sbom

import kotlin.time.Clock
import kotlin.time.Instant

import kotlinx.serialization.Serializable

import org.eclipse.apoapsis.sbom.sources.SbomServerIdentificationException
import org.eclipse.apoapsis.sbom.sources.SbomServerIdentifier
import org.eclipse.apoapsis.sbom.sources.SbomSource
import org.eclipse.apoapsis.sbom.sources.SbomSourceType

/**
 * The source of the SBOM of a repository of type SBOM, as identified when the repository was created or its URL
 * changed. Runs use it as it is, without guessing the type of the source from the URL again.
 */
@Serializable
data class StoredSbomSource(
    /** The type of the source, as the ID of an [SbomSourceType], such as "dependency-track". */
    val type: String,

    /** The URL of the repository the source was identified for. */
    val url: String,

    /** The base URL of the API of the server, if it differs from the URL of the frontend. */
    val apiUrl: String? = null,

    /** The version of the server software when the source was identified, for information only. */
    val serverVersion: String? = null,

    /** The time when the source was identified. */
    val identifiedAt: Instant
) {
    /** The type of the source. */
    val sourceType: SbomSourceType get() = SbomSourceType.forId(type)

    /**
     * Return the [SbomSource] to retrieve the SBOM of the version requested by the given [revision] of a run: for a
     * Dependency-Track project or a sbomify component, the version with this name, `latest`, or, if the revision is
     * empty, the version of the URL. Throw an [IllegalArgumentException] if the revision cannot be used for the source.
     */
    fun toSbomSource(revision: String): SbomSource =
        when (val source = SbomSource.parse(url, sourceType, revision.ifBlank { null })) {
            is SbomSource.DependencyTrackProject -> source.copy(apiUrl = apiUrl)
            else -> source
        }
}

/** An exception thrown if the source of the SBOM of a repository cannot be identified. */
class SbomSourceIdentificationException(message: String, cause: Throwable? = null) : Exception(message, cause)

/**
 * A class to identify the source of the SBOM of a repository of type SBOM from its URL: a project of a
 * Dependency-Track instance, a component or product of a sbomify instance, or an SBOM document. The URL determines
 * the candidate type, unless a type is given, and the server must confirm it through its public identification
 * endpoints (see [SbomServerIdentifier]); no credentials are used. The identification fails if the URL does not match
 * the type or the server is not of this type, so that a repository is never created for a source that cannot work.
 */
class SbomSourceIdentification(private val identifier: SbomServerIdentifier = SbomServerIdentifier()) {
    /**
     * Identify the source of the SBOM of a repository with the given [url], of the given [type] or of the type
     * detected from the URL. Throw an [SbomSourceIdentificationException] if it cannot be identified.
     */
    fun identify(url: String, type: SbomSourceType? = null): StoredSbomSource {
        val source = try {
            SbomSource.parse(url, type)
        } catch (e: IllegalArgumentException) {
            throw SbomSourceIdentificationException(e.message ?: "Invalid SBOM source URL '$url'.", e)
        }

        val server = try {
            identifier.identify(source)
        } catch (e: SbomServerIdentificationException) {
            throw SbomSourceIdentificationException(e.message ?: "Could not identify the server of '$url'.", e)
        }

        val frontendUrl = (source as? SbomSource.DependencyTrackProject)?.baseUrl

        return StoredSbomSource(
            type = server.type.id,
            url = url.trim(),
            apiUrl = server.apiUrl?.takeIf { frontendUrl != null && it != frontendUrl },
            serverVersion = server.version,
            identifiedAt = Clock.System.now()
        )
    }
}
