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

import kotlin.time.Instant

import kotlinx.serialization.Serializable

/** The types of sources of the SBOM of a repository of type SBOM. */
@Serializable
enum class SbomSourceType {
    /** A project of a Dependency-Track instance. */
    DEPENDENCY_TRACK,

    /** A component or a product of a sbomify instance. */
    SBOMIFY,

    /** An SBOM document that is downloaded as it is. */
    DOCUMENT
}

/**
 * The source of the SBOM of a repository of type SBOM, as identified when the repository was created or its URL
 * changed. Runs retrieve the SBOM from this source, unless an SBOM was uploaded.
 */
@Serializable
data class RepositorySbomSource(
    /** The type of the source. */
    val type: SbomSourceType,

    /** The URL of the repository the source was identified for. */
    val url: String,

    /** The base URL of the API of the server, if it differs from the URL of the frontend. */
    val apiUrl: String? = null,

    /** The version of the server software when the source was identified, for information only. */
    val serverVersion: String? = null,

    /** The time when the source was identified. */
    val identifiedAt: Instant
)

/** A request to identify the source of the SBOM of a repository again. */
@Serializable
data class PutRepositorySbomSource(
    /** The type of the source, or *null* to detect it from the URL of the repository. */
    val type: SbomSourceType? = null
)
