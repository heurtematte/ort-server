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

/** Information about the SBOM uploaded for a repository of type SBOM. */
@Serializable
data class RepositorySbom(
    /** The name of the uploaded file. */
    val fileName: String,

    /** The format of the SBOM, such as "CycloneDX JSON" or "SPDX tag-value". */
    val format: String,

    /** The media type of the SBOM. */
    val mediaType: String,

    /** The version of the specification the SBOM adheres to, such as "1.6" or "SPDX-2.3". */
    val specVersion: String,

    /** The size of the SBOM in bytes. */
    val size: Long,

    /** The SHA-256 checksum of the SBOM. */
    val sha256: String,

    /** The time when the SBOM was uploaded. */
    val uploadedAt: Instant,

    /** The name of the user who uploaded the SBOM. */
    val uploadedBy: String? = null,

    /** The number of components listed in the SBOM. */
    val componentCount: Int,

    /** The components the SBOM describes; they become the projects of the analysis. */
    val rootComponents: List<String> = emptyList(),

    /** Problems found in the SBOM that did not prevent it from being accepted. */
    val warnings: List<String> = emptyList()
)
