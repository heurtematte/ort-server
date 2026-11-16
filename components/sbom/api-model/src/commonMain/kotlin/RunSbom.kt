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

/** Information about the SBOM that a run of a repository of type SBOM analyzed. */
@Serializable
data class RunSbom(
    /** The name of the SBOM file: the name of the uploaded file, or the name given to the SBOM of the source. */
    val fileName: String,

    /** The format of the SBOM, such as "CycloneDX JSON" or "SPDX tag-value". */
    val format: String,

    /** The media type of the SBOM. */
    val mediaType: String,

    /** The version of the specification the SBOM adheres to, such as "1.6" or "SPDX-2.3". */
    val specVersion: String,

    /** The size of the SBOM in bytes. */
    val size: Long,

    /** The SHA-256 checksum of the SBOM, which is also the resolved revision of the run. */
    val sha256: String,

    /** The number of components listed in the SBOM. */
    val componentCount: Int,

    /**
     * The ID of the uploaded SBOM that the run analyzed, in the history of the SBOMs of the repository, or null if the
     * run obtained the SBOM from the source of the repository.
     */
    val uploadedSbomId: Long? = null,

    /** The URL of the source from which the run obtained the SBOM, or null if it analyzed an uploaded SBOM. */
    val sourceUrl: String? = null,

    /** The time when the run obtained the SBOM. */
    val analyzedAt: Instant
)
