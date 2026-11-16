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

package org.eclipse.apoapsis.ortserver.client.api

import io.ktor.client.HttpClient
import io.ktor.client.call.body
import io.ktor.client.request.delete
import io.ktor.client.request.get
import io.ktor.client.request.put
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsChannel
import io.ktor.http.ContentType
import io.ktor.http.contentType
import io.ktor.utils.io.ByteReadChannel

import org.eclipse.apoapsis.ortserver.components.sbom.RepositorySbom

/** A client for the API to manage the SBOMs of repositories of type SBOM. */
class SbomApi(
    /** The configured HTTP client for the interaction with the API. */
    private val client: HttpClient
) {
    /**
     * Upload the SBOM [content] for the repository with the given [repositoryId], replacing the current SBOM, and
     * return the [information][RepositorySbom] about the stored SBOM. The optional [fileName] is stored together with
     * the SBOM. Throw a [BadRequestException][org.eclipse.apoapsis.ortserver.client.BadRequestException] with the
     * message of the server if the repository is not of type SBOM or the [content] is not a valid SBOM.
     */
    suspend fun uploadSbom(repositoryId: Long, content: ByteArray, fileName: String? = null): RepositorySbom =
        client.put("api/v1/repositories/$repositoryId/sbom") {
            url {
                if (fileName != null) parameters.append("fileName", fileName)
            }

            contentType(ContentType.Application.OctetStream)
            setBody(content)
        }.body()

    /**
     * Get the [information][RepositorySbom] about the SBOM of the repository with the given [repositoryId]. Throw a
     * [NotFoundException][org.eclipse.apoapsis.ortserver.client.NotFoundException] if no SBOM has been uploaded.
     */
    suspend fun getSbom(repositoryId: Long): RepositorySbom =
        client.get("api/v1/repositories/$repositoryId/sbom").body()

    /**
     * Download the SBOM of the repository with the given [repositoryId] as it was uploaded. The SBOM is streamed to the
     * [streamTarget] function to avoid loading it into memory. Throw a
     * [NotFoundException][org.eclipse.apoapsis.ortserver.client.NotFoundException] if no SBOM has been uploaded.
     */
    suspend fun downloadSbom(repositoryId: Long, streamTarget: suspend (ByteReadChannel) -> Unit) {
        val response = client.get("api/v1/repositories/$repositoryId/sbom/content")

        streamTarget(response.bodyAsChannel())
    }

    /**
     * Delete the SBOM of the repository with the given [repositoryId]. Throw a
     * [NotFoundException][org.eclipse.apoapsis.ortserver.client.NotFoundException] if no SBOM has been uploaded.
     */
    suspend fun deleteSbom(repositoryId: Long) {
        client.delete("api/v1/repositories/$repositoryId/sbom")
    }
}
