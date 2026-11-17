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

package org.eclipse.apoapsis.ortserver.components.sbom.routes

import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.server.response.respond
import io.ktor.server.routing.Route

import org.eclipse.apoapsis.ortserver.components.authorization.rights.RepositoryPermission
import org.eclipse.apoapsis.ortserver.components.authorization.routes.OrtServerPrincipal.Companion.requirePrincipal
import org.eclipse.apoapsis.ortserver.components.authorization.routes.put
import org.eclipse.apoapsis.ortserver.components.authorization.routes.requirePermission
import org.eclipse.apoapsis.ortserver.components.sbom.RepositorySbom
import org.eclipse.apoapsis.ortserver.components.sbom.SbomStorageService
import org.eclipse.apoapsis.ortserver.services.RepositoryService
import org.eclipse.apoapsis.ortserver.shared.ktorutils.jsonBody
import org.eclipse.apoapsis.ortserver.shared.ktorutils.respondError
import org.eclipse.apoapsis.sbom.parser.SbomFormat
import org.eclipse.apoapsis.sbom.parser.SbomParseException

internal fun Route.putRepositorySbom(
    sbomStorageService: SbomStorageService,
    repositoryService: RepositoryService
) = put(
    "repositories/{repositoryId}/sbom",
    {
        operationId = "putRepositorySbom"
        summary = "Upload the SBOM of a repository."
        description = "Upload the SBOM to analyze for a repository of type SBOM, replacing an existing one. The SBOM " +
            "can be sent as the raw request body or as the first file of a multipart/form-data request. Supported " +
            "formats are CycloneDX (JSON and XML), SPDX 2.x (JSON, YAML, and tag-value), and SPDX 3.0 (JSON-LD); " +
            "the format is detected from the content. Runs started afterwards analyze the new SBOM."
        tags = listOf(SBOM_TAG)

        request {
            repositoryIdParameter()

            queryParameter<String>("fileName") {
                description = "The name of the uploaded file. If missing, the name from the multipart data is used."
                required = false
            }

            body<ByteArray> {
                description = "The SBOM document."
                required = true
                mediaTypes = SbomFormat.entries.mapTo(mutableSetOf()) { ContentType.parse(it.mediaType) } +
                    setOf(ContentType.Application.OctetStream, ContentType.MultiPart.FormData)
            }
        }

        response {
            HttpStatusCode.OK to {
                description = "The SBOM was stored."
                jsonBody<RepositorySbom> {}
            }

            HttpStatusCode.BadRequest to {
                description = "The repository is not of type SBOM, or the content is not a valid SBOM."
            }

            HttpStatusCode.NotFound to {
                description = "The repository does not exist."
            }

            HttpStatusCode.PayloadTooLarge to {
                description = "The SBOM exceeds the maximum size."
            }
        }
    },
    requirePermission(RepositoryPermission.WRITE)
) {
    val repository = call.requireSbomRepository(repositoryService) ?: return@put

    val uploaded = try {
        call.receiveUploadedFile(sbomStorageService.maxSize, call.request.queryParameters["fileName"])
    } catch (e: UploadTooLargeException) {
        call.respondError(HttpStatusCode.PayloadTooLarge, e.message.orEmpty())
        return@put
    }

    if (uploaded == null || uploaded.content.isEmpty()) {
        call.respondError(HttpStatusCode.BadRequest, "The request does not contain an SBOM.")
        return@put
    }

    try {
        val stored = sbomStorageService.store(
            repository.id,
            uploaded.content,
            uploaded.fileName,
            requirePrincipal().username
        )

        call.respond(HttpStatusCode.OK, stored.mapToApi())
    } catch (e: SbomParseException) {
        call.respondError(HttpStatusCode.BadRequest, "The uploaded file is not a valid SBOM.", e.message)
    }
}
