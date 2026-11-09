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

import io.ktor.http.ContentDisposition
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.server.response.header
import io.ktor.server.response.respond
import io.ktor.server.response.respondBytes
import io.ktor.server.routing.Route

import org.eclipse.apoapsis.ortserver.components.authorization.rights.RepositoryPermission
import org.eclipse.apoapsis.ortserver.components.authorization.routes.delete
import org.eclipse.apoapsis.ortserver.components.authorization.routes.get
import org.eclipse.apoapsis.ortserver.components.authorization.routes.requirePermission
import org.eclipse.apoapsis.ortserver.components.sbom.RepositorySbom
import org.eclipse.apoapsis.ortserver.components.sbom.SbomStorageService
import org.eclipse.apoapsis.ortserver.shared.ktorutils.jsonBody
import org.eclipse.apoapsis.ortserver.shared.ktorutils.requireIdParameter
import org.eclipse.apoapsis.ortserver.shared.ktorutils.respondError

internal fun Route.getRepositorySbom(sbomStorageService: SbomStorageService) = get(
    "repositories/{repositoryId}/sbom",
    {
        operationId = "getRepositorySbom"
        summary = "Get information about the SBOM of a repository."
        description = "Get the metadata of the SBOM uploaded for a repository of type SBOM."
        tags = listOf(SBOM_TAG)

        request { repositoryIdParameter() }

        response {
            HttpStatusCode.OK to {
                description = "Success."
                jsonBody<RepositorySbom> {}
            }

            HttpStatusCode.NotFound to {
                description = "No SBOM has been uploaded for the repository."
            }
        }
    },
    requirePermission(RepositoryPermission.READ)
) {
    val repositoryId = call.requireIdParameter("repositoryId")

    sbomStorageService.getMetadata(repositoryId)?.let { call.respond(HttpStatusCode.OK, it.mapToApi()) }
        ?: call.respondError(HttpStatusCode.NotFound, "No SBOM has been uploaded for repository '$repositoryId'.")
}

internal fun Route.getRepositorySbomContent(sbomStorageService: SbomStorageService) = get(
    "repositories/{repositoryId}/sbom/content",
    {
        operationId = "getRepositorySbomContent"
        summary = "Download the SBOM of a repository."
        description = "Download the SBOM uploaded for a repository of type SBOM as it was uploaded."
        tags = listOf(SBOM_TAG)

        request { repositoryIdParameter() }

        response {
            HttpStatusCode.OK to {
                description = "The SBOM document."
            }

            HttpStatusCode.NotFound to {
                description = "No SBOM has been uploaded for the repository."
            }
        }
    },
    requirePermission(RepositoryPermission.READ)
) {
    val repositoryId = call.requireIdParameter("repositoryId")
    val metadata = sbomStorageService.getMetadata(repositoryId)
    val content = metadata?.let { sbomStorageService.getContent(repositoryId) }

    if (metadata == null || content == null) {
        call.respondError(HttpStatusCode.NotFound, "No SBOM has been uploaded for repository '$repositoryId'.")
        return@get
    }

    call.response.header(
        HttpHeaders.ContentDisposition,
        ContentDisposition.Attachment.withParameter(ContentDisposition.Parameters.FileName, metadata.fileName)
            .toString()
    )
    call.respondBytes(content, ContentType.parse(metadata.format.mediaType))
}

internal fun Route.deleteRepositorySbom(sbomStorageService: SbomStorageService) = delete(
    "repositories/{repositoryId}/sbom",
    {
        operationId = "deleteRepositorySbom"
        summary = "Delete the SBOM of a repository."
        description = "Delete the SBOM uploaded for a repository of type SBOM. Afterwards, runs of the repository " +
            "download the SBOM from the repository URL."
        tags = listOf(SBOM_TAG)

        request { repositoryIdParameter() }

        response {
            HttpStatusCode.NoContent to {
                description = "The SBOM was deleted."
            }

            HttpStatusCode.NotFound to {
                description = "No SBOM has been uploaded for the repository."
            }
        }
    },
    requirePermission(RepositoryPermission.WRITE)
) {
    val repositoryId = call.requireIdParameter("repositoryId")

    if (sbomStorageService.delete(repositoryId)) {
        call.respond(HttpStatusCode.NoContent)
    } else {
        call.respondError(HttpStatusCode.NotFound, "No SBOM has been uploaded for repository '$repositoryId'.")
    }
}
