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

import io.github.smiley4.ktoropenapi.config.RequestConfig

import io.ktor.http.ContentDisposition
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.ApplicationCall
import io.ktor.server.response.header
import io.ktor.server.response.respond
import io.ktor.server.response.respondBytes
import io.ktor.server.routing.Route

import org.eclipse.apoapsis.ortserver.components.authorization.rights.RepositoryPermission
import org.eclipse.apoapsis.ortserver.components.authorization.routes.get
import org.eclipse.apoapsis.ortserver.components.authorization.routes.post
import org.eclipse.apoapsis.ortserver.components.authorization.routes.requirePermission
import org.eclipse.apoapsis.ortserver.components.sbom.RepositorySbom
import org.eclipse.apoapsis.ortserver.components.sbom.RunSbom
import org.eclipse.apoapsis.ortserver.components.sbom.SbomStorageService
import org.eclipse.apoapsis.ortserver.components.sbom.StoredRunSbom
import org.eclipse.apoapsis.ortserver.shared.ktorutils.jsonBody
import org.eclipse.apoapsis.ortserver.shared.ktorutils.requireIdParameter
import org.eclipse.apoapsis.ortserver.shared.ktorutils.respondError

internal fun Route.getRepositorySbomVersions(sbomStorageService: SbomStorageService) = get(
    "repositories/{repositoryId}/sbom/versions",
    {
        operationId = "getRepositorySbomVersions"
        summary = "Get the history of the SBOMs of a repository."
        description = "Get the metadata of all SBOMs uploaded for a repository of type SBOM, the latest first. The " +
            "current SBOM, which runs analyze, is flagged as current."
        tags = listOf(SBOM_TAG)

        request { repositoryIdParameter() }

        response {
            HttpStatusCode.OK to {
                description = "Success."
                jsonBody<List<RepositorySbom>> {}
            }
        }
    },
    requirePermission(RepositoryPermission.READ)
) {
    val repositoryId = call.requireIdParameter("repositoryId")

    call.respond(HttpStatusCode.OK, sbomStorageService.listVersions(repositoryId).map { it.mapToApi() })
}

internal fun Route.getRepositorySbomVersionContent(sbomStorageService: SbomStorageService) = get(
    "repositories/{repositoryId}/sbom/versions/{sbomId}/content",
    {
        operationId = "getRepositorySbomVersionContent"
        summary = "Download an SBOM from the history of a repository."
        description = "Download an SBOM uploaded for a repository of type SBOM as it was uploaded."
        tags = listOf(SBOM_TAG)

        request {
            repositoryIdParameter()
            sbomIdParameter()
        }

        response {
            HttpStatusCode.OK to {
                description = "The SBOM document."
            }

            HttpStatusCode.NotFound to {
                description = "The repository has no SBOM with this ID."
            }
        }
    },
    requirePermission(RepositoryPermission.READ)
) {
    val repositoryId = call.requireIdParameter("repositoryId")
    val sbomId = call.requireIdParameter("sbomId")

    sbomStorageService.getVersionContent(repositoryId, sbomId)?.let { (sbom, content) ->
        call.respondSbomFile(sbom.fileName, sbom.format.mediaType, content)
    } ?: call.respondNoSuchVersion(repositoryId, sbomId)
}

internal fun Route.postRepositorySbomVersionRestore(sbomStorageService: SbomStorageService) = post(
    "repositories/{repositoryId}/sbom/versions/{sbomId}/restore",
    {
        operationId = "postRepositorySbomVersionRestore"
        summary = "Make an SBOM from the history of a repository its current SBOM."
        description = "Make an SBOM uploaded before for a repository of type SBOM its current SBOM, so that runs " +
            "analyze it again."
        tags = listOf(SBOM_TAG)

        request {
            repositoryIdParameter()
            sbomIdParameter()
        }

        response {
            HttpStatusCode.OK to {
                description = "The SBOM is the current SBOM of the repository."
                jsonBody<RepositorySbom> {}
            }

            HttpStatusCode.NotFound to {
                description = "The repository has no SBOM with this ID."
            }
        }
    },
    requirePermission(RepositoryPermission.WRITE)
) {
    val repositoryId = call.requireIdParameter("repositoryId")
    val sbomId = call.requireIdParameter("sbomId")

    sbomStorageService.restore(repositoryId, sbomId)?.let { call.respond(HttpStatusCode.OK, it.mapToApi()) }
        ?: call.respondNoSuchVersion(repositoryId, sbomId)
}

private fun RequestConfig.sbomIdParameter() {
    pathParameter<Long>("sbomId") {
        description = "The ID of the SBOM in the history of the repository."
        required = true
    }
}

private suspend fun ApplicationCall.respondNoSuchVersion(repositoryId: Long, sbomId: Long) =
    respondError(HttpStatusCode.NotFound, "Repository '$repositoryId' has no SBOM with ID '$sbomId'.")

/** Respond with the given SBOM [content] as a file with the given [fileName] and [mediaType]. */
suspend fun ApplicationCall.respondSbomFile(fileName: String, mediaType: String, content: ByteArray) {
    response.header(
        HttpHeaders.ContentDisposition,
        ContentDisposition.Attachment.withParameter(ContentDisposition.Parameters.FileName, fileName).toString()
    )
    respondBytes(content, ContentType.parse(mediaType))
}

/** Map the metadata of the SBOM that a run analyzed to the API model. */
fun StoredRunSbom.mapToApi() =
    RunSbom(
        fileName = fileName,
        format = format.displayName,
        mediaType = format.mediaType,
        specVersion = specVersion,
        size = size,
        sha256 = sha256,
        componentCount = componentCount,
        uploadedSbomId = uploadedSbomId,
        sourceUrl = sourceUrl,
        analyzedAt = analyzedAt
    )
