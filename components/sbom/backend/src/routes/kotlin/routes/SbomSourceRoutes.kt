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

import io.ktor.http.HttpStatusCode
import io.ktor.server.request.receive
import io.ktor.server.response.respond
import io.ktor.server.routing.Route

import org.eclipse.apoapsis.ortserver.components.authorization.rights.RepositoryPermission
import org.eclipse.apoapsis.ortserver.components.authorization.routes.get
import org.eclipse.apoapsis.ortserver.components.authorization.routes.put
import org.eclipse.apoapsis.ortserver.components.authorization.routes.requirePermission
import org.eclipse.apoapsis.ortserver.components.sbom.PutRepositorySbomSource
import org.eclipse.apoapsis.ortserver.components.sbom.RepositorySbomSource
import org.eclipse.apoapsis.ortserver.components.sbom.SbomSourceIdentification
import org.eclipse.apoapsis.ortserver.components.sbom.SbomSourceIdentificationException
import org.eclipse.apoapsis.ortserver.components.sbom.SbomSourceType
import org.eclipse.apoapsis.ortserver.components.sbom.SbomStorageService
import org.eclipse.apoapsis.ortserver.components.sbom.StoredSbomSource
import org.eclipse.apoapsis.ortserver.services.RepositoryService
import org.eclipse.apoapsis.ortserver.shared.ktorutils.jsonBody
import org.eclipse.apoapsis.ortserver.shared.ktorutils.requireIdParameter
import org.eclipse.apoapsis.ortserver.shared.ktorutils.respondError
import org.eclipse.apoapsis.sbom.sources.SbomSourceType as PluginSbomSourceType

internal fun Route.getRepositorySbomSource(sbomStorageService: SbomStorageService) = get(
    "repositories/{repositoryId}/sbom/source",
    {
        operationId = "getRepositorySbomSource"
        summary = "Get the identified source of the SBOM of a repository."
        description = "Get the source of the SBOM of a repository of type SBOM, as identified when the repository " +
            "was created or its URL changed: a Dependency-Track project, a sbomify component or product, or an SBOM " +
            "document."
        tags = listOf(SBOM_TAG)

        request { repositoryIdParameter() }

        response {
            HttpStatusCode.OK to {
                description = "Success."
                jsonBody<RepositorySbomSource> {}
            }

            HttpStatusCode.NotFound to {
                description = "The source of the SBOM of the repository has not been identified."
            }
        }
    },
    requirePermission(RepositoryPermission.READ)
) {
    val repositoryId = call.requireIdParameter("repositoryId")

    sbomStorageService.getSource(repositoryId)?.let { call.respond(HttpStatusCode.OK, it.mapToApi()) }
        ?: call.respondError(
            HttpStatusCode.NotFound,
            "The source of the SBOM of repository '$repositoryId' has not been identified."
        )
}

internal fun Route.putRepositorySbomSource(
    sbomStorageService: SbomStorageService,
    repositoryService: RepositoryService,
    sbomSourceIdentification: SbomSourceIdentification
) = put(
    "repositories/{repositoryId}/sbom/source",
    {
        operationId = "putRepositorySbomSource"
        summary = "Identify the source of the SBOM of a repository again."
        description = "Identify the source of the SBOM of a repository of type SBOM from its URL again, for instance " +
            "after the server moved, and store it for the next runs. The type of the source is detected from the URL " +
            "unless it is given; the server must confirm it through its public identification endpoints."
        tags = listOf(SBOM_TAG)

        request {
            repositoryIdParameter()

            body<PutRepositorySbomSource> {
                description = "The type of the source, or no type to detect it from the URL."
                required = false
            }
        }

        response {
            HttpStatusCode.OK to {
                description = "The source was identified and stored."
                jsonBody<RepositorySbomSource> {}
            }

            HttpStatusCode.BadRequest to {
                description = "The repository is not of type SBOM, or its source cannot be identified."
            }

            HttpStatusCode.NotFound to {
                description = "The repository does not exist."
            }
        }
    },
    requirePermission(RepositoryPermission.WRITE)
) {
    val repository = call.requireSbomRepository(repositoryService) ?: return@put
    val request = runCatching { call.receive<PutRepositorySbomSource>() }.getOrDefault(PutRepositorySbomSource())

    try {
        val source = sbomSourceIdentification.identify(repository.url, request.type?.mapToPlugin())
        sbomStorageService.storeSource(repository.id, source)

        call.respond(HttpStatusCode.OK, source.mapToApi())
    } catch (e: SbomSourceIdentificationException) {
        call.respondError(HttpStatusCode.BadRequest, "Could not identify the source of the SBOM.", e.message)
    }
}

internal fun StoredSbomSource.mapToApi() =
    RepositorySbomSource(
        type = when (sourceType) {
            PluginSbomSourceType.DEPENDENCY_TRACK -> SbomSourceType.DEPENDENCY_TRACK
            PluginSbomSourceType.SBOMIFY -> SbomSourceType.SBOMIFY
            PluginSbomSourceType.DOCUMENT -> SbomSourceType.DOCUMENT
        },
        url = url,
        apiUrl = apiUrl,
        serverVersion = serverVersion,
        identifiedAt = identifiedAt
    )

private fun SbomSourceType.mapToPlugin() =
    when (this) {
        SbomSourceType.DEPENDENCY_TRACK -> PluginSbomSourceType.DEPENDENCY_TRACK
        SbomSourceType.SBOMIFY -> PluginSbomSourceType.SBOMIFY
        SbomSourceType.DOCUMENT -> PluginSbomSourceType.DOCUMENT
    }
