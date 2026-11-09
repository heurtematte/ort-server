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

import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.http.content.PartData
import io.ktor.http.content.forEachPart
import io.ktor.server.application.ApplicationCall
import io.ktor.server.request.contentType
import io.ktor.server.request.receiveChannel
import io.ktor.server.request.receiveMultipart
import io.ktor.server.routing.Route
import io.ktor.utils.io.jvm.javaio.toInputStream

import java.io.InputStream

import org.eclipse.apoapsis.ortserver.components.sbom.RepositorySbom
import org.eclipse.apoapsis.ortserver.components.sbom.SbomSourceIdentification
import org.eclipse.apoapsis.ortserver.components.sbom.SbomStorageService
import org.eclipse.apoapsis.ortserver.components.sbom.StoredSbom
import org.eclipse.apoapsis.ortserver.model.Repository
import org.eclipse.apoapsis.ortserver.model.RepositoryType
import org.eclipse.apoapsis.ortserver.services.RepositoryService
import org.eclipse.apoapsis.ortserver.shared.ktorutils.requireIdParameter
import org.eclipse.apoapsis.ortserver.shared.ktorutils.respondError

/** The tag used for the SBOM endpoints in the API documentation. */
internal const val SBOM_TAG = "Repositories"

/** Register the routes to manage the SBOMs of repositories of type SBOM. */
fun Route.sbomRoutes(
    sbomStorageService: SbomStorageService,
    repositoryService: RepositoryService,
    sbomSourceIdentification: SbomSourceIdentification
) {
    putRepositorySbom(sbomStorageService, repositoryService)
    getRepositorySbom(sbomStorageService)
    getRepositorySbomContent(sbomStorageService)
    deleteRepositorySbom(sbomStorageService)
    getRepositorySbomSource(sbomStorageService)
    putRepositorySbomSource(sbomStorageService, repositoryService, sbomSourceIdentification)
}

internal fun RequestConfig.repositoryIdParameter() {
    pathParameter<Long>("repositoryId") {
        description = "The ID of the repository."
        required = true
    }
}

internal fun StoredSbom.mapToApi() =
    RepositorySbom(
        fileName = fileName,
        format = format.displayName,
        mediaType = format.mediaType,
        specVersion = specVersion,
        size = size,
        sha256 = sha256,
        uploadedAt = uploadedAt,
        uploadedBy = uploadedBy,
        componentCount = componentCount,
        rootComponents = rootComponents,
        warnings = warnings
    )

/**
 * Return the repository referenced by the path of this call if it exists and is of type SBOM. Otherwise, respond with
 * an error and return *null*.
 */
internal suspend fun ApplicationCall.requireSbomRepository(repositoryService: RepositoryService): Repository? {
    val repositoryId = requireIdParameter("repositoryId")
    val repository = repositoryService.getRepository(repositoryId)

    return when {
        repository == null -> {
            respondError(HttpStatusCode.NotFound, "Repository with ID '$repositoryId' not found.")
            null
        }

        repository.type != RepositoryType.SBOM -> {
            respondError(
                HttpStatusCode.BadRequest,
                "This operation is only available for repositories of type '${RepositoryType.SBOM.name}', but " +
                    "repository " +
                    "'$repositoryId' is of type '${repository.type.name}'."
            )
            null
        }

        else -> repository
    }
}

/** The content of an uploaded file together with its optional name. */
internal class UploadedFile(val content: ByteArray, val fileName: String?)

/** An exception thrown if an uploaded file exceeds the maximum size. */
internal class UploadTooLargeException(maxSize: Long) :
    Exception("The uploaded file exceeds the maximum size of $maxSize bytes.")

/**
 * Receive an uploaded file of at most [maxSize] bytes. The file can either be the raw body of the request, or the first
 * file part of a multipart request. The file name is taken from the given [fileNameParameter] or the multipart data.
 */
internal suspend fun ApplicationCall.receiveUploadedFile(maxSize: Long, fileNameParameter: String?): UploadedFile? {
    if (request.contentType().match(ContentType.MultiPart.FormData)) {
        var uploaded: UploadedFile? = null

        receiveMultipart(formFieldLimit = maxSize + 1).forEachPart { part ->
            if (uploaded == null && part is PartData.FileItem) {
                val content = part.provider().toInputStream().readLimited(maxSize)
                uploaded = UploadedFile(content, fileNameParameter ?: part.originalFileName)
            }

            part.release()
        }

        return uploaded
    }

    return UploadedFile(receiveChannel().toInputStream().readLimited(maxSize), fileNameParameter)
}

/** Read this stream, but throw an [UploadTooLargeException] if it has more than [maxSize] bytes. */
private fun InputStream.readLimited(maxSize: Long): ByteArray =
    use { input ->
        val bytes = input.readNBytes(minOf(maxSize + 1, Int.MAX_VALUE.toLong()).toInt())
        if (bytes.size > maxSize) throw UploadTooLargeException(maxSize)
        bytes
    }
