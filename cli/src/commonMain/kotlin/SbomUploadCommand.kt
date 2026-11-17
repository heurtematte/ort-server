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

package org.eclipse.apoapsis.ortserver.cli

import com.github.ajalt.clikt.command.SuspendingCliktCommand
import com.github.ajalt.clikt.completion.CompletionCandidates
import com.github.ajalt.clikt.core.Context
import com.github.ajalt.clikt.parameters.options.convert
import com.github.ajalt.clikt.parameters.options.option
import com.github.ajalt.clikt.parameters.options.required
import com.github.ajalt.clikt.parameters.types.long

import io.ktor.http.HttpStatusCode

import okio.IOException
import okio.Path.Companion.toPath

import org.eclipse.apoapsis.ortserver.cli.model.AuthenticationError
import org.eclipse.apoapsis.ortserver.cli.model.CliInputException
import org.eclipse.apoapsis.ortserver.cli.model.printables.toPrintable
import org.eclipse.apoapsis.ortserver.cli.utils.createAuthenticatedOrtServerClient
import org.eclipse.apoapsis.ortserver.cli.utils.echoMessage
import org.eclipse.apoapsis.ortserver.cli.utils.readBytes
import org.eclipse.apoapsis.ortserver.client.BadRequestException
import org.eclipse.apoapsis.ortserver.client.NotFoundException
import org.eclipse.apoapsis.ortserver.client.ResponseException

class SbomUploadCommand : SuspendingCliktCommand(name = "upload") {
    private val repositoryId by option(
        "--repository-id",
        envvar = "OSC_REPOSITORY_ID",
        help = "The ID of the repository of type SBOM."
    ).long().required()

    private val file by option(
        "--file",
        envvar = "OSC_SBOM_UPLOAD_FILE",
        help = "The path to the SBOM file to upload.",
        completionCandidates = CompletionCandidates.Path
    ).convert { it.expandTilde().toPath() }
        .required()

    private val fileName by option(
        "--file-name",
        envvar = "OSC_SBOM_UPLOAD_FILE_NAME",
        help = "The file name to store with the SBOM. If not provided, the name of the uploaded file is used."
    )

    override fun help(context: Context) = "Upload the SBOM of a repository of type SBOM, replacing its current SBOM."

    override fun helpEpilog(context: Context) = """
        The format of the SBOM is detected from its content. The server validates the SBOM before storing it, and runs
        started afterwards, for instance with '$COMMAND_NAME runs start --repository-id <ID> ...', analyze it.
    """.trimIndent()

    @Suppress("ThrowsCount")
    override suspend fun run() {
        val content = try {
            file.readBytes()
        } catch (e: IOException) {
            throw CliInputException("Cannot read the SBOM file '$file': ${e.message}", e)
        }

        if (content.isEmpty()) throw CliInputException("The SBOM file '$file' is empty.")

        val client = createAuthenticatedOrtServerClient() ?: throw AuthenticationError()

        val sbom = try {
            client.sbom.uploadSbom(repositoryId, content, fileName ?: file.name)
        } catch (e: BadRequestException) {
            throw CliInputException(
                "Cannot upload the SBOM file '$file' to repository '$repositoryId': ${e.message}",
                e
            )
        } catch (e: NotFoundException) {
            throw SbomRepositoryNotFoundException("Repository with ID '$repositoryId' not found.", e)
        } catch (e: ResponseException) {
            if (e.status != HttpStatusCode.PayloadTooLarge) throw e

            throw CliInputException(
                "The SBOM file '$file' (${content.size} bytes) is too large to be uploaded: it exceeds the maximum " +
                    "size accepted by ORT Server or by a reverse proxy in front of it.",
                e
            )
        }

        echoMessage(sbom.toPrintable())
    }
}

/** Exception thrown if the repository to upload an SBOM for does not exist. */
private class SbomRepositoryNotFoundException(message: String, cause: Throwable) : NotFoundException(message, cause)
