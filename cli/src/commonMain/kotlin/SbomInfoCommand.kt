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
import com.github.ajalt.clikt.core.Context
import com.github.ajalt.clikt.parameters.options.option
import com.github.ajalt.clikt.parameters.options.required
import com.github.ajalt.clikt.parameters.types.long

import org.eclipse.apoapsis.ortserver.cli.model.AuthenticationError
import org.eclipse.apoapsis.ortserver.cli.model.printables.toPrintable
import org.eclipse.apoapsis.ortserver.cli.utils.createAuthenticatedOrtServerClient
import org.eclipse.apoapsis.ortserver.cli.utils.echoMessage
import org.eclipse.apoapsis.ortserver.client.NotFoundException

class SbomInfoCommand : SuspendingCliktCommand(name = "info") {
    private val repositoryId by option(
        "--repository-id",
        envvar = "OSC_REPOSITORY_ID",
        help = "The ID of the repository of type SBOM."
    ).long().required()

    override fun help(context: Context) = "Print information about the SBOM uploaded for a repository of type SBOM."

    override suspend fun run() {
        val client = createAuthenticatedOrtServerClient() ?: throw AuthenticationError()

        val sbom = try {
            client.sbom.getSbom(repositoryId)
        } catch (e: NotFoundException) {
            throw SbomNotFoundException(repositoryId, e)
        }

        echoMessage(sbom.toPrintable())
    }
}
