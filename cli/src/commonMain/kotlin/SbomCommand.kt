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

import com.github.ajalt.clikt.command.SuspendingNoOpCliktCommand
import com.github.ajalt.clikt.core.Context
import com.github.ajalt.clikt.core.subcommands

import org.eclipse.apoapsis.ortserver.client.NotFoundException

class SbomCommand : SuspendingNoOpCliktCommand(name = "sbom") {
    init {
        subcommands(SbomDownloadCommand(), SbomInfoCommand(), SbomUploadCommand())
    }

    override fun help(context: Context) = "Commands to manage the SBOM of a repository of type SBOM."
}

/** Exception thrown if no SBOM has been uploaded for the repository with the given [repositoryId]. */
internal class SbomNotFoundException(repositoryId: Long, cause: Throwable) :
    NotFoundException("No SBOM has been uploaded for repository '$repositoryId'.", cause)
