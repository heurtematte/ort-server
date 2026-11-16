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

package org.eclipse.apoapsis.ortserver.cli.model.printables

import com.github.ajalt.mordant.rendering.OverflowWrap
import com.github.ajalt.mordant.rendering.TextColors.blue
import com.github.ajalt.mordant.rendering.TextColors.yellow
import com.github.ajalt.mordant.rendering.Widget
import com.github.ajalt.mordant.table.GridBuilder
import com.github.ajalt.mordant.table.grid
import com.github.ajalt.mordant.widgets.Text

import org.eclipse.apoapsis.ortserver.cli.json
import org.eclipse.apoapsis.ortserver.components.sbom.RepositorySbom

/** A [CliPrintable] for the information about the [SBOM][RepositorySbom] of a repository of type SBOM. */
class RepositorySbomPrintable(private val sbom: RepositorySbom) : CliPrintable {
    override fun humanReadable(): Widget = grid {
        // Let the title span both columns, so that the names are narrow enough to show a SHA-256 checksum in a
        // terminal of 80 columns, the width usually assumed for CI logs.
        row { cell(yellow("SBOM Information")) { columnSpan = 2 } }
        sbomRow("File Name", sbom.fileName)
        sbomRow("Format", sbom.format)
        sbomRow("Version", sbom.specVersion)
        sbomRow("Components", sbom.componentCount)
        sbom.rootComponents.takeIf { it.isNotEmpty() }?.also { sbomRow("Describes", it.joinToString()) }
        sbomRow("Size", "${sbom.size} bytes")
        sbomRow("SHA-256", sbom.sha256)
        sbomRow("Uploaded", sbom.uploadedAt)
        sbom.uploadedBy?.takeIf { it.isNotBlank() }?.also { sbomRow("Uploaded By", it) }
        sbom.warnings.forEach { sbomRow("Warning", it) }
    }

    override fun json() = json.encodeToString(sbom)
}

fun RepositorySbom.toPrintable(): RepositorySbomPrintable = RepositorySbomPrintable(this)

/** Add a row with the [name] and the [value] of a property of an SBOM, wrapping long values instead of cutting them. */
private fun GridBuilder.sbomRow(name: String, value: Any) {
    row {
        cell(blue(name)) { padding { left = 2 } }
        cell(Text(value.toString(), overflowWrap = OverflowWrap.BREAK_WORD))
    }
}
