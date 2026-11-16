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

package org.eclipse.apoapsis.ortserver.components.sbom

import org.eclipse.apoapsis.ortserver.dao.repositories.ortrun.OrtRunsTable
import org.eclipse.apoapsis.ortserver.dao.repositories.repository.RepositoriesTable
import org.eclipse.apoapsis.ortserver.dao.utils.jsonb

import org.jetbrains.exposed.v1.core.ReferenceOption
import org.jetbrains.exposed.v1.core.Table
import org.jetbrains.exposed.v1.core.dao.id.LongIdTable
import org.jetbrains.exposed.v1.datetime.timestamp

/** A table with the SBOMs uploaded for repositories of type SBOM, including the ones replaced by later uploads. */
internal object RepositorySbomsTable : LongIdTable("repository_sboms") {
    val repositoryId = reference("repository_id", RepositoriesTable, onDelete = ReferenceOption.CASCADE)
    val sha256 = text("sha256")
    val fileName = text("file_name")
    val format = text("format")
    val specVersion = text("spec_version")
    val size = long("size")
    val componentCount = integer("component_count")
    val rootComponents = jsonb<List<String>>("root_components")
    val warnings = jsonb<List<String>>("warnings")
    val uploadedAt = timestamp("uploaded_at")
    val uploadedBy = text("uploaded_by").nullable()
    val isCurrent = bool("is_current")
}

/** A table with the SBOM that each run of a repository of type SBOM analyzed. */
internal object OrtRunSbomsTable : Table("ort_run_sboms") {
    val ortRunId = reference("ort_run_id", OrtRunsTable, onDelete = ReferenceOption.CASCADE)
    val repositorySbomId =
        optReference("repository_sbom_id", RepositorySbomsTable, onDelete = ReferenceOption.SET_NULL)
    val sha256 = text("sha256")
    val fileName = text("file_name")
    val format = text("format")
    val specVersion = text("spec_version")
    val size = long("size")
    val componentCount = integer("component_count")
    val sourceUrl = text("source_url").nullable()
    val analyzedAt = timestamp("analyzed_at")

    override val primaryKey = PrimaryKey(ortRunId, name = "${tableName}_pkey")
}
