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

package org.eclipse.apoapsis.ortserver.core.api

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

import org.eclipse.apoapsis.ortserver.api.v1.mapping.mapToModel
import org.eclipse.apoapsis.ortserver.api.v1.model.PatchRepository
import org.eclipse.apoapsis.ortserver.api.v1.model.PostRepository
import org.eclipse.apoapsis.ortserver.components.sbom.SbomSourceIdentification
import org.eclipse.apoapsis.ortserver.components.sbom.SbomSourceIdentificationException
import org.eclipse.apoapsis.ortserver.components.sbom.SbomStorageService
import org.eclipse.apoapsis.ortserver.components.sbom.StoredSbomSource
import org.eclipse.apoapsis.ortserver.model.Repository
import org.eclipse.apoapsis.ortserver.model.RepositoryType

/** The result of the identification of the source of a repository; [source] is *null* if none was needed. */
internal class IdentifiedSbomSource(val source: StoredSbomSource?)

/**
 * Identify the source of the SBOM of the repository to create from the given [request] if it is of type SBOM. Throw an
 * [SbomSourceIdentificationException], which results in status 400, if the source cannot be identified, so that a
 * repository whose source does not work fails fast, at creation, instead of at each run.
 */
internal suspend fun SbomSourceIdentification.identifyNew(request: PostRepository): IdentifiedSbomSource =
    IdentifiedSbomSource(
        request.url.takeIf { request.type.mapToModel() == RepositoryType.SBOM }?.let { identifyInBackground(it) }
    )

/**
 * Identify the source of the SBOM of the given [repository] if the given [update] makes it a repository of type SBOM
 * or changes the URL of a repository of type SBOM. Throw an [SbomSourceIdentificationException], which results in
 * status 400, if the source cannot be identified, so that the repository is not changed.
 */
internal suspend fun SbomSourceIdentification.identifyChanged(
    repository: Repository?,
    update: PatchRepository
): IdentifiedSbomSource {
    if (repository == null) return IdentifiedSbomSource(null)

    var type = repository.type
    var url = repository.url
    update.type.ifPresent { type = it.mapToModel() }
    update.url.ifPresent { url = it }

    val unchanged = repository.type == RepositoryType.SBOM && url == repository.url
    if (type != RepositoryType.SBOM || unchanged) return IdentifiedSbomSource(null)

    return IdentifiedSbomSource(identifyInBackground(url))
}

/** Store the source of the [identified] result for the repository with the given [repositoryId], if there is one. */
internal suspend fun SbomStorageService.storeIdentifiedSource(repositoryId: Long, identified: IdentifiedSbomSource) {
    identified.source?.let { storeSource(repositoryId, it) }
}

private suspend fun SbomSourceIdentification.identifyInBackground(url: String): StoredSbomSource =
    withContext(Dispatchers.IO) { identify(url) }
