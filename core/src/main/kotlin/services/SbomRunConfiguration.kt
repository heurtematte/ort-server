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

package org.eclipse.apoapsis.ortserver.core.services

import org.eclipse.apoapsis.ortserver.model.JobConfigurations

/** The ID of the package manager that analyzes the SBOM of a repository of type SBOM. */
internal const val SBOM_PACKAGE_MANAGER_ID = "SBOM"

/**
 * Return these job configurations for a run of a repository of type SBOM. The analyzer analyzes the SBOM of such a
 * repository only with the SBOM package manager, whatever package managers are configured, so the configuration of
 * the analyzer is restricted to this package manager and its options. This way, the configuration of the run shows
 * the package managers that are actually used.
 */
internal fun JobConfigurations.forSbomRepository(): JobConfigurations =
    copy(
        analyzer = analyzer.copy(
            enabledPackageManagers = listOf(SBOM_PACKAGE_MANAGER_ID),
            disabledPackageManagers = null,
            packageManagerOptions = analyzer.packageManagerOptions
                ?.filterKeys { it == SBOM_PACKAGE_MANAGER_ID }
                ?.mapValues { (_, config) -> config.copy(mustRunAfter = null) }
                ?.takeUnless { it.isEmpty() }
        )
    )
