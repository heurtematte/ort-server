/*
 * Copyright (C) 2023 The ORT Server Authors (See <https://github.com/eclipse-apoapsis/ort-server/blob/main/NOTICE>)
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

package org.eclipse.apoapsis.ortserver.workers.advisor

import org.eclipse.apoapsis.ortserver.model.AdvisorJobConfiguration
import org.eclipse.apoapsis.ortserver.services.ortrun.mapToOrt
import org.eclipse.apoapsis.ortserver.workers.common.context.WorkerContext

import org.ossreviewtoolkit.advisor.Advisor
import org.ossreviewtoolkit.model.OrtResult
import org.ossreviewtoolkit.model.Project
import org.ossreviewtoolkit.model.config.AdvisorConfiguration
import org.ossreviewtoolkit.plugins.advisors.api.AdviceProviderFactory

import org.slf4j.LoggerFactory

internal class AdvisorRunner {
    companion object {
        private val logger = LoggerFactory.getLogger(AdvisorRunner::class.java)
    }

    suspend fun run(context: WorkerContext, ortResult: OrtResult, config: AdvisorJobConfiguration): OrtResult {
        val advisors = config.advisors.orEmpty()
        logger.info("Advisor run with these advisors: '{}'.", advisors)

        val providerFactories = advisors.mapNotNull { AdviceProviderFactory.ALL[it] }
        if (providerFactories.size < advisors.size) {
            val invalidAdvisors = advisors.filter { it !in AdviceProviderFactory.ALL }
            logger.error("The following advisors could not be resolved: {}.", invalidAdvisors)
        }

        // Plugin IDs are case-insensitive, so normalize the keys of the plugin configs to the IDs of the advisors.
        val pluginConfigs = context.resolvePluginConfigSecrets(config.config).mapKeys { (advisor, _) ->
            AdviceProviderFactory.ALL[advisor]?.descriptor?.id ?: advisor
        }
        val advisorConfig = AdvisorConfiguration(
            config.skipExcluded,
            pluginConfigs.mapValues { it.value.mapToOrt() }
        )

        val advisor = Advisor(providerFactories, advisorConfig)

        // Without an analyzer result, ORT only logs a warning and returns the result as it is.
        if (ortResult.analyzer == null) return advisor.advise(ortResult, config.skipExcluded)

        // Like ORT, give advice for the projects as packages, too, except for the projects that no advice provider can
        // identify.
        val (unidentifiableProjects, projects) = ortResult.getProjects(config.skipExcluded)
            .partition { it.isSbomProjectWithoutRevision() }

        if (unidentifiableProjects.isNotEmpty()) {
            logger.info(
                "Giving no advice for {} project(s) of type '{}' without VCS revision: {}.",
                unidentifiableProjects.size,
                SBOM_PROJECT_TYPE,
                unidentifiableProjects.joinToString { it.id.toCoordinates() }
            )
        }

        val packages = projects.mapTo(mutableSetOf()) { it.toPackage() } +
            ortResult.getPackages(config.skipExcluded).mapTo(mutableSetOf()) { it.metadata }

        return ortResult.copy(advisor = advisor.advise(packages))
    }
}

/** The type of the projects that the SBOM package manager creates for the components that an SBOM describes. */
private const val SBOM_PROJECT_TYPE = "SBOM"

/**
 * Return whether this is a project created from an SBOM in a repository without VCS, such as a repository of type
 * SBOM. Advice providers cannot identify such a project: projects have no purl, and without a VCS revision OSV takes
 * the type of the project as the ecosystem to query, which it rejects as invalid for "SBOM".
 */
private fun Project.isSbomProjectWithoutRevision() =
    id.type == SBOM_PROJECT_TYPE && vcsProcessed.revision.isEmpty()
