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
import org.ossreviewtoolkit.model.Package
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

        // Like ORT, give advice for the projects as packages, too, but leave out what no advice provider can identify.
        val (unidentifiable, packages) = (
            ortResult.getProjects(config.skipExcluded).mapTo(mutableSetOf()) { it.toPackage() } +
                ortResult.getPackages(config.skipExcluded).mapTo(mutableSetOf()) { it.metadata }
            ).partition { it.isUnidentifiableSbomPackage() }

        if (unidentifiable.isNotEmpty()) {
            logger.info(
                "Giving no advice for {} project(s) and package(s) of type '{}' without purl or VCS revision: {}.",
                unidentifiable.size,
                SBOM_TYPE,
                unidentifiable.joinToString { it.id.toCoordinates() }
            )
        }

        return ortResult.copy(advisor = advisor.advise(packages.toSet()))
    }
}

/**
 * The type of the projects that the SBOM package manager creates for the components that an SBOM describes, and of
 * the packages for components without purl.
 */
private const val SBOM_TYPE = "SBOM"

/**
 * Return whether this is a project or package created from an SBOM that advice providers cannot identify, such as
 * the projects of a repository of type SBOM, which ORT gives no purl, or a component without purl. Without a purl and
 * a VCS revision, OSV takes the type as the ecosystem to query, which it rejects as invalid for "SBOM", and the other
 * advice providers skip it.
 */
private fun Package.isUnidentifiableSbomPackage() =
    id.type == SBOM_TYPE && purl.isEmpty() && vcsProcessed.revision.isEmpty()
