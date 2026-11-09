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

package org.eclipse.apoapsis.ortserver.workers.analyzer

import com.github.tomakehurst.wiremock.WireMockServer
import com.github.tomakehurst.wiremock.client.WireMock.aResponse
import com.github.tomakehurst.wiremock.client.WireMock.anyUrl
import com.github.tomakehurst.wiremock.client.WireMock.equalTo
import com.github.tomakehurst.wiremock.client.WireMock.get
import com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor
import com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo
import com.github.tomakehurst.wiremock.core.WireMockConfiguration

import com.typesafe.config.ConfigFactory

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.WordSpec
import io.kotest.engine.spec.tempdir
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain

import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.mockk

import java.io.IOException

import kotlin.time.Clock

import org.eclipse.apoapsis.ortserver.components.sbom.SbomStorageService
import org.eclipse.apoapsis.ortserver.components.sbom.StoredSbomSource
import org.eclipse.apoapsis.ortserver.components.sbom.sha256
import org.eclipse.apoapsis.ortserver.config.ConfigManager
import org.eclipse.apoapsis.ortserver.model.Repository
import org.eclipse.apoapsis.ortserver.model.RepositoryType
import org.eclipse.apoapsis.ortserver.model.repositories.RepositoryRepository
import org.eclipse.apoapsis.ortserver.model.util.asPresent
import org.eclipse.apoapsis.ortserver.storage.Storage
import org.eclipse.apoapsis.ortserver.storage.StorageProviderFactoryForTesting
import org.eclipse.apoapsis.sbom.parser.SbomFixtures
import org.eclipse.apoapsis.sbom.sources.SbomSourceType

private const val PROJECT_UUID = "11111111-2222-3333-4444-555555555555"
private const val OTHER_VERSION_UUID = "66666666-7777-8888-9999-000000000000"

class SbomDownloaderTest : WordSpec({
    val server = WireMockServer(WireMockConfiguration.options().dynamicPort())

    beforeSpec { server.start() }
    afterSpec { server.stop() }
    beforeEach { server.resetAll() }

    fun sbomRepository(id: Long, url: String, name: String? = null) =
        Repository(id, 1L, 1L, RepositoryType.SBOM, url, name)

    /** Return a storage service with the source of the given [type] identified for the repository [id] and [url]. */
    suspend fun identified(id: Long, url: String, type: SbomSourceType, apiUrl: String? = null) =
        SbomStorageService(createTestStorage()).apply {
            storeSource(id, StoredSbomSource(type.id, url, apiUrl, "4.14.5", Clock.System.now()))
        }

    fun projectUrl() = "${server.baseUrl()}/projects/$PROJECT_UUID"

    fun stubDependencyTrack() {
        val apiKey = equalTo("dt-api-key")

        server.stubFor(
            get(urlPathEqualTo("/api/v1/project/$PROJECT_UUID")).withHeader("X-Api-Key", apiKey)
                .willReturn(aResponse().withBody("""{"uuid": "$PROJECT_UUID", "name": "imap", "version": "2.0.3"}"""))
        )
        server.stubFor(
            get(urlPathEqualTo("/api/v1/project/latest/imap")).withHeader("X-Api-Key", apiKey)
                .willReturn(aResponse().withBody("""{"uuid": "$OTHER_VERSION_UUID", "version": "2.0.2"}"""))
        )
        server.stubFor(
            get(urlPathEqualTo("/api/v1/project/lookup")).withHeader("X-Api-Key", apiKey)
                .withQueryParam("name", equalTo("imap")).withQueryParam("version", equalTo("2.0.2"))
                .willReturn(aResponse().withBody("""{"uuid": "$OTHER_VERSION_UUID", "version": "2.0.2"}"""))
        )
        listOf(PROJECT_UUID to SbomFixtures.CYCLONEDX_1_4_JSON, OTHER_VERSION_UUID to SbomFixtures.CYCLONEDX_1_6_JSON)
            .forEach { (uuid, fixture) ->
                server.stubFor(
                    get(urlPathEqualTo("/api/v1/bom/cyclonedx/project/$uuid")).withHeader("X-Api-Key", apiKey)
                        .withQueryParam("format", equalTo("json"))
                        .withQueryParam("variant", equalTo("inventory"))
                        .willReturn(aResponse().withBody(SbomFixtures.bytes(fixture)))
                )
            }
    }

    fun stubSbomify() {
        val token = equalTo("Bearer sbomify-token")
        fun item(id: String, version: String) =
            """{"sbom": {"id": "$id", "name": "imap", "version": "$version", "format": "cyclonedx"}, """ +
                """"has_vulnerabilities_report": false, "releases": []}"""
        val pagination = """"pagination": {"total": 1, "page": 1, "page_size": 1}"""

        server.stubFor(
            get(urlPathEqualTo("/api/v1/components/cmp42/sboms")).withHeader("Authorization", token)
                .willReturn(aResponse().withBody("""{"items": [${item("s1", "2.0.3")}], $pagination}"""))
        )
        server.stubFor(
            get(urlPathEqualTo("/api/v1/components/cmp42/sboms")).withHeader("Authorization", token)
                .withQueryParam("version", equalTo("1.0"))
                .willReturn(aResponse().withBody("""{"items": [${item("s0", "1.0")}], $pagination}"""))
        )
        server.stubFor(
            get(urlPathEqualTo("/api/v1/components/cmp42/sboms")).withHeader("Authorization", token)
                .withQueryParam("version", equalTo("9.9"))
                .willReturn(aResponse().withBody("""{"items": [], $pagination}"""))
        )
        listOf("s1" to SbomFixtures.CYCLONEDX_1_4_JSON, "s0" to SbomFixtures.SPDX_2_3_JSON).forEach { (id, fixture) ->
            server.stubFor(
                get(urlPathEqualTo("/api/v1/sboms/$id/download")).withHeader("Authorization", token)
                    .willReturn(aResponse().withBody(SbomFixtures.bytes(fixture)))
            )
        }
    }

    "download" should {
        "use the SBOM uploaded for the repository" {
            val storageService = SbomStorageService(createTestStorage())
            val content = SbomFixtures.bytes(SbomFixtures.SPDX_2_3_YAML)
            storageService.store(1L, content, "p2repo.spdx.yaml", null)

            val result = SbomDownloader(storageService).download(
                sbomRepository(1L, "https://example.com/unused"),
                "",
                null,
                tempdir(),
                12L
            )

            result.directory.name shouldContain "analyzer-worker-12-download"
            result.directory.resolve("sbom.spdx.yaml").readBytes() shouldBe content
            result.initRevision shouldBe "main"
            result.resolvedRevision shouldBe "sha256:${content.sha256()}"
        }

        "export the SBOM of a Dependency-Track project" {
            stubDependencyTrack()

            val result = SbomDownloader(identified(2L, projectUrl(), SbomSourceType.DEPENDENCY_TRACK)).download(
                sbomRepository(2L, projectUrl()),
                "",
                SbomCredentials("ignored", "dt-api-key")
            )

            result.directory.resolve("sbom.cdx.json").readBytes() shouldBe
                SbomFixtures.bytes(SbomFixtures.CYCLONEDX_1_4_JSON)
            result.initRevision shouldBe "2.0.3"
        }

        "export the version of a Dependency-Track project that matches the revision" {
            stubDependencyTrack()

            val result = SbomDownloader(identified(3L, projectUrl(), SbomSourceType.DEPENDENCY_TRACK)).download(
                sbomRepository(3L, projectUrl()),
                "2.0.2",
                SbomCredentials("ignored", "dt-api-key")
            )

            result.directory.resolve("sbom.cdx.json").readBytes() shouldBe
                SbomFixtures.bytes(SbomFixtures.CYCLONEDX_1_6_JSON)
            result.initRevision shouldBe "2.0.2"
        }

        "export the latest version of a Dependency-Track project" {
            stubDependencyTrack()

            val result = SbomDownloader(identified(3L, projectUrl(), SbomSourceType.DEPENDENCY_TRACK)).download(
                sbomRepository(3L, projectUrl()),
                "latest",
                SbomCredentials("ignored", "dt-api-key")
            )

            result.directory.resolve("sbom.cdx.json").readBytes() shouldBe
                SbomFixtures.bytes(SbomFixtures.CYCLONEDX_1_6_JSON)
        }

        "explain a revision that is not a version of the Dependency-Track project" {
            stubDependencyTrack()

            shouldThrow<IOException> {
                SbomDownloader(identified(3L, projectUrl(), SbomSourceType.DEPENDENCY_TRACK)).download(
                    sbomRepository(3L, projectUrl()),
                    "main",
                    SbomCredentials("ignored", "dt-api-key")
                )
            }.message shouldBe "The Dependency-Track project 'imap' has no version 'main'. Use one of its versions, " +
                "'latest', or no version for the version of the project URL."
        }

        "call the API server identified for the Dependency-Track instance" {
            stubDependencyTrack()
            val frontendUrl = "http://dependency-track.invalid/projects/$PROJECT_UUID"
            val storage = identified(4L, frontendUrl, SbomSourceType.DEPENDENCY_TRACK, apiUrl = server.baseUrl())

            val result = SbomDownloader(storage).download(
                sbomRepository(4L, frontendUrl),
                "",
                SbomCredentials("ignored", "dt-api-key")
            )

            result.initRevision shouldBe "2.0.3"
        }

        "fail without any request if no credentials are available for Dependency-Track" {
            stubDependencyTrack()

            shouldThrow<IOException> {
                SbomDownloader(identified(4L, projectUrl(), SbomSourceType.DEPENDENCY_TRACK)).download(
                    sbomRepository(4L, projectUrl()),
                    "",
                    null
                )
            }.message.shouldNotBeNull {
                this shouldContain "No credentials are available"
                this shouldContain "permission 'VIEW_PORTFOLIO'"
            }

            server.findAll(getRequestedFor(anyUrl())).size shouldBe 0
        }

        "report missing permissions of Dependency-Track" {
            stubDependencyTrack()
            server.stubFor(
                get(urlPathEqualTo("/api/v1/project/$PROJECT_UUID")).atPriority(10)
                    .willReturn(aResponse().withStatus(401))
            )

            shouldThrow<IOException> {
                SbomDownloader(identified(4L, projectUrl(), SbomSourceType.DEPENDENCY_TRACK)).download(
                    sbomRepository(4L, projectUrl()),
                    "",
                    SbomCredentials("ignored", "wrong-key")
                )
            }.message.shouldNotBeNull {
                this shouldContain "failed with status 401"
                this shouldContain "permission 'VIEW_PORTFOLIO'"
            }
        }

        "fail if the source of the repository has not been identified" {
            shouldThrow<IOException> {
                SbomDownloader(SbomStorageService(createTestStorage())).download(
                    sbomRepository(5L, projectUrl()),
                    "",
                    SbomCredentials("ignored", "dt-api-key")
                )
            }.message shouldContain "The source of the SBOM of repository '5' has not been identified"
        }

        "fail if the source was identified for another URL" {
            shouldThrow<IOException> {
                SbomDownloader(identified(5L, projectUrl(), SbomSourceType.DEPENDENCY_TRACK)).download(
                    sbomRepository(5L, "${server.baseUrl()}/sboms/other.json"),
                    "",
                    null
                )
            }.message shouldContain "Identify it again"
        }

        "name the repository after the Dependency-Track project if it has no name" {
            stubDependencyTrack()
            val repositories = mockk<RepositoryRepository> {
                coEvery { update(any(), name = any()) } returns sbomRepository(6L, projectUrl(), "imap")
            }

            SbomDownloader(identified(6L, projectUrl(), SbomSourceType.DEPENDENCY_TRACK), repositories).download(
                sbomRepository(6L, projectUrl()),
                "",
                SbomCredentials("ignored", "dt-api-key")
            )

            coVerify(exactly = 1) { repositories.update(6L, name = "imap".asPresent()) }
        }

        "not rename a repository that has a name" {
            stubDependencyTrack()
            val repositories = mockk<RepositoryRepository>()

            SbomDownloader(identified(6L, projectUrl(), SbomSourceType.DEPENDENCY_TRACK), repositories).download(
                sbomRepository(6L, projectUrl(), "my name"),
                "",
                SbomCredentials("ignored", "dt-api-key")
            )

            coVerify(exactly = 0) { repositories.update(any(), name = any()) }
        }

        "download the latest SBOM of a sbomify component" {
            stubSbomify()
            val url = "${server.baseUrl()}/component/cmp42/"

            val result = SbomDownloader(identified(7L, url, SbomSourceType.SBOMIFY)).download(
                sbomRepository(7L, url),
                "",
                SbomCredentials("ignored", "sbomify-token")
            )

            result.directory.resolve("sbom.cdx.json").readBytes() shouldBe
                SbomFixtures.bytes(SbomFixtures.CYCLONEDX_1_4_JSON)
            result.initRevision shouldBe "2.0.3"
        }

        "download the SBOM of a sbomify component whose version matches the revision" {
            stubSbomify()
            val url = "${server.baseUrl()}/public/component/cmp42"

            val result = SbomDownloader(identified(8L, url, SbomSourceType.SBOMIFY)).download(
                sbomRepository(8L, url),
                "1.0",
                SbomCredentials("ignored", "sbomify-token")
            )

            result.directory.resolve("sbom.spdx.json").readBytes() shouldBe
                SbomFixtures.bytes(SbomFixtures.SPDX_2_3_JSON)
            result.initRevision shouldBe "1.0"
        }

        "fail if a sbomify component has no SBOM with the requested version" {
            stubSbomify()
            val url = "${server.baseUrl()}/component/cmp42/"

            shouldThrow<IOException> {
                SbomDownloader(identified(9L, url, SbomSourceType.SBOMIFY)).download(
                    sbomRepository(9L, url),
                    "9.9",
                    SbomCredentials("ignored", "sbomify-token")
                )
            }.message shouldContain "no SBOM with version '9.9'"
        }

        "download the aggregated SBOM of a public sbomify product without credentials" {
            server.stubFor(
                get(urlPathEqualTo("/api/v1/products/prd7/download")).withQueryParam("format", equalTo("cyclonedx"))
                    .willReturn(aResponse().withBody(SbomFixtures.bytes(SbomFixtures.CYCLONEDX_1_6_XML)))
            )
            val url = "${server.baseUrl()}/product/prd7/"

            val result = SbomDownloader(identified(10L, url, SbomSourceType.SBOMIFY)).download(
                sbomRepository(10L, url),
                "",
                null
            )

            result.directory.resolve("sbom.cdx.xml").isFile shouldBe true
        }

        "download an SBOM from a URL using basic authentication" {
            server.stubFor(
                get(urlPathEqualTo("/sboms/p2repo")).withBasicAuth("scott", "tiger")
                    .willReturn(aResponse().withBody(SbomFixtures.bytes(SbomFixtures.SPDX_2_3_TAG_VALUE)))
            )
            val url = "${server.baseUrl()}/sboms/p2repo"

            val result = SbomDownloader(identified(11L, url, SbomSourceType.DOCUMENT)).download(
                sbomRepository(11L, url),
                "",
                SbomCredentials("scott", "tiger")
            )

            result.directory.resolve("sbom.spdx").isFile shouldBe true
        }

        "fail if a revision is requested for a document" {
            val url = "${server.baseUrl()}/sboms/p2repo"

            shouldThrow<IOException> {
                SbomDownloader(identified(12L, url, SbomSourceType.DOCUMENT)).download(
                    sbomRepository(12L, url),
                    "main",
                    null
                )
            }.message shouldContain "The revision 'main' of the run cannot be used for repository '12'"
        }

        "fail if the URL does not point to an SBOM" {
            server.stubFor(
                get(urlPathEqualTo("/not-an-sbom")).willReturn(aResponse().withBody("""{"name": "package.json"}"""))
            )
            val url = "${server.baseUrl()}/not-an-sbom"

            shouldThrow<IOException> {
                SbomDownloader(identified(13L, url, SbomSourceType.DOCUMENT)).download(
                    sbomRepository(13L, url),
                    "",
                    null
                )
            }.message shouldContain "not an SBOM"
        }
    }

    "isBelow" should {
        "respect path boundaries when matching infrastructure service URLs" {
            "https://sbom.eclipse.org/projects/$PROJECT_UUID".isBelow("https://sbom.eclipse.org") shouldBe true
            "https://sbom.eclipse.org/projects/$PROJECT_UUID".isBelow("https://sbom.eclipse.org/") shouldBe true
            "https://sbom.eclipse.org".isBelow("https://sbom.eclipse.org") shouldBe true
            "https://sbom.eclipse.org.example.com/projects/x".isBelow("https://sbom.eclipse.org") shouldBe false
            "https://example.org/sboms-other/x".isBelow("https://example.org/sboms") shouldBe false
        }
    }
})

private fun createTestStorage(): Storage {
    val config = ConfigFactory.parseMap(mapOf("test" to mapOf("name" to StorageProviderFactoryForTesting.NAME)))
    return Storage.create("test", ConfigManager.create(config), mockk())
}
