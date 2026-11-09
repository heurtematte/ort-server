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
import com.github.tomakehurst.wiremock.client.WireMock.equalTo
import com.github.tomakehurst.wiremock.client.WireMock.get
import com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo
import com.github.tomakehurst.wiremock.core.WireMockConfiguration

import com.typesafe.config.ConfigFactory

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.WordSpec
import io.kotest.engine.spec.tempdir
import io.kotest.matchers.nulls.beNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.should
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain

import io.mockk.mockk

import java.io.IOException

import org.eclipse.apoapsis.ortserver.components.sbom.SbomStorageService
import org.eclipse.apoapsis.ortserver.components.sbom.sha256
import org.eclipse.apoapsis.ortserver.config.ConfigManager
import org.eclipse.apoapsis.ortserver.model.Repository
import org.eclipse.apoapsis.ortserver.model.RepositoryType
import org.eclipse.apoapsis.ortserver.storage.Storage
import org.eclipse.apoapsis.ortserver.storage.StorageProviderFactoryForTesting
import org.eclipse.apoapsis.sbom.parser.SbomFixtures

private const val PROJECT_UUID = "11111111-2222-3333-4444-555555555555"
private const val OTHER_VERSION_UUID = "66666666-7777-8888-9999-000000000000"

class SbomDownloaderTest : WordSpec({
    val server = WireMockServer(WireMockConfiguration.options().dynamicPort())

    beforeSpec { server.start() }
    afterSpec { server.stop() }
    beforeEach { server.resetAll() }

    fun sbomRepository(id: Long, url: String) = Repository(id, 1L, 1L, RepositoryType.SBOM, url)

    fun stubDependencyTrack() {
        val apiKey = equalTo("dt-api-key")

        server.stubFor(
            get(urlPathEqualTo("/api/v1/project/$PROJECT_UUID")).withHeader("X-Api-Key", apiKey)
                .willReturn(aResponse().withBody("""{"uuid": "$PROJECT_UUID", "name": "imap", "version": "2.0.3"}"""))
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

            val result = SbomDownloader(SbomStorageService(createTestStorage())).download(
                sbomRepository(2L, "${server.baseUrl()}/projects/$PROJECT_UUID"),
                "",
                SbomCredentials("ignored", "dt-api-key")
            )

            result.directory.resolve("sbom.cdx.json").readBytes() shouldBe
                SbomFixtures.bytes(SbomFixtures.CYCLONEDX_1_4_JSON)
            result.initRevision shouldBe "2.0.3"
        }

        "export the version of a Dependency-Track project that matches the revision" {
            stubDependencyTrack()

            val result = SbomDownloader(SbomStorageService(createTestStorage())).download(
                sbomRepository(3L, "${server.baseUrl()}/projects/$PROJECT_UUID"),
                "2.0.2",
                SbomCredentials("ignored", "dt-api-key")
            )

            result.directory.resolve("sbom.cdx.json").readBytes() shouldBe
                SbomFixtures.bytes(SbomFixtures.CYCLONEDX_1_6_JSON)
            result.initRevision shouldBe "2.0.2"
        }

        "report missing permissions of Dependency-Track" {
            stubDependencyTrack()
            server.stubFor(
                get(urlPathEqualTo("/api/v1/project/$PROJECT_UUID")).atPriority(10)
                    .willReturn(aResponse().withStatus(401))
            )

            shouldThrow<IOException> {
                SbomDownloader(SbomStorageService(createTestStorage())).download(
                    sbomRepository(4L, "${server.baseUrl()}/projects/$PROJECT_UUID"),
                    "",
                    SbomCredentials("ignored", "wrong-key")
                )
            }.message.shouldNotBeNull {
                this shouldContain "infrastructure service"
                this shouldContain "permission 'VIEW_PORTFOLIO'"
            }
        }

        "download the latest SBOM of a sbomify component" {
            stubSbomify()

            val result = SbomDownloader(SbomStorageService(createTestStorage())).download(
                sbomRepository(7L, "${server.baseUrl()}/component/cmp42/"),
                "",
                SbomCredentials("ignored", "sbomify-token")
            )

            result.directory.resolve("sbom.cdx.json").readBytes() shouldBe
                SbomFixtures.bytes(SbomFixtures.CYCLONEDX_1_4_JSON)
            result.initRevision shouldBe "2.0.3"
        }

        "download the SBOM of a sbomify component whose version matches the revision" {
            stubSbomify()

            val result = SbomDownloader(SbomStorageService(createTestStorage())).download(
                sbomRepository(8L, "${server.baseUrl()}/public/component/cmp42"),
                "1.0",
                SbomCredentials("ignored", "sbomify-token")
            )

            result.directory.resolve("sbom.spdx.json").readBytes() shouldBe
                SbomFixtures.bytes(SbomFixtures.SPDX_2_3_JSON)
            result.initRevision shouldBe "1.0"
        }

        "fail if a sbomify component has no SBOM with the requested version" {
            stubSbomify()

            shouldThrow<IOException> {
                SbomDownloader(SbomStorageService(createTestStorage())).download(
                    sbomRepository(9L, "${server.baseUrl()}/component/cmp42/"),
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

            val result = SbomDownloader(SbomStorageService(createTestStorage())).download(
                sbomRepository(10L, "${server.baseUrl()}/product/prd7/"),
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

            val result = SbomDownloader(SbomStorageService(createTestStorage())).download(
                sbomRepository(5L, "${server.baseUrl()}/sboms/p2repo"),
                "v1",
                SbomCredentials("scott", "tiger")
            )

            result.directory.resolve("sbom.spdx").isFile shouldBe true
            result.initRevision shouldBe "v1"
        }

        "fail if the URL does not point to an SBOM" {
            server.stubFor(
                get(urlPathEqualTo("/not-an-sbom")).willReturn(aResponse().withBody("""{"name": "package.json"}"""))
            )

            shouldThrow<IOException> {
                SbomDownloader(SbomStorageService(createTestStorage())).download(
                    sbomRepository(6L, "${server.baseUrl()}/not-an-sbom"),
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

    "SbomifyReference.parse" should {
        "recognize URLs of sbomify components and products" {
            SbomifyReference.parse("https://app.sbomify.com/component/Ab3_x-9/") shouldBe
                SbomifyReference("https://app.sbomify.com", SbomifyReference.Kind.COMPONENT, "Ab3_x-9")
            SbomifyReference.parse("https://sbomify.example.org/public/product/p1") shouldBe
                SbomifyReference("https://sbomify.example.org", SbomifyReference.Kind.PRODUCT, "p1")
            SbomifyReference.parse("https://app.sbomify.com/component/c1/releases/") should beNull()
            SbomifyReference.parse("https://example.org/sboms/bom.json") should beNull()
        }
    }

    "DependencyTrackProject.parse" should {
        "recognize URLs of Dependency-Track projects" {
            DependencyTrackProject.parse("https://sbom.eclipse.org/projects/$PROJECT_UUID") shouldBe
                DependencyTrackProject("https://sbom.eclipse.org", PROJECT_UUID)
            DependencyTrackProject.parse("https://example.org/dtrack/projects/$PROJECT_UUID/components") should beNull()
            DependencyTrackProject.parse("https://example.org/dtrack/projects/$PROJECT_UUID/") shouldBe
                DependencyTrackProject("https://example.org/dtrack", PROJECT_UUID)
            DependencyTrackProject.parse("https://github.com/eclipse-apoapsis/ort-server") should beNull()
        }
    }
})

private fun createTestStorage(): Storage {
    val config = ConfigFactory.parseMap(mapOf("test" to mapOf("name" to StorageProviderFactoryForTesting.NAME)))
    return Storage.create("test", ConfigManager.create(config), mockk())
}
