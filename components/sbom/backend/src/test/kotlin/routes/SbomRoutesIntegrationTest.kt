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

package org.eclipse.apoapsis.ortserver.components.sbom.routes

import io.kotest.assertions.ktor.client.shouldHaveStatus
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain

import io.ktor.client.call.body
import io.ktor.client.request.delete
import io.ktor.client.request.forms.formData
import io.ktor.client.request.forms.submitFormWithBinaryData
import io.ktor.client.request.get
import io.ktor.client.request.put
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsBytes
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.Headers
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpMethod
import io.ktor.http.HttpStatusCode
import io.ktor.http.contentType

import io.mockk.mockk

import org.eclipse.apoapsis.ortserver.components.sbom.PutRepositorySbomSource
import org.eclipse.apoapsis.ortserver.components.sbom.RepositorySbom
import org.eclipse.apoapsis.ortserver.components.sbom.RepositorySbomSource
import org.eclipse.apoapsis.ortserver.components.sbom.SbomSourceIdentification
import org.eclipse.apoapsis.ortserver.components.sbom.SbomSourceType
import org.eclipse.apoapsis.ortserver.components.sbom.SbomStorageService
import org.eclipse.apoapsis.ortserver.components.sbom.createStorage
import org.eclipse.apoapsis.ortserver.model.RepositoryType
import org.eclipse.apoapsis.ortserver.services.RepositoryService
import org.eclipse.apoapsis.ortserver.shared.ktorutils.AbstractIntegrationTest
import org.eclipse.apoapsis.sbom.parser.SbomFixtures
import org.eclipse.apoapsis.sbom.sources.DependencyTrackResponses.dependencyTrackInstance
import org.eclipse.apoapsis.sbom.sources.MockSbomServer

class SbomRoutesIntegrationTest : AbstractIntegrationTest({
    lateinit var repositoryService: RepositoryService
    var sbomRepositoryId = -1L

    beforeEach {
        repositoryService = RepositoryService(
            db = dbExtension.db,
            ortRunRepository = dbExtension.fixtures.ortRunRepository,
            repositoryRepository = dbExtension.fixtures.repositoryRepository,
            analyzerJobRepository = dbExtension.fixtures.analyzerJobRepository,
            advisorJobRepository = dbExtension.fixtures.advisorJobRepository,
            scannerJobRepository = dbExtension.fixtures.scannerJobRepository,
            evaluatorJobRepository = dbExtension.fixtures.evaluatorJobRepository,
            reporterJobRepository = dbExtension.fixtures.reporterJobRepository,
            notifierJobRepository = dbExtension.fixtures.notifierJobRepository,
            authorizationService = mockk()
        )

        sbomRepositoryId = dbExtension.fixtures.createRepository(
            type = RepositoryType.SBOM,
            url = "https://sbom.eclipse.org/projects/00000000-0000-0000-0000-000000000001"
        ).id
    }

    fun sbomTestApplication(
        sbomStorageService: SbomStorageService = SbomStorageService(createStorage()),
        block: suspend io.ktor.server.testing.ApplicationTestBuilder.(client: io.ktor.client.HttpClient) -> Unit
    ) = integrationTestApplication(
        routes = { sbomRoutes(sbomStorageService, repositoryService, SbomSourceIdentification()) },
        block = block
    )

    val dependencyTrack = MockSbomServer().apply { dependencyTrackInstance(version = "4.14.5") }
    val notDependencyTrack = MockSbomServer()

    afterSpec {
        dependencyTrack.close()
        notDependencyTrack.close()
    }

    suspend fun createSbomRepository(url: String) =
        dbExtension.fixtures.createRepository(type = RepositoryType.SBOM, url = url).id

    "PUT /repositories/{repositoryId}/sbom" should {
        "store an SBOM sent as request body and make it available" {
            sbomTestApplication { client ->
                val content = SbomFixtures.bytes(SbomFixtures.CYCLONEDX_1_6_JSON)

                val response = client.put("/repositories/$sbomRepositoryId/sbom?fileName=vertx.cdx.json") {
                    contentType(ContentType.parse("application/vnd.cyclonedx+json"))
                    setBody(content)
                }

                response shouldHaveStatus HttpStatusCode.OK
                val sbom = response.body<RepositorySbom>()
                sbom.fileName shouldBe "vertx.cdx.json"
                sbom.format shouldBe "CycloneDX JSON"
                sbom.specVersion shouldBe "1.6"
                sbom.uploadedBy shouldBe "testuser"

                client.get("/repositories/$sbomRepositoryId/sbom").body<RepositorySbom>() shouldBe sbom

                val download = client.get("/repositories/$sbomRepositoryId/sbom/content")
                download shouldHaveStatus HttpStatusCode.OK
                download.bodyAsBytes() shouldBe content
                download.headers[HttpHeaders.ContentType] shouldContain "application/vnd.cyclonedx+json"
                download.headers[HttpHeaders.ContentDisposition] shouldContain "vertx.cdx.json"
            }
        }

        "store an SBOM sent as multipart form data" {
            sbomTestApplication { client ->
                val response = client.submitFormWithBinaryData(
                    url = "/repositories/$sbomRepositoryId/sbom",
                    formData = formData {
                        append(
                            "file",
                            SbomFixtures.bytes(SbomFixtures.SPDX_2_3_TAG_VALUE),
                            Headers.build { append(HttpHeaders.ContentDisposition, "filename=\"p2repo.spdx\"") }
                        )
                    }
                ) { method = HttpMethod.Put }

                response shouldHaveStatus HttpStatusCode.OK
                with(response.body<RepositorySbom>()) {
                    fileName shouldBe "p2repo.spdx"
                    format shouldBe "SPDX tag-value"
                    componentCount shouldBe 21
                }
            }
        }

        "reject content that is not a valid SBOM" {
            sbomTestApplication { client ->
                val response = client.put("/repositories/$sbomRepositoryId/sbom") {
                    setBody("""{"name": "package.json"}""")
                }

                response shouldHaveStatus HttpStatusCode.BadRequest
                response.bodyAsText() shouldContain "not a valid SBOM"
            }
        }

        "reject SBOMs exceeding the maximum size" {
            sbomTestApplication(SbomStorageService(createStorage(), maxSize = 1000)) { client ->
                val response = client.put("/repositories/$sbomRepositoryId/sbom") {
                    setBody(SbomFixtures.bytes(SbomFixtures.CYCLONEDX_1_4_JSON))
                }

                response shouldHaveStatus HttpStatusCode.PayloadTooLarge
            }
        }

        "reject uploads to repositories that are not of type SBOM" {
            sbomTestApplication { client ->
                val response = client.put("/repositories/${dbExtension.fixtures.repository.id}/sbom") {
                    setBody(SbomFixtures.bytes(SbomFixtures.CYCLONEDX_1_4_JSON))
                }

                response shouldHaveStatus HttpStatusCode.BadRequest
                response.bodyAsText() shouldContain "type 'SBOM'"
            }
        }

        "respond with NotFound for a non-existing repository" {
            sbomTestApplication { client ->
                val response = client.put("/repositories/999999/sbom") {
                    setBody(SbomFixtures.bytes(SbomFixtures.CYCLONEDX_1_4_JSON))
                }

                response shouldHaveStatus HttpStatusCode.NotFound
            }
        }
    }

    "GET /repositories/{repositoryId}/sbom" should {
        "respond with NotFound if no SBOM was uploaded" {
            sbomTestApplication { client ->
                client.get("/repositories/$sbomRepositoryId/sbom") shouldHaveStatus HttpStatusCode.NotFound
                client.get("/repositories/$sbomRepositoryId/sbom/content") shouldHaveStatus HttpStatusCode.NotFound
            }
        }
    }

    "DELETE /repositories/{repositoryId}/sbom" should {
        "delete an uploaded SBOM" {
            sbomTestApplication { client ->
                client.put("/repositories/$sbomRepositoryId/sbom") {
                    setBody(SbomFixtures.bytes(SbomFixtures.SPDX_2_3_JSON))
                } shouldHaveStatus HttpStatusCode.OK

                client.delete("/repositories/$sbomRepositoryId/sbom") shouldHaveStatus HttpStatusCode.NoContent
                client.get("/repositories/$sbomRepositoryId/sbom") shouldHaveStatus HttpStatusCode.NotFound
                client.delete("/repositories/$sbomRepositoryId/sbom") shouldHaveStatus HttpStatusCode.NotFound
            }
        }
    }

    "PUT /repositories/{repositoryId}/sbom/source" should {
        "identify and store the source of the repository" {
            sbomTestApplication { client ->
                val url = "${dependencyTrack.baseUrl}/projects/00000000-0000-0000-0000-000000000002"
                val repositoryId = createSbomRepository(url)

                val response = client.put("/repositories/$repositoryId/sbom/source") {
                    contentType(ContentType.Application.Json)
                    setBody(PutRepositorySbomSource())
                }

                response shouldHaveStatus HttpStatusCode.OK
                val source = response.body<RepositorySbomSource>()
                source.type shouldBe SbomSourceType.DEPENDENCY_TRACK
                source.url shouldBe url
                source.apiUrl shouldBe null
                source.serverVersion shouldBe "4.14.5"

                client.get("/repositories/$repositoryId/sbom/source").body<RepositorySbomSource>() shouldBe source
            }
        }

        "reject a server that is not of the type of the URL" {
            sbomTestApplication { client ->
                val repositoryId =
                    createSbomRepository("${notDependencyTrack.baseUrl}/projects/00000000-0000-0000-0000-000000000003")

                val response = client.put("/repositories/$repositoryId/sbom/source") {
                    contentType(ContentType.Application.Json)
                    setBody(PutRepositorySbomSource())
                }

                response shouldHaveStatus HttpStatusCode.BadRequest
                response.bodyAsText() shouldContain "is not a Dependency-Track instance"
                client.get("/repositories/$repositoryId/sbom/source") shouldHaveStatus HttpStatusCode.NotFound
            }
        }

        "use the given type of source" {
            sbomTestApplication { client ->
                val repositoryId =
                    createSbomRepository("${notDependencyTrack.baseUrl}/projects/00000000-0000-0000-0000-000000000004")

                val response = client.put("/repositories/$repositoryId/sbom/source") {
                    contentType(ContentType.Application.Json)
                    setBody(PutRepositorySbomSource(SbomSourceType.DOCUMENT))
                }

                response shouldHaveStatus HttpStatusCode.OK
                response.body<RepositorySbomSource>().type shouldBe SbomSourceType.DOCUMENT
            }
        }
    }

    "GET /repositories/{repositoryId}/sbom/source" should {
        "respond with NotFound if the source has not been identified" {
            sbomTestApplication { client ->
                client.get("/repositories/$sbomRepositoryId/sbom/source") shouldHaveStatus HttpStatusCode.NotFound
            }
        }
    }
})
