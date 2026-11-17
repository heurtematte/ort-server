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

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.StringSpec
import io.kotest.matchers.collections.beEmpty
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.should
import io.kotest.matchers.shouldBe

import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.client.engine.mock.respondError
import io.ktor.client.engine.mock.toByteArray
import io.ktor.http.ContentType
import io.ktor.http.HttpMethod
import io.ktor.http.HttpStatusCode
import io.ktor.http.fullPath
import io.ktor.utils.io.readBuffer
import io.ktor.utils.io.readText

import kotlin.time.Instant

import org.eclipse.apoapsis.ortserver.client.BadRequestException
import org.eclipse.apoapsis.ortserver.client.NotFoundException
import org.eclipse.apoapsis.ortserver.client.api.SbomApi
import org.eclipse.apoapsis.ortserver.client.createOrtHttpClient
import org.eclipse.apoapsis.ortserver.components.sbom.RepositorySbom
import org.eclipse.apoapsis.ortserver.shared.apimodel.ErrorResponse

class SbomApiTest : StringSpec({
    "uploadSbom" should {
        "upload the content of the SBOM and return the stored SBOM" {
            val content = """{"bomFormat": "CycloneDX", "specVersion": "1.6"}""".encodeToByteArray()
            val mockEngine = MockEngine { jsonRespond(repositorySbom) }
            val sbomApi = SbomApi(createOrtHttpClient(engine = mockEngine))

            sbomApi.uploadSbom(42, content, "bom.cdx.json") shouldBe repositorySbom

            mockEngine.requestHistory shouldHaveSize 1
            with(mockEngine.requestHistory.first()) {
                method shouldBe HttpMethod.Put
                url.fullPath shouldBe "/api/v1/repositories/42/sbom?fileName=bom.cdx.json"
                body.contentType shouldBe ContentType.Application.OctetStream
                body.toByteArray() shouldBe content
            }
        }

        "not send a file name if none is given" {
            val mockEngine = MockEngine { jsonRespond(repositorySbom) }
            val sbomApi = SbomApi(createOrtHttpClient(engine = mockEngine))

            sbomApi.uploadSbom(42, "content".encodeToByteArray())

            mockEngine.requestHistory shouldHaveSize 1
            with(mockEngine.requestHistory.first()) {
                url.fullPath shouldBe "/api/v1/repositories/42/sbom"
                url.parameters.names() should beEmpty()
            }
        }

        "throw an exception with the message of the server if the SBOM is rejected" {
            val mockEngine = MockEngine {
                jsonRespond(
                    ErrorResponse("The uploaded file is not a valid SBOM.", "Unknown SBOM format."),
                    HttpStatusCode.BadRequest
                )
            }
            val sbomApi = SbomApi(createOrtHttpClient(engine = mockEngine))

            val exception = shouldThrow<BadRequestException> {
                sbomApi.uploadSbom(42, "not an SBOM".encodeToByteArray(), "notes.txt")
            }

            exception.message shouldBe "The uploaded file is not a valid SBOM. Cause: Unknown SBOM format."
        }
    }

    "getSbom" should {
        "return the information about the SBOM" {
            val mockEngine = MockEngine { jsonRespond(repositorySbom) }
            val sbomApi = SbomApi(createOrtHttpClient(engine = mockEngine))

            sbomApi.getSbom(42) shouldBe repositorySbom

            mockEngine.requestHistory shouldHaveSize 1
            with(mockEngine.requestHistory.first()) {
                method shouldBe HttpMethod.Get
                url.fullPath shouldBe "/api/v1/repositories/42/sbom"
            }
        }

        "throw an exception if no SBOM has been uploaded" {
            val mockEngine = MockEngine {
                jsonRespond(ErrorResponse("No SBOM has been uploaded for repository '42'."), HttpStatusCode.NotFound)
            }
            val sbomApi = SbomApi(createOrtHttpClient(engine = mockEngine))

            shouldThrow<NotFoundException> {
                sbomApi.getSbom(42)
            }
        }
    }

    "downloadSbom" should {
        "execute the streamTarget lambda with the content of the SBOM" {
            val content = """{"bomFormat": "CycloneDX", "specVersion": "1.6"}"""
            val mockEngine = MockEngine { respond(content) }
            val sbomApi = SbomApi(createOrtHttpClient(engine = mockEngine))

            val receivedContent = StringBuilder()
            sbomApi.downloadSbom(42) { channel ->
                receivedContent.append(channel.readBuffer().readText())
            }

            receivedContent.toString() shouldBe content
            mockEngine.requestHistory.first().url.fullPath shouldBe "/api/v1/repositories/42/sbom/content"
        }

        "throw an exception without calling the streamTarget lambda if no SBOM has been uploaded" {
            val mockEngine = MockEngine { respondError(HttpStatusCode.NotFound) }
            val sbomApi = SbomApi(createOrtHttpClient(engine = mockEngine))

            var called = false
            shouldThrow<NotFoundException> {
                sbomApi.downloadSbom(42) { called = true }
            }

            called shouldBe false
        }
    }

    "deleteSbom" should {
        "delete the SBOM" {
            val mockEngine = MockEngine { respond("", HttpStatusCode.NoContent) }
            val sbomApi = SbomApi(createOrtHttpClient(engine = mockEngine))

            sbomApi.deleteSbom(42)

            mockEngine.requestHistory shouldHaveSize 1
            with(mockEngine.requestHistory.first()) {
                method shouldBe HttpMethod.Delete
                url.fullPath shouldBe "/api/v1/repositories/42/sbom"
            }
        }

        "throw an exception if no SBOM has been uploaded" {
            val mockEngine = MockEngine { respondError(HttpStatusCode.NotFound) }
            val sbomApi = SbomApi(createOrtHttpClient(engine = mockEngine))

            shouldThrow<NotFoundException> {
                sbomApi.deleteSbom(42)
            }
        }
    }
})

private val repositorySbom = RepositorySbom(
    id = 3L,
    current = true,
    fileName = "bom.cdx.json",
    format = "CycloneDX JSON",
    mediaType = "application/vnd.cyclonedx+json",
    specVersion = "1.6",
    size = 1234,
    sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    uploadedAt = Instant.parse("2026-11-16T10:00:00Z"),
    uploadedBy = "ci-user",
    componentCount = 3,
    rootComponents = listOf("my-app"),
    warnings = listOf("The SBOM has an untested version.")
)
