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

import com.github.ajalt.clikt.command.test

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.StringSpec
import io.kotest.engine.spec.tempdir
import io.kotest.engine.spec.tempfile
import io.kotest.matchers.should
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain

import io.ktor.http.HttpStatusCode
import io.ktor.utils.io.ByteReadChannel

import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkStatic
import io.mockk.unmockkAll

import kotlin.time.Instant

import org.eclipse.apoapsis.ortserver.cli.OrtServerMain
import org.eclipse.apoapsis.ortserver.cli.json
import org.eclipse.apoapsis.ortserver.cli.model.CliInputException
import org.eclipse.apoapsis.ortserver.cli.utils.createAuthenticatedOrtServerClient
import org.eclipse.apoapsis.ortserver.client.BadRequestException
import org.eclipse.apoapsis.ortserver.client.NotFoundException
import org.eclipse.apoapsis.ortserver.client.OrtServerClient
import org.eclipse.apoapsis.ortserver.client.ResponseException
import org.eclipse.apoapsis.ortserver.client.api.SbomApi
import org.eclipse.apoapsis.ortserver.components.sbom.RepositorySbom

class SbomCommandTest : StringSpec({
    afterEach { unmockkAll() }

    "sbom upload command" should {
        "upload the file with its name and print the stored SBOM as JSON" {
            val file = tempfile(suffix = ".cdx.json").apply { writeText(SBOM_CONTENT) }
            val sbomMock = mockk<SbomApi> {
                coEvery { uploadSbom(any(), any(), any()) } returns repositorySbom
            }
            mockOrtServerClient(sbomMock)

            val result = OrtServerMain().test(
                listOf("--json", "sbom", "upload", "--repository-id", "42", "--file", file.absolutePath)
            )

            coVerify(exactly = 1) {
                sbomMock.uploadSbom(42, match { it.contentEquals(SBOM_CONTENT.encodeToByteArray()) }, file.name)
            }

            result.statusCode shouldBe 0
            result.output shouldContain json.encodeToString(repositorySbom)
        }

        "print the stored SBOM in a human-readable format that fits into 80 columns" {
            val file = tempfile(suffix = ".cdx.json").apply { writeText(SBOM_CONTENT) }
            val sbomMock = mockk<SbomApi> {
                coEvery { uploadSbom(any(), any(), any()) } returns repositorySbom
            }
            mockOrtServerClient(sbomMock)

            val result = OrtServerMain().test(
                listOf("sbom", "upload", "--repository-id", "42", "--file", file.absolutePath)
            )

            result.statusCode shouldBe 0
            with(result.output) {
                shouldContain(repositorySbom.fileName)
                shouldContain(repositorySbom.format)
                shouldContain(repositorySbom.specVersion)
                shouldContain("${repositorySbom.componentCount}")
                shouldContain("${repositorySbom.size} bytes")
                shouldContain(repositorySbom.sha256)
                shouldContain(repositorySbom.warnings.single())
            }
        }

        "use the given file name and the repository ID from the environment" {
            val file = tempfile(suffix = ".json").apply { writeText(SBOM_CONTENT) }
            val sbomMock = mockk<SbomApi> {
                coEvery { uploadSbom(any(), any(), any()) } returns repositorySbom
            }
            mockOrtServerClient(sbomMock)

            val result = OrtServerMain().test(
                listOf("sbom", "upload", "--file", file.absolutePath, "--file-name", "bom.cdx.json"),
                envvars = mapOf("OSC_REPOSITORY_ID" to "42")
            )

            coVerify(exactly = 1) {
                sbomMock.uploadSbom(42, any(), "bom.cdx.json")
            }

            result.statusCode shouldBe 0
        }

        "fail with the message of the server if the file is not a valid SBOM" {
            val file = tempfile(suffix = ".txt").apply { writeText("Not an SBOM") }
            val sbomMock = mockk<SbomApi> {
                coEvery { uploadSbom(any(), any(), any()) } throws
                    BadRequestException("The uploaded file is not a valid SBOM. Cause: Unknown SBOM format.")
            }
            mockOrtServerClient(sbomMock)

            val exception = shouldThrow<CliInputException> {
                OrtServerMain().test(listOf("sbom", "upload", "--repository-id", "42", "--file", file.absolutePath))
            }

            exception.message shouldBe "Cannot upload the SBOM file '${file.absolutePath}' to repository '42': " +
                "The uploaded file is not a valid SBOM. Cause: Unknown SBOM format."
        }

        "fail with the message of the server if the repository is not of type SBOM" {
            val file = tempfile(suffix = ".cdx.json").apply { writeText(SBOM_CONTENT) }
            val serverMessage = "This operation is only available for repositories of type 'SBOM', but repository " +
                "'42' is of type 'GIT'."
            val sbomMock = mockk<SbomApi> {
                coEvery { uploadSbom(any(), any(), any()) } throws BadRequestException(serverMessage)
            }
            mockOrtServerClient(sbomMock)

            val exception = shouldThrow<CliInputException> {
                OrtServerMain().test(listOf("sbom", "upload", "--repository-id", "42", "--file", file.absolutePath))
            }

            exception.message shouldContain serverMessage
        }

        "fail with a clear message if the repository does not exist" {
            val file = tempfile(suffix = ".cdx.json").apply { writeText(SBOM_CONTENT) }
            val sbomMock = mockk<SbomApi> {
                coEvery { uploadSbom(any(), any(), any()) } throws NotFoundException("Resource not found.")
            }
            mockOrtServerClient(sbomMock)

            val exception = shouldThrow<NotFoundException> {
                OrtServerMain().test(listOf("sbom", "upload", "--repository-id", "42", "--file", file.absolutePath))
            }

            exception.message shouldBe "Repository with ID '42' not found."
        }

        "fail with a clear message if the SBOM is too large" {
            val file = tempfile(suffix = ".cdx.json").apply { writeText(SBOM_CONTENT) }
            val sbomMock = mockk<SbomApi> {
                coEvery { uploadSbom(any(), any(), any()) } throws ResponseException(
                    "Request failed with status 413: <html>Request Entity Too Large</html>",
                    HttpStatusCode.PayloadTooLarge
                )
            }
            mockOrtServerClient(sbomMock)

            val exception = shouldThrow<CliInputException> {
                OrtServerMain().test(listOf("sbom", "upload", "--repository-id", "42", "--file", file.absolutePath))
            }

            exception.message shouldContain "is too large to be uploaded"
        }

        "fail without uploading anything if the file cannot be read" {
            val missingFile = tempdir().resolve("missing.cdx.json")
            val sbomMock = mockk<SbomApi>()
            mockOrtServerClient(sbomMock)

            val exception = shouldThrow<CliInputException> {
                OrtServerMain().test(
                    listOf("sbom", "upload", "--repository-id", "42", "--file", missingFile.absolutePath)
                )
            }

            exception.message shouldContain "Cannot read the SBOM file '${missingFile.absolutePath}'"
            coVerify(exactly = 0) { sbomMock.uploadSbom(any(), any(), any()) }
        }

        "fail without uploading anything if the file is empty" {
            val file = tempfile(suffix = ".cdx.json")
            val sbomMock = mockk<SbomApi>()
            mockOrtServerClient(sbomMock)

            val exception = shouldThrow<CliInputException> {
                OrtServerMain().test(listOf("sbom", "upload", "--repository-id", "42", "--file", file.absolutePath))
            }

            exception.message shouldBe "The SBOM file '${file.absolutePath}' is empty."
            coVerify(exactly = 0) { sbomMock.uploadSbom(any(), any(), any()) }
        }
    }

    "sbom info command" should {
        "print the information about the SBOM" {
            val sbomMock = mockk<SbomApi> {
                coEvery { getSbom(42) } returns repositorySbom
            }
            mockOrtServerClient(sbomMock)

            val result = OrtServerMain().test(listOf("--json", "sbom", "info", "--repository-id", "42"))

            result.statusCode shouldBe 0
            result.output shouldContain json.encodeToString(repositorySbom)
        }

        "fail with a clear message if no SBOM has been uploaded" {
            val sbomMock = mockk<SbomApi> {
                coEvery { getSbom(42) } throws NotFoundException("Resource not found.")
            }
            mockOrtServerClient(sbomMock)

            val exception = shouldThrow<NotFoundException> {
                OrtServerMain().test(listOf("sbom", "info", "--repository-id", "42"))
            }

            exception.message shouldBe "No SBOM has been uploaded for repository '42'."
        }
    }

    "sbom download command" should {
        "save the SBOM to the output file" {
            val output = tempdir().resolve("sboms/bom.cdx.json")
            val sbomMock = mockk<SbomApi> {
                coEvery { downloadSbom(42, any()) } coAnswers {
                    secondArg<suspend (ByteReadChannel) -> Unit>()(ByteReadChannel(SBOM_CONTENT))
                }
            }
            mockOrtServerClient(sbomMock)

            val result = OrtServerMain().test(
                listOf("sbom", "download", "--repository-id", "42", "--output", output.absolutePath)
            )

            result.statusCode shouldBe 0
            result.output.trimEnd() shouldBe output.absolutePath
            output.readText() shouldBe SBOM_CONTENT
        }

        "fail with a clear message if no SBOM has been uploaded" {
            val output = tempdir().resolve("bom.cdx.json")
            val sbomMock = mockk<SbomApi> {
                coEvery { downloadSbom(42, any()) } throws NotFoundException("Resource not found.")
            }
            mockOrtServerClient(sbomMock)

            val exception = shouldThrow<NotFoundException> {
                OrtServerMain().test(
                    listOf("sbom", "download", "--repository-id", "42", "--output", output.absolutePath)
                )
            }

            exception.message shouldBe "No SBOM has been uploaded for repository '42'."
            output.exists() shouldBe false
        }
    }
})

private const val SBOM_CONTENT = """{"bomFormat": "CycloneDX", "specVersion": "1.6"}"""

private val repositorySbom = RepositorySbom(
    id = 3L,
    current = true,
    fileName = "bom.cdx.json",
    format = "CycloneDX JSON",
    mediaType = "application/vnd.cyclonedx+json",
    specVersion = "1.6",
    size = SBOM_CONTENT.length.toLong(),
    sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    uploadedAt = Instant.parse("2026-11-16T10:00:00Z"),
    uploadedBy = "ci-user",
    componentCount = 3,
    rootComponents = listOf("my-app"),
    warnings = listOf("The SBOM has the untested version 1.8.")
)

/** Mock the creation of the ORT Server client to return a client that uses the given [sbomApi]. */
private fun mockOrtServerClient(sbomApi: SbomApi) {
    val ortServerClientMock = mockk<OrtServerClient> {
        every { sbom } returns sbomApi
    }

    mockkStatic(::createAuthenticatedOrtServerClient)
    every { createAuthenticatedOrtServerClient() } returns ortServerClientMock
}
