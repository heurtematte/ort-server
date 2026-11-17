/*
 * Copyright (C) 2025 The ORT Server Authors (See <https://github.com/eclipse-apoapsis/ort-server/blob/main/NOTICE>)
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
import io.kotest.core.spec.style.WordSpec
import io.kotest.matchers.shouldBe

import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.client.request.get
import io.ktor.client.request.post
import io.ktor.http.HttpStatusCode
import io.ktor.http.HttpStatusCode.Companion.BadRequest

import org.eclipse.apoapsis.ortserver.client.BadRequestException
import org.eclipse.apoapsis.ortserver.client.ResponseException
import org.eclipse.apoapsis.ortserver.client.createDefaultHttpClient
import org.eclipse.apoapsis.ortserver.client.createOrtHttpClient
import org.eclipse.apoapsis.ortserver.shared.apimodel.ErrorResponse

class HttpClientUtilsTest : WordSpec({
    "A default HTTP client" should {
        "retry a GET request with a 504 status code" {
            val maxRetries = 2
            var attempt = 0
            val mockEngine = MockEngine {
                attempt += 1
                if (attempt <= maxRetries) {
                    respond(content = "Gateway Timeout", status = HttpStatusCode.GatewayTimeout)
                } else {
                    respond(content = "OK")
                }
            }

            val client = createDefaultHttpClient(engine = mockEngine, maxRetriesOnTimeout = maxRetries)
            val response = client.get("http://test.example.org")

            response.status shouldBe HttpStatusCode.OK
        }

        "retry only the configured number of times" {
            val maxRetries = 1
            var attempt = 0
            val mockEngine = MockEngine {
                attempt += 1
                respond(content = "Gateway Timeout", status = HttpStatusCode.GatewayTimeout)
            }

            val client = createDefaultHttpClient(engine = mockEngine, maxRetriesOnTimeout = maxRetries)
            val response = client.get("http://test.example.org")

            response.status shouldBe HttpStatusCode.GatewayTimeout
            attempt shouldBe maxRetries + 1
        }

        "not retry a GET request with a different status code" {
            var attempt = 0
            val mockEngine = MockEngine {
                attempt += 1
                respond(content = "Bad Request", status = HttpStatusCode.BadRequest)
            }

            val client = createDefaultHttpClient(engine = mockEngine)
            val response = client.get("http://test.example.org")

            response.status shouldBe HttpStatusCode.BadRequest
            attempt shouldBe 1
        }

        "not retry a request with a different method" {
            var attempt = 0
            val mockEngine = MockEngine {
                attempt += 1
                respond(content = "Gateway Timeout", status = HttpStatusCode.GatewayTimeout)
            }

            val client = createDefaultHttpClient(engine = mockEngine)
            val response = client.post("http://test.example.org")

            response.status shouldBe HttpStatusCode.GatewayTimeout
            attempt shouldBe 1
        }

        "allow disabling the retry mechanism" {
            var attempt = 0
            val mockEngine = MockEngine {
                attempt += 1
                respond(content = "Gateway Timeout", status = HttpStatusCode.GatewayTimeout)
            }

            val client = createDefaultHttpClient(engine = mockEngine, maxRetriesOnTimeout = 0)
            val response = client.get("http://test.example.org")

            response.status shouldBe HttpStatusCode.GatewayTimeout
            attempt shouldBe 1
        }
    }

    "An ORT HTTP client" should {
        "throw a BadRequestException with the message and the cause of an error response" {
            val mockEngine = MockEngine {
                jsonRespond(ErrorResponse("Invalid request body.", "Missing field 'revision'."), BadRequest)
            }

            val client = createOrtHttpClient(engine = mockEngine)

            val exception = shouldThrow<BadRequestException> { client.get("http://test.example.org") }
            exception.message shouldBe "Invalid request body. Cause: Missing field 'revision'."
        }

        "throw a BadRequestException with the message of an error response without a cause" {
            val mockEngine = MockEngine {
                jsonRespond(ErrorResponse("The request does not contain an SBOM."), BadRequest)
            }

            val client = createOrtHttpClient(engine = mockEngine)

            val exception = shouldThrow<BadRequestException> { client.get("http://test.example.org") }
            exception.message shouldBe "The request does not contain an SBOM."
        }

        "throw a BadRequestException with a default message if the response is not an error response" {
            val mockEngine = MockEngine { respond(content = "Bad Request", status = BadRequest) }

            val client = createOrtHttpClient(engine = mockEngine)

            val exception = shouldThrow<BadRequestException> { client.get("http://test.example.org") }
            exception.message shouldBe "Request is invalid."
        }

        "throw a ResponseException with the message of an error response" {
            val mockEngine = MockEngine {
                jsonRespond(
                    ErrorResponse("The uploaded file exceeds the maximum size of 10 bytes."),
                    HttpStatusCode.PayloadTooLarge
                )
            }

            val client = createOrtHttpClient(engine = mockEngine)

            val exception = shouldThrow<ResponseException> { client.get("http://test.example.org") }
            exception.status shouldBe HttpStatusCode.PayloadTooLarge
            exception.message shouldBe
                "Request failed with status 413: The uploaded file exceeds the maximum size of 10 bytes."
        }

        "throw a ResponseException with the body if the response is not an error response" {
            val mockEngine = MockEngine {
                respond(content = "<html>Request Entity Too Large</html>", status = HttpStatusCode.PayloadTooLarge)
            }

            val client = createOrtHttpClient(engine = mockEngine)

            val exception = shouldThrow<ResponseException> { client.get("http://test.example.org") }
            exception.message shouldBe "Request failed with status 413: <html>Request Entity Too Large</html>"
        }
    }
})
