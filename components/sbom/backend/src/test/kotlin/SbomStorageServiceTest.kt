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

package org.eclipse.apoapsis.ortserver.components.sbom

import com.typesafe.config.ConfigFactory

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.WordSpec
import io.kotest.engine.spec.tempdir
import io.kotest.matchers.collections.containExactly
import io.kotest.matchers.nulls.beNull
import io.kotest.matchers.should
import io.kotest.matchers.shouldBe

import io.mockk.mockk

import org.eclipse.apoapsis.ortserver.config.ConfigManager
import org.eclipse.apoapsis.ortserver.storage.Storage
import org.eclipse.apoapsis.ortserver.storage.StorageProviderFactoryForTesting
import org.eclipse.apoapsis.sbom.parser.SbomFixtures
import org.eclipse.apoapsis.sbom.parser.SbomFormat
import org.eclipse.apoapsis.sbom.parser.SbomParseException

class SbomStorageServiceTest : WordSpec({
    "store" should {
        "store a valid SBOM together with its metadata" {
            val service = SbomStorageService(createStorage())
            val content = SbomFixtures.bytes(SbomFixtures.CYCLONEDX_1_4_XML)

            val metadata = service.store(REPOSITORY_ID, content, "path/to/imap.cdx.xml", "alice")

            metadata.fileName shouldBe "imap.cdx.xml"
            metadata.format shouldBe SbomFormat.CYCLONEDX_XML
            metadata.specVersion shouldBe "1.4"
            metadata.size shouldBe content.size.toLong()
            metadata.sha256 shouldBe content.sha256()
            metadata.uploadedBy shouldBe "alice"
            metadata.componentCount shouldBe 5
            metadata.rootComponents should containExactly("org.eclipse.angus:imap:2.0.3")

            service.getMetadata(REPOSITORY_ID) shouldBe metadata
            service.getContent(REPOSITORY_ID) shouldBe content
        }

        "derive a file name from the format if none is given" {
            val service = SbomStorageService(createStorage())

            val metadata = service.store(REPOSITORY_ID, SbomFixtures.bytes(SbomFixtures.SPDX_2_3_TAG_VALUE), null, null)

            metadata.fileName shouldBe "sbom.spdx"
        }

        "replace an existing SBOM" {
            val service = SbomStorageService(createStorage())
            service.store(REPOSITORY_ID, SbomFixtures.bytes(SbomFixtures.CYCLONEDX_1_4_JSON), null, null)

            service.store(REPOSITORY_ID, SbomFixtures.bytes(SbomFixtures.SPDX_2_3_JSON), null, null)

            service.getMetadata(REPOSITORY_ID)?.format shouldBe SbomFormat.SPDX_JSON
        }

        "reject content that is not an SBOM" {
            val service = SbomStorageService(createStorage())

            shouldThrow<SbomParseException> {
                service.store(OTHER_REPOSITORY_ID, """{"name": "package.json"}""".toByteArray(), null, null)
            }

            service.getMetadata(OTHER_REPOSITORY_ID) should beNull()
        }

        "reject SBOMs exceeding the maximum size" {
            val service = SbomStorageService(createStorage(), maxSize = 100)

            shouldThrow<IllegalArgumentException> {
                service.store(OTHER_REPOSITORY_ID, SbomFixtures.bytes(SbomFixtures.CYCLONEDX_1_4_JSON), null, null)
            }
        }
    }

    "downloadTo" should {
        "write the SBOM to a file with an extension matching its format" {
            val service = SbomStorageService(createStorage())
            val content = SbomFixtures.bytes(SbomFixtures.SPDX_3_0_JSON_LD)
            service.store(REPOSITORY_ID, content, "upload.json", null)

            val (file, metadata) = checkNotNull(service.downloadTo(REPOSITORY_ID, tempdir()))

            file.name shouldBe "sbom.spdx3.json"
            file.readBytes() shouldBe content
            metadata.format shouldBe SbomFormat.SPDX3_JSON_LD
        }

        "return null if no SBOM is stored" {
            SbomStorageService(createStorage()).downloadTo(UNKNOWN_REPOSITORY_ID, tempdir()) should beNull()
        }
    }

    "delete" should {
        "delete a stored SBOM" {
            val service = SbomStorageService(createStorage())
            service.store(REPOSITORY_ID, SbomFixtures.bytes(SbomFixtures.CYCLONEDX_1_4_JSON), null, null)

            service.delete(REPOSITORY_ID) shouldBe true

            service.getMetadata(REPOSITORY_ID) should beNull()
            service.getContent(REPOSITORY_ID) should beNull()
            service.delete(REPOSITORY_ID) shouldBe false
        }
    }
})

private const val REPOSITORY_ID = 42L
private const val OTHER_REPOSITORY_ID = 43L
private const val UNKNOWN_REPOSITORY_ID = 44L

/** Create a [Storage] backed by the in-memory test storage provider. */
internal fun createStorage(): Storage {
    val config = ConfigFactory.parseMap(mapOf("test" to mapOf("name" to StorageProviderFactoryForTesting.NAME)))
    return Storage.create("test", ConfigManager.create(config), mockk())
}
