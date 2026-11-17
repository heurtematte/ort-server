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
import io.kotest.matchers.collections.beEmpty
import io.kotest.matchers.collections.containExactly
import io.kotest.matchers.collections.containExactlyInAnyOrder
import io.kotest.matchers.nulls.beNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.should
import io.kotest.matchers.shouldBe

import io.mockk.mockk

import kotlin.time.Clock

import kotlinx.serialization.json.Json

import org.eclipse.apoapsis.ortserver.config.ConfigManager
import org.eclipse.apoapsis.ortserver.dao.test.DatabaseTestExtension
import org.eclipse.apoapsis.ortserver.dao.utils.toDatabasePrecision
import org.eclipse.apoapsis.ortserver.model.RepositoryType
import org.eclipse.apoapsis.ortserver.storage.Storage
import org.eclipse.apoapsis.ortserver.storage.StorageProviderFactoryForTesting
import org.eclipse.apoapsis.sbom.parser.SbomFixtures
import org.eclipse.apoapsis.sbom.parser.SbomFormat
import org.eclipse.apoapsis.sbom.parser.SbomParseException
import org.eclipse.apoapsis.sbom.parser.SbomParser

class SbomStorageServiceTest : WordSpec({
    val dbExtension = extension(DatabaseTestExtension())

    lateinit var storage: Storage
    lateinit var service: SbomStorageService
    var repositoryId = -1L

    beforeEach {
        storage = createStorage()
        service = SbomStorageService(storage, dbExtension.db)
        repositoryId = dbExtension.fixtures.createRepository(type = RepositoryType.SBOM, url = "upload:bom.json").id
    }

    "store" should {
        "store a valid SBOM together with its metadata as the current SBOM" {
            val content = SbomFixtures.bytes(SbomFixtures.CYCLONEDX_1_4_XML)

            val metadata = service.store(repositoryId, content, "path/to/imap.cdx.xml", "alice")

            metadata.fileName shouldBe "imap.cdx.xml"
            metadata.format shouldBe SbomFormat.CYCLONEDX_XML
            metadata.specVersion shouldBe "1.4"
            metadata.size shouldBe content.size.toLong()
            metadata.sha256 shouldBe content.sha256()
            metadata.uploadedBy shouldBe "alice"
            metadata.componentCount shouldBe 5
            metadata.rootComponents should containExactly("org.eclipse.angus:imap:2.0.3")
            metadata.current shouldBe true

            service.getMetadata(repositoryId) shouldBe metadata
            service.getContent(repositoryId) shouldBe content
        }

        "derive a file name from the format if none is given" {
            val metadata = service.store(repositoryId, SbomFixtures.bytes(SbomFixtures.SPDX_2_3_TAG_VALUE), null, null)

            metadata.fileName shouldBe "sbom.spdx"
        }

        "replace the current SBOM and keep the previous one in the history" {
            val first = service.store(repositoryId, SbomFixtures.bytes(SbomFixtures.CYCLONEDX_1_4_JSON), null, null)

            val second = service.store(repositoryId, SbomFixtures.bytes(SbomFixtures.SPDX_2_3_JSON), null, null)

            service.getMetadata(repositoryId) shouldBe second
            service.listVersions(repositoryId) should containExactly(second, first.copy(current = false))
        }

        "reject content that is not an SBOM" {
            shouldThrow<SbomParseException> {
                service.store(repositoryId, """{"name": "package.json"}""".toByteArray(), null, null)
            }

            service.getMetadata(repositoryId) should beNull()
            service.listVersions(repositoryId) should beEmpty()
        }

        "reject SBOMs exceeding the maximum size" {
            val limitedService = SbomStorageService(storage, dbExtension.db, maxSize = 100)

            shouldThrow<IllegalArgumentException> {
                limitedService.store(repositoryId, SbomFixtures.bytes(SbomFixtures.CYCLONEDX_1_4_JSON), null, null)
            }
        }
    }

    "getVersionContent" should {
        "return an SBOM from the history with its content" {
            val content = SbomFixtures.bytes(SbomFixtures.CYCLONEDX_1_4_JSON)
            val first = service.store(repositoryId, content, "first.cdx.json", null)
            service.store(repositoryId, SbomFixtures.bytes(SbomFixtures.SPDX_2_3_JSON), null, null)

            val (sbom, versionContent) = service.getVersionContent(repositoryId, first.id).shouldNotBeNull()

            sbom shouldBe first.copy(current = false)
            versionContent shouldBe content
        }

        "return null for an SBOM of another repository" {
            val otherRepositoryId = dbExtension.fixtures.createRepository(type = RepositoryType.SBOM).id
            val content = SbomFixtures.bytes(SbomFixtures.CYCLONEDX_1_4_JSON)
            val other = service.store(otherRepositoryId, content, null, null)

            service.getVersionContent(repositoryId, other.id) should beNull()
        }
    }

    "restore" should {
        "make an SBOM from the history the current SBOM" {
            val firstContent = SbomFixtures.bytes(SbomFixtures.CYCLONEDX_1_4_JSON)
            val first = service.store(repositoryId, firstContent, null, null)
            val second = service.store(repositoryId, SbomFixtures.bytes(SbomFixtures.SPDX_2_3_JSON), null, null)

            service.restore(repositoryId, first.id) shouldBe first

            service.getMetadata(repositoryId) shouldBe first
            service.getContent(repositoryId) shouldBe firstContent
            service.listVersions(repositoryId) should containExactly(second.copy(current = false), first)
        }

        "return null for an unknown SBOM" {
            val current = service.store(repositoryId, SbomFixtures.bytes(SbomFixtures.CYCLONEDX_1_4_JSON), null, null)

            service.restore(repositoryId, current.id + 1) should beNull()

            service.getMetadata(repositoryId) shouldBe current
        }
    }

    "downloadTo" should {
        "write the current SBOM to a file with an extension matching its format" {
            val content = SbomFixtures.bytes(SbomFixtures.SPDX_3_0_JSON_LD)
            service.store(repositoryId, content, "upload.json", null)

            val (file, metadata) = checkNotNull(service.downloadTo(repositoryId, tempdir()))

            file.name shouldBe "sbom.spdx3.json"
            file.readBytes() shouldBe content
            metadata.format shouldBe SbomFormat.SPDX3_JSON_LD
        }

        "return null if the repository has no current SBOM" {
            service.downloadTo(repositoryId, tempdir()) should beNull()
        }
    }

    "delete" should {
        "stop using the current SBOM but keep it in the history" {
            val sbom = service.store(repositoryId, SbomFixtures.bytes(SbomFixtures.CYCLONEDX_1_4_JSON), null, null)

            service.delete(repositoryId) shouldBe true

            service.getMetadata(repositoryId) should beNull()
            service.getContent(repositoryId) should beNull()
            service.listVersions(repositoryId) should containExactly(sbom.copy(current = false))
            service.delete(repositoryId) shouldBe false
        }
    }

    "storeRunSbom" should {
        "record the uploaded SBOM that a run analyzed" {
            val content = SbomFixtures.bytes(SbomFixtures.CYCLONEDX_1_4_JSON)
            val uploaded = service.store(repositoryId, content, "imap.cdx.json", null)
            val runId = dbExtension.fixtures.createOrtRun(repositoryId).id

            val document = SbomParser.parse(content)

            service.storeRunSbom(runId, repositoryId, content, document, "imap.cdx.json", uploaded, null)

            val (runSbom, runContent) = service.getRunSbomContent(runId).shouldNotBeNull()
            runSbom.ortRunId shouldBe runId
            runSbom.repositoryId shouldBe repositoryId
            runSbom.fileName shouldBe "imap.cdx.json"
            runSbom.format shouldBe SbomFormat.CYCLONEDX_JSON
            runSbom.sha256 shouldBe uploaded.sha256
            runSbom.componentCount shouldBe uploaded.componentCount
            runSbom.uploadedSbomId shouldBe uploaded.id
            runSbom.sourceUrl should beNull()
            runContent shouldBe content
        }

        "record an SBOM obtained from a source, replacing the one recorded before for the run" {
            val runId = dbExtension.fixtures.createOrtRun(repositoryId).id
            val first = SbomFixtures.bytes(SbomFixtures.CYCLONEDX_1_4_JSON)
            service.storeRunSbom(runId, repositoryId, first, SbomParser.parse(first), "first.cdx.json", null, "a")
            val second = SbomFixtures.bytes(SbomFixtures.SPDX_2_3_JSON)

            service.storeRunSbom(runId, repositoryId, second, SbomParser.parse(second), "app-1.0.spdx.json", null, "b")

            val (runSbom, runContent) = service.getRunSbomContent(runId).shouldNotBeNull()
            runSbom.fileName shouldBe "app-1.0.spdx.json"
            runSbom.uploadedSbomId should beNull()
            runSbom.sourceUrl shouldBe "b"
            runContent shouldBe second
        }

        "return null for a run that analyzed no SBOM" {
            val runId = dbExtension.fixtures.createOrtRun(repositoryId).id

            service.getRunSbom(runId) should beNull()
            service.getRunSbomContent(runId) should beNull()
        }
    }

    "deleteAll" should {
        "delete the contents of the uploaded SBOMs and the SBOMs of runs" {
            val uploaded = SbomFixtures.bytes(SbomFixtures.CYCLONEDX_1_4_JSON)
            service.store(repositoryId, uploaded, null, null)
            val fromSource = SbomFixtures.bytes(SbomFixtures.SPDX_2_3_JSON)
            val runId = dbExtension.fixtures.createOrtRun(repositoryId).id
            val document = SbomParser.parse(fromSource)
            service.storeRunSbom(runId, repositoryId, fromSource, document, "a.spdx.json", null, "a")

            val contents = service.listContents(repositoryId)
            service.deleteAll(repositoryId, contents)

            contents should containExactlyInAnyOrder(uploaded.sha256(), fromSource.sha256())
            contents.forEach { storage.containsKey(SbomStorageService.contentKey(repositoryId, it)) shouldBe false }
        }
    }

    "the import of an SBOM stored without history" should {
        "make it the current SBOM of the repository" {
            val content = SbomFixtures.bytes(SbomFixtures.CYCLONEDX_1_4_JSON)
            val legacy = StoredSbom(
                fileName = "legacy.cdx.json",
                format = SbomFormat.CYCLONEDX_JSON,
                specVersion = "1.4",
                size = content.size.toLong(),
                sha256 = content.sha256(),
                uploadedAt = Clock.System.now().toDatabasePrecision(),
                uploadedBy = "bob",
                componentCount = 5
            )
            storage.write(SbomStorageService.legacyContentKey(repositoryId), content)
            storage.write(SbomStorageService.legacyMetadataKey(repositoryId), Json.encodeToString(legacy))

            val metadata = service.getMetadata(repositoryId).shouldNotBeNull()

            metadata shouldBe legacy.copy(id = metadata.id, current = true)
            service.getContent(repositoryId) shouldBe content
            storage.containsKey(SbomStorageService.legacyContentKey(repositoryId)) shouldBe false
            storage.containsKey(SbomStorageService.legacyMetadataKey(repositoryId)) shouldBe false
            service.listVersions(repositoryId) should containExactly(metadata)
        }
    }
})

/** Create a [Storage] backed by the in-memory test storage provider. */
internal fun createStorage(): Storage {
    val config = ConfigFactory.parseMap(mapOf("test" to mapOf("name" to StorageProviderFactoryForTesting.NAME)))
    return Storage.create("test", ConfigManager.create(config), mockk())
}
