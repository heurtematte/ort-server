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

import java.io.File
import java.security.MessageDigest

import kotlin.time.Clock
import kotlin.time.Instant

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

import org.eclipse.apoapsis.ortserver.storage.Key
import org.eclipse.apoapsis.ortserver.storage.Storage
import org.eclipse.apoapsis.ortserver.storage.Storage.Companion.dataString
import org.eclipse.apoapsis.sbom.parser.SbomDocument
import org.eclipse.apoapsis.sbom.parser.SbomFormat
import org.eclipse.apoapsis.sbom.parser.SbomParseException
import org.eclipse.apoapsis.sbom.parser.SbomParser

/** Metadata about the SBOM stored for a repository of type SBOM. */
@Serializable
data class StoredSbom(
    /** The name of the uploaded file. */
    val fileName: String,

    /** The detected format of the SBOM. */
    val format: SbomFormat,

    /** The version of the specification the SBOM adheres to. */
    val specVersion: String,

    /** The size of the SBOM in bytes. */
    val size: Long,

    /** The SHA-256 checksum of the SBOM content. */
    val sha256: String,

    /** The time when the SBOM was uploaded. */
    val uploadedAt: Instant,

    /** The name of the user who uploaded the SBOM. */
    val uploadedBy: String? = null,

    /** The number of components listed in the SBOM. */
    val componentCount: Int,

    /** The coordinates of the components the SBOM describes. */
    val rootComponents: List<String> = emptyList(),

    /** Problems found while parsing the SBOM. */
    val warnings: List<String> = emptyList()
)

/**
 * A service to manage the SBOMs uploaded for repositories of type SBOM. The SBOMs are kept in a [storage], together
 * with their metadata. An SBOM is parsed before it is stored, so that only valid SBOMs in supported formats are
 * accepted. The size of uploaded SBOMs is limited to [maxSize] bytes.
 */
class SbomStorageService(
    private val storage: Storage,
    val maxSize: Long = DEFAULT_MAX_SIZE
) {
    companion object {
        /** The name of the storage type for SBOMs in the configuration. */
        const val STORAGE_TYPE = "sbomStorage"

        /** The default maximum size of an SBOM in bytes. */
        const val DEFAULT_MAX_SIZE = 256L * 1024 * 1024

        private val json = Json { ignoreUnknownKeys = true }

        /** Return the storage key for the content of the SBOM of the repository with the given [repositoryId]. */
        fun contentKey(repositoryId: Long) = Key("repository-$repositoryId/sbom")

        /** Return the storage key for the metadata of the SBOM of the repository with the given [repositoryId]. */
        fun metadataKey(repositoryId: Long) = Key("repository-$repositoryId/sbom-metadata.json")

        /** Return the storage key for the identified source of the repository with the given [repositoryId]. */
        fun sourceKey(repositoryId: Long) = Key("repository-$repositoryId/sbom-source.json")
    }

    /**
     * Parse the SBOM [content] uploaded with the optional [fileName] by the user [uploadedBy] and store it for the
     * repository with the given [repositoryId], replacing an existing SBOM. Return the metadata of the stored SBOM.
     * Throw an [SbomParseException] if the content is not a valid SBOM in a supported format.
     */
    suspend fun store(repositoryId: Long, content: ByteArray, fileName: String?, uploadedBy: String?): StoredSbom {
        require(content.size <= maxSize) { "The SBOM exceeds the maximum size of $maxSize bytes." }

        val document = SbomParser.parse(content)

        val metadata = StoredSbom(
            fileName = fileName?.substringAfterLast('/')?.takeUnless { it.isBlank() }
                ?: "sbom.${document.format.fileExtension}",
            format = document.format,
            specVersion = document.specVersion,
            size = content.size.toLong(),
            sha256 = content.sha256(),
            uploadedAt = Clock.System.now(),
            uploadedBy = uploadedBy,
            componentCount = document.components.size,
            rootComponents = document.rootCoordinates(),
            warnings = document.warnings
        )

        storage.write(contentKey(repositoryId), content, document.format.mediaType)
        storage.write(metadataKey(repositoryId), json.encodeToString(metadata), "application/json")

        return metadata
    }

    /** Return the metadata of the SBOM stored for the repository with the given [repositoryId], or *null*. */
    suspend fun getMetadata(repositoryId: Long): StoredSbom? =
        metadataKey(repositoryId).takeIf { storage.containsKey(it) }?.let { key ->
            storage.read(key).use { entry -> json.decodeFromString<StoredSbom>(entry.dataString) }
        }

    /** Return the content of the SBOM stored for the repository with the given [repositoryId], or *null*. */
    suspend fun getContent(repositoryId: Long): ByteArray? =
        contentKey(repositoryId).takeIf { storage.containsKey(it) }?.let { key ->
            storage.read(key).use { entry -> entry.data.readAllBytes() }
        }

    /**
     * Write the SBOM stored for the repository with the given [repositoryId] to a file in the given [directory] whose
     * name has the extension of the SBOM format, so that the SBOM package manager recognizes it. Return the file and
     * the metadata, or *null* if no SBOM is stored for the repository.
     */
    suspend fun downloadTo(repositoryId: Long, directory: File): Pair<File, StoredSbom>? {
        val metadata = getMetadata(repositoryId) ?: return null
        val file = directory.resolve("sbom.${metadata.format.fileExtension}")

        storage.read(contentKey(repositoryId)).use { entry ->
            file.outputStream().use { entry.data.copyTo(it) }
        }

        return file to metadata
    }

    /** Delete the uploaded SBOM of the repository with the given [repositoryId]. Return *false* if there was none. */
    suspend fun delete(repositoryId: Long): Boolean {
        val deleted = storage.delete(contentKey(repositoryId))
        return storage.delete(metadataKey(repositoryId)) || deleted
    }

    /**
     * Store the [source] identified for the repository with the given [repositoryId], replacing the one identified
     * before.
     */
    suspend fun storeSource(repositoryId: Long, source: StoredSbomSource) {
        storage.write(sourceKey(repositoryId), json.encodeToString(source), "application/json")
    }

    /** Return the source identified for the repository with the given [repositoryId], or *null*. */
    suspend fun getSource(repositoryId: Long): StoredSbomSource? =
        sourceKey(repositoryId).takeIf { storage.containsKey(it) }?.let { key ->
            storage.read(key).use { entry -> json.decodeFromString<StoredSbomSource>(entry.dataString) }
        }

    /**
     * Delete the source identified for the repository with the given [repositoryId]. Return *false* if there was none.
     */
    suspend fun deleteSource(repositoryId: Long): Boolean = storage.delete(sourceKey(repositoryId))

    /** Delete all data of the repository with the given [repositoryId]: its uploaded SBOM and its identified source. */
    suspend fun deleteAll(repositoryId: Long) {
        delete(repositoryId)
        deleteSource(repositoryId)
    }
}

/** Return the coordinates of the root components of this document. */
private fun SbomDocument.rootCoordinates(): List<String> =
    roots.mapNotNull { components[it] }.map { component ->
        listOfNotNull(component.group, component.name, component.version).joinToString(":")
    }

/** Return the hex-encoded SHA-256 checksum of this content. */
@OptIn(ExperimentalStdlibApi::class)
fun ByteArray.sha256(): String = MessageDigest.getInstance("SHA-256").digest(this).toHexString()
