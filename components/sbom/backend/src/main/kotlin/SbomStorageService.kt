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

import org.eclipse.apoapsis.ortserver.dao.repositories.ortrun.OrtRunsTable
import org.eclipse.apoapsis.ortserver.dao.transaction
import org.eclipse.apoapsis.ortserver.dao.utils.toDatabasePrecision
import org.eclipse.apoapsis.ortserver.storage.Key
import org.eclipse.apoapsis.ortserver.storage.Storage
import org.eclipse.apoapsis.ortserver.storage.Storage.Companion.dataString
import org.eclipse.apoapsis.sbom.parser.SbomDocument
import org.eclipse.apoapsis.sbom.parser.SbomFormat
import org.eclipse.apoapsis.sbom.parser.SbomParseException
import org.eclipse.apoapsis.sbom.parser.SbomParser

import org.jetbrains.exposed.v1.core.Op
import org.jetbrains.exposed.v1.core.ResultRow
import org.jetbrains.exposed.v1.core.SortOrder
import org.jetbrains.exposed.v1.core.and
import org.jetbrains.exposed.v1.core.eq
import org.jetbrains.exposed.v1.jdbc.Database
import org.jetbrains.exposed.v1.jdbc.deleteWhere
import org.jetbrains.exposed.v1.jdbc.insert
import org.jetbrains.exposed.v1.jdbc.insertAndGetId
import org.jetbrains.exposed.v1.jdbc.select
import org.jetbrains.exposed.v1.jdbc.selectAll
import org.jetbrains.exposed.v1.jdbc.update

/** Metadata about an SBOM uploaded for a repository of type SBOM. */
@Serializable
data class StoredSbom(
    /** The ID of the upload, which identifies this version of the SBOM in the history of the repository. */
    val id: Long = 0,

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
    val warnings: List<String> = emptyList(),

    /** Whether this is the current SBOM of the repository, which its runs analyze. */
    val current: Boolean = false
)

/** Metadata about the SBOM that a run of a repository of type SBOM analyzed. */
data class StoredRunSbom(
    /** The ID of the run. */
    val ortRunId: Long,

    /** The ID of the repository of the run. */
    val repositoryId: Long,

    /** The name of the SBOM file: the name of the uploaded file, or the name given to the SBOM of the source. */
    val fileName: String,

    /** The format of the SBOM. */
    val format: SbomFormat,

    /** The version of the specification the SBOM adheres to. */
    val specVersion: String,

    /** The size of the SBOM in bytes. */
    val size: Long,

    /** The SHA-256 checksum of the SBOM content. */
    val sha256: String,

    /** The number of components listed in the SBOM. */
    val componentCount: Int,

    /** The ID of the uploaded SBOM that the run analyzed, or *null* if the run obtained the SBOM from its source. */
    val uploadedSbomId: Long?,

    /** The URL of the source from which the run obtained the SBOM, or *null* if the run analyzed an uploaded SBOM. */
    val sourceUrl: String?,

    /** The time when the run obtained the SBOM. */
    val analyzedAt: Instant
)

/**
 * A service to manage the SBOMs of repositories of type SBOM. It keeps the history of the SBOMs uploaded for a
 * repository, one of which is the current SBOM that runs analyze, and the SBOM that each run analyzed, so that it can
 * be traced and downloaded later. The metadata is kept in the [database][db], the contents in a [storage], addressed by
 * their SHA-256 checksum, so that the same content is stored only once per repository. An SBOM is parsed before it is
 * stored, so that only valid SBOMs in supported formats are accepted. The size of uploaded SBOMs is limited to
 * [maxSize] bytes.
 */
@Suppress("TooManyFunctions")
class SbomStorageService(
    private val storage: Storage,
    private val db: Database,
    val maxSize: Long = DEFAULT_MAX_SIZE
) {
    companion object {
        /** The name of the storage type for SBOMs in the configuration. */
        const val STORAGE_TYPE = "sbomStorage"

        /** The default maximum size of an SBOM in bytes. */
        const val DEFAULT_MAX_SIZE = 256L * 1024 * 1024

        private val json = Json { ignoreUnknownKeys = true }

        /** Return the storage key for the content with the given [sha256] checksum of an SBOM of a repository. */
        fun contentKey(repositoryId: Long, sha256: String) = Key("repository-$repositoryId/sbom-content/$sha256")

        /** Return the storage key for the identified source of the repository with the given [repositoryId]. */
        fun sourceKey(repositoryId: Long) = Key("repository-$repositoryId/sbom-source.json")

        /** Return the storage key of the content of an SBOM stored before the history was kept. */
        internal fun legacyContentKey(repositoryId: Long) = Key("repository-$repositoryId/sbom")

        /** Return the storage key of the metadata of an SBOM stored before the history was kept. */
        internal fun legacyMetadataKey(repositoryId: Long) = Key("repository-$repositoryId/sbom-metadata.json")
    }

    /**
     * Parse the SBOM [content] uploaded with the optional [fileName] by the user [uploadedBy] and store it as the
     * current SBOM of the repository with the given [repositoryId]. The SBOM that was current before is kept in the
     * history. Return the metadata of the stored SBOM. Throw an [SbomParseException] if the content is not a valid SBOM
     * in a supported format.
     */
    suspend fun store(repositoryId: Long, content: ByteArray, fileName: String?, uploadedBy: String?): StoredSbom {
        require(content.size <= maxSize) { "The SBOM exceeds the maximum size of $maxSize bytes." }

        val document = SbomParser.parse(content)
        val sha256 = content.sha256()

        importLegacySbom(repositoryId)
        writeContent(repositoryId, sha256, content, document.format)

        val sbom = StoredSbom(
            fileName = fileName?.substringAfterLast('/')?.takeUnless { it.isBlank() }
                ?: "sbom.${document.format.fileExtension}",
            format = document.format,
            specVersion = document.specVersion,
            size = content.size.toLong(),
            sha256 = sha256,
            uploadedAt = Clock.System.now().toDatabasePrecision(),
            uploadedBy = uploadedBy,
            componentCount = document.components.size,
            rootComponents = document.rootCoordinates(),
            warnings = document.warnings,
            current = true
        )

        return db.transaction { insert(repositoryId, sbom) }
    }

    /** Return the metadata of the current SBOM of the repository with the given [repositoryId], or *null*. */
    suspend fun getMetadata(repositoryId: Long): StoredSbom? {
        importLegacySbom(repositoryId)

        return db.transaction { selectSboms(repositoryId) { RepositorySbomsTable.isCurrent eq true }.singleOrNull() }
    }

    /** Return the content of the current SBOM of the repository with the given [repositoryId], or *null*. */
    suspend fun getContent(repositoryId: Long): ByteArray? =
        getMetadata(repositoryId)?.let { readContent(repositoryId, it.sha256) }

    /** Return the history of the SBOMs uploaded for the repository with the given [repositoryId], the latest first. */
    suspend fun listVersions(repositoryId: Long): List<StoredSbom> {
        importLegacySbom(repositoryId)

        return db.transaction { selectSboms(repositoryId) { Op.TRUE } }
    }

    /** Return the uploaded SBOM with the given [id] of the repository with the given [repositoryId], or *null*. */
    suspend fun getVersion(repositoryId: Long, id: Long): StoredSbom? =
        db.transaction { selectSboms(repositoryId) { RepositorySbomsTable.id eq id }.singleOrNull() }

    /**
     * Return the uploaded SBOM with the given [id] of the repository with the given [repositoryId] together with its
     * content, or *null* if there is no such SBOM.
     */
    suspend fun getVersionContent(repositoryId: Long, id: Long): Pair<StoredSbom, ByteArray>? {
        val sbom = getVersion(repositoryId, id) ?: return null
        return readContent(repositoryId, sbom.sha256)?.let { sbom to it }
    }

    /**
     * Make the uploaded SBOM with the given [id] the current SBOM of the repository with the given [repositoryId], so
     * that runs analyze it again. Return its metadata, or *null* if there is no such SBOM.
     */
    suspend fun restore(repositoryId: Long, id: Long): StoredSbom? =
        db.transaction {
            val sbom = selectSboms(repositoryId) { RepositorySbomsTable.id eq id }.singleOrNull()
                ?: return@transaction null

            unsetCurrent(repositoryId)
            RepositorySbomsTable.update({ RepositorySbomsTable.id eq id }) { it[isCurrent] = true }

            sbom.copy(current = true)
        }

    /**
     * Write the current SBOM of the repository with the given [repositoryId] to a file in the given [directory] whose
     * name has the extension of the SBOM format, so that the SBOM package manager recognizes it. Return the file and
     * the metadata, or *null* if the repository has no current SBOM.
     */
    suspend fun downloadTo(repositoryId: Long, directory: File): Pair<File, StoredSbom>? {
        val metadata = getMetadata(repositoryId) ?: return null
        val file = directory.resolve("sbom.${metadata.format.fileExtension}")

        storage.read(contentKey(repositoryId, metadata.sha256)).use { entry ->
            file.outputStream().use { entry.data.copyTo(it) }
        }

        return file to metadata
    }

    /**
     * Stop using the current SBOM of the repository with the given [repositoryId], so that runs analyze the SBOM of
     * its source again. The SBOM stays in the history and can be restored. Return *false* if there was no current
     * SBOM.
     */
    suspend fun delete(repositoryId: Long): Boolean {
        importLegacySbom(repositoryId)

        return db.transaction { unsetCurrent(repositoryId) > 0 }
    }

    /**
     * Record that the run with the given [ortRunId] of the repository with the given [repositoryId] analyzed the SBOM
     * with the given [content], parsed as [document] and stored in a file with the given [fileName]. The SBOM is the
     * [uploaded] SBOM of the repository, or was obtained from the source with the given [sourceUrl]. The content is
     * stored unless the same content is already stored for the repository. Return the recorded metadata.
     */
    @Suppress("LongParameterList")
    suspend fun storeRunSbom(
        ortRunId: Long,
        repositoryId: Long,
        content: ByteArray,
        document: SbomDocument,
        fileName: String,
        uploaded: StoredSbom?,
        sourceUrl: String?
    ): StoredRunSbom {
        val sha256 = content.sha256()
        writeContent(repositoryId, sha256, content, document.format)

        val runSbom = StoredRunSbom(
            ortRunId = ortRunId,
            repositoryId = repositoryId,
            fileName = fileName,
            format = document.format,
            specVersion = document.specVersion,
            size = content.size.toLong(),
            sha256 = sha256,
            componentCount = document.components.size,
            uploadedSbomId = uploaded?.id,
            sourceUrl = sourceUrl.takeIf { uploaded == null },
            analyzedAt = Clock.System.now().toDatabasePrecision()
        )

        db.transaction {
            // A retried analyzer job of the run replaces the SBOM recorded before.
            OrtRunSbomsTable.deleteWhere { OrtRunSbomsTable.ortRunId eq ortRunId }
            OrtRunSbomsTable.insert {
                it[this.ortRunId] = ortRunId
                it[repositorySbomId] = runSbom.uploadedSbomId
                it[this.sha256] = sha256
                it[this.fileName] = fileName
                it[format] = runSbom.format.name
                it[specVersion] = runSbom.specVersion
                it[size] = runSbom.size
                it[componentCount] = runSbom.componentCount
                it[this.sourceUrl] = runSbom.sourceUrl
                it[analyzedAt] = runSbom.analyzedAt
            }
        }

        return runSbom
    }

    /** Return the metadata of the SBOM that the run with the given [ortRunId] analyzed, or *null*. */
    suspend fun getRunSbom(ortRunId: Long): StoredRunSbom? =
        db.transaction {
            OrtRunSbomsTable.innerJoin(OrtRunsTable)
                .select(OrtRunSbomsTable.columns + OrtRunsTable.repositoryId)
                .where { OrtRunSbomsTable.ortRunId eq ortRunId }
                .singleOrNull()
                ?.toRunSbom()
        }

    /**
     * Return the metadata of the SBOM that the run with the given [ortRunId] analyzed together with its content, or
     * *null* if no SBOM was recorded for the run.
     */
    suspend fun getRunSbomContent(ortRunId: Long): Pair<StoredRunSbom, ByteArray>? {
        val runSbom = getRunSbom(ortRunId) ?: return null
        return readContent(runSbom.repositoryId, runSbom.sha256)?.let { runSbom to it }
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

    /**
     * Return the SHA-256 checksums of the SBOM contents stored for the repository with the given [repositoryId]: the
     * uploaded ones and the ones that its runs analyzed. As this information is deleted together with the repository,
     * it must be obtained before the repository is deleted, and passed to [deleteAll] afterward.
     */
    suspend fun listContents(repositoryId: Long): Set<String> =
        db.transaction {
            val uploaded = RepositorySbomsTable.select(RepositorySbomsTable.sha256)
                .where { RepositorySbomsTable.repositoryId eq repositoryId }
                .mapTo(mutableSetOf()) { it[RepositorySbomsTable.sha256] }

            OrtRunSbomsTable.innerJoin(OrtRunsTable)
                .select(OrtRunSbomsTable.sha256)
                .where { OrtRunsTable.repositoryId eq repositoryId }
                .mapTo(uploaded) { it[OrtRunSbomsTable.sha256] }
        }

    /**
     * Delete the SBOM data of the deleted repository with the given [repositoryId] from the storage: the SBOM
     * [contents] obtained with [listContents] before the repository was deleted, and its identified source.
     */
    suspend fun deleteAll(repositoryId: Long, contents: Set<String>) {
        contents.forEach { storage.delete(contentKey(repositoryId, it)) }
        storage.delete(legacyContentKey(repositoryId))
        storage.delete(legacyMetadataKey(repositoryId))
        deleteSource(repositoryId)
    }

    /**
     * Import the SBOM that an earlier version of this service stored for the repository with the given [repositoryId]
     * without history into the history. It becomes the current SBOM unless another one is current already.
     */
    private suspend fun importLegacySbom(repositoryId: Long) {
        val metadataKey = legacyMetadataKey(repositoryId)
        if (!storage.containsKey(metadataKey)) return

        val contentKey = legacyContentKey(repositoryId)
        if (storage.containsKey(contentKey)) {
            val metadata = storage.read(metadataKey).use { json.decodeFromString<StoredSbom>(it.dataString) }
            val content = storage.read(contentKey).use { it.data.readAllBytes() }
            writeContent(repositoryId, metadata.sha256, content, metadata.format)

            db.transaction {
                val hasCurrent = selectSboms(repositoryId) { RepositorySbomsTable.isCurrent eq true }.isNotEmpty()
                val imported = metadata.copy(
                    uploadedAt = metadata.uploadedAt.toDatabasePrecision(),
                    current = !hasCurrent
                )

                insert(repositoryId, imported)
            }

            storage.delete(contentKey)
        }

        storage.delete(metadataKey)
    }

    /** Write the given [content] with the given [sha256] checksum for the repository, unless it is stored already. */
    private suspend fun writeContent(repositoryId: Long, sha256: String, content: ByteArray, format: SbomFormat) {
        val key = contentKey(repositoryId, sha256)
        if (!storage.containsKey(key)) storage.write(key, content, format.mediaType)
    }

    /** Return the content with the given [sha256] checksum stored for the repository, or *null*. */
    private suspend fun readContent(repositoryId: Long, sha256: String): ByteArray? =
        contentKey(repositoryId, sha256).takeIf { storage.containsKey(it) }?.let { key ->
            storage.read(key).use { entry -> entry.data.readAllBytes() }
        }
}

/**
 * Insert the given [sbom] into the history of the repository with the given [repositoryId]. If it is current, the SBOM
 * that was current before is no longer. Return the SBOM with its ID.
 */
private fun insert(repositoryId: Long, sbom: StoredSbom): StoredSbom {
    if (sbom.current) unsetCurrent(repositoryId)

    val id = RepositorySbomsTable.insertAndGetId {
        it[this.repositoryId] = repositoryId
        it[sha256] = sbom.sha256
        it[fileName] = sbom.fileName
        it[format] = sbom.format.name
        it[specVersion] = sbom.specVersion
        it[size] = sbom.size
        it[componentCount] = sbom.componentCount
        it[rootComponents] = sbom.rootComponents
        it[warnings] = sbom.warnings
        it[uploadedAt] = sbom.uploadedAt
        it[uploadedBy] = sbom.uploadedBy
        it[isCurrent] = sbom.current
    }

    return sbom.copy(id = id.value)
}

/** Mark the current SBOM of the repository with the given [repositoryId] as no longer current. */
private fun unsetCurrent(repositoryId: Long): Int =
    RepositorySbomsTable.update({
        (RepositorySbomsTable.repositoryId eq repositoryId) and (RepositorySbomsTable.isCurrent eq true)
    }) { it[isCurrent] = false }

/** Return the SBOMs of the repository with the given [repositoryId] that match the [condition], the latest first. */
private fun selectSboms(repositoryId: Long, condition: () -> Op<Boolean>): List<StoredSbom> =
    RepositorySbomsTable.selectAll()
        .where { (RepositorySbomsTable.repositoryId eq repositoryId) and condition() }
        .orderBy(RepositorySbomsTable.id, SortOrder.DESC)
        .map { it.toStoredSbom() }

private fun ResultRow.toStoredSbom() =
    StoredSbom(
        id = this[RepositorySbomsTable.id].value,
        fileName = this[RepositorySbomsTable.fileName],
        format = SbomFormat.valueOf(this[RepositorySbomsTable.format]),
        specVersion = this[RepositorySbomsTable.specVersion],
        size = this[RepositorySbomsTable.size],
        sha256 = this[RepositorySbomsTable.sha256],
        uploadedAt = this[RepositorySbomsTable.uploadedAt],
        uploadedBy = this[RepositorySbomsTable.uploadedBy],
        componentCount = this[RepositorySbomsTable.componentCount],
        rootComponents = this[RepositorySbomsTable.rootComponents],
        warnings = this[RepositorySbomsTable.warnings],
        current = this[RepositorySbomsTable.isCurrent]
    )

private fun ResultRow.toRunSbom() =
    StoredRunSbom(
        ortRunId = this[OrtRunSbomsTable.ortRunId].value,
        repositoryId = this[OrtRunsTable.repositoryId].value,
        fileName = this[OrtRunSbomsTable.fileName],
        format = SbomFormat.valueOf(this[OrtRunSbomsTable.format]),
        specVersion = this[OrtRunSbomsTable.specVersion],
        size = this[OrtRunSbomsTable.size],
        sha256 = this[OrtRunSbomsTable.sha256],
        componentCount = this[OrtRunSbomsTable.componentCount],
        uploadedSbomId = this[OrtRunSbomsTable.repositorySbomId]?.value,
        sourceUrl = this[OrtRunSbomsTable.sourceUrl],
        analyzedAt = this[OrtRunSbomsTable.analyzedAt]
    )

/** Return the coordinates of the root components of this document. */
private fun SbomDocument.rootCoordinates(): List<String> =
    roots.mapNotNull { components[it] }.map { component ->
        listOfNotNull(component.group, component.name, component.version).joinToString(":")
    }

/** Return the hex-encoded SHA-256 checksum of this content. */
@OptIn(ExperimentalStdlibApi::class)
fun ByteArray.sha256(): String = MessageDigest.getInstance("SHA-256").digest(this).toHexString()
