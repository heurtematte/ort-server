/*
 * Copyright (C) 2022 The ORT Server Authors (See <https://github.com/eclipse-apoapsis/ort-server/blob/main/NOTICE>)
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

@file:Suppress("TooManyFunctions")

package org.eclipse.apoapsis.ortserver.dao

import com.zaxxer.hikari.HikariConfig
import com.zaxxer.hikari.HikariDataSource

import java.sql.SQLException

import javax.sql.DataSource

import kotlin.coroutines.cancellation.CancellationException
import kotlin.random.Random
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext

import org.eclipse.apoapsis.ortserver.shared.coroutines.Virtual

import org.flywaydb.core.Flyway
import org.flywaydb.core.api.configuration.FluentConfiguration

import org.jetbrains.exposed.v1.core.DatabaseConfig
import org.jetbrains.exposed.v1.core.Op
import org.jetbrains.exposed.v1.core.dao.id.EntityID
import org.jetbrains.exposed.v1.dao.LongEntity
import org.jetbrains.exposed.v1.dao.LongEntityClass
import org.jetbrains.exposed.v1.dao.exceptions.EntityNotFoundException
import org.jetbrains.exposed.v1.exceptions.ExposedSQLException
import org.jetbrains.exposed.v1.jdbc.Database
import org.jetbrains.exposed.v1.jdbc.JdbcTransaction
import org.jetbrains.exposed.v1.jdbc.SizedCollection
import org.jetbrains.exposed.v1.jdbc.SizedIterable
import org.jetbrains.exposed.v1.jdbc.transactions.suspendTransaction
import org.jetbrains.exposed.v1.jdbc.transactions.transactionManager

import org.koin.core.module.Module
import org.koin.core.module.dsl.singleOf
import org.koin.dsl.module

import org.postgresql.util.PSQLException

import org.slf4j.LoggerFactory

private val logger = LoggerFactory.getLogger(DataSource::class.java)

/** Connect the database. */
fun DataSource.connect() = Database.connect(
    datasource = this,
    databaseConfig = getDatabaseConfig()
)

private fun getDatabaseConfig(): DatabaseConfig =
    DatabaseConfig {
        sqlLogger = SqlQueryTraceLogger

        // This only affects transactions started with `suspendTransaction`.
        dispatcher = Dispatchers.Virtual
    }

/** Run the database migrations. */
fun DataSource.migrate() {
    Flyway(getFlywayConfig(this)).migrate()
}

private fun getFlywayConfig(dataSource: DataSource) = FluentConfiguration()
    .dataSource(dataSource)
    .cleanDisabled(false)
    .createSchemas(true)
    .baselineOnMigrate(true)

fun createDataSource(config: DataSourceConfig): DataSource {
    val dataSourceConfig = HikariConfig().apply {
        driverClassName = "org.postgresql.Driver"
        jdbcUrl = "jdbc:postgresql://${config.host}:${config.port}/${config.name}"
        schema = config.schema
        username = config.username
        password = config.password

        connectionTimeout = config.connectionTimeout
        idleTimeout = config.idleTimeout
        keepaliveTime = config.keepaliveTime
        maxLifetime = config.maxLifetime
        maximumPoolSize = config.maximumPoolSize
        minimumIdle = config.minimumIdle

        addDataSourceProperty("ApplicationName", "ort_server")
        addDataSourceProperty("sslmode", config.sslMode)
        config.sslCert?.let { addDataSourceProperty("sslcert", it) }
        config.sslKey?.let { addDataSourceProperty("sslkey", it) }
        config.sslRootCert?.let { addDataSourceProperty("sslrootcert", it) }

        config.initSqlStatement?.let {
            logger.info("Setting connection initialization statement to '{}'.", it)
            connectionInitSql = it
        }
    }

    dataSourceConfig.validate()

    return runCatching {
        HikariDataSource(dataSourceConfig)
    }.onFailure {
        logger.error("Failed to create data source.", it)
    }.getOrThrow()
}

/**
 * Return a Koin [Module] that sets up a database connection based on the current application configuration.
 * Depending on the [startEager] parameter, the database connection is established either eagerly or lazily.
 */
fun databaseModule(startEager: Boolean = true): Module = module {
    singleOf(DataSourceConfig::create)

    single(createdAtStart = startEager) { createDataSource(get()).connect() }
}

/**
 * Execute the [block] in a database [suspendTransaction], configured with the provided [transactionIsolation] and
 * [readOnly], and return the result. Throws an exception in case of a failure.
 *
 * Calls to [Database.transaction] and [Database.transactionCatching] from [block] are running in the same transaction,
 * as long as the coroutine context is not dropped. This is because Exposed's `suspendTransaction` stores the current
 * transaction in the coroutine context. Otherwise, nested calls will start a new transaction.
 */
suspend fun <T> Database.transaction(
    transactionIsolation: Int = transactionManager.defaultIsolationLevel,
    readOnly: Boolean = transactionManager.defaultReadOnly,
    block: suspend JdbcTransaction.() -> T
): T =
    transactionCatching(transactionIsolation, readOnly, block).getOrThrow()

/**
 * Execute the [block] in a database [suspendTransaction], configured with the provided [transactionIsolation] and
 * [readOnly], and return a wrapped [Result] object. [CancellationException] and [Error] are propagated, all other
 * exceptions are wrapped in a [Result] object and delegated to the caller.
 *
 * Calls to [Database.transaction] and [Database.transactionCatching] from [block] are running in the same transaction,
 * as long as the coroutine context is not dropped. This is because Exposed's `suspendTransaction` stores the current
 * transaction in the coroutine context. Otherwise, nested calls will start a new transaction.
 */
@Suppress("ForbiddenMethodCall", "TooGenericExceptionCaught")
suspend fun <T> Database.transactionCatching(
    transactionIsolation: Int = transactionManager.defaultIsolationLevel,
    readOnly: Boolean = transactionManager.defaultReadOnly,
    block: suspend JdbcTransaction.() -> T
): Result<T> =
    try {
        val result = withContext(Dispatchers.Virtual) {
            suspendTransaction(this@transactionCatching, transactionIsolation, readOnly) { block() }
        }
        Result.success(result)
    } catch (e: CancellationException) {
        throw e // Preserve structured concurrency.
    } catch (e: Error) {
        throw e // Don't swallow fatal JVM errors.
    } catch (e: Throwable) {
        Result.failure<T>(e).mapExceptions()
    }

/**
 * Return the encapsulated value in case of [success][Result.isSuccess]. In case of [failure][Result.isFailure] return
 * `null` if an [EntityNotFoundException] was thrown, Otherwise re-throw the exception.
 */
fun <T> Result<T>.getEntityOrNull() = getOrElse {
    when (it) {
        is EntityNotFoundException -> null
        else -> throw it
    }
}

/** The default number of attempts of [Database.transactionWithRetry]. */
private const val DEFAULT_TRANSACTION_ATTEMPTS = 5

/** The default maximum delay before the first retry of [Database.transactionWithRetry]. */
private val DEFAULT_TRANSACTION_RETRY_DELAY = 2.seconds

/** The maximum number of causes of an exception that are checked, to protect against cycles. */
private const val MAX_EXCEPTION_CAUSES = 20

/** The SQL states of failures caused by a concurrent transaction, after which a transaction can succeed if retried. */
private val CONCURRENT_TRANSACTION_SQL_STATES = setOf(
    PostgresErrorCodes.DEADLOCK_DETECTED.value,
    PostgresErrorCodes.SERIALIZATION_FAILURE.value,
    PostgresErrorCodes.UNIQUE_CONSTRAINT_VIOLATION.value
)

/**
 * Execute the [block] in a database transaction like [Database.transaction], and retry it up to [maxAttempts] times in
 * total if it fails because of a concurrent transaction: a deadlock, a serialization failure, or a unique constraint
 * violation because a concurrent transaction inserted the same row first. This happens when concurrent transactions
 * get or create the same shared entities, such as identifiers, VCS information, or remote artifacts, for instance when
 * the results of many runs are stored at the same time. Exposed already repeats a failed transaction, but immediately,
 * while the concurrent transactions are still running, so that it fails again. Therefore, wait for a random delay of up
 * to [maxDelay] times the number of failed attempts before each retry, so that the transactions do not collide again.
 *
 * The transaction is rolled back after such a failure, so retrying it is safe as long as the [block] only changes the
 * database. As a nested call runs in the transaction of its caller, which the failure aborts, this function must be
 * called outside of other transactions.
 */
suspend fun <T> Database.transactionWithRetry(
    maxAttempts: Int = DEFAULT_TRANSACTION_ATTEMPTS,
    maxDelay: Duration = DEFAULT_TRANSACTION_RETRY_DELAY,
    block: suspend JdbcTransaction.() -> T
): T {
    require(maxAttempts > 0) { "The number of attempts must be positive, but is $maxAttempts." }

    var attempt = 1

    while (true) {
        val result = transactionCatching(block = block)
        val failure = result.exceptionOrNull()

        if (failure == null || attempt >= maxAttempts || !failure.isCausedByConcurrentTransaction()) {
            return result.getOrThrow()
        }

        logger.warn(
            "Transaction failed because of a concurrent transaction, starting attempt {} of {}: {}",
            attempt + 1,
            maxAttempts,
            failure.message?.lineSequence()?.firstOrNull()
        )

        delay(Random.nextLong(maxDelay.inWholeMilliseconds * attempt + 1).milliseconds)
        attempt++
    }
}

/** Return whether this exception or one of its causes is a failure caused by a concurrent transaction. */
private fun Throwable.isCausedByConcurrentTransaction(): Boolean =
    generateSequence(this) { it.cause }.take(MAX_EXCEPTION_CAUSES).filterIsInstance<SQLException>().any { exception ->
        // Failed batches report the failure of each statement as the next exception.
        generateSequence(exception) { it.nextException }.take(MAX_EXCEPTION_CAUSES).any {
            it.sqlState in CONCURRENT_TRANSACTION_SQL_STATES
        }
    }

/** Map the generic database exceptions to more specific exceptions. */
internal fun <T> Result<T>.mapExceptions(): Result<T> =
    recoverCatching {
        if (it is ExposedSQLException) {
            when (it.sqlState) {
                PostgresErrorCodes.INVALID_REGULAR_EXPRESSION.value -> {
                    throw QueryParametersException(
                        (it.cause as? PSQLException)?.serverErrorMessage?.message ?: "Invalid regular expression.",
                        it
                    )
                }

                PostgresErrorCodes.UNIQUE_CONSTRAINT_VIOLATION.value -> {
                    throw UniqueConstraintException("Unique constraint violation: ${it.message}.", it)
                }
            }
        }

        throw it
    }

/**
 * Find a single entity of this entity class based on the passed in [condition]. Throw an [EntityNotFoundException] if
 * no entity is matched by the selection criteria. This extension function is useful to implement certain get
 * operations in repositories operating on multiple properties that uniquely identify an entity. Note: It should be
 * ensured via constraints in the database that the query will not return multiple entities.
 */
fun <T : LongEntity> LongEntityClass<T>.findSingle(condition: Op<Boolean>): T =
    find(condition).singleOrNull() ?: throw EntityNotFoundException(EntityID(0L, table), this)

/**
 * Map the given [modelObjects] collection to a [SizedIterable] of data objects using the given [mapper] function.
 * This function should be used to populate intermediate tables used for the implementation of m:n relations. It
 * makes sure that the result does not contain any duplicates.
 */
fun <M, D> mapAndDeduplicate(modelObjects: Collection<M>?, mapper: (M) -> D): SizedIterable<D> =
    SizedCollection(mapToSet(modelObjects, mapper).orEmpty())

/** Map the given [modelObjects] collection to a [Set] using the given [mapper] function. */
private fun <D, M> mapToSet(modelObjects: Iterable<M>?, mapper: (M) -> D): Set<D>? =
    modelObjects?.mapTo(mutableSetOf(), mapper)
