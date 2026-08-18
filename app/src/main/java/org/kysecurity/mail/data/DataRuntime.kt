package org.kysecurity.mail.data

import android.content.Context
import androidx.room.Room
import net.zetetic.database.sqlcipher.SupportOpenHelperFactory
import org.kysecurity.mail.SingletonGraph
import org.kysecurity.mail.security.DatabaseKey
import org.kysecurity.mail.security.HostileLocationSettings

class DataGraph(context: Context) : org.kysecurity.mail.ClosableGraph {
    private val appContext = context.applicationContext

    /**
     * In-memory when Hostile Location Protection is on (see the 2026-07-22 security-hardening
     * spec) — every repository/DAO is unchanged either way, since both builders produce the
     * same [AppDatabase] type; only where its rows live differs. Toggling the setting requires
     * an app relaunch ([org.kysecurity.mail.security.AppRestart]) since this decision is only made
     * once, at construction time.
     */
    val database: AppDatabase = if (HostileLocationSettings(appContext).isEnabled()) {
        Room.inMemoryDatabaseBuilder(appContext, AppDatabase::class.java).build()
    } else {
        Room.databaseBuilder(appContext, AppDatabase::class.java, DATABASE_NAME)
            .openHelperFactory(encryptedOpenHelperFactory(appContext))
            .addMigrations(
                AppDatabase.MIGRATION_1_2,
                AppDatabase.MIGRATION_2_3,
                AppDatabase.MIGRATION_3_4,
                AppDatabase.MIGRATION_4_5,
                AppDatabase.MIGRATION_5_6,
                AppDatabase.MIGRATION_6_7,
                AppDatabase.MIGRATION_7_8,
                AppDatabase.MIGRATION_8_9,
                AppDatabase.MIGRATION_9_10,
                AppDatabase.MIGRATION_10_11,
            )
            .build()
    }

    /**
     * SQLCipher, keyed from [DatabaseKey].
     *
     * Encryption at rest is unconditional. Hostile Location Protection remains the stronger mode,
     * where there is no file at all.
     *
     * The conversion of an existing plaintext file runs here, before Room opens it, because Room
     * would otherwise fail to open a database it cannot read. See [DatabaseMigration].
     */
    private fun encryptedOpenHelperFactory(appContext: Context): SupportOpenHelperFactory {
        // Before anything touches SQLCipher. See [sqlCipherLoaded] — the library ships the .so and
        // loads it nowhere, so without this the first Room query throws UnsatisfiedLinkError on a
        // background thread.
        if (!sqlCipherLoaded) throw DatabaseUnavailableException("libsqlcipher.so could not be loaded")
        // The framework's SQLiteOpenHelper creates `databases/` on demand; SQLCipher's does not,
        // and on a fresh install nothing else has created it.
        appContext.getDatabasePath(DATABASE_NAME).parentFile?.mkdirs()
        val passphrase = DatabaseKey.passphrase(appContext)
        // Checked. On false the file on disk is still plaintext, and building the factory anyway
        // hands a plaintext file to SQLCipher — which surfaces as SQLITE_NOTADB on the first query,
        // on a background thread, on every launch, with the cause nowhere near the symptom.
        if (!DatabaseMigration.encryptIfNeeded(appContext, DATABASE_NAME, passphrase)) {
            throw DatabaseUnavailableException("$DATABASE_NAME could not be converted to an encrypted database")
        }
        // A fresh array each time: SupportOpenHelperFactory zeroes the one it is given once the
        // database is open.
        return SupportOpenHelperFactory(passphrase.toByteArray(Charsets.UTF_8))
    }

    /**
     * Closes the database when this graph is dropped.
     *
     * `SingletonGraph.invalidate()` alone only stopped handing this instance out; the database
     * stayed open, and [org.kysecurity.mail.security.AppRestart] does not kill the process. Under
     * Hostile Location Protection that leaked an in-memory database still holding every cached
     * message body.
     *
     * [org.kysecurity.mail.security.SecurityWipe.closeAndDeleteDatabase] still uses `takeGraph()` and
     * closes explicitly, because it also has to quiesce in-flight mail work first and then verify
     * the file is gone — this is the ordinary teardown, not that one.
     */
    override fun closeGraph() {
        if (database.isOpen) database.close()
    }
}

/** The one place the file name is written. [org.kysecurity.mail.security.SecurityWipe] deletes it and
 *  [DatabaseMigration] converts it, and a third spelling of the string is a bug waiting to happen. */
const val DATABASE_NAME = "kypost_mail.db"

/**
 * The local database cannot be opened, and serving the app without it would mean presenting an
 * empty mailbox over data that is still on disk.
 *
 * Named rather than a bare `IllegalStateException` so the failure is greppable in a crash report
 * and distinguishable from a Room schema problem.
 */
class DatabaseUnavailableException(message: String) : IllegalStateException(message)

/** Standalone singleton, kept independent of PushGraph/KyPostApp — mirrors how PushGraph itself
 *  stands alone rather than nesting inside another graph. */
object DataRuntime {
    private val holder = SingletonGraph(::DataGraph)

    fun graph(context: Context): DataGraph = holder.get(context)

    /** See [org.kysecurity.mail.SingletonGraph.invalidate] — used by
     *  [org.kysecurity.mail.security.AppRestart]. */
    fun invalidate() = holder.invalidate()

    /** See [org.kysecurity.mail.SingletonGraph.take] — used by
     *  [org.kysecurity.mail.security.SecurityWipe.closeAndDeleteDatabase], which has to close the
     *  database instance that is actually in use, not a freshly built stand-in. */
    fun takeGraph(): DataGraph? = holder.take()

    /** See [org.kysecurity.mail.SingletonGraph.peek] — used by
     *  [org.kysecurity.mail.push.PushRepository.purgeAccountScopedData], which must not resurrect a
     *  database that [org.kysecurity.mail.security.SecurityWipe] has already closed and deleted. */
    fun peekGraph(): DataGraph? = holder.peek()
}
