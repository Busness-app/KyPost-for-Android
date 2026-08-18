package org.kysecurity.mail.data

import android.content.Context
import androidx.room.Room
import androidx.sqlite.db.framework.FrameworkSQLiteOpenHelperFactory
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import net.zetetic.database.sqlcipher.SupportOpenHelperFactory
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File

/**
 * `kypost_mail.db` holds every cached message body, the whole contact book and contacts' PGP keys,
 * and it was a plain SQLite file — readable by anyone who could get the file off the device,
 * whatever the app lock said. These tests are the evidence that it no longer is.
 *
 * Instrumented rather than JVM because SQLCipher is a native library: a unit test would prove
 * nothing about what actually lands on disk.
 */
@RunWith(AndroidJUnit4::class)
class DatabaseEncryptionTest {

    private val context: Context = InstrumentationRegistry.getInstrumentation().targetContext
    private val dbName = "encryption_test.db"
    private val passphrase = "dGVzdC1wYXNzcGhyYXNlLWZvci1lbmNyeXB0aW9uLXRlc3Q="

    private fun dbFile(): File = context.getDatabasePath(dbName)

    private fun deleteAll() {
        context.deleteDatabase(dbName)
        File(dbFile().parentFile, "$dbName.encrypting").delete()
    }

    @Before
    fun setUp() {
        // The tests below open Room directly rather than through DataGraph, so they have to do
        // what DataGraph's factory does: load the native library, and make sure `databases/`
        // exists. Both were real findings — the AAR loads nothing itself, and SQLCipher's helper
        // does not create the directory the framework helper creates on demand.
        assertTrue("libsqlcipher.so must load", sqlCipherLoaded)
        deleteAll()
        val dir = dbFile().parentFile!!
        val made = dir.mkdirs()
        assertTrue(
            "dir=${dir.absolutePath} made=$made exists=${dir.exists()} " +
                "dataDir=${context.dataDir} dataDirExists=${context.dataDir.exists()} " +
                "filesDir=${context.filesDir} filesDirExists=${context.filesDir.exists()} " +
                "pkg=${context.packageName}",
            dir.isDirectory,
        )
    }
    @After fun tearDown() = deleteAll()

    /** SQLite's magic header. Present in a plaintext file, absent once SQLCipher owns it. */
    private fun startsWithSqliteHeader(file: File): Boolean {
        // Spelled out byte by byte rather than reused from production, so the test cannot agree
        // with a bug in the code it is checking — which is exactly what happened: both said
        // "SQLite format 3 " with a trailing space, where the real magic ends with a NUL.
        val expected = byteArrayOf(
            0x53, 0x51, 0x4c, 0x69, 0x74, 0x65, 0x20, 0x66,
            0x6f, 0x72, 0x6d, 0x61, 0x74, 0x20, 0x33, 0x00,
        )
        val header = ByteArray(expected.size)
        file.inputStream().use { it.read(header) }
        return header.contentEquals(expected)
    }

    private fun openEncrypted(): AppDatabase =
        Room.databaseBuilder(context, AppDatabase::class.java, dbName)
            .openHelperFactory(SupportOpenHelperFactory(passphrase.toByteArray(Charsets.UTF_8)))
            .build()

    private fun openPlaintext(): AppDatabase =
        Room.databaseBuilder(context, AppDatabase::class.java, dbName)
            .openHelperFactory(FrameworkSQLiteOpenHelperFactory())
            .build()

    /** RoomDatabase is not Closeable, so `use` does not apply to it. */
    private fun <T> AppDatabase.useDb(block: (AppDatabase) -> T): T =
        try {
            block(this)
        } finally {
            close()
        }

    private fun sampleEmail(id: String, body: String) = EmailEntity(
        messageId = id,
        folder = "INBOX",
        sender = "ada@example.com",
        subject = "subject-$id",
        body = body,
        sourceMode = "relay",
    )

    /**
     * The claim in one test: a message body written through Room does not appear as plaintext in
     * the file on disk, and the file is not a readable SQLite database at all.
     */
    @Test
    fun messageBodiesAreNotReadableInTheDatabaseFile() {
        val secret = "the-quick-brown-fox-jumps-over-the-lazy-dog-SECRETMARKER"
        openEncrypted().useDb { db ->
            db.emailDao().upsertAll(listOf(sampleEmail("e1", secret)))
        }

        val bytes = dbFile().readBytes()
        assertFalse("the SQLite header must be encrypted away", startsWithSqliteHeader(dbFile()))
        assertFalse(
            "the message body must not appear in the file",
            String(bytes, Charsets.ISO_8859_1).contains("SECRETMARKER"),
        )
    }

    /** The control: without the openHelperFactory this test would pass vacuously, so prove that a
     *  plaintext database really does leak the body. If this ever fails, the assertion above is
     *  not testing what it claims. */
    @Test
    fun aPlaintextDatabaseDoesLeakTheBody() {
        val secret = "the-quick-brown-fox-jumps-over-the-lazy-dog-SECRETMARKER"
        openPlaintext().useDb { db ->
            db.emailDao().upsertAll(listOf(sampleEmail("e1", secret)))
        }

        val bytes = dbFile().readBytes()
        assertTrue("control: a plaintext file keeps the SQLite header", startsWithSqliteHeader(dbFile()))
        assertTrue(
            "control: a plaintext file leaks the body",
            String(bytes, Charsets.ISO_8859_1).contains("SECRETMARKER"),
        )
    }

    @Test
    fun anEncryptedDatabaseRoundTripsThroughRoom() {
        openEncrypted().useDb { db ->
            db.emailDao().upsertAll(listOf(sampleEmail("e1", "hello")))
        }
        openEncrypted().useDb { db ->
            assertEquals("hello", db.emailDao().getById("e1")?.body)
        }
    }

    /**
     * The upgrade path for every existing install: an unencrypted database is converted in place,
     * every row survives, and Room's `user_version` is carried across so it does not try to re-run
     * migrations against an already-migrated schema.
     */
    @Test
    fun anExistingPlaintextDatabaseIsConvertedWithoutLosingRows() {
        openPlaintext().useDb { db ->
            db.emailDao().upsertAll(
                listOf(sampleEmail("e1", "first body"), sampleEmail("e2", "second body")),
            )
        }
        assertTrue("precondition: the file starts plaintext", startsWithSqliteHeader(dbFile()))
        val versionBefore = openPlaintext().useDb { it.openHelper.readableDatabase.version }

        val converted = DatabaseMigration.encryptIfNeeded(context, dbName, passphrase)

        assertTrue("conversion must report success", converted)
        assertFalse("the file must no longer be plaintext", startsWithSqliteHeader(dbFile()))
        openEncrypted().useDb { db ->
            assertEquals(versionBefore, db.openHelper.readableDatabase.version)
            assertEquals("first body", db.emailDao().getById("e1")?.body)
            assertEquals("second body", db.emailDao().getById("e2")?.body)
        }
    }

    /** Idempotent: running it again on an already-encrypted file must be a no-op, not a corruption. */
    @Test
    fun convertingAnAlreadyEncryptedDatabaseIsANoOp() {
        openEncrypted().useDb { db -> db.emailDao().upsertAll(listOf(sampleEmail("e1", "body"))) }

        assertTrue(DatabaseMigration.encryptIfNeeded(context, dbName, passphrase))

        openEncrypted().useDb { db -> assertEquals("body", db.emailDao().getById("e1")?.body) }
    }

    @Test
    fun convertingWhenThereIsNoDatabaseIsANoOp() {
        assertTrue(DatabaseMigration.encryptIfNeeded(context, dbName, passphrase))
        assertFalse(dbFile().exists())
    }
}
