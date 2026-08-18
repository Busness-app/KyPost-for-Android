package org.kysecurity.mail.data

import android.content.Context
import net.zetetic.database.sqlcipher.SQLiteDatabase
import java.io.File

private const val TAG = "DatabaseMigration"

/** The 16 bytes SQLite writes at offset 0: `SQLite format 3` followed by a terminating NUL. */
private val SQLITE_MAGIC = "SQLite format 3".toByteArray(Charsets.US_ASCII) + 0

/**
 * Loads SQLCipher's native library, once.
 *
 * **Nothing in the AAR does this.** Verified by disassembling every class in
 * `sqlcipher-android-4.10.0.aar`: there is no `System.loadLibrary` call anywhere in it, so
 * `libsqlcipher.so` ships in `jni/` and is never loaded unless the app loads it. Room opens the
 * database lazily on a background thread, so a missing load surfaces as an `UnsatisfiedLinkError`
 * on the first query rather than at startup — which is why this is a `by lazy` referenced from
 * both entry points ([DatabaseMigration] and `DataGraph`'s factory) instead of a call one of them
 * remembers to make.
 */
internal val sqlCipherLoaded: Boolean by lazy {
    runCatching { System.loadLibrary("sqlcipher") }
        .onFailure { android.util.Log.e(TAG, "Could not load libsqlcipher.so", it) }
        .isSuccess
}

/**
 * One-time conversion of a pre-encryption `kypost_mail.db` into an encrypted one.
 *
 * Existing installs have a plaintext database on disk. Deleting it and re-syncing would be simpler
 * and is wrong: `pending_contact_changes` holds contact edits the user made offline that have not
 * reached the relay yet, and those exist nowhere else. So the file is converted rather than
 * discarded, with SQLCipher's own `sqlcipher_export`.
 *
 * The sequence is crash-safe in the only direction that matters. Everything is written to a temp
 * file; the original is replaced only once the export has completed and the temp file has been
 * reopened and verified with the new key. A process death at any point leaves either the original
 * plaintext database (retried next launch) or the finished encrypted one — never a half-written
 * file that Room would open and treat as corrupt.
 */
internal object DatabaseMigration {

    /**
     * Converts [databaseName] in place if it is still plaintext. Safe to call on every launch, and
     * cheap when there is nothing to do — [isPlaintext] reads sixteen bytes.
     *
     * @return true if the database is now encrypted, or there was nothing to convert.
     */
    fun encryptIfNeeded(context: Context, databaseName: String, passphrase: String): Boolean {
        val appContext = context.applicationContext
        val plain = appContext.getDatabasePath(databaseName)
        if (!plain.exists()) return true
        if (!isPlaintext(plain)) return true

        android.util.Log.i(TAG, "Converting $databaseName to an encrypted database")
        val temp = File(plain.parentFile, "$databaseName.encrypting")
        cleanUp(temp)

        if (!sqlCipherLoaded) return false

        return runCatching {
            // Opened with NO key: this is still a plaintext file, and SQLCipher reads those when no
            // key is set. The ATTACHed database below is the one that gets the key.
            // CREATE_IF_NECESSARY is not about the source, which exists — SQLite will only create
            // the ATTACHed file if the connection doing the attaching was opened with permission
            // to create. Without it the ATTACH fails with errno 2 and the export never runs.
            val source = SQLiteDatabase.openDatabase(
                plain.absolutePath,
                null,
                SQLiteDatabase.OPEN_READWRITE or SQLiteDatabase.CREATE_IF_NECESSARY,
            )
            val userVersion: Int
            try {
                userVersion = source.version
                // rawExecSQL, because ATTACH and the sqlcipher_export() function are not statements
                // the binder-based API models. The key is BOUND, never interpolated. It is also why
                // DatabaseKey stores base64: the bytes SQLite sees for this text parameter are then
                // identical to the ones SupportOpenHelperFactory is handed, so both derive the same
                // key. Verified end to end by DatabaseEncryptionTest.
                source.rawExecSQL(
                    "ATTACH DATABASE ? AS encrypted KEY ?",
                    temp.absolutePath,
                    passphrase,
                )
                source.rawExecSQL("SELECT sqlcipher_export('encrypted')")
                // sqlcipher_export copies schema and rows but NOT user_version, and Room reads
                // user_version to decide whether to run migrations. Without this the fresh file
                // reports version 0, and Room either re-runs every migration against a populated
                // schema or refuses to open it.
                source.rawExecSQL("PRAGMA encrypted.user_version = $userVersion")
                source.rawExecSQL("DETACH DATABASE encrypted")
            } finally {
                source.close()
            }

            // Verify BEFORE replacing anything: an export that produced an unopenable file must not
            // be allowed to overwrite the only readable copy of the user's pending contact edits.
            val verify = SQLiteDatabase.openDatabase(
                temp.absolutePath,
                passphrase.toByteArray(Charsets.UTF_8),
                null,
                SQLiteDatabase.OPEN_READONLY,
                null,
            )
            try {
                check(verify.version == userVersion) { "converted database reports version ${verify.version}" }
            } finally {
                verify.close()
            }

            // The journal files belong to the plaintext database and are meaningless next to the
            // new one; leaving them also leaves plaintext WAL pages on disk.
            check(plain.delete()) { "could not remove the plaintext database" }
            File(plain.parentFile, "$databaseName-wal").delete()
            File(plain.parentFile, "$databaseName-shm").delete()
            check(temp.renameTo(plain)) { "could not move the converted database into place" }
            android.util.Log.i(TAG, "Converted $databaseName to an encrypted database")
            true
        }.getOrElse {
            android.util.Log.e(TAG, "Could not convert $databaseName; leaving it as it was", it)
            cleanUp(temp)
            false
        }
    }

    /**
     * Whether [file] is an unencrypted SQLite database.
     *
     * SQLite writes a 16-byte magic at offset 0. SQLCipher encrypts the whole file including that
     * header, so its absence identifies an already-converted database. Checking the header is the
     * documented way round, and it is cheaper and more reliable than trying to open the file both
     * ways.
     *
     * **The magic ends with a NUL, not a space.** Spelling it "SQLite format 3 " with a trailing
     * space made this return false for every genuine plaintext database — so `encryptIfNeeded`
     * reported "already encrypted", no existing install would ever have been converted, and Room
     * would then have handed a plaintext file to SQLCipher and failed to open it. Caught by
     * `DatabaseEncryptionTest`, which asserts the plaintext control case and not just the happy
     * path.
     */
    private fun isPlaintext(file: File): Boolean = runCatching {
        val header = ByteArray(SQLITE_MAGIC.size)
        file.inputStream().use { it.read(header) }
        header.contentEquals(SQLITE_MAGIC)
    }.getOrDefault(false)

    private fun cleanUp(temp: File) {
        temp.delete()
        File(temp.parentFile, "${temp.name}-wal").delete()
        File(temp.parentFile, "${temp.name}-shm").delete()
    }
}
