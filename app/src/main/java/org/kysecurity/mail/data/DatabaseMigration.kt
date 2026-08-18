package org.kysecurity.mail.data

import android.content.Context
import net.zetetic.database.sqlcipher.SQLiteDatabase
import java.io.File

private const val TAG = "DatabaseMigration"

/** The 16 bytes SQLite writes at offset 0: `SQLite format 3` followed by a terminating NUL. */
private val SQLITE_MAGIC = "SQLite format 3".toByteArray(Charsets.US_ASCII) + 0

/**
 * Loads SQLCipher's native library, once. Nothing in the AAR does it, so `libsqlcipher.so` ships in
 * `jni/` and is never loaded unless the app loads it. Room opens the database lazily on a background
 * thread, so a missing load would otherwise surface as an `UnsatisfiedLinkError` on the first query.
 */
internal val sqlCipherLoaded: Boolean by lazy {
    runCatching { System.loadLibrary("sqlcipher") }
        .onFailure { android.util.Log.e(TAG, "Could not load libsqlcipher.so", it) }
        .isSuccess
}

/**
 * One-time conversion of a pre-encryption `kypost_mail.db` into an encrypted one.
 *
 * The file is converted rather than discarded because `pending_contact_changes` holds contact edits
 * the user made offline that exist nowhere else.
 *
 * Crash safety rests on one property: the only step that changes which file *is* the database is a
 * single `rename(2)`, which the kernel applies atomically and which replaces the target. There is no
 * instant at which neither file is a usable database. [recoverInterrupted] additionally salvages the
 * temp file left by an earlier build that deleted the original before renaming.
 */
internal object DatabaseMigration {

    /**
     * Converts [databaseName] in place if it is still plaintext. Safe to call on every launch.
     *
     * @return true if the database is now encrypted, or there was nothing to convert. **Callers must
     *   check this**: on false the file on disk is still plaintext, and handing it to SQLCipher
     *   produces an unopenable database rather than a reported failure.
     */
    fun encryptIfNeeded(context: Context, databaseName: String, passphrase: String): Boolean {
        val appContext = context.applicationContext
        val plain = appContext.getDatabasePath(databaseName)
        val temp = File(plain.parentFile, "$databaseName.encrypting")

        if (recoverInterrupted(plain, temp, passphrase)) return true
        if (!plain.exists()) return true
        if (!isPlaintext(plain)) return true

        android.util.Log.i(TAG, "Converting $databaseName to an encrypted database")
        cleanUp(temp)
        if (!sqlCipherLoaded) return false

        return runCatching {
            val userVersion = exportToTemp(plain, temp, passphrase)

            // Verify BEFORE anything is replaced: an export that produced an unopenable file must
            // not be allowed to overwrite the only readable copy of the user's pending edits.
            check(versionUnder(temp, passphrase) == userVersion) { "converted database failed verification" }

            // The plaintext journals belong to the file about to be replaced. `source.close()`
            // above checkpoints and removes them in the normal case; this covers the case where it
            // did not, and it runs before the rename so the encrypted file is never momentarily
            // paired with a foreign WAL. An interruption here still leaves the checkpointed
            // plaintext database in place, which the next launch converts again.
            deleteJournals(plain)

            // The one step that changes which file is the database, and it is atomic.
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
     * Adopts a converted database left stranded by an interrupted run.
     *
     * Builds up to and including 0.3.2 deleted the plaintext file before renaming the converted one
     * into place. A process death in that window left no database and an orphaned `.encrypting`
     * file holding the entire mailbox — which the old `if (!plain.exists()) return true` read as
     * "nothing to convert", so Room created an empty database over the top and the orphan was never
     * looked at again. Devices in that state are still out there; this is how they get their mail
     * back.
     *
     * @return true when [temp] is now the database.
     */
    private fun recoverInterrupted(plain: File, temp: File, passphrase: String): Boolean {
        if (plain.exists() || !temp.exists()) return false
        if (!sqlCipherLoaded) return false

        // Only adopt a file this device can actually read. A temp written under a passphrase that
        // has since been destroyed is unrecoverable, and renaming it into place would replace a
        // recoverable empty state with an unopenable one.
        if (versionUnder(temp, passphrase) == null) {
            android.util.Log.e(TAG, "Orphaned ${temp.name} does not open under the current key; discarding it")
            cleanUp(temp)
            return false
        }
        if (!temp.renameTo(plain)) {
            android.util.Log.e(TAG, "Could not adopt orphaned ${temp.name}")
            return false
        }
        android.util.Log.i(TAG, "Recovered ${plain.name} from an interrupted conversion")
        return true
    }

    /** Copies [plain] into a fresh encrypted [temp], returning the `user_version` it carried. */
    private fun exportToTemp(plain: File, temp: File, passphrase: String): Int {
        // Opened with NO key: this is still a plaintext file. CREATE_IF_NECESSARY is not about the
        // source, which exists — SQLite only creates the ATTACHed file if the attaching connection
        // was opened with permission to create.
        val source = SQLiteDatabase.openDatabase(
            plain.absolutePath,
            null,
            SQLiteDatabase.OPEN_READWRITE or SQLiteDatabase.CREATE_IF_NECESSARY,
        )
        try {
            val userVersion = source.version
            // rawExecSQL, because ATTACH and sqlcipher_export() are not statements the binder-based
            // API models. The key is BOUND, never interpolated — and DatabaseKey stores base64 so
            // the bytes SQLite sees for this text parameter are identical to the ones
            // SupportOpenHelperFactory is handed, making both derive the same key.
            source.rawExecSQL("ATTACH DATABASE ? AS encrypted KEY ?", temp.absolutePath, passphrase)
            source.rawExecSQL("SELECT sqlcipher_export('encrypted')")
            // sqlcipher_export copies schema and rows but NOT user_version, which Room reads to
            // decide whether to run migrations.
            source.rawExecSQL("PRAGMA encrypted.user_version = $userVersion")
            source.rawExecSQL("DETACH DATABASE encrypted")
            return userVersion
        } finally {
            source.close()
        }
    }

    /** The `user_version` of [file] read under [passphrase], or null if it will not open. */
    private fun versionUnder(file: File, passphrase: String): Int? = runCatching {
        val db = SQLiteDatabase.openDatabase(
            file.absolutePath,
            passphrase.toByteArray(Charsets.UTF_8),
            null,
            SQLiteDatabase.OPEN_READONLY,
            null,
        )
        try {
            db.version
        } finally {
            db.close()
        }
    }.getOrNull()

    /**
     * Whether [file] is an unencrypted SQLite database.
     *
     * SQLCipher encrypts the whole file including SQLite's 16-byte header, so the magic's absence
     * identifies an already-converted database.
     *
     * Throws rather than guessing when the header cannot be read at all. Answering "encrypted" there
     * — which `runCatching { ... }.getOrDefault(false)` did, as did a short read whose count was
     * discarded — hands a plaintext file to SQLCipher and produces a database that never opens
     * again.
     */
    private fun isPlaintext(file: File): Boolean {
        val header = ByteArray(SQLITE_MAGIC.size)
        // Looped, not a single read(): `InputStream.read` may return fewer bytes than asked for,
        // and the discarded count left the tail zeroed — so a plaintext database read as encrypted.
        // `readNBytes` would say this in one line but is API 33; this app's minSdk is 31.
        val read = file.inputStream().use { stream ->
            var filled = 0
            while (filled < header.size) {
                val count = stream.read(header, filled, header.size - filled)
                if (count < 0) break
                filled += count
            }
            filled
        }
        // A file too short to hold the header is not a database this code should be reasoning
        // about; treat it as not-plaintext and let the open path report it.
        if (read < header.size) return false
        return header.contentEquals(SQLITE_MAGIC)
    }

    private fun deleteJournals(database: File) {
        File(database.parentFile, "${database.name}-wal").delete()
        File(database.parentFile, "${database.name}-shm").delete()
    }

    private fun cleanUp(temp: File) {
        temp.delete()
        deleteJournals(temp)
    }
}
