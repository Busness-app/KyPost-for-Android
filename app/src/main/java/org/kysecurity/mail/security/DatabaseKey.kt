package org.kysecurity.mail.security

import android.content.Context
import android.util.Base64
import org.kysecurity.mail.data.DATABASE_NAME
import java.security.SecureRandom
import java.util.Arrays

private const val TAG = "DatabaseKey"
private const val PREFS_FILE = "db_key_secure"
private const val KEY_PASSPHRASE = "db_passphrase"
private const val PASSPHRASE_BYTES = 32

/**
 * The SQLCipher passphrase for `kypost_mail.db`, held in a Keystore-backed store.
 *
 * `kypost_mail.db` was a plain SQLite file. It holds every cached message body, the whole contact
 * book, and contacts' PGP keys — and [AppLockStore]'s own KDoc admitted the app lock "does nothing
 * against someone who simply reads `kypost_mail.db` offline". For a client whose stated purpose is
 * confidential mail, "your mail is in the clear on disk unless you find and enable Hostile Location
 * Protection" was the wrong default.
 *
 * The passphrase is 32 random bytes, not derived from the user's PIN. That is deliberate:
 *
 * - The database has to open in processes where no PIN has been entered — an FCM delivery, a
 *   WorkManager sync — so a PIN-derived key would either break those or force the PIN to be cached
 *   somewhere worse.
 * - The threat this closes is **offline** reading of the file. A random key inside
 *   `EncryptedSharedPreferences` (and so, transitively, inside the AndroidKeyStore) cannot be
 *   extracted from the file system alone, which is exactly the attacker this is for.
 * - It is explicitly **not** a defence against a live, rooted, running device. Hostile Location
 *   Protection remains the answer to that, and it is stronger: under it there is no file at all.
 */
internal object DatabaseKey {

    /**
     * The passphrase, minted on first use, as printable ASCII.
     *
     * **Printable on purpose.** SQLCipher takes a passphrase either as bytes (via
     * `SupportOpenHelperFactory`) or as SQL text (in the `ATTACH … KEY ?` that
     * [org.kysecurity.mail.data.DatabaseMigration] needs), and it derives the same key from both only
     * if both see the same byte sequence. Storing raw random bytes made that a guess about how
     * `String` ↔ `ByteArray` round-trips through SQLite's text encoding; base64 removes the
     * question — `text.toByteArray(UTF_8)` and the SQL literal are byte-identical by construction.
     *
     * 32 random bytes of entropy, base64 to 44 characters.
     */
    fun passphrase(context: Context): String {
        val appContext = context.applicationContext
        val prefs = openEncryptedPrefs(appContext, PREFS_FILE) {
            android.util.Log.e(TAG, "Database key store keyset is undecryptable", it)
        }
        prefs.getString(KEY_PASSPHRASE, null)?.let { return it }
        discardUnopenableDatabase(appContext)

        val fresh = ByteArray(PASSPHRASE_BYTES).also { SecureRandom().nextBytes(it) }
        val encoded = Base64.encodeToString(fresh, Base64.NO_WRAP)
        Arrays.fill(fresh, 0)
        // commit(), like every other security-relevant write in this package: a process death
        // before an async flush would leave a database encrypted under a key nothing remembers.
        prefs.edit().putString(KEY_PASSPHRASE, encoded).commit()
        return encoded
    }

    /**
     * Deletes [DATABASE_NAME] when a passphrase has to be minted while a database file already
     * exists.
     *
     * No stored passphrase plus an existing file means one thing: [openEncryptedPrefs] reset an
     * undecryptable keyset out from under us, and the file on disk is encrypted under a key that no
     * longer exists anywhere. The rows are already unrecoverable at that point — the only remaining
     * question is whether the app can still start, and without this it cannot: Room hands the file
     * to SQLCipher, which fails SQLITE_NOTADB on the first query, on a background thread, on every
     * launch, forever. [org.kysecurity.mail.data.DataGraph] guards that symptom for a file that is
     * still *plaintext* and had no guard for this, the case where the key is gone.
     *
     * Records the loss so [org.kysecurity.mail.security.LockedActivity] tells the user their cached
     * mail is gone, rather than presenting an empty mailbox.
     */
    private fun discardUnopenableDatabase(appContext: Context) {
        if (!appContext.getDatabasePath(DATABASE_NAME).exists()) return
        android.util.Log.e(TAG, "The database key was reset; $DATABASE_NAME can never be opened again")
        recordCredentialReset(appContext, DATABASE_NAME)
        appContext.deleteDatabase(DATABASE_NAME)
    }

    /** Part of [SecurityWipe]: an encrypted database is only as gone as its key. Returns the step
     *  names it could not remove, matching the other teardown helpers. */
    fun destroy(context: Context): List<String> {
        val appContext = context.applicationContext
        return if (appContext.deleteSharedPreferences(PREFS_FILE)) {
            emptyList()
        } else {
            val file = java.io.File(java.io.File(appContext.dataDir, "shared_prefs"), "$PREFS_FILE.xml")
            if (file.exists()) listOf("deleteDatabaseKey") else emptyList()
        }
    }

}
