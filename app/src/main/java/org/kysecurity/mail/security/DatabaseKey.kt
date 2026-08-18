package org.kysecurity.mail.security

import android.content.Context
import android.util.Base64
import java.security.SecureRandom
import java.util.Arrays

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
        val prefs = openEncryptedPrefs(context, PREFS_FILE) {
            android.util.Log.e("DatabaseKey", "Database key store keyset is undecryptable", it)
        }
        prefs.getString(KEY_PASSPHRASE, null)?.let { return it }

        val fresh = ByteArray(PASSPHRASE_BYTES).also { SecureRandom().nextBytes(it) }
        val encoded = Base64.encodeToString(fresh, Base64.NO_WRAP)
        Arrays.fill(fresh, 0)
        // commit(), like every other security-relevant write in this package: a process death
        // before an async flush would leave a database encrypted under a key nothing remembers.
        prefs.edit().putString(KEY_PASSPHRASE, encoded).commit()
        return encoded
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
