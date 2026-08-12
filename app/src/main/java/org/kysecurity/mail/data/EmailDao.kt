package org.kysecurity.mail.data

import androidx.room.Dao
import androidx.room.Query
import androidx.room.Transaction
import androidx.room.Upsert

/**
 * Blocking (non-suspend) by design: callers already run on a background executor thread,
 * so there is no need to add coroutines to the mail path just for this cache.
 */
@Dao
interface EmailDao {
    @Query("SELECT * FROM emails WHERE folder = :folder ORDER BY atUtc DESC")
    fun getByFolder(folder: String): List<EmailEntity>

    @Upsert
    fun upsertAll(emails: List<EmailEntity>)

    @Query("UPDATE emails SET status = :status WHERE messageId = :id")
    fun updateStatus(id: String, status: String)

    @Query("UPDATE emails SET folder = :folder WHERE messageId = :id")
    fun updateFolder(id: String, folder: String)

    /** Used when the pairing changes: cached bodies belong to the account that delivered them, and
     *  nothing else in this table is subscriber-scoped. */
    @Query("DELETE FROM emails")
    fun clearAll()

    @Query("DELETE FROM emails WHERE messageId = :id")
    fun deleteById(id: String)

    @Query("SELECT body FROM emails WHERE messageId = :id")
    fun getBody(id: String): String?

    @Query("SELECT * FROM emails WHERE messageId = :id")
    fun getById(id: String): EmailEntity?

    @Query("DELETE FROM emails WHERE folder = :folder AND messageId NOT IN (:keepIds)")
    fun pruneStaleInFolder(folder: String, keepIds: List<String>)

    /**
     * Drops the locally cached plaintext of mail the **server** decrypted.
     *
     * `pgpEncrypted = 1` with a non-empty body is exactly [PgpMessageState.DECRYPTED_BY_SERVER]: the
     * message was encrypted in the mailbox and the server opened it with an account key it held. Once
     * the account moves to a client-held key that plaintext is the one copy of the message the new
     * threat model does not account for — the server can no longer produce it, and nothing else on
     * the device would remove it until the next full snapshot up to 24 hours later.
     *
     * Ordinary unencrypted mail is untouched: `pgpEncrypted = 0` there, and clearing it would be
     * collateral for no privacy gain.
     *
     * `body IS NOT NULL` is not redundant. `body` is nullable and `body != ''` evaluates to NULL —
     * not true — for a null body, so the guard makes "no body to clear" explicit rather than relying
     * on three-valued logic to skip the row.
     *
     * Clears `preview` alongside `body` because the preview is derived from the decrypted text and
     * would otherwise leave the opening of every message readable. It does **not** clear `subject`:
     * a blanked subject leaves an unreadable inbox row until the next sync, and only the OpenPGP
     * protected-subject extension puts message content there. That case is left to the full snapshot.
     */
    @Query("UPDATE emails SET body = '', preview = '' WHERE pgpEncrypted = 1 AND body IS NOT NULL AND body != ''")
    fun clearServerDecryptedBodies(): Int

    /** Reconciles a full-list fetch into the cache: upsert what came back, drop what didn't. */
    @Transaction
    fun replaceFolderSnapshot(folder: String, emails: List<EmailEntity>) {
        upsertAll(emails)
        pruneStaleInFolder(folder, emails.map { it.messageId })
    }
}
