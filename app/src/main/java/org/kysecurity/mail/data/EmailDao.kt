package org.kysecurity.mail.data

import androidx.room.Dao
import androidx.room.Query
import androidx.room.Transaction
import androidx.room.Upsert

/** Every per-message statement takes the folder as well as the id: the pair is the primary key
 *  (see [EmailEntity]), and an id-only `WHERE` would reach a same-UID row in another mailbox. */
@Dao
interface EmailDao {
    @Query("SELECT * FROM emails WHERE folder = :folder ORDER BY atUtc DESC")
    fun getByFolder(folder: String): List<EmailEntity>

    @Upsert
    fun upsertAll(emails: List<EmailEntity>)

    @Query("UPDATE emails SET status = :status WHERE messageId = :id AND folder = :folder")
    fun updateStatus(id: String, folder: String, status: String)

    /** Used when the pairing changes: cached bodies belong to the account that delivered them, and
     *  nothing else in this table is subscriber-scoped. */
    @Query("DELETE FROM emails")
    fun clearAll()

    @Query("DELETE FROM emails WHERE messageId = :id AND folder = :folder")
    fun deleteById(id: String, folder: String)

    @Query("SELECT * FROM emails WHERE messageId = :id AND folder = :folder")
    fun getById(id: String, folder: String): EmailEntity?

    @Query("DELETE FROM emails WHERE folder = :folder AND messageId NOT IN (:keepIds)")
    fun pruneStaleInFolder(folder: String, keepIds: List<String>)

    /** Drops cached plaintext of mail the server decrypted. Subject is deliberately left alone. */
    // `body IS NOT NULL` is not redundant: `body != ''` is NULL, not false, for a null body.
    @Query("UPDATE emails SET body = '', preview = '' WHERE pgpEncrypted = 1 AND body IS NOT NULL AND body != ''")
    fun clearServerDecryptedBodies(): Int

    @Transaction
    fun replaceFolderSnapshot(folder: String, emails: List<EmailEntity>) {
        upsertAll(emails)
        pruneStaleInFolder(folder, emails.map { it.messageId })
    }

    /** The whole delta applied as one transaction, so a mid-apply failure cannot leave the folder
     *  half-updated. [pruneKeepIds] is null for a partial delta: only a full window can say what
     *  is absent. */
    @Transaction
    fun applyFolderDelta(
        folder: String,
        upserts: List<EmailEntity>,
        removedIds: List<String>,
        pruneKeepIds: List<String>?,
    ) {
        upsertAll(upserts)
        removedIds.forEach { deleteById(it, folder) }
        if (pruneKeepIds != null) pruneStaleInFolder(folder, pruneKeepIds)
    }
}
