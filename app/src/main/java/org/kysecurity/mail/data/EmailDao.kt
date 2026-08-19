package org.kysecurity.mail.data

import androidx.room.Dao
import androidx.room.Query
import androidx.room.Transaction
import androidx.room.Upsert

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

    /** Drops cached plaintext of mail the server decrypted. Subject is deliberately left alone. */
    // `body IS NOT NULL` is not redundant: `body != ''` is NULL, not false, for a null body.
    @Query("UPDATE emails SET body = '', preview = '' WHERE pgpEncrypted = 1 AND body IS NOT NULL AND body != ''")
    fun clearServerDecryptedBodies(): Int

    @Transaction
    fun replaceFolderSnapshot(folder: String, emails: List<EmailEntity>) {
        upsertAll(emails)
        pruneStaleInFolder(folder, emails.map { it.messageId })
    }
}
