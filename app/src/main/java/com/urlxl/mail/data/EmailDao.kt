package com.urlxl.mail.data

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

    /** Reconciles a full-list fetch into the cache: upsert what came back, drop what didn't. */
    @Transaction
    fun replaceFolderSnapshot(folder: String, emails: List<EmailEntity>) {
        upsertAll(emails)
        pruneStaleInFolder(folder, emails.map { it.messageId })
    }
}
