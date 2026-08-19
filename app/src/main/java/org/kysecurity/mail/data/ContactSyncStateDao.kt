package org.kysecurity.mail.data

import androidx.room.Dao
import androidx.room.Query
import androidx.room.Upsert

@Dao
interface ContactSyncStateDao {
    @Query("SELECT cursor FROM contact_sync_state WHERE subscriberId = :subscriberId")
    suspend fun cursor(subscriberId: String): Long?

    @Upsert
    suspend fun upsert(state: ContactSyncStateEntity)

    // The unpair purge must clear this table: a stale cursor makes a re-pair resume from nothing.
    @Query("DELETE FROM contact_sync_state")
    suspend fun clearAll()
}
