package com.urlxl.mail.data

import androidx.room.Dao
import androidx.room.Query
import androidx.room.Upsert

@Dao
interface ContactSyncStateDao {
    @Query("SELECT cursor FROM contact_sync_state WHERE subscriberId = :subscriberId")
    suspend fun cursor(subscriberId: String): Long?

    @Upsert
    suspend fun upsert(state: ContactSyncStateEntity)
}
