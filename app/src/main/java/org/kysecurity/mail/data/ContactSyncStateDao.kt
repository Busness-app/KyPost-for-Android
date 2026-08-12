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

    /**
     * Drops every stored cursor.
     *
     * The cursor moved out of the `contacts_state` DataStore into this table, but the unpair purge
     * was not moved with it: it still deleted the DataStore file the cursor no longer lives in. Since
     * `subscriberId` is stable per account, a re-pair to the same account resumed from the stale
     * cursor, the server returned nothing changed since it, and the address book stayed empty
     * indefinitely with no error surfaced. Each ever-paired account also left a plaintext
     * `subscriberId` row behind -- the exact residue the purge deletes `contacts_state` to prevent.
     */
    @Query("DELETE FROM contact_sync_state")
    suspend fun clearAll()
}
