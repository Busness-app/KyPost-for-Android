package com.urlxl.mail.contacts

import android.content.Context
import androidx.datastore.preferences.core.longPreferencesKey
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import com.urlxl.mail.ScopedValue
import com.urlxl.mail.data.AppDatabase
import com.urlxl.mail.data.ContactSyncStateEntity

private val Context.contactsDataStore by preferencesDataStore(name = "contacts_state")

/**
 * Durable per-subscriber sync cursor, scoped to the subscriber so re-pairing as someone else
 * starts clean. The first read imports the legacy DataStore value; later updates stay in Room so
 * they can commit with the contact outbox acknowledgement.
 */
class ContactCursorStore(context: Context, private val db: AppDatabase) {
    private val legacyCursor = ScopedValue(
        dataStore = context.contactsDataStore,
        scopeKey = stringPreferencesKey("contacts_cursor_sub"),
        valueKey = longPreferencesKey("contacts_cursor"),
    )

    suspend fun cursor(subscriberId: String): Long {
        db.contactSyncStateDao().cursor(subscriberId)?.let { return it }
        val legacy = legacyCursor.get(subscriberId) ?: 0L
        db.contactSyncStateDao().upsert(ContactSyncStateEntity(subscriberId, legacy))
        return legacy
    }

    suspend fun advanceCursor(subscriberId: String, newCursor: Long) {
        val current = db.contactSyncStateDao().cursor(subscriberId) ?: 0L
        db.contactSyncStateDao().upsert(ContactSyncStateEntity(subscriberId, maxOf(current, newCursor)))
    }

    /** Used for tooOld handling: discard the cursor so the next sync does a full since=0 pull. */
    suspend fun resetCursor(subscriberId: String) {
        db.contactSyncStateDao().upsert(ContactSyncStateEntity(subscriberId, 0L))
    }
}
