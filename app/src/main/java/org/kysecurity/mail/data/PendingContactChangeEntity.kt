package org.kysecurity.mail.data

import androidx.room.Entity
import androidx.room.PrimaryKey

/** Offline queue of not-yet-synced local contact edits, flushed by ContactSyncRepository.sync(). */
@Entity(tableName = "pending_contact_changes")
data class PendingContactChangeEntity(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    /** Client-side temp id for a not-yet-synced create; equal to the real uid for update/delete. */
    val localUid: String,
    val rev: Long = 0,
    /** "create" | "update" | "delete" */
    val changeType: String,
    /** Full Contact field snapshot at edit time (empty/ignored for delete). */
    val payloadJson: String = "",
    val createdAtEpochMs: Long,
)
