package org.kysecurity.mail.data

import androidx.room.Entity
import androidx.room.PrimaryKey

/** Durable contact-sync cursor, kept beside the contact/outbox rows it acknowledges. */
@Entity(tableName = "contact_sync_state")
data class ContactSyncStateEntity(
    @PrimaryKey val subscriberId: String,
    val cursor: Long,
)
