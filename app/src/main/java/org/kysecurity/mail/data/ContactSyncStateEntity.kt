package org.kysecurity.mail.data

import androidx.room.Entity
import androidx.room.PrimaryKey

@Entity(tableName = "contact_sync_state")
data class ContactSyncStateEntity(
    @PrimaryKey val subscriberId: String,
    val cursor: Long,
)
