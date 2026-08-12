package org.kysecurity.mail.data

import androidx.room.Entity
import androidx.room.PrimaryKey

/**
 * Bridges a backend group's [groupId] to the Android `ContactsContract.Groups._ID` row it was
 * lazily materialized as on-device, the same "remote ID <-> local row ID" problem
 * [DeviceContactLinkEntity] already solves for contacts themselves.
 */
@Entity(tableName = "group_links")
data class GroupLinkEntity(
    @PrimaryKey val groupId: String,
    val androidGroupRowId: Long,
)
