package org.kysecurity.mail.data

import androidx.room.Entity
import androidx.room.PrimaryKey

@Entity(tableName = "group_links")
data class GroupLinkEntity(
    @PrimaryKey val groupId: String,
    val androidGroupRowId: Long,
)
