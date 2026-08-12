package org.kysecurity.mail.data

import androidx.room.Entity
import androidx.room.PrimaryKey

/**
 * Local cache of the backend's groups list (`GET /api/groups`), full-refreshed on each sync
 * cycle — small list, no delta cursor needed, mirrors [ContactEntity]'s `uid`/`rev` shape but
 * without the JSON-column machinery since a group has no list-valued fields.
 */
@Entity(tableName = "groups")
data class GroupEntity(
    @PrimaryKey val id: String,
    val name: String,
    val rev: Long,
)
