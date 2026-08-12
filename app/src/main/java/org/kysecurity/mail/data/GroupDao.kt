package org.kysecurity.mail.data

import androidx.room.Dao
import androidx.room.Query
import androidx.room.Upsert

/** Mirrors [ContactDao]'s suspend-based shape for the small, full-refreshed groups cache. */
@Dao
interface GroupDao {
    @Query("SELECT * FROM groups")
    suspend fun getAll(): List<GroupEntity>

    @Query("SELECT * FROM groups WHERE id = :id")
    suspend fun getById(id: String): GroupEntity?

    @Upsert
    suspend fun upsertAll(groups: List<GroupEntity>)

    @Query("DELETE FROM groups WHERE id NOT IN (:ids)")
    suspend fun deleteNotIn(ids: List<String>)

    @Query("DELETE FROM groups")
    suspend fun clearAll()
}
