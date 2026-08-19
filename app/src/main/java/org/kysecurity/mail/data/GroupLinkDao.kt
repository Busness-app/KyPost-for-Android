package org.kysecurity.mail.data

import androidx.room.Dao
import androidx.room.Query
import androidx.room.Upsert

@Dao
interface GroupLinkDao {
    @Query("SELECT * FROM group_links")
    suspend fun getAll(): List<GroupLinkEntity>

    @Query("SELECT * FROM group_links WHERE groupId = :groupId")
    suspend fun getByGroupId(groupId: String): GroupLinkEntity?

    @Upsert
    suspend fun upsert(link: GroupLinkEntity)

    @Query("DELETE FROM group_links WHERE groupId = :groupId")
    suspend fun deleteByGroupId(groupId: String)

    /** Used when the pairing changes — group links are scoped to the account that owned them. */
    @Query("DELETE FROM group_links")
    suspend fun clearAll()
}
