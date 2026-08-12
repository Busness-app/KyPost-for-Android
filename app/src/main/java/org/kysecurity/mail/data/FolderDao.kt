package org.kysecurity.mail.data

import androidx.room.Dao
import androidx.room.Query
import androidx.room.Transaction
import androidx.room.Upsert

@Dao
interface FolderDao {
    @Query("SELECT * FROM folders")
    fun getAll(): List<FolderEntity>

    @Query("DELETE FROM folders")
    fun clearAll()

    @Upsert
    fun upsertAll(folders: List<FolderEntity>)

    @Transaction
    fun replaceAll(folders: List<FolderEntity>) {
        clearAll()
        upsertAll(folders)
    }
}
