package org.kysecurity.mail.data

import androidx.room.Dao
import androidx.room.Query
import androidx.room.Upsert

@Dao
interface DeviceContactLinkDao {
    @Query("SELECT * FROM device_contact_links")
    suspend fun getAll(): List<DeviceContactLinkEntity>

    @Query("SELECT * FROM device_contact_links WHERE uid = :uid")
    suspend fun getByUid(uid: String): DeviceContactLinkEntity?

    @Query("SELECT * FROM device_contact_links WHERE rawContactId = :rawContactId")
    suspend fun getByRawContactId(rawContactId: Long): DeviceContactLinkEntity?

    @Upsert
    suspend fun upsert(link: DeviceContactLinkEntity)

    @Query("DELETE FROM device_contact_links WHERE uid = :uid")
    suspend fun deleteByUid(uid: String)

    /** Reconciliation renames a locally-created contact's temp uid to the server-assigned one.
     *  The link row keys on uid, so it has to follow that rename — otherwise the new uid looks
     *  unlinked and [org.kysecurity.mail.contacts.device.DeviceContactRepository.pushRoomChangesToDevice]
     *  inserts a SECOND raw contact, while the old row is orphaned and can never be reclaimed
     *  (`getByUid` on the dead uid returns null forever). */
    @Query("UPDATE device_contact_links SET uid = :serverUid WHERE uid = :localUid")
    suspend fun remapUid(localUid: String, serverUid: String)

    /** Drops links pointing at raw contacts this app does not own. Older builds linked a uid to a
     *  raw contact belonging to another account (Google, Samsung) whenever a single email or phone
     *  matched, which made every later write and delete for that uid target the other account's
     *  row. Existing installs can already carry such rows, so they are swept on startup. */
    @Query("DELETE FROM device_contact_links WHERE rawContactId IN (:rawContactIds)")
    suspend fun deleteByRawContactIds(rawContactIds: List<Long>)

    /** Used when every synced raw contact is removed at once — see
     *  [org.kysecurity.mail.contacts.device.DeviceContactRepository.deleteAllSyncedDeviceContacts]. */
    @Query("DELETE FROM device_contact_links")
    suspend fun deleteAll()
}
