package com.urlxl.mail.contacts.device

import android.content.Context
import android.provider.ContactsContract

/**
 * Removes the raw contacts this app published into the OS contacts provider, **without touching any
 * graph**.
 *
 * [DeviceContactRepository.deleteAllSyncedDeviceContacts] does the same provider delete, but reaching
 * it means constructing [DeviceContactsGraph], whose constructor calls `DataRuntime.graph(...)`. On
 * the teardown paths that matters: during a security wipe the database has already been closed and
 * deleted, so building that graph recreates `kypost_mail.db` on disk — and with the hostile-location
 * flag file also already gone, it recreates it *disk-backed*. Teardown callers use this instead.
 *
 * The rows are the reason this exists at all: they live outside the app sandbox, so nothing the wipe
 * deletes from `/data/data` reaches them, and an unpair that cleared only the local link table left
 * the previous account's entire address book in ContactsContract with no index back to it.
 */
object DeviceContactPurge {
    private const val TAG = "DeviceContactPurge"

    /**
     * Deletes every raw contact under this app's sync account.
     *
     * `CALLER_IS_SYNCADAPTER` makes the delete immediate rather than leaving tombstoned rows that
     * still hold the contact data for an account that is about to be removed.
     *
     * Returns the number of rows deleted, or -1 if the provider refused. Callers that must report
     * failure (the wipe) check the sign; callers that are best-effort ignore it.
     */
    fun deleteSyncedRows(context: Context): Int {
        val uri = ContactsContract.RawContacts.CONTENT_URI.buildUpon()
            .appendQueryParameter(ContactsContract.CALLER_IS_SYNCADAPTER, "true")
            .appendQueryParameter(ContactsContract.RawContacts.ACCOUNT_NAME, DeviceContactAccount.ACCOUNT_NAME)
            .appendQueryParameter(ContactsContract.RawContacts.ACCOUNT_TYPE, DeviceContactAccount.ACCOUNT_TYPE)
            .build()
        return try {
            context.applicationContext.contentResolver.delete(
                uri,
                "${ContactsContract.RawContacts.ACCOUNT_TYPE} = ?",
                arrayOf(DeviceContactAccount.ACCOUNT_TYPE),
            )
        } catch (e: SecurityException) {
            // No WRITE_CONTACTS means this app never published a row, so there is nothing to delete
            // and this is a success, not a refusal. Conflating the two made EVERY wipe on a device
            // that never enabled device-contact sync -- the default, since the permission is
            // requested only from DeviceContactSyncEnabler -- report Incomplete. The user was told
            // their data might still be present when every byte was gone, the destructive wipe then
            // re-ran on the next launches, and it finally advised a reinstall.
            android.util.Log.i(TAG, "No contacts permission, so no synced rows can exist", e)
            0
        } catch (e: Exception) {
            android.util.Log.e(TAG, "Failed to delete synced raw contacts", e)
            -1
        }
    }
}
