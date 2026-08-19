package org.kysecurity.mail.contacts.device

import android.content.Context
import android.provider.ContactsContract

// Touches no graph: DataRuntime.graph(...) would recreate kypost_mail.db during a wipe.
object DeviceContactPurge {
    private const val TAG = "DeviceContactPurge"

    /** CALLER_IS_SYNCADAPTER deletes immediately. Returns rows deleted, or -1 if unreachable. */
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
            // No WRITE_CONTACTS means this app never published a row, so 0 is a success, not a refusal.
            android.util.Log.i(TAG, "No contacts permission, so no synced rows can exist", e)
            0
        } catch (e: Exception) {
            android.util.Log.e(TAG, "Failed to delete synced raw contacts", e)
            -1
        }
    }
}
