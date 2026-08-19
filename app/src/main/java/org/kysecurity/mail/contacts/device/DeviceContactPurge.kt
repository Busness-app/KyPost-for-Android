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
        val appContext = context.applicationContext
        return try {
            appContext.contentResolver.delete(
                uri,
                "${ContactsContract.RawContacts.ACCOUNT_TYPE} = ?",
                arrayOf(DeviceContactAccount.ACCOUNT_TYPE),
            )
        } catch (e: SecurityException) {
            // A missing WRITE_CONTACTS does not mean no rows exist; the account tells them apart.
            val accountExists = DeviceContactAccountManager(appContext).accountExists()
            if (accountExists) {
                android.util.Log.e(TAG, "Contacts permission is gone but the sync account remains; rows may survive", e)
            } else {
                android.util.Log.i(TAG, "No contacts permission and no sync account, so no synced rows can exist", e)
            }
            deniedPermissionRowOutcome(accountExists)
        } catch (e: Exception) {
            android.util.Log.e(TAG, "Failed to delete synced raw contacts", e)
            -1
        }
    }
}

/** @return 0 when no rows can exist, or -1 when rows may exist and could not be reached. */
internal fun deniedPermissionRowOutcome(accountExists: Boolean): Int = if (accountExists) -1 else 0
