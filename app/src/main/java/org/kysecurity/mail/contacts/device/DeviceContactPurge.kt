package org.kysecurity.mail.contacts.device

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
     * Returns the number of rows deleted, or -1 if the rows could not be reached — whether the
     * provider refused outright or the contacts permission has since been revoked while this app's
     * sync account (and so its rows) is still on the device. Callers that must report failure (the
     * wipe) check the sign; callers that are best-effort ignore it.
     */
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
            // A missing WRITE_CONTACTS does NOT mean this app never published a row: runtime
            // permissions are revocable, by the user and (since Android 11) by the OS auto-resetting
            // them for unused apps. Treating "cannot reach the provider" as "nothing to reach" is
            // how a wipe reported Complete over an address book still in ContactsContract.
            //
            // The account tells them apart. Every raw contact this app writes is owned by it, CP2
            // hard-deletes an account's rows when the account goes, and enumerating our own account
            // needs no permission -- so no account means no rows.
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

/**
 * What a provider [SecurityException] means, given whether this app's sync account is still present.
 *
 * Pure and Android-free so the decision has a plain JVM test: the surrounding function needs a real
 * ContentResolver and a revoked runtime permission, which no instrumented test can arrange.
 *
 * @return 0 when no rows can exist, or -1 when rows may exist and could not be reached.
 */
internal fun deniedPermissionRowOutcome(accountExists: Boolean): Int = if (accountExists) -1 else 0
