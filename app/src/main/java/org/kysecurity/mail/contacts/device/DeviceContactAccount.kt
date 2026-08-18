package org.kysecurity.mail.contacts.device

import android.accounts.Account
import android.accounts.AccountManager
import android.content.Context
import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

private const val TAG = "DeviceContactAccount"

object DeviceContactAccount {
    const val ACCOUNT_TYPE = "org.kysecurity.mail.contacts"
    const val ACCOUNT_NAME = "KyPost"

    fun account(): Account = Account(ACCOUNT_NAME, ACCOUNT_TYPE)
}

class DeviceContactAccountManager(private val context: Context) {
    private val accountManager = AccountManager.get(context)

    /**
     * Whether this app's sync account is currently on the device.
     *
     * Needs no permission: `getAccountsByType` always returns accounts whose authenticator is
     * signed by the caller, and this app ships that authenticator. That matters because the two
     * callers below run during teardown, after the contacts permissions may already be gone.
     *
     * This is also the only durable answer to "could this app have published rows into
     * ContactsContract" — every raw contact it writes is owned by this account, and CP2
     * hard-deletes an account's rows when the account goes. See [DeviceContactPurge].
     */
    fun accountExists(): Boolean = runCatching {
        accountManager.getAccountsByType(DeviceContactAccount.ACCOUNT_TYPE)
            .any { it.name == DeviceContactAccount.ACCOUNT_NAME }
    }.onFailure { Log.e(TAG, "Could not enumerate this app's sync accounts", it) }
        .getOrDefault(false)

    /**
     * Creates the sync account if it is not already there.
     *
     * Blocking AccountManager IPC, so callers must be on an IO dispatcher — the `suspend` marker
     * alone does not move work off the caller's thread, and this used to be awaited straight from
     * `lifecycleScope.launch`, i.e. on the main thread.
     */
    suspend fun ensureAccount(): Boolean = withContext(Dispatchers.IO) {
        if (accountExists()) return@withContext true
        try {
            accountManager.addAccountExplicitly(DeviceContactAccount.account(), null, null)
        } catch (e: kotlinx.coroutines.CancellationException) {
            throw e
        } catch (e: Exception) {
            // Logged, not swallowed: the caller gates "sync is enabled" on this answer, and a
            // silent false enabled a periodic worker with no account to write under.
            Log.e(TAG, "Could not create the contacts sync account", e)
            false
        }
    }

    suspend fun removeAccount(): Boolean =
        withContext(Dispatchers.IO) { removeAccountBlocking() }

    /**
     * Same work as [removeAccount] without the `suspend` marker, for callers already inside a
     * non-suspending block — see [org.kysecurity.mail.security.SecurityWipe.removeSyncedDeviceContacts].
     * `removeAccountExplicitly` is a synchronous AccountManager call either way.
     *
     * Removing the account is what makes CP2 hard-delete the raw contacts under it, so this is the
     * last line of defence for rows that live outside this app's sandbox. A failure here must reach
     * the caller — see [org.kysecurity.mail.security.SecurityWipe]'s `deviceContactAccount` step,
     * which turns a false into a reported incomplete wipe.
     */
    fun removeAccountBlocking(): Boolean {
        return try {
            accountManager.removeAccountExplicitly(DeviceContactAccount.account())
        } catch (e: Exception) {
            Log.e(TAG, "Could not remove the contacts sync account", e)
            false
        }
    }
}
