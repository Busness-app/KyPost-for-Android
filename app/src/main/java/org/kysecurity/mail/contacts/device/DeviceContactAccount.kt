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

    /** Needs no permission: getAccountsByType returns accounts this app's own authenticator signs. */
    fun accountExists(): Boolean = runCatching {
        accountManager.getAccountsByType(DeviceContactAccount.ACCOUNT_TYPE)
            .any { it.name == DeviceContactAccount.ACCOUNT_NAME }
    }.onFailure { Log.e(TAG, "Could not enumerate this app's sync accounts", it) }
        .getOrDefault(false)

    /** Blocking AccountManager IPC — `suspend` alone would not move it off the caller's thread. */
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

    /** Removing the account is what makes CP2 hard-delete its raw contacts; false must reach callers. */
    fun removeAccountBlocking(): Boolean {
        return try {
            accountManager.removeAccountExplicitly(DeviceContactAccount.account())
        } catch (e: Exception) {
            Log.e(TAG, "Could not remove the contacts sync account", e)
            false
        }
    }
}
