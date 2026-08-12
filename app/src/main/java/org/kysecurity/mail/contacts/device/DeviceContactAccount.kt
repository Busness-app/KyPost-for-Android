package org.kysecurity.mail.contacts.device

import android.accounts.Account
import android.accounts.AccountManager
import android.content.Context

object DeviceContactAccount {
    const val ACCOUNT_TYPE = "org.kysecurity.mail.contacts"
    const val ACCOUNT_NAME = "KyPost"

    fun account(): Account = Account(ACCOUNT_NAME, ACCOUNT_TYPE)
}

class DeviceContactAccountManager(private val context: Context) {
    private val accountManager = AccountManager.get(context)

    suspend fun ensureAccount(): Boolean {
        val account = DeviceContactAccount.account()
        val existing = accountManager.getAccountsByType(DeviceContactAccount.ACCOUNT_TYPE)
        if (existing.any { it.name == account.name }) {
            return true
        }
        return try {
            accountManager.addAccountExplicitly(account, null, null)
        } catch (e: Exception) {
            false
        }
    }

    suspend fun removeAccount(): Boolean = removeAccountBlocking()

    /** Same work as [removeAccount] without the `suspend` marker, for callers already inside a
     *  non-suspending block — see [org.kysecurity.mail.security.SecurityWipe.removeSyncedDeviceContacts].
     *  `removeAccountExplicitly` is a synchronous AccountManager call either way. */
    fun removeAccountBlocking(): Boolean {
        val account = DeviceContactAccount.account()
        return try {
            accountManager.removeAccountExplicitly(account)
        } catch (e: Exception) {
            false
        }
    }
}
