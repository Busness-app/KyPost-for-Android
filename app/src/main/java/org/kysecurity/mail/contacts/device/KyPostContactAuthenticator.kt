package org.kysecurity.mail.contacts.device

import android.accounts.AbstractAccountAuthenticator
import android.accounts.AccountAuthenticatorResponse
import android.accounts.AccountManager
import android.content.Context
import android.os.Bundle

class KyPostContactAuthenticator(context: Context) : AbstractAccountAuthenticator(context) {
    override fun editProperties(
        response: AccountAuthenticatorResponse?,
        accountType: String?,
    ): Bundle = throw UnsupportedOperationException()

    override fun addAccount(
        response: AccountAuthenticatorResponse?,
        accountType: String?,
        authTokenType: String?,
        requiredFeatures: Array<out String>?,
        options: Bundle?,
    ): Bundle? = null

    override fun confirmCredentials(
        response: AccountAuthenticatorResponse?,
        account: android.accounts.Account?,
        options: Bundle?,
    ): Bundle? = null

    override fun getAuthToken(
        response: AccountAuthenticatorResponse?,
        account: android.accounts.Account?,
        authTokenType: String?,
        options: Bundle?,
    ): Bundle = throw UnsupportedOperationException()

    override fun getAuthTokenLabel(authTokenType: String?): String? = null

    override fun updateCredentials(
        response: AccountAuthenticatorResponse?,
        account: android.accounts.Account?,
        authTokenType: String?,
        options: Bundle?,
    ): Bundle? = null

    override fun hasFeatures(
        response: AccountAuthenticatorResponse?,
        account: android.accounts.Account?,
        features: Array<out String>?,
    ): Bundle = Bundle().apply { putBoolean(AccountManager.KEY_BOOLEAN_RESULT, false) }
}
