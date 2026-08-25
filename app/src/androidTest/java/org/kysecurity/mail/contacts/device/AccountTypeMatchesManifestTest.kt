package org.kysecurity.mail.contacts.device

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith
import org.kysecurity.mail.BuildConfig
import org.kysecurity.mail.R

/** contact_authenticator.xml is what the platform registers; DeviceContactAccount is what the app
 *  asks AccountManager for. If they disagree the account silently never resolves, and nothing at
 *  compile time notices. */
@RunWith(AndroidJUnit4::class)
class AccountTypeMatchesManifestTest {
    @Test
    fun theRegisteredAccountTypeIsTheOneTheAppAsksFor() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        assertEquals(
            "${BuildConfig.APPLICATION_ID}.contacts",
            context.getString(R.string.contact_account_type),
        )
        assertEquals(context.getString(R.string.contact_account_type), DeviceContactAccount.ACCOUNT_TYPE)
    }
}
