package org.kysecurity.mail.contacts.device

import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/** DeviceContactPurge and SecurityWipe both rest on these account calls. */
@RunWith(AndroidJUnit4::class)
class DeviceContactAccountTeardownTest {
    private val context = ApplicationProvider.getApplicationContext<android.content.Context>()
    private val accounts = DeviceContactAccountManager(context)

    @After
    fun removeAccount() {
        accounts.removeAccountBlocking()
    }

    @Test
    fun accountExists_tracksCreationAndRemoval() = runBlocking {
        assertTrue("ensureAccount should report success", accounts.ensureAccount())
        assertTrue("the account it just created should be visible", accounts.accountExists())

        assertTrue("removeAccountBlocking should report success", accounts.removeAccountBlocking())
        assertFalse("the removed account must not still be visible", accounts.accountExists())
    }

    /** `ensureAccount` is idempotent — the enabler calls it on every enable, including re-enables. */
    @Test
    fun ensureAccount_isIdempotent() = runBlocking {
        assertTrue(accounts.ensureAccount())
        assertTrue(accounts.ensureAccount())
        assertTrue(accounts.accountExists())
    }

    @Test
    fun deleteSyncedRows_withNoAccount_isNotAFailure() {
        accounts.removeAccountBlocking()
        assertFalse(accounts.accountExists())

        assertTrue(
            "a device with no sync account must not report a purge failure",
            DeviceContactPurge.deleteSyncedRows(context) >= 0,
        )
    }
}
