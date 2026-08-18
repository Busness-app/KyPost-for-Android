package org.kysecurity.mail.contacts.device

import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * The sync account is what the contacts teardown now rests on, in two places, so it needs to
 * actually answer.
 *
 * - `DeviceContactPurge.deleteSyncedRows` uses [DeviceContactAccountManager.accountExists] to tell
 *   "the contacts permission was revoked and rows may survive" from "nothing was ever published".
 * - `SecurityWipe`'s `deviceContactAccount` step uses it to decide whether a failed removal is a
 *   reportable failure. Removing the account is what makes CP2 hard-delete the raw contacts under
 *   it, so it is the last thing standing between a wipe and an address book left outside the
 *   sandbox.
 *
 * Both used to be unasserted: nothing in either test tree touched `removeAccountBlocking`,
 * `accountExists` or `deleteSyncedRows`.
 */
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

    /**
     * With no account present the purge reports 0 (nothing could exist), never a failure. This is
     * the case that made every wipe on a device that never enabled sync report Incomplete when the
     * denied-permission branch was first tightened, so it is pinned here.
     */
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
