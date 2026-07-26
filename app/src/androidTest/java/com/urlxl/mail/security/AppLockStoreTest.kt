package com.urlxl.mail.security

import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class AppLockStoreTest {
    private val context = ApplicationProvider.getApplicationContext<android.content.Context>()

    @Before
    fun resetState() {
        AppLockStore(context).reset()
    }

    @Test
    fun setPin_thenVerifyPin_succeedsWithCorrectPin() {
        val store = AppLockStore(context)
        store.setPin("123456")
        assertTrue(store.verifyPin("123456"))
    }

    @Test
    fun verifyPin_fails_withWrongPin() {
        val store = AppLockStore(context)
        store.setPin("123456")
        assertFalse(store.verifyPin("000000"))
    }

    @Test
    fun lockEnabled_defaultsFalse_andPersistsWhenSet() {
        val store = AppLockStore(context)
        assertFalse(store.isLockEnabled())
        store.setLockEnabled(true)
        assertTrue(AppLockStore(context).isLockEnabled())
    }

    @Test
    fun failedAttempts_incrementAndReset() {
        val store = AppLockStore(context)
        assertEquals(1, store.incrementFailedAttempts())
        assertEquals(2, store.incrementFailedAttempts())
        store.resetFailedAttempts()
        assertEquals(1, store.incrementFailedAttempts())
    }

    @Test
    fun reset_clearsPinAndLockState() {
        val store = AppLockStore(context)
        store.setPin("123456")
        store.setLockEnabled(true)
        store.incrementFailedAttempts()

        store.reset()

        val fresh = AppLockStore(context)
        assertFalse(fresh.isLockEnabled())
        assertFalse(fresh.verifyPin("123456"))
        assertEquals(1, fresh.incrementFailedAttempts())
    }

    @Test
    fun tripwire_isUnsetUntilALockIsConfigured() {
        val store = AppLockStore(context)
        assertFalse(store.wasLockEnabled())
        assertFalse(store.tripwireBroken())
    }

    @Test
    fun tripwire_recordsThatALockExisted_andClearsWhenTheLockIsTurnedOff() {
        val store = AppLockStore(context)
        store.setPin("482913")
        store.setLockEnabled(true)
        assertTrue(AppLockStore(context).wasLockEnabled())

        store.setLockEnabled(false)
        assertFalse(AppLockStore(context).wasLockEnabled())
    }

    @Test
    fun tripwire_trips_whenTheEncryptedStateVanishesWhileALockWasConfigured() {
        val store = AppLockStore(context)
        store.setPin("482913")
        store.setLockEnabled(true)

        // Simulates an attacker deleting the keyset (or OS-level key invalidation) to turn the
        // lock off. The old behaviour was to recreate the file empty and report "no lock
        // configured", opening straight into the inbox with every cached message still on disk.
        context.deleteSharedPreferences("app_lock_secure")

        val recovered = AppLockStore(context)
        assertFalse(recovered.isLockEnabled())
        assertTrue("deleting the encrypted store must be detectable", recovered.tripwireBroken())
    }

    @Test
    fun corruptedKeyset_doesNotCrash_andTripsTheTripwire() {
        val store = AppLockStore(context)
        store.setPin("482913")
        store.setLockEnabled(true)

        val rawPrefs = context.getSharedPreferences("app_lock_secure", android.content.Context.MODE_PRIVATE)
        val valueKeysetKey = "__androidx_security_crypto_encrypted_prefs_value_keyset__"
        val originalKeyset = rawPrefs.getString(valueKeysetKey, null)
        assertTrue("expected an existing value keyset to corrupt", !originalKeyset.isNullOrEmpty())
        val corrupted = originalKeyset!!.toCharArray().also { chars ->
            // Flip a handful of chars mid-string so the keyset is still non-blank but its AEAD
            // ciphertext/tag no longer verifies against the real Keystore key.
            for (i in chars.indices step 7) chars[i] = if (chars[i] == 'A') 'B' else 'A'
        }.concatToString()
        rawPrefs.edit().putString(valueKeysetKey, corrupted).commit()

        // Must not throw despite the corrupted keyset (this line crashed before the fix).
        val recovered = AppLockStore(context)

        assertFalse("corrupted store should reset to unlocked, not stale/garbage data", recovered.isLockEnabled())

        // But "unlocked" alone is not an acceptable outcome: the tripwire is what turns this into
        // a wipe at startup rather than a free pass into the cached mailbox.
        assertTrue("a corrupted keyset must trip the tripwire", recovered.tripwireBroken())

        // The reset must leave a genuinely working store behind, not just a non-crashing shell.
        recovered.setPin("903471")
        assertTrue(AppLockStore(context).verifyPin("903471"))
        assertFalse("setting a new PIN clears the tripwire", AppLockStore(context).tripwireBroken())
    }
}
