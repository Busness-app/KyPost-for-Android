package org.kysecurity.mail.security

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
        store.setPin("123456".toCharArray())
        assertTrue(store.verifyPin("123456".toCharArray()))
    }

    @Test
    fun verifyPin_fails_withWrongPin() {
        val store = AppLockStore(context)
        store.setPin("123456".toCharArray())
        assertFalse(store.verifyPin("000000".toCharArray()))
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
        store.setPin("123456".toCharArray())
        store.setLockEnabled(true)
        store.incrementFailedAttempts()

        store.reset()

        val fresh = AppLockStore(context)
        assertFalse(fresh.isLockEnabled())
        assertFalse(fresh.verifyPin("123456".toCharArray()))
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
        store.setPin("482913".toCharArray())
        store.setLockEnabled(true)
        assertTrue(AppLockStore(context).wasLockEnabled())

        store.setLockEnabled(false)
        assertFalse(AppLockStore(context).wasLockEnabled())
    }

    @Test
    fun tripwire_trips_whenTheEncryptedStateVanishesWhileALockWasConfigured() {
        val store = AppLockStore(context)
        store.setPin("482913".toCharArray())
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
        store.setPin("482913".toCharArray())
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
        recovered.setPin("903471".toCharArray())
        assertTrue(AppLockStore(context).verifyPin("903471".toCharArray()))
        assertFalse("setting a new PIN clears the tripwire", AppLockStore(context).tripwireBroken())
    }

    /**
     * The bypass the plain-file tripwire did not close.
     *
     * As an unauthenticated `MODE_PRIVATE` file, the marker was defeated by deleting *two* files
     * instead of one: with `app_lock_tripwire.xml` gone alongside `app_lock_secure.xml`,
     * `wasLockEnabled()` read false and the lock was simply gone, with no wipe. The durable half of
     * the marker is now a Keystore alias, which writing to the app sandbox cannot remove.
     */
    @Test
    fun tripwire_trips_whenBothPreferenceFilesAreDeleted() {
        val store = AppLockStore(context)
        store.setPin("482913".toCharArray())
        store.setLockEnabled(true)

        context.deleteSharedPreferences("app_lock_secure")
        context.deleteSharedPreferences("app_lock_tripwire")

        val recovered = AppLockStore(context)
        assertFalse(recovered.isLockEnabled())
        assertTrue("deleting both files must still be detectable", recovered.tripwireBroken())
    }

    /**
     * The other direction, which the plain file made possible: anything that could write the app
     * sandbox could forge `lock_was_enabled=true` on a device that never had a lock and make the
     * next launch destroy the user's mail. The marker is now HMACed under a Keystore key, so a
     * forged value does not authenticate.
     *
     * The assertion is deliberately about `tripwireBroken()`, not `wasLockEnabled()`: a forged
     * marker reads as tampering either way, but on a store that never had a lock there is nothing
     * to protect and nothing to destroy.
     */
    @Test
    fun tripwire_doesNotFireOnAForgedMarkerWhenNoLockWasEverConfigured() {
        // Nothing configured: no PIN, no lock, and crucially no Keystore alias.
        AppLockStore(context).reset()

        context.getSharedPreferences("app_lock_tripwire", android.content.Context.MODE_PRIVATE)
            .edit()
            .putBoolean("lock_was_enabled", true)
            .putString("lock_was_enabled_mac", "Zm9yZ2Vk")
            .commit()

        assertFalse(
            "a forged marker with no Keystore key behind it must not arm a wipe",
            AppLockStore(context).tripwireBroken(),
        )
    }

    /** Turning the lock off must not leave the durable marker armed — otherwise the next launch
     *  reads "a lock was configured" over a store with no PIN hash and wipes. */
    @Test
    fun tripwire_isDisarmedWhenTheLockIsTurnedOff() {
        val store = AppLockStore(context)
        store.setPin("482913".toCharArray())
        store.setLockEnabled(true)

        store.reset()

        val recovered = AppLockStore(context)
        assertFalse(recovered.wasLockEnabled())
        assertFalse(recovered.tripwireBroken())
    }

    /**
     * The salt guard used to log and return, telling the caller a salt had been persisted when it
     * had not — after which the device secret was wrapped under a key nothing would reproduce.
     */
    @Test(expected = IllegalStateException::class)
    fun credentialSalt_refusesToOverwrite_loudly() {
        val store = AppLockStore(context)
        store.setCredentialSalt(ByteArray(16) { 1 })
        store.setCredentialSalt(ByteArray(16) { 2 })
    }
}
