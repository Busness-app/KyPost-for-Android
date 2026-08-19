package org.kysecurity.mail.security

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.kysecurity.mail.data.DataRuntime
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.concurrent.thread

/**
 * The flag that decides whether the user's mail exists on disk at all.
 *
 * This suite used to assert two things — the default is false, and it persists — because there was
 * nothing else to assert: the setting was a bare `Boolean` in a `MODE_PRIVATE` preferences file,
 * the exact primitive [KeystoreTripwireKey]'s KDoc spends a paragraph proving is not a control. The
 * app-lock tripwire got a Keystore anchor over a much smaller claim. This one had none, so an
 * attacker who could write the app sandbox could turn protection off and the next process start
 * would quietly begin writing decrypted mail to disk for a user who had chosen the mode precisely
 * so that no file would exist.
 *
 * The tamper tests below are the ones that matter, and none of them could have been written before.
 */
@RunWith(AndroidJUnit4::class)
class HostileLocationSettingsTest {
    private val context = ApplicationProvider.getApplicationContext<Context>()

    private fun markerPrefs() = context.getSharedPreferences(
        "org.kysecurity.mail.hostile_location_settings",
        Context.MODE_PRIVATE,
    )

    @Before
    @After
    fun resetState() {
        HostileLocationSettings(context).setEnabled(false)
        // The tamper tests below leave the posture reading ENABLED for the length of a method, and
        // DataRuntime is a process-lifetime singleton that caches whichever shape of DataGraph was
        // built first — in-memory under protection, disk-backed without it. A neighbouring class
        // that asks for an on-disk database would otherwise inherit an in-memory one and fail on a
        // precondition it never set. Dropping the holder is what AppRestart.relaunch does in
        // production after every real toggle; this class has to do it by hand because it fakes
        // postures the production toggle never produces.
        DataRuntime.invalidate()
    }

    @Test
    fun isEnabled_defaultsFalse() {
        assertFalse(HostileLocationSettings(context).isEnabled())
    }

    @Test
    fun setEnabled_persistsAcrossInstances() {
        HostileLocationSettings(context).setEnabled(true)
        assertTrue(HostileLocationSettings(context).isEnabled())
    }

    @Test
    fun enablingMintsTheKeystoreAnchor() {
        assertFalse("no key before protection was ever enabled", KeystoreHlpKey.exists())
        HostileLocationSettings(context).setEnabled(true)
        assertTrue("the durable half of the marker must exist", KeystoreHlpKey.exists())
    }

    @Test
    fun disablingDestroysTheKeystoreAnchor() {
        HostileLocationSettings(context).setEnabled(true)
        HostileLocationSettings(context).setEnabled(false)
        assertFalse(KeystoreHlpKey.exists())
        assertEquals(HostileLocationState.DISABLED, HostileLocationSettings(context).state())
    }

    // --- Tampering. Each of these was a silent, successful downgrade before the anchor existed. ---

    @Test
    fun forgingTheFlagToFalseDoesNotTurnProtectionOff() {
        // THE attack. Protection is on; something with sandbox write flips the boolean. Before the
        // anchor this worked: the next DataGraph built a disk-backed database and the app started
        // persisting decrypted mail, with nothing shown to the user.
        HostileLocationSettings(context).setEnabled(true)
        markerPrefs().edit().putBoolean("enabled", false).commit()

        assertEquals(
            "a forged value must fail towards ENABLED — the direction where no file exists",
            HostileLocationState.ENABLED,
            HostileLocationSettings(context).state(),
        )
        assertTrue(HostileLocationSettings(context).isEnabled())
    }

    @Test
    fun deletingBothMarkerFieldsDoesNotTurnProtectionOff() {
        // The other half: don't forge the value, just remove the evidence. The Keystore alias
        // survives file deletion, which is what makes its presence the durable claim.
        HostileLocationSettings(context).setEnabled(true)
        markerPrefs().edit().clear().commit()

        assertEquals(HostileLocationState.ENABLED, HostileLocationSettings(context).state())
    }

    @Test
    fun aCorruptMacDoesNotTurnProtectionOff() {
        HostileLocationSettings(context).setEnabled(true)
        markerPrefs().edit()
            .putBoolean("enabled", false)
            .putString("enabled_mac", "bm90IGEgcmVhbCBtYWM")
            .commit()

        assertEquals(HostileLocationState.ENABLED, HostileLocationSettings(context).state())
    }

    @Test
    fun aForgedEnabledFlagOnAFreshInstallIsNotHonoured() {
        // The mirror-image weaponisation, and the reason "no key means DISABLED" must come before
        // the marker is read at all: writing `enabled=true` onto a device that never enabled
        // protection would otherwise make the app present an empty mailbox as if it were the
        // user's, on first launch, forever.
        markerPrefs().edit().putBoolean("enabled", true).putString("enabled_mac", "AAAA").commit()

        assertEquals(HostileLocationState.DISABLED, HostileLocationSettings(context).state())
        assertFalse(HostileLocationSettings(context).isEnabled())
    }

    @Test
    fun aFreshInstallIsDisabledNotUnreadable() {
        // Guards the branch order: if "no key" were treated as tampering, every new install would
        // block on first launch behind LockedActivity's unreadable-marker notice.
        markerPrefs().edit().clear().commit()
        assertEquals(HostileLocationState.DISABLED, HostileLocationSettings(context).state())
    }

    /** Enabling mints a Keystore key, which is slow. A posture read landing inside that window
     *  cached DISABLED for the life of the process, while the UI went on showing protection ON. */
    @Test
    fun aReadRacingEnableDoesNotLeaveProtectionOff() {
        repeat(10) { attempt ->
            HostileLocationSettings(context).setEnabled(false)
            val stop = AtomicBoolean(false)
            val reader = thread {
                while (!stop.get()) {
                    HostileLocationSettings(context).isEnabled()
                    Thread.yield()
                }
            }

            HostileLocationSettings(context).setEnabled(true)
            stop.set(true)
            reader.join()

            assertTrue(
                "attempt $attempt: protection read as OFF after setEnabled(true)",
                HostileLocationSettings(context).isEnabled(),
            )
        }
    }
}
