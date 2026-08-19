package org.kysecurity.mail.security

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Where the PIN pepper lives is not a diagnostic — it is the load-bearing assumption of the PIN
 * threat model. [PinPolicy] allows an 8-12 digit numeric PIN and [CREDENTIAL_KDF_ITERATIONS] is
 * 150k "because the Keystore pepper carries the margin". The pepper carries it only while it
 * cannot be extracted; on a software-backed Keystore the guessing goes offline against 10^8
 * candidates and 150k rounds of PBKDF2-HMAC-SHA256, which was never sized to be the barrier.
 *
 * These assert the reporting, not the hardware: CI emulators are software-backed, so a test that
 * required TRUSTED_ENVIRONMENT would only ever assert what image it was running on.
 */
@RunWith(AndroidJUnit4::class)
class PepperSecurityLevelTest {

    @Test
    fun anAbsentPepperReportsUnknownRatherThanSoftware() {
        KeystorePinPepper.destroy()

        // "There is no key" must not read as "the key is extractable"; the two lead to different
        // user-facing claims and only one of them is about this device's hardware.
        assertEquals(PepperSecurityLevel.UNKNOWN, pinPepperSecurityLevel())
    }

    @Test
    fun aMintedPepperReportsAConcreteLevel() {
        KeystorePinPepper.destroy()
        KeystorePinPepper.ensureExists()

        val level = pinPepperSecurityLevel()

        // Whatever the emulator provides, the query must resolve it. UNKNOWN here would mean the
        // KeyInfo lookup itself is broken, and every posture claim built on it is unfounded.
        assertNotEquals(
            "a key that exists must report where it lives, or nothing may be claimed about it",
            PepperSecurityLevel.UNKNOWN,
            level,
        )
    }

    @Test
    fun unknownIsNeverCountedAsHardwareBacked() {
        // Never round an unproven safety property up. UNKNOWN means the Keystore would not say,
        // and "would not say" is not "yes".
        assertEquals(false, PepperSecurityLevel.UNKNOWN.isHardwareBacked())
        assertEquals(false, PepperSecurityLevel.SOFTWARE.isHardwareBacked())
        assertEquals(true, PepperSecurityLevel.TRUSTED_ENVIRONMENT.isHardwareBacked())
        assertEquals(true, PepperSecurityLevel.STRONGBOX.isHardwareBacked())
    }

    @org.junit.After
    fun restorePepper() {
        // Other suites derive credential keys against this alias; leaving it destroyed would fail
        // them for a reason that is not theirs.
        KeystorePinPepper.ensureExists()
    }
}
