package org.kysecurity.mail.pgp

import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class EnrollmentStateTest {

    private val vault = EnrollmentVault(ApplicationProvider.getApplicationContext())

    // Block body, not an expression body: destroy() returns the steps it could not
    // complete, and JUnit requires @Before/@After to return void.
    @Before fun clean() { vault.destroy() }
    @After fun cleanup() { vault.destroy() }

    @Test
    fun noKeyReportsNotEnrolled() {
        assertEquals(EnrollmentStatus.NO_KEY, probeEnrollment(vault))
    }

    /** A key with no sealed blob is not enrollment. This is the app-reinstall shape: the Keystore
     *  can be repopulated while the blob is gone. */
    @Test
    fun keyWithoutBlobReportsNotEnrolled() {
        vault.ensureKey()
        assertEquals(EnrollmentStatus.NO_BLOB, probeEnrollment(vault))
    }

    /** The probe runs from a background worker, so it must report ENROLLED with no prompt. */
    @Test
    fun healthyLockedKeyReportsEnrolledWithoutAPrompt() {
        vault.ensureKey()
        vault.store(ByteArray(12) { 3 }, ByteArray(48) { 4 })

        assertEquals(EnrollmentStatus.ENROLLED, probeEnrollment(vault))
    }

    /** Follows reality DOWN, not just up. */
    @Test
    fun destroyedKeyReportsNotEnrolled() {
        vault.ensureKey()
        vault.store(ByteArray(12), ByteArray(48))
        vault.destroy()

        assertEquals(EnrollmentStatus.NO_KEY, probeEnrollment(vault))
    }

    /** Cipher.init on GCM succeeds against any key, so a fresh key must never keep an old blob. */
    @Test
    fun regeneratingTheKeyDiscardsABlobItCannotOpen() {
        vault.ensureKey()
        vault.store(ByteArray(12) { 7 }, ByteArray(48) { 8 })
        assertEquals(EnrollmentStatus.ENROLLED, probeEnrollment(vault))

        // Exactly what the OS does when the lock screen is removed: the alias goes, the blob stays.
        java.security.KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            .deleteEntry(EnrollmentVault.ALIAS)
        assertEquals(EnrollmentStatus.NO_KEY, probeEnrollment(vault))

        vault.ensureKey()

        assertEquals(
            "a newly minted key must not inherit a blob sealed under the destroyed one",
            EnrollmentStatus.NO_BLOB,
            probeEnrollment(vault),
        )
    }
}
