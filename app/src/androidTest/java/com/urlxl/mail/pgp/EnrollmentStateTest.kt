package com.urlxl.mail.pgp

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

    @Before fun clean() = vault.destroy()
    @After fun cleanup() = vault.destroy()

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

    /**
     * The load-bearing case: a healthy, merely-locked key must report ENROLLED **without any user
     * authentication**, because this probe runs from a background worker where nothing can show a
     * prompt. If this fails, the spec's decision 4 needs revisiting before the reporting path is
     * trusted — see the note in this task.
     */
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
}
