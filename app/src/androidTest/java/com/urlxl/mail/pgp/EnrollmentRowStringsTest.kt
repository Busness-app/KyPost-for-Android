package com.urlxl.mail.pgp

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.urlxl.mail.R
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Every state a user can be shown has real, distinct copy.
 *
 * Not an `ActivityScenario` walk: driving `SecuritySettingsActivity` through nine states needs
 * injection points that screen does not have, and this repository has no Activity-launching test to
 * build on. What *can* rot silently is a resource that was never added, a duplicate that makes two
 * different situations read identically, or a string that drifts into promising behaviour the app
 * does not have — and all three are caught here against a real Context.
 *
 * The mapping under test is the one the screens use; if a screen stops using it, that is visible in
 * review rather than here.
 */
@RunWith(AndroidJUnit4::class)
class EnrollmentRowStringsTest {

    private val context: Context = ApplicationProvider.getApplicationContext()

    private val rowCopy: Map<EnrollmentRow, Int> = mapOf(
        EnrollmentRow.HostileLocation to R.string.security_encryption_hostile_location,
        EnrollmentRow.NoSecureLockScreen to R.string.security_encryption_no_lock_screen,
        EnrollmentRow.KeyInvalidated to R.string.security_encryption_invalidated,
        EnrollmentRow.Enrolled to R.string.security_encryption_enrolled,
        EnrollmentRow.ServerHeldKey to R.string.security_encryption_server_held,
        EnrollmentRow.NoIdentity to R.string.security_encryption_no_identity,
        EnrollmentRow.CouldNotCheck to R.string.security_encryption_could_not_check,
        EnrollmentRow.NotEnrolled to R.string.security_encryption_not_enrolled,
    )

    @Test
    fun everyRowHasCopy() {
        for ((row, id) in rowCopy) {
            val text = context.getString(id)
            assertTrue("$row has no copy", text.isNotBlank())
        }
    }

    /** Two rows that read the same are two situations the user cannot tell apart. */
    @Test
    fun noTwoRowsReadTheSame() {
        val rendered = rowCopy.values.map { context.getString(it) }
        assertEquals("every row must be distinguishable", rendered.size, rendered.toSet().size)
    }

    /**
     * **The capability rule, enforced.** A user who completes this ceremony gets a device that HOLDS
     * a key it does not yet USE. Any string here claiming the user can read encrypted mail on this
     * device is false until the deferred decryption work lands.
     */
    @Test
    fun noStringClaimsThisDeviceCanReadEncryptedMail() {
        val all = rowCopy.values.map { context.getString(it) } + listOf(
            context.getString(R.string.enrollment_enrolled),
            context.getString(R.string.enrollment_enrolled_detail),
            context.getString(R.string.enrollment_code_intro),
        )
        // "use encrypted mail on this device" and not the shorter "use encrypted mail": the
        // account-level rows legitimately say "your account doesn't use encrypted mail yet", which
        // is a fact about the account and not a claim about what this device does. What is banned is
        // the device-scoped promise — security_encryption_no_lock_screen used to read "Set a screen
        // lock to use encrypted mail on this device", and a user who followed it through the whole
        // ceremony was then told "You'll still read your encrypted mail in your browser for now".
        val banned = listOf(
            "can read",
            "can now read",
            "able to read",
            "decrypt",
            "use encrypted mail on this device",
        )
        for (text in all) {
            for (phrase in banned) {
                assertFalse(
                    "copy describes behaviour, not capability: \"$text\"",
                    text.lowercase().contains(phrase),
                )
            }
        }
    }

    /** The one failure with its own copy must actually differ from the generic one, and must not
     *  accuse — a key rotation mid-ceremony produces exactly the same failure as a substitution. */
    @Test
    fun theCouldNotOpenCopyIsItsOwnAndDoesNotAccuse() {
        val specific = context.getString(R.string.enrollment_failed_could_not_open)
        val generic = context.getString(R.string.enrollment_failed_generic)

        assertTrue(specific != generic)
        for (word in listOf("attack", "attacker", "tamper", "malicious", "hacked")) {
            assertFalse("the copy must describe, not accuse: $specific", specific.lowercase().contains(word))
        }
    }
}
