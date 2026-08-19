package org.kysecurity.mail.pgp

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.kysecurity.mail.R
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

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

    /** The device HOLDS a key it does not yet USE, so no copy may promise reading mail here. */
    @Test
    fun noStringClaimsThisDeviceCanReadEncryptedMail() {
        val all = rowCopy.values.map { context.getString(it) } + listOf(
            context.getString(R.string.enrollment_enrolled),
            context.getString(R.string.enrollment_enrolled_detail),
            context.getString(R.string.enrollment_code_intro),
        )
        // Device-scoped only: account rows may say "your account doesn't use encrypted mail yet".
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
