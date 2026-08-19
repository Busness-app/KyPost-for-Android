package org.kysecurity.mail.contacts

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/** Patterns.EMAIL_ADDRESS is unusable in JVM unit tests, so this coverage lives here. */
@RunWith(AndroidJUnit4::class)
class RecipientMatchingInstrumentedTest {

    @Test
    fun isValidEmailFormat_rejectsMalformedAddresses() {
        assertTrue(isValidEmailFormat("ada@example.com"))
        assertFalse(isValidEmailFormat("not-an-email"))
        assertFalse(isValidEmailFormat("ada@"))
        assertFalse(isValidEmailFormat(""))
    }
}
