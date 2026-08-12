package org.kysecurity.mail.contacts

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/** [isValidEmailFormat] wraps [android.util.Patterns.EMAIL_ADDRESS], a real Android framework
 *  class — its static fields aren't initialized under the plain-JUnit `app/src/test` stub jar
 *  (see `app/src/test/AGENTS.md`: "Avoid ... Android framework dependencies in JVM unit tests"),
 *  so this coverage lives here instead. */
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
