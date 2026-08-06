package com.urlxl.mail.pgp

import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class EnrollmentSessionTest {

    @After fun cleanup() = EnrollmentSession.clear()

    @Test
    fun holdsTheKeyForTheSession() {
        EnrollmentSession.put("-----BEGIN PGP PRIVATE KEY BLOCK-----")
        assertEquals("-----BEGIN PGP PRIVATE KEY BLOCK-----", EnrollmentSession.peek())
    }

    @Test
    fun clearForgetsIt() {
        EnrollmentSession.put("secret")
        EnrollmentSession.clear()
        assertNull(EnrollmentSession.peek())
    }

    /** Zeroed in place, not merely dereferenced: a String's backing array cannot be wiped, so a
     *  heap dump taken after the app locked would still hold the private key. */
    @Test
    fun clearZeroesTheBackingArray() {
        EnrollmentSession.put("secret")
        val held = EnrollmentSession.backingArrayForTest()
        EnrollmentSession.clear()
        assertEquals("      ", String(held))
    }

    /** Replacing one key must not strand the previous one in the heap — re-running the ceremony is
     *  an ordinary thing to do, and it would leave a copy per attempt. */
    @Test
    fun putZeroesWhatItReplaces() {
        EnrollmentSession.put("first!")
        val first = EnrollmentSession.backingArrayForTest()

        EnrollmentSession.put("second")

        assertEquals("      ", String(first))
        assertEquals("second", EnrollmentSession.peek())
    }
}
