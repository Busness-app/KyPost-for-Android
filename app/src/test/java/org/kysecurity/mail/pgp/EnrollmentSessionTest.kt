package org.kysecurity.mail.pgp

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

    /**
     * The holder must be reachable from the process-wide reset, not only from the app lock.
     *
     * `ProcessState.resetAll()` is what the security wipe, `AppRestart.relaunch` and the unpair
     * purge all go through, and it resets only holders that registered. An unregistered holder is
     * not merely missed — `resetAll()` returns it in no failure list, so the wipe's
     * `step("inMemoryPlaintext")` records success and the wipe reports Complete with the account's
     * opened private key still in the heap of a process the relaunch does not kill.
     */
    @Test
    fun theProcessWideResetClearsIt() {
        EnrollmentSession.put("-----BEGIN PGP PRIVATE KEY BLOCK-----")

        val failed = org.kysecurity.mail.ProcessState.resetAll()

        assertNull(EnrollmentSession.peek())
        assertEquals(emptyList<String>(), failed)
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
