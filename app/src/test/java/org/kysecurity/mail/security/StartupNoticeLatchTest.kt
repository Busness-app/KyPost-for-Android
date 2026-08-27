package org.kysecurity.mail.security

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger

/** [claimNotice] is the gate LockedActivity's startup notices go through. The bug it exists for:
 *  the credential-reset dialog was built by the screen that was on its way to UnlockActivity, so
 *  it died with that finishing Activity while the process-wide latch stayed set — and a database
 *  key reset ("your cached mail is gone") was never shown to anyone with the app lock on. */
class StartupNoticeLatchTest {

    @Test
    fun aScreenThatCannotShowTheNoticeDoesNotSpendTheLatch() {
        val latch = AtomicBoolean(false)

        assertFalse(claimNotice(pending = true, canShow = false, latch = latch))

        assertFalse("the latch must be left for a screen that can actually show it", latch.get())
    }

    /** The regression: locked launch -> UnlockActivity -> a real screen must still get the notice. */
    @Test
    fun theNoticeSurvivesAnUnlockRoundTrip() {
        val latch = AtomicBoolean(false)

        // The screen that bounces to UnlockActivity.
        assertFalse(claimNotice(pending = true, canShow = false, latch = latch))
        // MainActivity, recreated after the unlock.
        assertTrue(claimNotice(pending = true, canShow = true, latch = latch))
    }

    @Test
    fun theNoticeIsShownOnlyOncePerSession() {
        val latch = AtomicBoolean(false)

        assertTrue(claimNotice(pending = true, canShow = true, latch = latch))
        // Rotation, a second screen, resume: the pref stays set until the user taps OK.
        assertFalse(claimNotice(pending = true, canShow = true, latch = latch))
        assertFalse(claimNotice(pending = true, canShow = true, latch = latch))
    }

    @Test
    fun nothingPendingLeavesTheLatchForALaterReset() {
        val latch = AtomicBoolean(false)

        assertFalse(claimNotice(pending = false, canShow = true, latch = latch))

        assertFalse(latch.get())
        assertTrue("a reset recorded later must still be reportable", claimNotice(true, true, latch))
    }

    /** A resumed and a starting Activity can reach this on the same process; exactly one dialog. */
    @Test
    fun onlyOneOfManyConcurrentScreensClaimsTheNotice() {
        val latch = AtomicBoolean(false)
        val claims = AtomicInteger(0)
        val start = CountDownLatch(1)
        val pool = Executors.newFixedThreadPool(8)
        try {
            val done = CountDownLatch(8)
            repeat(8) {
                pool.execute {
                    start.await()
                    if (claimNotice(pending = true, canShow = true, latch = latch)) claims.incrementAndGet()
                    done.countDown()
                }
            }
            start.countDown()
            assertTrue(done.await(10, TimeUnit.SECONDS))
        } finally {
            pool.shutdownNow()
        }

        assertEquals(1, claims.get())
    }
}
