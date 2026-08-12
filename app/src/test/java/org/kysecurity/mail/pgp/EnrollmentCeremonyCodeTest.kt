package org.kysecurity.mail.pgp

import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Base64

/**
 * The published key, the displayed code, and the polling window.
 *
 * Every assertion here distinguishes a correct implementation from a plausible wrong one. Audit
 * run-6 found the previous plan's Task 7 asserting `WorkInfo.progress`, which is empty for every
 * worker ever enqueued — it would have passed against a credential leak.
 */
class EnrollmentCeremonyCodeTest {

    private fun bucketOf(ports: FakePorts): Long = ports.clock.epochSeconds() / 120L

    /**
     * **The one security property the device half owns.**
     *
     * The browser derives its code from the key the *server* handed it and refuses to seal unless
     * the two match. If this device ever derived from a server-supplied value — or from a cached
     * copy of what it published — the comparison would compare the server against itself and the
     * whole control would be decoration.
     *
     * [FakeEnrollmentKeys] returns a different point from `rawPublicKey()` than the one
     * `encodedPublicKey()` base64s, so "derived from the keystore" and "derived from what was
     * published" are different strings. That is what makes this test able to fail.
     */
    @Test
    fun theCodeDerivesFromTheKeystoreKeyAndNotFromWhatWasPublished() = runBlocking {
        val ports = FakePorts()
        val bucket = bucketOf(ports)

        ports.ceremony().run()

        val shown = ports.states.filterIsInstance<EnrollmentUiState.ShowingCode>().first()
        val fromKeystore = deviceEnrollmentCode(ports.keys.keystorePoint, "dev-1", bucket)
        assertEquals(fromKeystore, shown.code)

        val published = Base64.getDecoder().decode(ports.transport.publishedKeys.single())
        val fromPublished = deviceEnrollmentCode(published, "dev-1", bucket)
        assertNotEquals(
            "the code must not be derivable from the published value",
            fromPublished,
            shown.code,
        )
    }

    /**
     * Any write to the account's PGP identity clears the stored key server-side, so a device that
     * published only at pairing fails silently after a rotation — the user sees a code, types it,
     * and nothing ever arrives.
     */
    @Test
    fun theKeyIsPublishedOnEveryCeremonyNotOnce() = runBlocking {
        val ports = FakePorts()

        ports.ceremony().run()
        ports.ceremony().run()

        assertEquals(2, ports.transport.publishedKeys.size)
        assertEquals("each ceremony mints a fresh keypair", 2, ports.keys.newKeyPairCalls)
    }

    /**
     * Three buckets are crossed in a five-minute window (0s, 120s, 240s), so exactly three codes are
     * shown. Fewer means the code went stale on screen while the browser had moved on; more means it
     * is being recomputed off the boundary, and the user is re-reading a code for no reason.
     */
    @Test
    fun theCodeRecomputesOnTheBucketBoundaryAndNotBefore() = runBlocking {
        val ports = FakePorts()

        ports.ceremony().run()

        val shown = ports.states.filterIsInstance<EnrollmentUiState.ShowingCode>()
        assertEquals(3, shown.size)
        assertEquals("each bucket gives a different code", 3, shown.map { it.code }.toSet().size)
    }

    /** The countdown has to point at the end of the current bucket, not at a fixed offset. */
    @Test
    fun theExpiryIsTheEndOfTheCurrentBucket() = runBlocking {
        val ports = FakePorts()
        val bucket = bucketOf(ports)

        ports.ceremony().run()

        val shown = ports.states.filterIsInstance<EnrollmentUiState.ShowingCode>().first()
        assertEquals((bucket + 1) * 120L * 1_000L, shown.expiresAtEpochMs)
    }

    /**
     * The window is bounded, and the bound is not cosmetic: the screen holds a published enrollment
     * key and a code the user is reading aloud, and spec 1 requires `deleteKeyPair()` on the exits of
     * a ceremony — so there has to *be* a defined exit rather than a loop that runs until the process
     * dies.
     *
     * 300 seconds at 3-second intervals is exactly 100 attempts.
     */
    @Test
    fun pollingStopsAtTheDeadline() = runBlocking {
        val ports = FakePorts()

        ports.ceremony().run()

        assertEquals(100, ports.transport.fetchCalls)
        assertTrue(ports.states.last() is EnrollmentUiState.WaitingTimedOut)
        assertTrue("every wait is the 3-second interval", ports.clock.sleeps.all { it == 3_000L })
    }

    /**
     * A resumed window must put a code back on screen **before it does anything else.**
     *
     * `shownBucket` is instance state that survives the loop, so a window reopened in the same bucket
     * it closed in finds it unchanged and emits nothing. The screen then stays on `WaitingTimedOut` —
     * "Nothing has arrived in the last five minutes" — while a window runs silently behind it, and
     * the state that says the ceremony is *waiting on the browser* never appears. `poll()` resets
     * `shownBucket` on entry to prevent it.
     *
     * The two existing tests cannot catch a missing reset and both pass without it:
     * `theCodeRecomputesOnTheBucketBoundaryAndNotBefore` sees the same emissions either way because
     * the first window already starts at `Long.MIN_VALUE`, and
     * `checkAgainOpensAFreshWindowAgainstTheSameKeypair` derives its expected bucket *from the
     * emission it receives*, so it cannot notice one that never arrived.
     *
     * The envelope is made to arrive on the resumed window's FIRST fetch. That is what makes this
     * decisive rather than merely slow: with the reset the next state is `ShowingCode`, without it
     * the ceremony goes straight to `Opening` and no code is ever re-shown.
     */
    @Test
    fun aResumedWindowShowsACodeBeforeItPolls() = runBlocking {
        val ports = FakePorts()
        val ceremony = ports.ceremony()

        ceremony.run()
        assertTrue(ports.states.last() is EnrollmentUiState.WaitingTimedOut)

        // Same bucket the window closed in: the clock is not advanced here on purpose. A test that
        // advanced it would cross a boundary, the bucket would differ, and the emission would happen
        // with or without the reset — which is exactly how this fix came to have no test.
        val probe = FakeEnrollmentKeys()
        ports.transport.fetchWhenExhausted =
            EnrollmentCallResult.Envelope(sealEnvelope(probe))
        val afterTimeout = ports.states.size

        ceremony.checkAgain()

        assertTrue(
            "the resumed window must re-show the code before polling; without poll()'s shownBucket " +
                "reset the screen is left on WaitingTimedOut and jumps straight to ${ports.states[afterTimeout]}",
            ports.states[afterTimeout] is EnrollmentUiState.ShowingCode,
        )
    }

    /**
     * **"Check again" resumes; it does not restart.**
     *
     * A restart would rotate the key, which would invalidate the code the user may have already
     * typed into the browser. Leaving the screen and re-entering is the restart, and that path does
     * rotate.
     */
    @Test
    fun checkAgainOpensAFreshWindowAgainstTheSameKeypair() = runBlocking {
        val ports = FakePorts()
        val ceremony = ports.ceremony()

        ceremony.run()
        val statesBeforeResume = ports.states.size

        ceremony.checkAgain()

        assertEquals("a second full window ran", 200, ports.transport.fetchCalls)
        assertEquals("the key must not be re-minted", 1, ports.keys.newKeyPairCalls)
        assertEquals("the key must not be republished", 1, ports.transport.publishedKeys.size)

        // The code itself still rotates with the 120-second bucket — that is not a restart, and
        // the browser accepts the current bucket. What must not change is the key BEHIND it, so
        // the assertion is that the resumed code is still derivable from the same keystore point.
        val resumed = ports.states.drop(statesBeforeResume)
            .filterIsInstance<EnrollmentUiState.ShowingCode>()
            .first()
        val resumedBucket = resumed.expiresAtEpochMs / 1_000L / 120L - 1L
        assertEquals(
            "the resumed code must come from the same keypair the user already read",
            deviceEnrollmentCode(ports.keys.keystorePoint, "dev-1", resumedBucket),
            resumed.code,
        )
    }

    /** 404 is "never sealed" and "expired" collapsed into one result by design. Both mean keep
     *  waiting, not fail. */
    @Test
    fun aNotFoundKeepsWaiting() = runBlocking {
        val ports = FakePorts(
            fetchResults = mutableListOf(
                EnrollmentCallResult.NotFound,
                EnrollmentCallResult.NotFound,
                EnrollmentCallResult.Envelope("{}"),
            ),
        )

        ports.ceremony().run()

        assertEquals(3, ports.transport.fetchCalls)
        assertTrue(ports.states.any { it is EnrollmentUiState.Opening })
    }

    /** A transient network failure or a 429 mid-window is not a reason to tear down a ceremony the
     *  user is halfway through typing. */
    @Test
    fun aTransientFailureOrRateLimitKeepsWaiting() = runBlocking {
        val ports = FakePorts(
            fetchResults = mutableListOf(
                EnrollmentCallResult.Failed("connection reset"),
                EnrollmentCallResult.RateLimited(5L),
                EnrollmentCallResult.Envelope("{}"),
            ),
        )

        ports.ceremony().run()

        assertEquals(3, ports.transport.fetchCalls)
        // Up to the point the envelope arrives. What happens to a `{}` envelope afterwards is
        // Task 5's business, and this test must not start asserting it.
        assertTrue(
            ports.states.takeWhile { it !is EnrollmentUiState.Opening }
                .none { it is EnrollmentUiState.Failed },
        )
    }

    /** A credential the server refuses will not start working, and the ceremony holds a published
     *  key that must not be left behind. */
    @Test
    fun a401WhilePollingFailsAndDestroysTheKeypair() = runBlocking {
        val ports = FakePorts(
            fetchResults = mutableListOf(EnrollmentCallResult.Unauthorized),
        )

        ports.ceremony().run()

        assertEquals(
            EnrollmentUiState.Failed(FailureReason.UNAUTHORIZED),
            ports.states.last(),
        )
        assertEquals(1, ports.keys.deleteCalls)
    }

    @Test
    fun aRejectedPublishFailsAndDestroysTheKeypair() = runBlocking {
        val ports = FakePorts(publishResult = EnrollmentCallResult.Failed("boom"))

        ports.ceremony().run()

        assertEquals(
            EnrollmentUiState.Failed(FailureReason.PUBLISH_REJECTED),
            ports.states.last(),
        )
        assertEquals(1, ports.keys.deleteCalls)
        assertEquals("nothing may be polled for", 0, ports.transport.fetchCalls)
    }

    @Test
    fun a401OnPublishIsItsOwnReason() = runBlocking {
        val ports = FakePorts(publishResult = EnrollmentCallResult.Unauthorized)

        ports.ceremony().run()

        assertEquals(EnrollmentUiState.Failed(FailureReason.UNAUTHORIZED), ports.states.last())
    }

    @Test
    fun a429OnPublishIsItsOwnReason() = runBlocking {
        val ports = FakePorts(publishResult = EnrollmentCallResult.RateLimited(30L))

        ports.ceremony().run()

        assertEquals(EnrollmentUiState.Failed(FailureReason.RATE_LIMITED), ports.states.last())
    }
}
