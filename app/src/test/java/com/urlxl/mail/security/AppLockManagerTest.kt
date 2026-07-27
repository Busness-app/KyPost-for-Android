package com.urlxl.mail.security

import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/** In-memory [AppLockState] test double — lets [AppLockManager] be unit-tested without a real
 *  Context/Keystore, matching how [AppLockStore] backs the real interface. */
private class FakeAppLockState(
    private var lockEnabled: Boolean = true,
    private var pin: String? = "482913",
    private var credentialSalt: ByteArray? = null,
) : AppLockState {
    private var biometricEnabled = false
    private var credentialGateEnabled = false
    var failedAttempts = 0
        private set
    private var lockoutUntilElapsed = 0L
    private var lockoutDuration = 0L

    override fun isLockEnabled() = lockEnabled
    override fun setLockEnabled(enabled: Boolean) { lockEnabled = enabled }
    override fun isBiometricEnabled() = biometricEnabled
    override fun setBiometricEnabled(enabled: Boolean) { biometricEnabled = enabled }
    override fun isCredentialPinGateEnabled() = credentialGateEnabled
    override fun setCredentialPinGateEnabled(enabled: Boolean) { credentialGateEnabled = enabled }
    override fun setPin(pin: String) { this.pin = pin }
    override fun verifyPin(pin: String) = this.pin == pin
    override fun hasPin() = pin != null
    override fun incrementFailedAttempts(): Int { failedAttempts++; return failedAttempts }
    override fun resetFailedAttempts() { failedAttempts = 0; lockoutUntilElapsed = 0L; lockoutDuration = 0L }
    override fun lockoutUntilElapsedMs() = lockoutUntilElapsed
    override fun lockoutDurationMs() = lockoutDuration
    override fun setLockout(untilElapsedMs: Long, durationMs: Long) {
        lockoutUntilElapsed = untilElapsedMs
        lockoutDuration = durationMs
    }
    override fun credentialSalt() = credentialSalt
    override fun setCredentialSalt(salt: ByteArray) { credentialSalt = salt }
    override fun reset() {
        lockEnabled = false; pin = null; biometricEnabled = false; credentialGateEnabled = false
        failedAttempts = 0; lockoutUntilElapsed = 0L; lockoutDuration = 0L
    }
}

/** JVM tests have no AndroidKeyStore, so credential-key derivation gets a fixed pepper. */
private object TestPepper : CredentialPepper {
    override fun mix(derived: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec("test-pepper".toByteArray(), "HmacSHA256"))
        return mac.doFinal(derived)
    }
}

class AppLockManagerTest {
    private lateinit var state: FakeAppLockState
    private var wipeCount = 0
    private var wipeResult: WipeResult = WipeResult.Complete
    private var clock = 1_000L
    private lateinit var manager: AppLockManager

    private fun newManager(withState: FakeAppLockState = state) = AppLockManager(
        state = withState,
        elapsedRealtimeMs = { clock },
        pepper = TestPepper,
        onWipe = { wipeCount++; wipeResult },
    )

    @Before
    fun setUp() {
        state = FakeAppLockState()
        wipeCount = 0
        wipeResult = WipeResult.Complete
        clock = 1_000L
        manager = newManager()
    }

    @Test
    fun locked_startsTrue_whenLockEnabled() {
        assertTrue(manager.locked.value)
    }

    @Test
    fun locked_startsFalse_whenLockDisabled() {
        assertFalse(newManager(FakeAppLockState(lockEnabled = false)).locked.value)
    }

    @Test
    fun attemptPin_withCorrectPin_unlocksAndResetsAttempts() = runBlocking {
        assertEquals(UnlockAttemptResult.Success, manager.attemptPin("482913"))
        assertFalse(manager.locked.value)
        assertEquals(0, state.failedAttempts)
    }

    @Test
    fun attemptPin_withWrongPin_staysLockedAndNoDelayFirstTwoTimes() = runBlocking {
        val first = manager.attemptPin("000001")
        assertTrue(first is UnlockAttemptResult.Rejected)
        assertEquals(0L, (first as UnlockAttemptResult.Rejected).delayMillis)
        assertTrue(manager.locked.value)
    }

    @Test
    fun attemptPin_escalatesDelay_fromThirdWrongAttempt() = runBlocking {
        repeat(2) { manager.attemptPin("000001") }
        val third = manager.attemptPin("000001") as UnlockAttemptResult.Rejected
        assertEquals(30_000L, third.delayMillis)
    }

    @Test
    fun attemptPin_wipes_afterTenWrongAttempts() = runBlocking {
        repeat(9) {
            manager.attemptPin("000001")
            // Step past each escalating lockout so the attempts actually land.
            clock += 60 * 60_000L
        }
        assertEquals(UnlockAttemptResult.Wiped, manager.attemptPin("000001"))
        assertEquals(1, wipeCount)
    }

    /** A wipe that fails a step must not be reported as a completed wipe: the UI would otherwise
     *  show the same clean first-run state while the cached mail is still on disk. */
    @Test
    fun attemptPin_reportsWipeFailed_whenTheWipeDidNotComplete() = runBlocking {
        wipeResult = WipeResult.Incomplete(listOf("database"))
        repeat(9) {
            manager.attemptPin("000001")
            clock += 60 * 60_000L
        }

        val result = manager.attemptPin("000001")

        assertTrue("expected WipeFailed, got $result", result is UnlockAttemptResult.WipeFailed)
        assertEquals(listOf("database"), (result as UnlockAttemptResult.WipeFailed).failedSteps)
        assertEquals(1, wipeCount)
    }

    // --- Lockout enforcement lives in the manager, not in the view -----------------------------

    @Test
    fun attemptPin_isRejectedWithoutConsumingAnAttempt_whileLockedOut() = runBlocking {
        repeat(3) { manager.attemptPin("000001") }
        val attemptsAfterLockout = state.failedAttempts

        // No clock advance: the lockout from the third wrong attempt is still active.
        val duringLockout = manager.attemptPin("000001")

        assertTrue(duringLockout is UnlockAttemptResult.Rejected)
        assertTrue((duringLockout as UnlockAttemptResult.Rejected).delayMillis > 0)
        assertEquals(attemptsAfterLockout, state.failedAttempts)
    }

    @Test
    fun attemptPin_refusesTheCorrectPinToo_whileLockedOut() = runBlocking {
        repeat(3) { manager.attemptPin("000001") }

        // The throttle is not a "wrong PIN" penalty that a lucky guess can skip past — while it is
        // active nothing is verified at all.
        assertTrue(manager.attemptPin("482913") is UnlockAttemptResult.Rejected)
        assertTrue(manager.locked.value)
    }

    @Test
    fun attemptPin_succeedsAgain_onceTheLockoutHasElapsed() = runBlocking {
        repeat(3) { manager.attemptPin("000001") }
        clock += 30_000L

        assertEquals(UnlockAttemptResult.Success, manager.attemptPin("482913"))
    }

    @Test
    fun remainingLockout_isClampedToTheStoredDuration_afterAMonotonicClockReset() = runBlocking {
        repeat(3) { manager.attemptPin("000001") }
        assertEquals(30_000L, manager.remainingLockoutMillis())

        // A reboot restarts elapsedRealtime at zero, which naively reads as "the whole previous
        // uptime still to go". Clamping keeps it bounded at the delay that was actually applied.
        clock = 0L
        assertEquals(30_000L, manager.remainingLockoutMillis())
    }

    @Test
    fun remainingLockout_isZero_whenNoLockoutWasEverSet() {
        assertEquals(0L, manager.remainingLockoutMillis())
    }

    // --- Background grace window --------------------------------------------------------------

    @Test
    fun isLockedNow_staysFalse_insideTheGraceWindow() = runBlocking {
        manager.attemptPin("482913")
        assertFalse(manager.isLockedNow())

        manager.scheduleLock(clock + 30_000L)
        clock += 29_999L

        assertFalse("the grace window has not expired yet", manager.isLockedNow())
    }

    @Test
    fun isLockedNow_locksOnceTheGraceWindowExpires_withoutLockNowEverBeingCalled() = runBlocking {
        manager.attemptPin("482913")
        manager.scheduleLock(clock + 30_000L)

        clock += 30_000L

        // The whole point: nothing called lockNow(). KyPostApp's Handler runs on uptimeMillis,
        // which does not advance in deep sleep, so on a pocketed phone it may not have fired.
        // Before this existed, `locked` stayed false for the entire time the app was backgrounded,
        // and PushNotificationDispatcher put the sender and subject on the lock screen in full.
        assertTrue(manager.isLockedNow())
        assertTrue("the observable flow must catch up too", manager.locked.value)
    }

    @Test
    fun isLockedNow_dropsCachedCredentialKeys_whenTheGraceWindowExpires() = runBlocking {
        val salt = CredentialCipher.randomSalt()
        val gated = FakeAppLockState(credentialSalt = salt).apply { setCredentialPinGateEnabled(true) }
        val gatedManager = newManager(gated)
        gatedManager.attemptPin("482913")
        assertTrue(gatedManager.cachedCredentialKeys() != null)

        gatedManager.scheduleLock(clock + 30_000L)
        clock += 30_000L

        // The credential gate is meant to withhold the device secret from a backgrounded app;
        // holding the keys until something called lockNow() left it open indefinitely.
        assertTrue(gatedManager.cachedCredentialKeys() == null)
    }

    @Test
    fun cancelScheduledLock_disarmsAnExpiredWindow_forAnAppThatCameBack() = runBlocking {
        manager.attemptPin("482913")
        manager.scheduleLock(clock + 30_000L)

        manager.cancelScheduledLock()
        clock += 60_000L

        assertFalse("returning to the foreground inside the window must not lock later", manager.isLockedNow())
    }

    @Test
    fun isLockedNow_ignoresTheDeadline_whenTheLockIsDisabled() {
        val open = newManager(FakeAppLockState(lockEnabled = false))
        open.scheduleLock(clock + 1_000L)
        clock += 1_000L

        assertFalse(open.isLockedNow())
    }

    // --- Credential keys ----------------------------------------------------------------------

    @Test
    fun attemptPin_withCredentialGateEnabled_cachesDerivedKeys_untilLocked() = runBlocking {
        val salt = CredentialCipher.randomSalt()
        val gated = FakeAppLockState(credentialSalt = salt).apply { setCredentialPinGateEnabled(true) }
        val gatedManager = newManager(gated)

        gatedManager.attemptPin("482913")
        assertTrue(gatedManager.cachedCredentialKeys() != null)

        gatedManager.lockNow()
        assertTrue(gatedManager.cachedCredentialKeys() == null)
    }

    @Test
    fun attemptPin_withCredentialGateEnabled_andNoExistingSalt_generatesAndPersistsSalt() = runBlocking {
        val gated = FakeAppLockState().apply { setCredentialPinGateEnabled(true) }
        val gatedManager = newManager(gated)
        assertTrue(gated.credentialSalt() == null)

        gatedManager.attemptPin("482913")

        assertTrue(gatedManager.cachedCredentialKeys() != null)
        assertTrue(gated.credentialSalt() != null)
    }

    @Test
    fun attemptPin_withCredentialGateDisabled_neverCachesKeys() = runBlocking {
        manager.attemptPin("482913")
        assertTrue(manager.cachedCredentialKeys() == null)
    }

    @Test
    fun deriveAndCacheCredentialKeys_refusesAnUnverifiedPin() = runBlocking {
        assertFalse(manager.deriveAndCacheCredentialKeys("000001"))
        assertTrue(manager.cachedCredentialKeys() == null)
    }
}
