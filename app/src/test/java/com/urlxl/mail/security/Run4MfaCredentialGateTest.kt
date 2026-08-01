package com.urlxl.mail.security

import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Regression tests for the credential-gate MFA path.
 *
 * Covers the state `MfaApprovalActivity.promptAppLockPin` lands in when the credential PIN gate is
 * on and the app is locked — which its own KDoc calls the normal case for an MFA challenge. A
 * notification tap does not unlock the app, so `cachedCredentialKeys()` correctly returns null
 * throughout; the key the just-authenticated decision needs comes from `credentialKeysForDecision()`
 * instead. Before that split existed, every gated approve *and deny* died locally in
 * `MfaResponseClient` with "Device is not registered yet" and no request ever left the device — a
 * user who knew a sign-in was hostile could not deny it.
 */
private class GateState(
    private var lockEnabled: Boolean = true,
    private var pin: String? = "48291374",
    private var credentialSalt: ByteArray? = null,
    private var credentialGateEnabled: Boolean = true,
) : AppLockState {
    private var biometricEnabled = false
    private var failedAttempts = 0
    private var lockoutUntilElapsed = 0L
    private var lockoutDuration = 0L

    override fun isLockEnabled() = lockEnabled
    override fun setLockEnabled(enabled: Boolean) { lockEnabled = enabled }
    override fun isBiometricEnabled() = biometricEnabled
    override fun setBiometricEnabled(enabled: Boolean) { biometricEnabled = enabled }
    override fun isCredentialPinGateEnabled() = credentialGateEnabled
    override fun setCredentialPinGateEnabled(enabled: Boolean) { credentialGateEnabled = enabled }
    override fun setPin(pin: String) { this.pin = pin }
    override fun verifyPin(pin: String): Boolean = this.pin == pin
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
    override fun reset() = Unit
}

private object GatePepper : CredentialPepper {
    override fun mix(derived: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec("run4-pepper".toByteArray(), "HmacSHA256"))
        return mac.doFinal(derived)
    }
}

class Run4MfaCredentialGateTest {

    private fun manager(state: GateState) = AppLockManager(
        state = state,
        elapsedRealtimeMs = { 1_000L },
        pepper = GatePepper,
        onWipe = { WipeResult.Complete },
    )

    /**
     * The exact call MfaApprovalActivity.promptAppLockPin makes when credentialGateNeedsPin() is
     * true: the PIN verifies, the key is derived, and the decision is sendable — while the app stays
     * locked, so nothing else in the process gains access to the mailbox.
     */
    @Test
    fun mfaPinYieldsASendableDecisionWithoutUnlockingTheApp() = runBlocking {
        val state = GateState()
        val m = manager(state)

        // Fresh process, lock enabled -> AppLockManager starts locked, exactly as an FCM-delivery
        // process does.
        assertTrue("fresh process must start locked", m.isLockedNow())
        assertNull("credentialGateNeedsPin() precondition", m.cachedCredentialKeys())

        val result = m.deriveAndCacheCredentialKeys("48291374")
        assertTrue("correct PIN must verify", result is UnlockAttemptResult.Success)

        // MfaApprovalActivity captures this and hands it to MfaResponder, which passes it to
        // PushRepository.pairingForAuthenticatedCall(keys).
        assertNotNull(
            "the just-authenticated decision must be sendable",
            m.credentialKeysForDecision(),
        )

        // ...and none of that unlocks the app. A notification tap must not open the mailbox, and
        // background sync must still be withheld from the credential.
        assertTrue("the app stays locked", m.isLockedNow())
        assertNull("background consumers still get nothing", m.cachedCredentialKeys())
    }

    /** A wrong PIN derives nothing, so there is no decision key to capture. */
    @Test
    fun aWrongPinYieldsNoDecisionKey() = runBlocking {
        val state = GateState()
        val m = manager(state)

        val result = m.deriveAndCacheCredentialKeys("00000000")
        assertTrue(result is UnlockAttemptResult.Rejected)
        assertNull("no key may be derived from an unverified PIN", m.credentialKeysForDecision())
    }

    /** The contrast: the unlock screen's path clears _locked first, so the same key is usable. */
    @Test
    fun theUnlockScreenPathYieldsAUsableCredential() = runBlocking {
        val state = GateState()
        val m = manager(state)

        val result = m.attemptPin("48291374")
        assertTrue(result is UnlockAttemptResult.Success)
        assertNotNull("attemptPin unlocks first, so the key is readable", m.cachedCredentialKeys())
    }

    /** The other branch of credentialGateNeedsPin(): unlocked by biometric, so no PIN key cached.
     *  Here the MFA PIN prompt does work, which is why the bug above is easy to miss. */
    @Test
    fun theBiometricOnlySessionBranchDoesWork() = runBlocking {
        val state = GateState()
        val m = manager(state)
        m.unlockWithBiometric()
        assertNull("biometric unlock derives no PIN key", m.cachedCredentialKeys())

        val result = m.deriveAndCacheCredentialKeys("48291374")
        assertTrue(result is UnlockAttemptResult.Success)
        assertNotNull("unlocked already, so the derived key is readable", m.cachedCredentialKeys())
    }
}
