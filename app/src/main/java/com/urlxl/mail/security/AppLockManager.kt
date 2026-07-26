package com.urlxl.mail.security

import android.os.SystemClock
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.withContext

sealed class UnlockAttemptResult {
    object Success : UnlockAttemptResult()
    data class Rejected(val delayMillis: Long) : UnlockAttemptResult()
    object Wiped : UnlockAttemptResult()

    /** The wipe threshold was reached and the wipe ran, but at least one step failed — so local
     *  data may still be on disk. Distinct from [Wiped] because the UI must not tell the user
     *  their data is gone when it might not be; see [WipeResult]. */
    data class WipeFailed(val failedSteps: List<String>) : UnlockAttemptResult()
}

/**
 * In-memory app-lock state for the current process — "locked" means "since this process started,
 * has the correct PIN/biometric been presented," it is never persisted. [onWipe] runs
 * [SecurityWipe]'s work; kept as an injected callback rather than a direct dependency so this
 * class stays unit-testable without a Context.
 *
 * [attemptPin] and [deriveAndCacheCredentialKeys] are `suspend` because both run PBKDF2 at 150k
 * iterations (a few hundred ms) and both hit `commit()`-backed Keystore preferences. They used to
 * be called straight from click listeners on the main thread; the wipe path additionally ran a
 * `runBlocking` database teardown there, which is an ANR on the one code path nobody exercises.
 */
class AppLockManager(
    private val state: AppLockState,
    private val elapsedRealtimeMs: () -> Long = SystemClock::elapsedRealtime,
    // Injected so credential-key derivation is exercisable off-device; the default needs a real
    // AndroidKeyStore. See [CredentialPepper].
    private val pepper: CredentialPepper = KeystoreCredentialPepper,
    private val onWipe: suspend () -> WipeResult,
) {
    private val _locked = MutableStateFlow(state.isLockEnabled())
    val locked: StateFlow<Boolean> = _locked.asStateFlow()

    @Volatile
    private var credentialKeys: CredentialKeys? = null

    fun lockNow() {
        if (state.isLockEnabled()) _locked.value = true
        credentialKeys = null
    }

    fun unlockWithBiometric() {
        _locked.value = false
        state.resetFailedAttempts()
        // Biometric unlock can't derive a PIN-based key — the credential gate simply stays
        // unavailable for the rest of this session if the user unlocks via biometric only,
        // exactly as documented: it requires the PIN specifically.
    }

    /**
     * Returns [UnlockAttemptResult.Rejected] with the delay the caller should hold the PIN field
     * disabled for (0 for the first two wrong attempts), or [UnlockAttemptResult.Wiped] once
     * [LockoutPolicy.WIPE_THRESHOLD] consecutive wrong attempts have accumulated — in which case
     * [onWipe] has already run by the time this returns.
     *
     * The active lockout is enforced *here*, not just by the disabled submit button in
     * [UnlockActivity]. Leaving it to the view meant the policy existed only for as long as that
     * one screen remained the only caller, and any second entry point would have been an
     * unthrottled brute-force oracle.
     */
    suspend fun attemptPin(pin: String): UnlockAttemptResult = withContext(Dispatchers.Default) {
        val remaining = remainingLockoutMillis()
        if (remaining > 0) return@withContext UnlockAttemptResult.Rejected(remaining)

        if (state.verifyPin(pin)) {
            state.resetFailedAttempts()
            cacheCredentialKeysIfEnabled(pin)
            _locked.value = false
            return@withContext UnlockAttemptResult.Success
        }

        val attempts = state.incrementFailedAttempts()
        if (LockoutPolicy.shouldWipe(attempts)) {
            return@withContext when (val wipe = onWipe()) {
                is WipeResult.Complete -> UnlockAttemptResult.Wiped
                is WipeResult.Incomplete -> UnlockAttemptResult.WipeFailed(wipe.failedSteps)
            }
        }
        val delay = LockoutPolicy.delayMillisFor(attempts)
        if (delay > 0) state.setLockout(elapsedRealtimeMs() + delay, delay)
        UnlockAttemptResult.Rejected(delay)
    }

    /**
     * How long the PIN field should stay disabled for, or 0 if there's no active lockout.
     *
     * Clamped to the stored duration because [AppLockState.lockoutUntilElapsedMs] is on the
     * monotonic timebase, which resets to zero on reboot: without the clamp, rebooting mid-lockout
     * would read the stored deadline as "the whole of the previous uptime remaining". Clamping
     * fails safe — worst case is re-serving the original delay once.
     */
    fun remainingLockoutMillis(): Long {
        val duration = state.lockoutDurationMs()
        if (duration <= 0L) return 0L
        return (state.lockoutUntilElapsedMs() - elapsedRealtimeMs()).coerceIn(0L, duration)
    }

    /** The PIN-derived keys for unwrapping `deviceSecret`, if "require unlock to receive
     *  push/MFA" is on and the app is currently unlocked via PIN — null otherwise, including
     *  the instant [lockNow] runs. See [com.urlxl.mail.push.SecurePairingStore]. */
    fun cachedCredentialKeys(): CredentialKeys? = credentialKeys

    /** Drops the cached keys without locking. Needed when the credential gate is switched off: the
     *  keys otherwise stayed cached, and [com.urlxl.mail.push.PushRepository.savePairing] would
     *  re-wrap a later pairing behind a gate that is no longer enabled and will never open. */
    fun dropCredentialKeys() {
        credentialKeys = null
    }

    /**
     * Verifies [pin] under the same lockout and wipe accounting as [attemptPin], without unlocking
     * the app. Every PIN check has to come through here or through [attemptPin]: the settings
     * screens used to call `AppLockState.verifyPin` directly, which meant unlimited untimed guesses
     * that never advanced the wipe counter — precisely the unthrottled second entry point
     * [attemptPin]'s own contract warns about.
     */
    suspend fun verifyPinThrottled(pin: String): UnlockAttemptResult = withContext(Dispatchers.Default) {
        val remaining = remainingLockoutMillis()
        if (remaining > 0) return@withContext UnlockAttemptResult.Rejected(remaining)

        if (state.verifyPin(pin)) {
            state.resetFailedAttempts()
            return@withContext UnlockAttemptResult.Success
        }

        val attempts = state.incrementFailedAttempts()
        if (LockoutPolicy.shouldWipe(attempts)) {
            return@withContext when (val wipe = onWipe()) {
                is WipeResult.Complete -> UnlockAttemptResult.Wiped
                is WipeResult.Incomplete -> UnlockAttemptResult.WipeFailed(wipe.failedSteps)
            }
        }
        val delay = LockoutPolicy.delayMillisFor(attempts)
        if (delay > 0) state.setLockout(elapsedRealtimeMs() + delay, delay)
        UnlockAttemptResult.Rejected(delay)
    }

    /**
     * Derives and caches the credential keys on demand, regardless of whether the credential gate
     * is currently enabled — used when the user is toggling the gate itself, where there is no
     * "successful unlock" event to hang off of and no PIN-derived key can be assumed to already be
     * cached (the current session may have been unlocked via biometric only). Verifies [pin]
     * against the stored hash first and returns `false` without deriving anything if it's wrong —
     * never derives a key from an unverified PIN.
     */
    suspend fun deriveAndCacheCredentialKeys(pin: String): Boolean = withContext(Dispatchers.Default) {
        // Throttled like every other PIN check — this is reachable from the settings screen, so
        // verifying directly against the store made it an unthrottled oracle for the one secret
        // a biometric-only unlock does not already grant.
        if (verifyPinThrottled(pin) !is UnlockAttemptResult.Success) return@withContext false
        credentialKeys = deriveUsingPersistedSalt(pin)
        true
    }

    private fun cacheCredentialKeysIfEnabled(pin: String) {
        if (!state.isCredentialPinGateEnabled()) return
        credentialKeys = deriveUsingPersistedSalt(pin)
    }

    private fun deriveUsingPersistedSalt(pin: String): CredentialKeys {
        val salt = state.credentialSalt() ?: CredentialCipher.randomSalt().also { state.setCredentialSalt(it) }
        return CredentialCipher.deriveKeys(pin, salt, pepper)
    }
}
