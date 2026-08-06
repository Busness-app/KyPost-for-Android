package com.urlxl.mail.security

import android.os.SystemClock
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext

sealed class UnlockAttemptResult {
    object Success : UnlockAttemptResult()
    data class Rejected(val delayMillis: Long) : UnlockAttemptResult()
    object Wiped : UnlockAttemptResult()

    /**
     * The PIN could not be checked at all — the Keystore pepper backing the stored verifier is
     * gone or unusable, so neither "correct" nor "wrong" is knowable.
     *
     * Distinct from [Rejected] because it **must not count toward the wipe threshold**. Folding it
     * into "wrong PIN" meant an OS-level Keystore invalidation made every correct PIN read as
     * wrong, and ten of those destroyed the user's mail, contacts and pairing in response to an
     * event they neither caused nor could avoid. See [PepperUnavailableException].
     */
    object VerifierUnavailable : UnlockAttemptResult()

    /** The wipe threshold was reached and the wipe ran, but at least one step failed — so local
     *  data may still be on disk. Distinct from [Wiped] because the UI must not tell the user
     *  their data is gone when it might not be; see [WipeResult]. */
    data class WipeFailed(val failedSteps: List<String>, val willRetry: Boolean) : UnlockAttemptResult()
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

    /**
     * Observable lock state, for screens that react to it.
     *
     * A **security decision must use [isLockedNow] instead**: this flow only changes when something
     * calls [lockNow], and the background grace window's timer is not a guarantee that anything
     * will. See [scheduleLock].
     */
    val locked: StateFlow<Boolean> = _locked.asStateFlow()

    @Volatile
    private var credentialKeys: CredentialKeys? = null

    /**
     * Serialises every PIN check in the process.
     *
     * [attemptPin], [verifyPinThrottled] and [deriveAndCacheCredentialKeys] all run
     * check-lockout → verify → account-for-failure, and [AppLockState.incrementFailedAttempts] is a
     * read-modify-write on a `SharedPreferences` int. Without this, two checks in flight together on
     * the multi-threaded [Dispatchers.Default] pool — the settings screen and a notification-tapped
     * [com.urlxl.mail.push.MfaApprovalActivity], or simply a double submit — both read the same
     * attempt count and both write `n + 1`, so the lockout ladder and the wipe threshold under-count.
     * They also both pass the lockout gate at the same instant, which is an unthrottled parallel
     * guessing window.
     *
     * Non-reentrant: everything that runs under it must call [verifyLocked], never a public method
     * on this class.
     */
    private val pinGate = Mutex()

    /**
     * When a pending background grace window expires, on [android.os.SystemClock.elapsedRealtime]'s
     * timebase. Zero means no lock is pending (the app is in the foreground, or already locked).
     */
    @Volatile
    private var lockDeadlineElapsedMs: Long = 0L

    fun lockNow() {
        lockDeadlineElapsedMs = 0L
        if (state.isLockEnabled()) _locked.value = true
        credentialKeys = null
        // Unconditional, exactly like credentialKeys above: the opened PGP private key is plaintext
        // held for the unlock session, and "the app locked" is the whole of its lifetime. Gating it
        // on isLockEnabled() would keep it alive on the path where the lock was just turned off.
        com.urlxl.mail.pgp.EnrollmentSession.clear()
    }

    /**
     * Arms the background grace window: the app counts as locked from [deadlineElapsedMs] onward
     * whether or not anything has called [lockNow] by then.
     *
     * [com.urlxl.mail.KyPostApp] also posts a `Handler` callback for the same deadline, because
     * something has to actually flip [locked] for the UI and drop the cached credential keys. That
     * callback is not sufficient on its own: `Handler.postDelayed` runs on `uptimeMillis`, which
     * does not advance while the device is in deep sleep — precisely the pocketed-phone case the
     * grace window's own doc invokes. The deadline recorded here is on `elapsedRealtime`, which
     * does, so [isLockedNow] gives the right answer even if the callback has not run yet.
     */
    fun scheduleLock(deadlineElapsedMs: Long) {
        lockDeadlineElapsedMs = deadlineElapsedMs
    }

    /** Disarms a pending grace window — the app came back to the foreground inside it. */
    fun cancelScheduledLock() {
        lockDeadlineElapsedMs = 0L
    }

    /**
     * Whether the app is locked *right now*, resolving an expired-but-unfired grace window on the
     * spot (and flipping [locked] as a side effect, so the UI catches up too).
     *
     * This is what every gate on lock state must call. Reading [locked] directly meant the sender
     * and subject redaction in [com.urlxl.mail.push.PushNotificationDispatcher] — and the credential
     * gate below — stayed off for as long as nothing happened to call [lockNow], which with a
     * background grace window is unbounded.
     */
    fun isLockedNow(): Boolean {
        if (_locked.value) return true
        val deadline = lockDeadlineElapsedMs
        if (deadline != 0L && elapsedRealtimeMs() >= deadline) {
            lockNow()
            return _locked.value
        }
        return false
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
        pinGate.withLock {
            verifyLocked(pin) {
                // Unlock FIRST, derive second. The credential key comes from a *different* Keystore
                // alias than the PIN verifier, so it can be lost on its own — and a correct PIN
                // whose wrapping key has gone is still a correct PIN. Deriving first meant a throw
                // from the Keystore skipped the unlock and left the user locked out of an app whose
                // PIN they had just entered correctly.
                _locked.value = false
                cacheCredentialKeysIfEnabled(pin)
            }
        }
    }

    /**
     * The whole check-verify-account sequence, run under [pinGate] by every public entry point.
     *
     * [onSuccess] is what distinguishes the callers — unlock the app, cache a credential key, or
     * nothing at all. Deliberately a lambda rather than a boolean flag: a boolean parameter that
     * selects between fundamentally different post-conditions is exactly the shape that let
     * `verifyPinThrottled` and `attemptPin` drift into two copies of the same accounting code.
     */
    private suspend fun verifyLocked(pin: String, onSuccess: () -> Unit): UnlockAttemptResult {
        val remaining = remainingLockoutMillis()
        if (remaining > 0) return UnlockAttemptResult.Rejected(remaining)

        // The verifier itself may be unevaluable, which is not a wrong PIN and must not be counted
        // as one — the `incrementFailedAttempts()` below is what feeds the wipe threshold.
        val verified = try {
            state.verifyPin(pin)
        } catch (e: PepperUnavailableException) {
            android.util.Log.e("AppLockManager", "PIN verifier is unevaluable; refusing to count an attempt", e)
            return UnlockAttemptResult.VerifierUnavailable
        }

        if (verified) {
            state.resetFailedAttempts()
            onSuccess()
            return UnlockAttemptResult.Success
        }

        val attempts = state.incrementFailedAttempts()
        if (LockoutPolicy.shouldWipe(attempts)) {
            return when (val wipe = onWipe()) {
                is WipeResult.Complete -> UnlockAttemptResult.Wiped
                is WipeResult.Incomplete -> UnlockAttemptResult.WipeFailed(wipe.failedSteps, wipe.willRetry)
            }
        }
        val delay = LockoutPolicy.delayMillisFor(attempts)
        if (delay > 0) state.setLockout(elapsedRealtimeMs() + delay, delay)
        return UnlockAttemptResult.Rejected(delay)
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
     *  the instant [lockNow] runs. See [com.urlxl.mail.push.SecurePairingStore].
     *
     *  Routed through [isLockedNow] rather than reading the field directly: with a background grace
     *  window, `lockNow()` may not have run yet even though the window has expired, and these keys
     *  are exactly what the gate exists to withhold from a backgrounded app. */
    fun cachedCredentialKeys(): CredentialKeys? {
        if (isLockedNow()) return null
        return credentialKeys
    }

    /**
     * The credential keys for **one decision taken on a foreground screen that has just verified the
     * PIN itself**, without [cachedCredentialKeys]' lock check.
     *
     * That check is right for every background consumer — a sync worker must not use the credential
     * while the app is locked, which is the whole point of the gate. It was wrong for
     * [com.urlxl.mail.push.MfaApprovalActivity], which is deliberately not a [LockedActivity] and is
     * reached from a notification tap on a locked (usually freshly started) process. There the user
     * entered the correct PIN, [deriveAndCacheCredentialKeys] returned `Success` and cached the key,
     * and the very next read through `cachedCredentialKeys()` returned null because `_locked` was
     * still true — so the approve *and the deny* died in [com.urlxl.mail.push.MfaResponseClient]
     * with "Device is not registered yet" and no request was ever made. A user who knew a sign-in
     * was hostile could not deny it.
     *
     * Deliberately **not** an unlock: unlocking the app from a notification tap would hand the same
     * key to background sync and open the mailbox, which is exactly what the gate withholds. The
     * caller holds the result for the life of one authenticated decision and drops it in `onStop`.
     */
    fun credentialKeysForDecision(): CredentialKeys? = credentialKeys

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
        pinGate.withLock { verifyLocked(pin) {} }
    }

    /**
     * Derives and caches the credential keys on demand, regardless of whether the credential gate
     * is currently enabled — used when the user is toggling the gate itself, where there is no
     * "successful unlock" event to hang off of and no PIN-derived key can be assumed to already be
     * cached (the current session may have been unlocked via biometric only). Verifies [pin]
     * against the stored hash first and derives nothing if it's wrong — never derives a key from an
     * unverified PIN.
     *
     * Returns the full [UnlockAttemptResult], not a `Boolean`. It used to collapse everything that
     * was not [UnlockAttemptResult.Success] into `false`, which silently discarded
     * [UnlockAttemptResult.Wiped] — this path runs the same wipe threshold as every other PIN check,
     * so the caller has to be told when the wipe has actually run. See
     * [com.urlxl.mail.security.resolvePinAttempt].
     */
    suspend fun deriveAndCacheCredentialKeys(pin: String): UnlockAttemptResult = withContext(Dispatchers.Default) {
        // Throttled like every other PIN check — this is reachable from the settings screen, so
        // verifying directly against the store made it an unthrottled oracle for the one secret
        // a biometric-only unlock does not already grant.
        pinGate.withLock {
            // Unlike the unlock path, this caller specifically asked for the key — the settings
            // screen is about to switch the credential gate on and re-wrap the device secret behind
            // it. A derivation that failed must therefore be reported, not swallowed: proceeding
            // would enable a gate with no key to open it.
            var derivationFailed = false
            val result = verifyLocked(pin) {
                credentialKeys = try {
                    deriveUsingPersistedSalt(pin)
                } catch (e: PepperUnavailableException) {
                    android.util.Log.e("AppLockManager", "Credential key derivation is unavailable", e)
                    derivationFailed = true
                    null
                }
            }
            if (result is UnlockAttemptResult.Success && derivationFailed) {
                UnlockAttemptResult.VerifierUnavailable
            } else {
                result
            }
        }
    }

    /** Best-effort by contract: this runs as a side effect of unlocking, and a Keystore that cannot
     *  produce the wrapping key leaves the gated secret unavailable for the session — exactly as a
     *  biometric-only unlock does — rather than failing the unlock. [deriveAndCacheCredentialKeys]
     *  is the path where the caller actually asked for the key, and it reports the failure. */
    private fun cacheCredentialKeysIfEnabled(pin: String) {
        if (!state.isCredentialPinGateEnabled()) return
        credentialKeys = runCatching { deriveUsingPersistedSalt(pin) }
            .onFailure { android.util.Log.e("AppLockManager", "Could not derive credential keys on unlock", it) }
            .getOrNull()
    }

    private fun deriveUsingPersistedSalt(pin: String): CredentialKeys {
        // Create-on-demand is right for the *wrapping* key, and wrong for the PIN verifier — which
        // is why the two live behind separate aliases and separate accessors now. Losing this key
        // makes an existing wrapped secret undecryptable (the GCM tag stops verifying,
        // SecurePairingStore reads it as "credential unavailable", the user re-pairs), which is the
        // failure direction CredentialCipher's KDoc already chose. Losing the *verifier's* key
        // instead made a correct PIN read as wrong forever, and wiped the device on the tenth try.
        if (pepper === KeystoreCredentialPepper) KeystoreCredentialPepper.ensureExists()
        val salt = state.credentialSalt() ?: CredentialCipher.randomSalt().also { state.setCredentialSalt(it) }
        return CredentialCipher.deriveKeys(pin, salt, pepper)
    }
}
