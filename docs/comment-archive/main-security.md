# Comment archive - main/security

Comments removed from `app/src/main/java/org/kysecurity/mail/security/` by the ponytail sweep.
Each entry gives the declaration or line the comment sat above, then the removed text verbatim.

## app/src/main/java/org/kysecurity/mail/security/AppLockManager.kt

### `object VerifierUnavailable : UnlockAttemptResult()`
Replaced in source by: `/** Not a wrong PIN: it must not count toward the wipe threshold. */`
```
    /**
     * The PIN could not be checked at all — the Keystore pepper backing the stored verifier is
     * gone or unusable, so neither "correct" nor "wrong" is knowable.
     *
     * Distinct from [Rejected] because it **must not count toward the wipe threshold**. Folding it
     * into "wrong PIN" meant an OS-level Keystore invalidation made every correct PIN read as
     * wrong, and ten of those destroyed the user's mail, contacts and pairing in response to an
     * event they neither caused nor could avoid. See [PepperUnavailableException].
     */
```

### `data class WipeFailed(val failedSteps: List<String>, val willRetry: Boolean) : UnlockAttemptResult()`
Replaced in source by: `/** The wipe ran but a step failed, so data may remain; the UI must not claim it is gone. */`
```
    /** The wipe threshold was reached and the wipe ran, but at least one step failed — so local
     *  data may still be on disk. Distinct from [Wiped] because the UI must not tell the user
     *  their data is gone when it might not be; see [WipeResult]. */
```

### `class AppLockManager(`
Replaced in source by: `/** In-process lock state only: "locked" is never persisted. [onWipe] is injected for tests. */`
```
/**
 * In-memory app-lock state for the current process — "locked" means "since this process started,
 * has the correct PIN/biometric been presented," it is never persisted. [onWipe] runs
 * [SecurityWipe]'s work; kept as an injected callback rather than a direct dependency so this
 * class stays unit-testable without a Context.
 */
```

### `val locked: StateFlow<Boolean> = _locked.asStateFlow()`
Replaced in source by: `/** A security decision must use [isLockedNow]: this flow only moves when [lockNow] runs. */`
```
    /**
     * Observable lock state, for screens that react to it.
     *
     * A **security decision must use [isLockedNow] instead**: this flow only changes when something
     * calls [lockNow], and the background grace window's timer is not a guarantee that anything
     * will. See [scheduleLock].
     */
```

### `private val pinGate = Mutex()`
Replaced in source by: `/** Serialises every PIN check. Non-reentrant: code under it must call [verifyLocked]. */`
```
    /**
     * Serialises every PIN check in the process.
     *
     * [attemptPin], [verifyPinThrottled] and [deriveAndCacheCredentialKeys] all run
     * check-lockout → verify → account-for-failure, and [AppLockState.incrementFailedAttempts] is a
     * read-modify-write on a `SharedPreferences` int. Without this, two checks in flight together on
     * the multi-threaded [Dispatchers.Default] pool — the settings screen and a notification-tapped
     * [org.kysecurity.mail.push.MfaApprovalActivity], or simply a double submit — both read the same
     * attempt count and both write `n + 1`, so the lockout ladder and the wipe threshold under-count.
     * They also both pass the lockout gate at the same instant, which is an unthrottled parallel
     * guessing window.
     *
     * Non-reentrant: everything that runs under it must call [verifyLocked], never a public method
     * on this class.
     */
```

### `@Volatile`
Replaced in source by: `/** Grace-window deadline on elapsedRealtime; zero means no lock is pending. */`
```
    /**
     * When a pending background grace window expires, on [android.os.SystemClock.elapsedRealtime]'s
     * timebase. Zero means no lock is pending (the app is in the foreground, or already locked).
     */
```

### `org.kysecurity.mail.pgp.EnrollmentSession.clear()`
Replaced in source by: `// Unconditional, like credentialKeys: gating on isLockEnabled() would keep it alive.`
```
        // Unconditional, exactly like credentialKeys above: the opened PGP private key is plaintext
        // held for the unlock session, and "the app locked" is the whole of its lifetime. Gating it
        // on isLockEnabled() would keep it alive on the path where the lock was just turned off.
```

### `fun scheduleLock(deadlineElapsedMs: Long) {`
Replaced in source by: `/** elapsedRealtime, unlike the Handler's uptimeMillis, advances during deep sleep. */`
```
    /**
     * Arms the background grace window: the app counts as locked from [deadlineElapsedMs] onward
     * whether or not anything has called [lockNow] by then.
     *
     * [org.kysecurity.mail.KyPostApp] also posts a `Handler` callback for the same deadline, because
     * something has to actually flip [locked] for the UI and drop the cached credential keys. That
     * callback is not sufficient on its own: `Handler.postDelayed` runs on `uptimeMillis`, which
     * does not advance while the device is in deep sleep — precisely the pocketed-phone case the
     * grace window's own doc invokes. The deadline recorded here is on `elapsedRealtime`, which
     * does, so [isLockedNow] gives the right answer even if the callback has not run yet.
     */
```

### `fun isLockedNow(): Boolean {`
Replaced in source by: `/** What every gate must call: it resolves an expired-but-unfired grace window. */`
```
    /**
     * Whether the app is locked *right now*, resolving an expired-but-unfired grace window on the
     * spot (and flipping [locked] as a side effect, so the UI catches up too).
     *
     * This is what every gate on lock state must call. Reading [locked] directly meant the sender
     * and subject redaction in [org.kysecurity.mail.push.PushNotificationDispatcher] — and the credential
     * gate below — stayed off for as long as nothing happened to call [lockNow], which with a
     * background grace window is unbounded.
     */
```

### `fun unlockWithBiometric(keys: CredentialKeys): UnlockAttemptResult {`
Replaced in source by: `/** Keys come from [BiometricUnlockVault]; caching mirrors [attemptPin]. */`
```
    /**
     * Unlocks with the keys a biometric authentication just produced — [keys] comes out of
     * [BiometricUnlockVault], sealed there by the last PIN unlock and openable only through a
     * `BiometricPrompt.CryptoObject`.
     *
     * Caching mirrors [attemptPin] exactly — only when the gate is on does anything need the key,
     * and only then is it held.
     */
```

### `val remaining = remainingLockoutMillis()`
Replaced in source by: `// Under the same lockout as every PIN check; a fingerprint must not clear the ladder.`
```
        // Under the same lockout as every PIN check. This used to unlock and reset the attempt
        // counter with no gate at all, so a fingerprint mid-ladder cleared an hour of accumulated
        // delay AND the progress toward the wipe threshold — an escape hatch from the throttle,
        // given to the one attacker `setInvalidatedByBiometricEnrollment(true)` is aimed at, by
        // omission rather than by decision.
```

### `suspend fun attemptPin(pin: CharArray): UnlockAttemptResult = withContext(Dispatchers.Default) {`
Replaced in source by: `/** On [UnlockAttemptResult.Wiped], [onWipe] has already run by the time this returns. */`
```
    /**
     * Returns [UnlockAttemptResult.Rejected] with the delay the caller should hold the PIN field
     * disabled for (0 for the first two wrong attempts), or [UnlockAttemptResult.Wiped] once
     * the user's configured wrong-attempt threshold has been reached — in which case [onWipe] has
     * already run by the time this returns. The threshold is a user choice and can be turned off
     * entirely; see [LockoutPolicy] and [AppLockState.wipeAfterAttempts].
     */
```

### `_locked.value = false`
Replaced in source by: `// Unlock FIRST: a lost wrapping key must not lock out a correct PIN.`
```
                // Unlock FIRST, derive second. The credential key comes from a *different* Keystore
                // alias than the PIN verifier, so it can be lost on its own — and a correct PIN
                // whose wrapping key has gone is still a correct PIN. Deriving first meant a throw
                // from the Keystore skipped the unlock and left the user locked out of an app whose
                // PIN they had just entered correctly.
```

### `private suspend fun verifyLocked(pin: CharArray, onSuccess: () -> Unit): UnlockAttemptResult {`
Replaced in source by: `/** The check-verify-account sequence; every public entry point runs it under [pinGate]. */`
```
    /**
     * The whole check-verify-account sequence, run under [pinGate] by every public entry point.
     *
     * [onSuccess] is what distinguishes the callers — unlock the app, cache a credential key, or
     * nothing at all. Deliberately a lambda rather than a boolean flag: a boolean parameter that
     * selects between fundamentally different post-conditions is exactly the shape that let
     * `verifyPinThrottled` and `attemptPin` drift into two copies of the same accounting code.
     */
```

### `fun remainingLockoutMillis(): Long {`
Replaced in source by: `/** Clamped to the stored duration: the monotonic clock resets to zero on reboot. */`
```
    /**
     * How long the PIN field should stay disabled for, or 0 if there's no active lockout.
     *
     * Clamped to the stored duration because [AppLockState.lockoutUntilElapsedMs] is on the
     * monotonic timebase, which resets to zero on reboot: without the clamp, rebooting mid-lockout
     * would read the stored deadline as "the whole of the previous uptime remaining". Clamping
     * fails safe — worst case is re-serving the original delay once.
     */
```

### `fun cachedCredentialKeys(): CredentialKeys? {`
Replaced in source by: `/** Null while locked — routed through [isLockedNow], since [lockNow] may not have run yet. */`
```
    /** The PIN-derived keys for unwrapping `deviceSecret`, if "require unlock to receive
     *  push/MFA" is on and the app is currently unlocked via PIN — null otherwise, including
     *  the instant [lockNow] runs. See [org.kysecurity.mail.push.SecurePairingStore].
     *
     *  Routed through [isLockedNow] rather than reading the field directly: with a background grace
     *  window, `lockNow()` may not have run yet even though the window has expired, and these keys
     *  are exactly what the gate exists to withhold from a backgrounded app. */
```

### `class DecisionToken private constructor(`
Replaced in source by: `/** Private constructor plus an issuer check: `internal` alone would not prove anything. */`
```
    /**
     * Proof that its holder ran a PIN check on **this** manager that returned
     * [UnlockAttemptResult.Success], carrying the keys that check derived.
     *
     * The constructor is `private` and the token records its issuer. `internal constructor` did
     * not make this a type-system guarantee: `internal` is module-visible and this app is one
     * module, so all 386 source files could mint a token and the KDoc claiming otherwise was
     * strictly worse than the comment it replaced — it invited the next reader to stop checking.
     * [keysFor] now verifies the issuer, so a forged token fails where it is used rather than
     * passing silently.
     */
```

### `suspend fun resealForBiometric(pin: CharArray) = withContext(Dispatchers.Default) {`
Replaced in source by: `/** PIN-change path only: without it the old PIN's keys stay sealed and stop unwrapping. */`
```
    /**
     * Re-seals the biometric blob under [pin], which the caller has just established as the app-lock
     * PIN.
     *
     * Only the PIN-change path needs this. Everything else that seals does so as a consequence of a
     * *verified* PIN; here the PIN is new, so there is nothing to verify it against. Skipping it
     * would leave the previous PIN's keys sealed, and with the credential gate on the next biometric
     * unlock would produce a key that no longer unwraps `deviceSecret` — every authenticated call
     * failing behind a UI still reading "Paired".
     */
```

### `pinGate.withLock {`
Replaced in source by: `// Under pinGate: the salt is minted on first use, so concurrent derivations must not race.`
```
        // Under pinGate like every other caller of deriveUsingPersistedSalt. It generates and
        // persists the credential salt on first use, so two concurrent derivations could each mint
        // one: thread A wraps deviceSecret under KDF(pin, S1) while thread B persists S2, after
        // which the stored salt no longer matches the stored ciphertext and the GCM tag never
        // verifies again. The pairing then reads as "credential unavailable" forever behind a UI
        // still saying Paired, which is exactly the unrepairable state preserveStoredSecret exists
        // to prevent. This was the one derivation path outside the gate.
```

### `fun dropCredentialKeys() {`
Replaced in source by: `/** Needed when the credential gate is switched off, or a later pairing re-wraps behind it. */`
```
    /** Drops the cached keys without locking. Needed when the credential gate is switched off: the
     *  keys otherwise stayed cached, and [org.kysecurity.mail.push.PushRepository.savePairing] would
     *  re-wrap a later pairing behind a gate that is no longer enabled and will never open. */
```

### `suspend fun verifyPinThrottled(pin: CharArray): UnlockAttemptResult = withContext(Dispatchers.Default) {`
Replaced in source by: `/** Every PIN check must come through here or [attemptPin]; direct verifyPin is unthrottled. */`
```
    /**
     * Verifies [pin] under the same lockout and wipe accounting as [attemptPin], without unlocking
     * the app. Every PIN check has to come through here or through [attemptPin]: the settings
     * screens used to call `AppLockState.verifyPin` directly, which meant unlimited untimed guesses
     * that never advanced the wipe counter — precisely the unthrottled second entry point
     * [attemptPin]'s own contract warns about.
     */
```

### `suspend fun verifyPinForDecision(`
Replaced in source by: `/** Deliberately not an unlock: a notification tap must not open the mailbox. */`
```
    /**
     * Runs the same throttled check as [attemptPin] and, on success only, hands back a
     * [DecisionToken] holding the keys — **without unlocking the app**.
     *
     * Deliberately not an unlock: unlocking from a notification tap would hand the same key to
     * background sync and open the mailbox, which is exactly what the gate withholds. The caller
     * holds the token for the life of one authenticated decision and drops it in `onStop`.
     */
```

### `fun keysFor(token: DecisionToken): CredentialKeys? {`
Replaced in source by: `/** Keys the token carries, or null when none were needed. Throws if issued elsewhere. */`
```
    /** The keys a [DecisionToken] carries, or null when the gate was off and none were needed.
     *
     *  @throws IllegalArgumentException if [token] was not issued by this manager — see
     *    [DecisionToken]. */
```

### `suspend fun deriveAndCacheCredentialKeys(pin: CharArray): UnlockAttemptResult = withContext(Dispatchers.Default) {`
Replaced in source by: `/** Derives regardless of the gate, but only after [pin] verifies against the stored hash. */`
```
    /**
     * Derives and caches the credential keys on demand, regardless of whether the credential gate
     * is currently enabled — used when the user is toggling the gate itself, where there is no
     * "successful unlock" event to hang off of and no PIN-derived key can be assumed to already be
     * cached (the current session may have been unlocked via biometric only). Verifies [pin]
     * against the stored hash first and derives nothing if it's wrong — never derives a key from an
     * unverified PIN.
     */
```

### `pinGate.withLock {`
Replaced in source by: `// Throttled like every other PIN check; the settings screen is a reachable oracle.`
```
        // Throttled like every other PIN check — this is reachable from the settings screen, so
        // verifying directly against the store made it an unthrottled oracle for the one secret
        // a biometric-only unlock does not already grant.
```

### `var derivationFailed = false`
Replaced in source by: `// The caller asked for the key, so a failed derivation must be reported.`
```
            // Unlike the unlock path, this caller specifically asked for the key — the settings
            // screen is about to switch the credential gate on and re-wrap the device secret behind
            // it. A derivation that failed must therefore be reported, not swallowed: proceeding
            // would enable a gate with no key to open it.
```

### `private fun deriveSealAndCache(pin: CharArray) {`
Replaced in source by: `/** Derives unconditionally and is best-effort: a failure must not fail the unlock. */`
```
    /**
     * Derives the credential keys, seals them for the next biometric unlock, and caches them if the
     * gate is on.
     *
     * **Derives unconditionally**, where this used to skip the work entirely with the gate off. The
     * gate is off by default, and the seal is what makes a fingerprint produce real key material
     * instead of setting a boolean — skipping it on the default configuration would leave the app
     * lock exactly as bypassable as it was. The gate still decides whether anything is *retained*:
     * with it off nothing needs the key, so nothing holds it, and the extra derivation costs one
     * PBKDF2 on a screen that has just run another.
     *
     * Best-effort by contract: this runs as a side effect of unlocking, and a Keystore that cannot
     * produce the wrapping key leaves the gated secret unavailable for the session rather than
     * failing the unlock. [deriveAndCacheCredentialKeys] is the path where the caller actually asked
     * for the key, and it reports the failure.
     */
```

### `if (pepper === KeystoreCredentialPepper) KeystoreCredentialPepper.ensureExists()`
Replaced in source by: `// Create-on-demand suits the wrapping key, not the verifier; hence separate aliases.`
```
        // Create-on-demand is right for the *wrapping* key, and wrong for the PIN verifier — which
        // is why the two live behind separate aliases and separate accessors now. Losing this key
        // makes an existing wrapped secret undecryptable (the GCM tag stops verifying,
        // SecurePairingStore reads it as "credential unavailable", the user re-pairs), which is the
        // failure direction CredentialCipher's KDoc already chose. Losing the *verifier's* key
        // instead made a correct PIN read as wrong forever, and wiped the device on the tenth try.
```

## app/src/main/java/org/kysecurity/mail/security/AppLockSettings.kt

### `class AppLockSettings(context: Context) {`
Replaced in source by: `/** Plain prefs, not [AppLockStore]: read from onStop, which must not touch the Keystore. */`
```
/**
 * How long the app may stay backgrounded before the app lock re-engages.
 *
 * A plain, unencrypted preference rather than part of [AppLockStore]: it is not a secret, and it is
 * read from `Application.onStop`, which must not touch the Keystore on the main thread.
 */
```

### `const val DEFAULT_GRACE_MILLIS = 30_000L`
```
        /** Long enough for a file-picker or chooser round trip, short enough that a pocketed
         *  phone re-locks before anyone picks it up. */
```

### `val OPTIONS_MILLIS = longArrayOf(0L, 30_000L, 60_000L, 300_000L)`
```
        /** The choices offered in Security settings, longest-lived first in the UI. */
```

## app/src/main/java/org/kysecurity/mail/security/AppLockStore.kt

### `@file:Suppress("DEPRECATION")`
Replaced in source by: `// androidx.security-crypto is deprecated with no replacement; swapping it is a format migration.`
```
// androidx.security-crypto is deprecated in full with no replacement API. Swapping it out is a
// migration of the at-rest credential format, not a warning fix, so it is deliberately not done
// here. File-scoped because the deprecation also fires on the imports below.
```

### `private const val KEY_WIPE_AFTER_ATTEMPTS = "wipe_after_attempts"`
Replaced in source by: `/** Absent means never chosen (the default); [WIPE_DISABLED] stores "the user turned it off". */`
```
/** Absent means "never chosen", which reads as [LockoutPolicy.DEFAULT_WIPE_THRESHOLD]. The
 *  sentinel below is how "the user turned the wipe off" is stored, since absent already means
 *  something else. */
```

### `enum class TripwireState {`
Replaced in source by: `/** UNREADABLE is deliberate: neither answer is safe, so [LockedActivity] blocks instead. */`
```
/**
 * What the app-lock tripwire can actually say, which is three things rather than two.
 *
 * [UNREADABLE] is the one that used to be missing. The Keystore alias is the durable half of the
 * marker, so a Keystore that cannot be consulted leaves the question genuinely unanswered — and
 * both available answers were wrong. Answering "configured" wipes a fresh install over a
 * transient `keystore2` restart; answering with the *file's* claim, which is what this did, hands
 * the decision to an unauthenticated `MODE_PRIVATE` file that anything able to write the sandbox
 * can forge — the exact "write `lock_was_enabled=true` and the next launch destroys the user's
 * mail" attack the Keystore half was introduced to close.
 *
 * So it is not answered here at all. [org.kysecurity.mail.security.LockedActivity] blocks the app
 * until the Keystore can be consulted again, which is neither a wipe nor an unlock.
 */
```

### `fun enableLock()`
Replaced in source by: `/** No `setLockEnabled(false)`: disarming is [reset], which also destroys the key and hash. */`
```
    /** Arms the lock. There is deliberately no `setLockEnabled(false)`: disarming is [reset],
     *  which also destroys the PIN hash and [KeystoreTripwireKey]. A `Boolean` here selected
     *  between two entirely different sequences, and the `false` one — write an authenticated
     *  marker, *then* destroy the key that authenticates it — threw
     *  [PepperUnavailableException] on any device that had never armed the lock. It had no
     *  production caller, so nothing ever ran it. */
```

### `fun lockoutUntilElapsedMs(): Long`
Replaced in source by: `/** Monotonic elapsedRealtime, not wall clock; [lockoutDurationMs] clamps it after a reboot. */`
```
    /**
     * Lockout deadline on [android.os.SystemClock.elapsedRealtime]'s monotonic timebase, not the
     * wall clock: a wall-clock deadline is cleared by setting the device date forward, which is
     * not a defence at all. [lockoutDurationMs] is stored alongside it purely to clamp the
     * remaining time after a reboot, since elapsedRealtime restarts at zero there and the stored
     * deadline would otherwise read as the device's entire previous uptime.
     */
```

### `fun wipeAfterAttempts(): Int?`
Replaced in source by: `/** Null when the wipe is off. Encrypted, because it decides whether mail is destroyed. */`
```
    /**
     * How many consecutive wrong PINs trigger [SecurityWipe], or null when the user has turned the
     * wipe off.
     *
     * Lives in the encrypted store rather than [AppLockSettings] deliberately: it is the one
     * setting whose value decides whether the user's mail gets destroyed, so it must not be
     * writable by anything that can write a plain preferences file.
     */
```

### `fun credentialSalt(): ByteArray?`
Replaced in source by: `/** Persisted once: regenerating it makes already-wrapped secrets undecryptable. */`
```
    /** PBKDF2 salt for [CredentialCipher.deriveKeys], generated once on first use and persisted —
     *  regenerating it per-unlock would make any secret already wrapped under the old key
     *  undecryptable. Null until [setCredentialSalt] has been called at least once. */
```

### `class AppLockStore(context: Context) : AppLockState {`
Replaced in source by: `/** Every write uses commit(): apply() lets a force-stop drop the failed-attempt counter. */`
```
/**
 * Keystore-backed storage for the app-lock PIN and its associated state — same
 * `EncryptedSharedPreferences` pattern as [org.kysecurity.mail.push.SecurePairingStore]. The PIN
 * itself is never stored, only [PinHasher]'s salted hash.
 *
 * Every write here uses `commit()`, never `apply()`. `apply()` returns before the write reaches
 * disk, which for [incrementFailedAttempts] is an unlimited-guess bypass: try a PIN, force-stop the
 * app before the async flush lands, repeat with the counter never advancing. [AppLockManager] keeps
 * every caller off the main thread so the durability can be afforded.
 */
```

### `private val tripwire: SharedPreferences =`
Replaced in source by: `/** Marker for "a lock was configured": this file plus the unforgeable [KeystoreTripwireKey]. */`
```
    /**
     * The "a lock was configured" marker: a preference file **plus** [KeystoreTripwireKey].
     *
     * The encrypted store above can become unreadable — Keystore invalidation, or an attacker
     * deleting the keyset — and recreating it empty would report `isLockEnabled() == false`, so
     * deleting one file would disable the lock. This marker lets [tripwireBroken] tell "never
     * configured" apart from "configured, and the state just vanished", and treat the latter as
     * hostile.
     *
     * **The Keystore half is what makes it a control rather than a speed bump.** As a bare
     * `MODE_PRIVATE` file this was both defeatable and weaponisable by anyone who could write the
     * app sandbox: delete both preference files and the lock is gone with no wipe, or write
     * `lock_was_enabled=true` onto a device that never had a lock and the next launch destroys the
     * user's mail. The alias cannot be forged or deleted by writing files, so its presence is the
     * durable claim and the HMAC below is what binds the file's value to it.
     *
     * **Scope boundary.** The tripwire only fires at app *launch*, so it defends the UI against
     * someone who tampers and then uses the app. The at-rest protection for the cached mail itself
     * is SQLCipher (see [DatabaseKey]), with Hostile Location Protection
     * ([HostileLocationSettings]) as the stronger mode in which no file exists at all.
     */
```

### `fun tripwireState(): TripwireState {`
Replaced in source by: `/** Fails towards CONFIGURED on tampering, and towards UNREADABLE when the Keystore is mute. */`
```
    /**
     * Whether a lock was configured, as far as anything that survives file deletion can tell.
     *
     * Fails towards [TripwireState.CONFIGURED] on tampering, and towards [TripwireState.UNREADABLE]
     * — not towards either answer — when the Keystore cannot be consulted at all. See
     * [TripwireState].
     */
```

### `fun wasLockEnabled(): Boolean = tripwireState() == TripwireState.CONFIGURED`
Replaced in source by: `/** UNREADABLE answers false here; [LockedActivity] handles it by refusing to open at all. */`
```
    /** [tripwireState] collapsed to the question [tripwireBroken] asks. [TripwireState.UNREADABLE]
     *  answers false here — asserting "configured" off an unauthenticated file is the forged-marker
     *  wipe this class exists to prevent — and is handled instead by
     *  [LockedActivity], which refuses to open the app at all while the Keystore cannot be
     *  consulted. Answering it here in either direction is what made one branch defeatable and the
     *  other weaponisable. */
```

### `if (!PinHasher.matchesLegacy(pin, salt, hash)) return false`
Replaced in source by: `// Pre-pepper hash: upgrade in place, but only on a correct PIN.`
```
        // Pre-pepper hash from an older install: verify against the v1 derivation, then upgrade in
        // place so the unpeppered value — which is offline-crackable in seconds for a 6-digit PIN —
        // stops existing on disk. Only ever upgrades on a *correct* PIN, so a wrong guess cannot
        // rewrite the verifier.
```

### `override fun setCredentialSalt(salt: ByteArray) {`
Replaced in source by: `/** Refuses to overwrite: a second salt makes every already-wrapped secret undecryptable. */`
```
    /**
     * Writes the credential salt, and **refuses to overwrite an existing one**.
     *
     * A second write is always a bug: every secret already wrapped under the old salt becomes
     * permanently undecryptable the moment it lands. [AppLockManager] serialises the only two paths
     * that generate one, so this is unreachable — and it throws rather than logging, because
     * returning normally told the caller the salt had been persisted when it had not. The caller
     * then wrapped the device secret under a key nothing would ever reproduce, which is a worse
     * outcome than the crash.
     */
```

### `tripwire.edit().clear().commit()`
Replaced in source by: `// Tripwire FIRST: clearing the store first leaves a window that reads as a broken tripwire.`
```
        // Tripwire FIRST. `tripwireBroken()` is "a lock was configured but the PIN hash is gone",
        // so clearing the encrypted store first opens a window where that is momentarily true —
        // and process death inside it makes SecurityWipe.enforceTripwire destroy the database, the
        // OS contact rows and the pairing on the next launch, in response to a user turning OFF
        // a setting. This order fails safe instead: an interruption leaves the lock enabled with a
        // valid hash, which the user can simply retry.
```

### `KeystoreTripwireKey.destroy()`
Replaced in source by: `// Left behind, the durable half would arm a wipe on the next launch.`
```
        // The durable half of the marker. Left behind, it says "a lock was configured" over a store
        // that no longer holds a PIN hash, which is exactly the tripwire condition — so turning the
        // lock off would arm a wipe for the next launch.
```

### `private fun buildEncryptedPrefs(appContext: Context): SharedPreferences =`
Replaced in source by: `/** A reset here does NOT mean no lock was set; the tripwire above still says one was. */`
```
    /** See [openEncryptedPrefs]: resets only on an undecryptable keyset, never on a transient I/O
     *  failure. A reset here does NOT mean "no lock was ever set" — the plain tripwire above still
     *  says one was, and [SecurityWipe.enforceTripwire] destroys the cached data before it can be
     *  read. */
```

### `val counterLock = Any()`
Replaced in source by: `/** Shared across instances: [SecurityWipe] builds its own store; a field lock is none. */`
```
        /**
         * Serialises the failed-attempt read-modify-write across **every** instance.
         *
         * `private val` on the instance did not: [SecurityWipe] builds its own [AppLockStore], so
         * the two synchronised on two different monitors and serialised nothing — while the comment
         * here named that second instance as the reason the lock existed. A counter that feeds the
         * wipe threshold cannot be protected by a monitor that each holder gets a fresh copy of.
         *
         * Still process-scoped. If push ever moves to its own process, `SharedPreferences` offers
         * nothing here and this needs a file lock.
         */
```

## app/src/main/java/org/kysecurity/mail/security/AppRestart.kt

### `object AppRestart {`
```
/**
 * Rebuilds every process-scoped graph and returns the user to a fresh [MainActivity].
 *
 * Needed whenever a setting requires a new [org.kysecurity.mail.data.DataGraph] — Room decides
 * disk-backed vs in-memory once, at construction time — or after [SecurityWipe] has closed the
 * database out from under the live graph.
 */
```

### `suspend fun relaunch(activity: Activity) {`
Replaced in source by: `/** Suspending: teardown awaits executor termination and zeroes held attachment plaintext. */`
```
    /**
     * **Suspending, because the teardown blocks.** [invalidateGraphs] waits up to
     * `MailBackgroundExecutor.QUIESCE_TIMEOUT_MS` on `awaitTermination`, and `ProcessState.resetAll`
     * zeroes up to 64 MB of held attachment plaintext. Every caller of this reached it on the main
     * thread — two of them via an explicit `withContext(Dispatchers.Main)` — so the security-
     * critical path was also a guaranteed multi-hundred-millisecond frozen frame, and an ANR on a
     * slow device.
     */
```

### `org.kysecurity.mail.ProcessState.resetAll()`
Replaced in source by: `// The process survives, so process-scoped state needs an explicit reset.`
```
            // Statics do not die with the task. Invalidating the graph holders rebuilds everything
            // *they* own, but every process-scoped `object` — the draft cache, the forward handoff,
            // the ephemeral attachment plaintext, the PGP custody cache — survives untouched,
            // because this no longer kills the process. Enumerating them by hand at each call site
            // is what let EphemeralAttachmentBytes hold 64 MB of decrypted mail across a security
            // wipe; the registry is the fix. See [org.kysecurity.mail.ProcessScopedState].
```

## app/src/main/java/org/kysecurity/mail/security/AttachmentAction.kt

### `enum class AttachmentAction { VIEW_EPHEMERAL, SAVE_TO_DOWNLOADS }`
```
/** Whether a tapped attachment should be viewed ephemerally (no disk write at all) or saved to
 *  the public Downloads collection — see "Attachments" under Hostile Location Protection in the
 *  2026-07-22 security-hardening spec. */
```

### `fun attachmentActionFor(hostileLocationProtectionEnabled: Boolean): AttachmentAction =`
Replaced in source by: `/** A tap always views ephemerally; saving is a separate, separately confirmed action. */`
```
/**
 * What a *tap* on an attachment does. Always an ephemeral view, whatever the protection setting.
 *
 * Saving is still available, as [AttachmentAction.SAVE_TO_DOWNLOADS], but it is now a deliberate
 * second action with its own confirmation rather than the meaning of a single tap. The protection
 * setting decides whether saving is *offered at all*, which is the decision it was always for.
 */
```

## app/src/main/java/org/kysecurity/mail/security/AuthGateKey.kt

### `object AuthGateKey {`
Replaced in source by: `/** Device credential is allowed here, unlike the vault: no app PIN exists on this path. */`
```
/**
 * Turns "the user authenticated" from a callback the app trusts into something the OS attests to,
 * on the one screen that holds no secret of its own to bind a prompt to.
 *
 * [BiometricUnlockVault] is the better shape and is used wherever it can be: there the prompt
 * produces the app's real keys, so a forged success yields nothing usable. It needs the app-lock PIN
 * to have sealed something first. The MFA approval screen must still gate a decision when no PIN is
 * set and nothing is sealed, and the gate below is what stands in: a key that does not exist outside
 * the Keystore, cannot be used without a live authentication, and therefore cannot be produced by an
 * instrumented process hooking `onAuthenticationSucceeded`.
 *
 * **Device credential is allowed here, unlike the unlock vault.** The vault excludes it because the
 * device lock-screen PIN must not become a way past this app's own PIN. There is no app PIN on this
 * path at all, so the screen lock is not bypassing anything — it is the whole of the authentication.
 */
```

### `fun cipher(): Cipher? {`
Replaced in source by: `/** Null when the device won't hold the key; callers must fail closed. Blocking: Keystore. */`
```
    /**
     * A cipher to hand to `BiometricPrompt.CryptoObject`, or null when this device will not hold the
     * key — on API 31+ that means no secure lock screen at all. Callers must fail closed on null:
     * a prompt raised without one has nothing to prove it ran.
     *
     * Blocking: Keystore. Call it off the main thread.
     */
```

### `Log.e(TAG, "Gate key unusable; minting a replacement", existing.exceptionOrNull())`
Replaced in source by: `// Nothing is sealed under this key, so a replacement loses nothing.`
```
        // The key exists in some form but will not operate. Nothing is sealed under it, so a
        // replacement loses nothing and is just as unusable without the user. Logged at error
        // level, not info: on a key configured the way [generate] configures it this should not
        // happen, and a silent re-mint is how a real problem stays invisible.
```

### `fun proves(cipher: Cipher): Boolean = runCatching { cipher.doFinal(PROOF) }.isSuccess`
Replaced in source by: `/** False when the key refuses to run, which is what a forged success callback produces. */`
```
    /**
     * Whether the OS actually unlocked [cipher] — false when the key refuses to run, which is what
     * a success callback invoked by anything other than a real authentication produces.
     */
```

### `.setInvalidatedByBiometricEnrollment(false)`
Replaced in source by: `// Deliberate: the gate already accepts device credential, so enrollment adds no bypass.`
```
            // Explicitly NOT invalidated by biometric enrollment, which is the platform default.
            //
            // That default is right for [BiometricUnlockVault], which excludes device credential:
            // there, a newly enrolled finger really would be a new way past this app's own PIN.
            // Here the gate already accepts AUTH_DEVICE_CREDENTIAL — and enrolling a biometric
            // requires that same credential — so anyone who could enroll a finger could already
            // satisfy this key. Leaving the default on therefore buys no security and costs the
            // user their MFA approval path for a benign action (adding a second fingerprint),
            // which [cipher] can only answer by silently minting a replacement.
```

## app/src/main/java/org/kysecurity/mail/security/BiometricUnlockVault.kt

### `class BiometricUnlock(val cipher: Cipher, val sealed: ByteArray)`
```
/**
 * What a biometric prompt needs to turn a fingerprint into [CredentialKeys]: the cipher to hand to
 * `BiometricPrompt.CryptoObject`, and the blob that cipher will open once the user has authenticated.
 */
```

### `class BiometricUnlockVault(context: Context) : BiometricKeySealer {`
Replaced in source by: `/** Biometric only: device credential would make the lock-screen PIN a way past the app PIN. */`
```
/**
 * Makes a fingerprint produce the app's real key material instead of setting a boolean.
 *
 * **Biometric only, and invalidated by enrollment.** Including `AUTH_DEVICE_CREDENTIAL` — as
 * [org.kysecurity.mail.pgp.EnrollmentVault] does — would make the device lock-screen PIN a way past
 * this app's own PIN, which it is not today. The cost is that adding a fingerprint destroys the key:
 * biometric unlock then falls back to the PIN until the next PIN unlock re-seals, which is the right
 * direction to fail in, since the attacker that exclusion targets is precisely someone who knows the
 * device credential and enrolls their own finger.
 *
 * The blob is stored in plain `SharedPreferences`. It is already RSA-OAEP ciphertext under a
 * hardware-backed key that will not decrypt without the user, so a second layer of
 * `EncryptedSharedPreferences` would buy nothing and inherit that library's unreadable-keyset
 * failure mode.
 */
```

### `override fun seal(keys: CredentialKeys) {`
Replaced in source by: `/** Re-sealing on every PIN unlock is the automatic recovery from an invalidated key. */`
```
    /**
     * Seals [keys] for the next biometric unlock, replacing whatever was there.
     *
     * Re-sealing on every PIN unlock rather than only when nothing is stored: it costs one RSA
     * encryption, and it is what makes recovery from an enrollment-invalidated key automatic — the
     * open path destroys the dead key, and the next PIN unlock mints a new one here with no state to
     * track and no repair path to get wrong.
     *
     * A device with no enrolled biometric cannot hold this key at all, so nothing is stored and any
     * previous blob is dropped. That is not an error: it is the normal state of a PIN-only user.
     */
```

### `fun prepareUnlock(): BiometricUnlock? {`
Replaced in source by: `/** Null when biometric unlock is not on offer; drops an invalidated key. Blocking: Keystore. */`
```
    /**
     * The prompt material, or null when biometric unlock is simply not on offer — nothing sealed, no
     * key, or a key the OS has invalidated because a biometric was enrolled since.
     *
     * Blocking: Keystore and disk. Call it off the main thread.
     *
     * An invalidated key is destroyed here rather than reported. Leaving it would mean every
     * subsequent PIN unlock sealed a fresh blob under a private key that can never open it, and the
     * unlock screen offering a fingerprint that always fails.
     */
```

## app/src/main/java/org/kysecurity/mail/security/CredentialCipher.kt

### `internal const val CREDENTIAL_KDF_ITERATIONS = 150_000`
Replaced in source by: `/** One constant for both PIN derivations; 150k, because the Keystore pepper carries the margin. */`
```
/**
 * The PBKDF2 work factor for **both** PIN-derived values in this package: the wrapping key here and
 * the stored verifier in [PinHasher].
 *
 * One constant, not two. It was declared separately in each file with the same value and no link
 * between them, so raising one would silently have left the other — and nothing would have failed,
 * because the two derivations are never compared to each other.
 *
 * 150k is below OWASP's current standalone guidance, and that is a deliberate reading of what is
 * actually defending the keyspace. Neither derivation is offline-attackable on its own: both are
 * peppered afterwards with a non-exportable AndroidKeyStore HMAC ([CredentialPepper]), so every
 * guess costs a Keystore round trip on the device the secret was created on. Against
 * [PinPolicy.MIN_LENGTH]'s 10^8 that is the term that matters; the iteration count buys the margin
 * for a PIN shorter than the floor, which only pre-existing installs have. Raise it here and both
 * derivations move together — which is the point.
 */
```

### `class WrappedSecret(val iv: ByteArray, val ciphertext: ByteArray)`
Replaced in source by: `/** Not a data class: generated equals would be identity over ByteArray. Nothing compares these. */`
```
/** **Not a `data class`**: Kotlin would generate identity `equals`/`hashCode` over the two
 *  [ByteArray] fields while advertising structural equality, and a wrapped credential is exactly
 *  the kind of value someone reaches for `==` or a `Set` on. Nothing compares these.
 *
 *  The PBKDF2 salt is deliberately not part of this type — it's an input to [CredentialCipher.deriveKeys],
 *  owned and persisted once per pairing by the caller ([org.kysecurity.mail.push.SecurePairingStore]),
 *  not an output of wrapping a single value. */
```

### `class CredentialKeys(val current: SecretKeySpec, val legacy: SecretKeySpec) {`
Replaced in source by: `/** Not a data class, for [WrappedSecret]'s reason: nothing may compare these structurally. */`
```
/**
 * The two keys one PIN can produce, so a secret wrapped under the old scheme is still readable.
 *
 * **Not a `data class`**, for the same reason [WrappedSecret] and
 * [org.kysecurity.mail.security.PinHash] are not — and this one was one for a long time while those
 * two each carried a paragraph forbidding the shape. `SourceRulesTest` only looked for `ByteArray`,
 * so a pair of `SecretKeySpec` walked straight past it. Nothing compares these; the only `==` in
 * the tree is a null check on `cachedCredentialKeys()`.
 */
```

### `fun interface CredentialPepper {`
Replaced in source by: `/** Injected rather than hardcoded so wrapping stays testable without an AndroidKeyStore. */`
```
/**
 * Mixes a device-bound secret into the PBKDF2 output. Injected rather than hardcoded so the
 * wrapping logic stays testable off-device — [KeystoreCredentialPepper] needs a real
 * `AndroidKeyStore`, which a JVM unit test does not have.
 */
```

### `object KeystoreCredentialPepper : CredentialPepper {`
Replaced in source by: `/** [mix] reads only and throws if the key is gone; creation is [ensureExists]. */`
```
/**
 * The production pepper: an HMAC-SHA256 key generated in, and never extractable from, the
 * AndroidKeyStore.
 *
 * [mix] reads only, and throws [PepperUnavailableException] if the key is gone. Creation is
 * [ensureExists], called from the paths that are establishing a new secret rather than checking an
 * existing one.
 */
```

### `object KeystorePinPepper : CredentialPepper {`
Replaced in source by: `/** A separate alias from [KeystoreCredentialPepper]'s: verifier and wrapping key must differ. */`
```
/** The app-lock PIN verifier's pepper. A **separate** alias from [KeystoreCredentialPepper]'s so
 *  the verifier and the wrapping key are not interchangeable: with one shared key, a stored PIN
 *  hash and a wrapping key would be the same derivation under two names. */
```

### `object KeystoreTripwireKey : CredentialPepper {`
Replaced in source by: `/** The alias's mere existence is the tripwire's durable half; a file marker can be forged. */`
```
/**
 * Authenticates [AppLockStore]'s tripwire marker, and — by merely existing — *is* the durable half
 * of it.
 *
 * A third alias, because it answers a different question from the other two. The tripwire's job is
 * to tell "a lock was configured and its state has vanished" apart from "no lock was ever
 * configured", and it used to do that with an unencrypted, unauthenticated preferences file. That
 * file is writable by anything that can write the app's sandbox, which made it defeatable in one
 * direction (delete both preference files and the lock is simply gone) and weaponisable in the
 * other (write `lock_was_enabled=true` onto a device that never had a lock, and the next launch
 * destroys the user's mail).
 *
 * A Keystore alias fixes both halves at once: it cannot be forged, it cannot be deleted by writing
 * to the app's files, and its presence survives exactly the deletion the tripwire is watching for.
 */
```

### `object KeystoreHlpKey : CredentialPepper {`
Replaced in source by: `/** As [KeystoreTripwireKey], but for the protection flag: existence is the durable half. */`
```
/**
 * Authenticates [HostileLocationSettings]'s enabled flag, and — by merely existing — *is* the
 * durable half of it.
 *
 * A fourth alias, and the argument for it is [KeystoreTripwireKey]'s own argument applied to the
 * setting it never covered. That KDoc establishes that a bare `MODE_PRIVATE` preferences file is
 * "writable by anything that can write the app's sandbox", so it is "defeatable in one direction
 * and weaponisable in the other" — and then Hostile Location Protection, the mode this app tells
 * at-risk users to turn on when they expect the device to be inspected or seized, was exactly such
 * a file and nothing else.
 *
 * Both directions were live. Flip the flag to `false` and the next process start builds a
 * **disk-backed** database ([org.kysecurity.mail.data.DataGraph]), starts persisting decrypted mail
 * and contacts, and lets an attachment tap write to shared Downloads — silently, for a user who
 * chose the mode precisely so that no file would exist. Flip it to `true` and the cached mail
 * disappears instead. A Keystore alias cannot be forged or deleted by writing files, which is what
 * makes the marker below mean something.
 */
```

### `class PepperUnavailableException(alias: String, cause: Throwable? = null) :`
```
/**
 * The pepper key for [alias] is gone or unusable, so a PIN cannot be evaluated at all.
 */
```

### `private fun pepperKeyOrNull(alias: String): SecretKey? {`
Replaced in source by: `/** Null only on a clean "no entry"; any failure to consult the Keystore throws instead. */`
```
/**
 * The pepper key for [alias], or null when the Keystore answered and simply holds no such key.
 *
 * **"Absent" and "could not ask" are different answers and this is where they part.** Any failure
 * to consult the Keystore — a `keystore2` restart, a vendor HAL hiccup, binder death under memory
 * pressure — throws [PepperUnavailableException]. Only a clean "no entry" returns null.
 *
 * Collapsing the two is not a style question. [createPepperKeyIfAbsent] mints a replacement at the
 * same alias, which *overwrites* the existing key: one transient Keystore failure during an
 * ordinary unlock therefore destroyed the pepper that the stored `deviceSecret` was wrapped under,
 * permanently, behind a UI still reading "Paired". That is the same "destroy a credential in
 * response to a transient failure" defect [openEncryptedPrefs] exists to prevent, reached through a
 * different door.
 */
```

### `private fun pepperKey(alias: String): SecretKey =`
Replaced in source by: `/** Reads only; never creates — see [createPepperKeyIfAbsent]. */`
```
/**
 * Reads the pepper key. **Never creates one** — see [createPepperKeyIfAbsent], which is called only
 * from the paths that are legitimately establishing a new verifier ([PinHasher.hash] via
 * `setPin`, and the first wrap of a device secret).
 *
 * Splitting read from create is the whole fix: on the *verify* path, a missing key means the
 * verifier can no longer be evaluated, and the only safe answer is to say so rather than to mint a
 * new key and start returning "wrong PIN" forever.
 */
```

### `private fun createPepperKeyIfAbsent(alias: String): SecretKey {`
Replaced in source by: `/** Throws when the Keystore is unreadable: generating there would overwrite a good key. */`
```
/**
 * Creates the pepper key if it does not exist yet, and returns it. Idempotent.
 *
 * Throws [PepperUnavailableException] rather than generating when the Keystore could not be read at
 * all — generating there would overwrite a key that is still perfectly good.
 */
```

### `val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_HMAC_SHA256, ANDROID_KEYSTORE)`
Replaced in source by: `// Deliberately no setUserAuthenticationRequired: background token rotations need this key.`
```
    // Deliberately not setUserAuthenticationRequired: the app-lock PIN is this app's own
    // secret, not a device credential the Keystore can gate on, and this key is also needed
    // by background token rotations. Non-exportability is the property being bought here.
```

### `object CredentialCipher {`
Replaced in source by: `/** The Keystore pepper binds the wrapping key to the device; losing it means the user re-pairs. */`
```
/**
 * PIN-derived AES-GCM wrapping for the pairing `deviceSecret`.
 *
 * A 6-digit PIN is a 10^6 keyspace: 150k PBKDF2 iterations alone put a full offline sweep of an
 * extracted blob within minutes on one GPU. [deriveKeys] therefore mixes the PBKDF2 output with a
 * non-exportable AndroidKeyStore HMAC key, so deriving the wrapping key requires the device the
 * secret was wrapped on — an attacker holding only the blob has nothing to brute-force against.
 * The PIN is still required, so the key stays re-derivable on demand after any unlock; what this
 * stops is the attack that never touches the app, and therefore never trips the wipe counter.
 *
 * If the Keystore pepper is lost (OS-level key invalidation, keystore reset), unwrapping fails
 * and the user re-pairs. That is the intended direction to fail in.
 */
```

### `fun unwrap(wrapped: WrappedSecret, key: SecretKeySpec): String? = runCatching {`
Replaced in source by: `/** Null on a wrong key or a failed GCM tag; callers treat it as unavailable, never a crash. */`
```
    /** Null on a wrong key or corrupted/tampered ciphertext (GCM's auth tag fails to verify) —
     *  callers (see [org.kysecurity.mail.push.SecurePairingStore]) treat this as "credential
     *  unavailable right now," never as a crash. */
```

## app/src/main/java/org/kysecurity/mail/security/CredentialEnvelope.kt

### `private val OAEP = OAEPParameterSpec(`
Replaced in source by: `/** AndroidKeyStore's OAEP uses MGF1-SHA-1 whatever the transformation name says. */`
```
/**
 * OAEP with SHA-256 for the digest and **SHA-1 for the MGF1**.
 *
 * That mismatch is not a typo and not a weakness — it is what the AndroidKeyStore provider actually
 * implements. Asking it for `RSA/ECB/OAEPWithSHA-256AndMGF1Padding` gets a cipher whose MGF1 digest
 * is SHA-1 regardless of the name, so sealing with the JCE default (MGF1-SHA-256) and opening on
 * device produces a padding error rather than the keys. Naming both digests explicitly, on both
 * sides, is what makes the round trip in [CredentialEnvelopeTest] evidence about the device.
 */
```

### `object CredentialEnvelope {`
```
/**
 * Seals [CredentialKeys] so a later biometric authentication can produce them again.
 *
 * Deliberately free of any Android dependency, so the parameters above are unit-testable. The
 * Keystore half lives in [BiometricUnlockVault].
 */
```

### `fun open(sealed: ByteArray, cipher: Cipher): CredentialKeys? {`
```
    /**
     * Null whenever [sealed] does not open into exactly two AES keys — a blob from a key that has
     * since been replaced, a truncated file, anything. Every caller's response is the same and is
     * always safe: fall back to the PIN.
     */
```

### `fun interface BiometricKeySealer {`
```
/**
 * Hands [AppLockManager] a way to seal the keys it derives on a PIN unlock without dragging a
 * `Context` — and therefore a real AndroidKeyStore — into a class that is unit-tested on the JVM.
 * [BiometricUnlockVault] is the implementation; the default seals nothing.
 */
```

## app/src/main/java/org/kysecurity/mail/security/CredentialGateSync.kt

### `suspend fun rewrapPairingIfNeeded(context: Context, appLockManager: AppLockManager) {`
Replaced in source by: `/** Re-wraps the pairing secret under the current credential key; call after each PIN unlock. */`
```
/**
 * Re-wraps the current pairing's `deviceSecret` behind the credential key whenever it isn't
 * already wrapped under the current scheme.
 *
 * Two cases reach here:
 *
 * 1. It is stored unwrapped from before the gate was switched on — the pairing predates the toggle,
 *    so the secret sits in the clear behind a gate the user believes is closed.
 * 2. It was wrapped by a build from before the Keystore pepper existed
 *    ([org.kysecurity.mail.push.SecurePairingStore.SECRET_VERSION_LEGACY]), and is therefore still
 *    brute-forceable offline. Re-wrapping migrates it to the peppered key.
 *
 * **This is a migration, not a recovery.** It can only re-wrap a secret that is still readable; a
 * secret that was never stored is gone, and the `isNullOrBlank` guard below returns rather than
 * pretending otherwise. Keeping a secret storable in the first place is
 * [org.kysecurity.mail.push.PushRepository.canPersistDeviceSecret]'s job, enforced in
 * [org.kysecurity.mail.push.PushSyncCoordinator] before any registration mints one.
 *
 * Call after every successful PIN unlock (see [UnlockActivity]) — at that point a fresh credential
 * key is cached and either gap can be closed immediately. A biometric unlock derives no PIN key, so
 * [UnlockActivity] demands the PIN outright whenever the gate is on rather than leaving these gaps
 * open until some later unlock that a biometric user may never perform.
 *
 * `Dispatchers.Default`, not [NonCancellable] alone. `withContext` replaces only the context
 * elements it is handed, and [NonCancellable] is a [kotlinx.coroutines.Job] — the dispatcher is
 * inherited. Every caller here is an Activity's `lifecycleScope`, i.e. `Dispatchers.Main.immediate`,
 * so the Keystore reads, the AES-GCM unwrap and the `commit()` below all ran on the UI thread.
 */
```

## app/src/main/java/org/kysecurity/mail/security/DatabaseKey.kt

### `internal object DatabaseKey {`
Replaced in source by: `/** SQLCipher passphrase: 32 random bytes, not PIN-derived — the DB opens with no PIN entered. */`
```
/**
 * The SQLCipher passphrase for `kypost_mail.db`, held in a Keystore-backed store.
 *
 * `kypost_mail.db` was a plain SQLite file. It holds every cached message body, the whole contact
 * book, and contacts' PGP keys — and [AppLockStore]'s own KDoc admitted the app lock "does nothing
 * against someone who simply reads `kypost_mail.db` offline". For a client whose stated purpose is
 * confidential mail, "your mail is in the clear on disk unless you find and enable Hostile Location
 * Protection" was the wrong default.
 *
 * The passphrase is 32 random bytes, not derived from the user's PIN. That is deliberate:
 *
 * - The database has to open in processes where no PIN has been entered — an FCM delivery, a
 *   WorkManager sync — so a PIN-derived key would either break those or force the PIN to be cached
 *   somewhere worse.
 * - The threat this closes is **offline** reading of the file. A random key inside
 *   `EncryptedSharedPreferences` (and so, transitively, inside the AndroidKeyStore) cannot be
 *   extracted from the file system alone, which is exactly the attacker this is for.
 * - It is explicitly **not** a defence against a live, rooted, running device. Hostile Location
 *   Protection remains the answer to that, and it is stronger: under it there is no file at all.
 */
```

### `fun passphrase(context: Context): String {`
Replaced in source by: `/** Base64 so the byte helper and the ATTACH ... KEY SQL text derive the same key. */`
```
    /**
     * The passphrase, minted on first use, as printable ASCII.
     *
     * **Printable on purpose.** SQLCipher takes a passphrase either as bytes (via
     * `SupportOpenHelperFactory`) or as SQL text (in the `ATTACH … KEY ?` that
     * [org.kysecurity.mail.data.DatabaseMigration] needs), and it derives the same key from both only
     * if both see the same byte sequence. Storing raw random bytes made that a guess about how
     * `String` ↔ `ByteArray` round-trips through SQLite's text encoding; base64 removes the
     * question — `text.toByteArray(UTF_8)` and the SQL literal are byte-identical by construction.
     *
     * 32 random bytes of entropy, base64 to 44 characters.
     */
```

### `private fun discardUnopenableDatabase(appContext: Context) {`
Replaced in source by: `/** No stored passphrase with a file present means the keyset reset; the file can never open. */`
```
    /**
     * Deletes [DATABASE_NAME] when a passphrase has to be minted while a database file already
     * exists.
     *
     * No stored passphrase plus an existing file means one thing: [openEncryptedPrefs] reset an
     * undecryptable keyset out from under us, and the file on disk is encrypted under a key that no
     * longer exists anywhere. The rows are already unrecoverable at that point — the only remaining
     * question is whether the app can still start, and without this it cannot: Room hands the file
     * to SQLCipher, which fails SQLITE_NOTADB on the first query, on a background thread, on every
     * launch, forever. [org.kysecurity.mail.data.DataGraph] guards that symptom for a file that is
     * still *plaintext* and had no guard for this, the case where the key is gone.
     *
     * Records the loss so [org.kysecurity.mail.security.LockedActivity] tells the user their cached
     * mail is gone, rather than presenting an empty mailbox.
     */
```

## app/src/main/java/org/kysecurity/mail/security/DownloadedAttachmentLedger.kt

### `object DownloadedAttachmentLedger {`
Replaced in source by: `/** Downloads rows outlive the sandbox wipe; plain prefs so it survives the database delete. */`
```
/**
 * Remembers the MediaStore rows this app wrote into shared Downloads, so [SecurityWipe] can delete
 * them.
 *
 * Attachments saved with Hostile Location Protection *off* — the default — go to shared storage on a
 * single unprompted tap ([org.kysecurity.mail.EmailDetailActivity.downloadAttachment]). Those files live
 * outside the app sandbox, so nothing the wipe deletes reaches them: they survived the wipe, the
 * app-lock reset and the re-pair, while the first screen afterwards told the user "Local data on
 * this device has been erased". Message attachments are frequently the most sensitive thing the app
 * handles, so that claim has to cover them.
 *
 * Deliberately a plain preference file rather than a Room table: it has to be readable and writable
 * *after* [SecurityWipe] has closed and deleted the database, and it is a set of opaque URI strings
 * with no message metadata in it.
 */
```

### `fun record(context: Context, uri: Uri) {`
```
    /** Records a row this app inserted into MediaStore Downloads. */
```

### `fun deleteAll(context: Context) {`
Replaced in source by: `/** Keeps only the URIs it could not delete, then throws, so a resume has the rest. */`
```
    /**
     * Deletes every recorded row, keeps the ones it could not delete, and throws if any remain.
     *
     * Three things were wrong here, each of which let the wipe report a complete erasure over
     * attachment plaintext still sitting in shared Downloads:
     *
     * - `Result.getOrDefault(0)` mapped a **thrown** delete to `0`, which is not `< 0`, so every
     *   exception read as a successful deletion.
     * - `0` was treated as "already gone". MediaProvider also returns `0` for a row that exists and
     *   that this package may not touch — after an `_id` reassignment from an OS update or a Media
     *   Storage "Clear storage", for instance. Verified: a delete returned `0` with the file still
     *   on disk. So the count alone cannot distinguish the two; the row has to be re-queried.
     * - The ledger was cleared **before** the throw, and the `sharedPrefs` step deleted the ledger
     *   file regardless of outcome, so the `willRetry = true` the user was promised was
     *   unfulfillable: a resumed wipe found an empty ledger and reported the step as succeeded.
     *
     * Only successfully deleted URIs are removed, so a resume has exactly the remaining work — and
     * the file itself is now removed here, on success only, rather than by the sweep. Keeping the
     * *record* while dropping the *file* was the half of the fix that was missed: the two have to
     * live and die together or the retry has nothing to iterate.
     */
```

### `store.edit().putStringSet(KEY_URIS, undeleted).commit()`
Replaced in source by: `// commit(), not apply(): a resumed wipe may start in a different process.`
```
        // Keep what is still there so a resumed wipe has work to do; drop only what is really gone.
        // commit(), not apply(): a resumed wipe may start in a different process, and it also
        // flushes any record() still pending so the file delete below cannot race it.
```

### `appContext.deleteSharedPreferences(PREFS_NAME)`
Replaced in source by: `// Delete the ledger only on full success, so a failed sweep keeps the file to retry from.`
```
        // Everything recorded is gone, so the ledger has no remaining purpose. Removing it here —
        // and nowhere else — is what lets the wipe retain the file across a failed sweep without
        // leaving a stale one behind after a successful one.
```

## app/src/main/java/org/kysecurity/mail/security/EncryptedPrefs.kt

### `@file:Suppress("DEPRECATION")`
Replaced in source by: `// androidx.security-crypto is deprecated with no replacement; swapping it is a format migration.`
```
// androidx.security-crypto is deprecated in full with no replacement API. Swapping it out is a
// migration of the at-rest credential format, not a warning fix, so it is deliberately not done
// here. File-scoped because the deprecation also fires on the imports below.
```

### `internal const val CREDENTIAL_RESET_PREFS = "org.kysecurity.mail.credential_reset"`
Replaced in source by: `/** Plain, so it survives the reset it reports; not in [SecurityWipe]'s retained set. */`
```
/** Records that an encrypted store was reset, so the app can tell the user rather than presenting
 *  a clean first-run screen over a secret it destroyed.
 *
 *  Plain, so it survives the reset of the encrypted store it is reporting on. It is deliberately
 *  **not** in [SecurityWipe]'s retained set — a full wipe destroys it along with everything else,
 *  because after a wipe there is no unexpected loss left to warn about and the notice would land on
 *  top of "your data has been erased" saying the same thing less clearly. (An earlier version of
 *  this comment claimed the opposite and was simply wrong; `PREFS_NAMES_RETAINED` never listed it.) */
```

### `internal fun openEncryptedPrefs(`
Replaced in source by: `/** Resets only on a genuinely undecryptable keyset; every other failure propagates. */`
```
/**
 * Opens a Keystore-backed [EncryptedSharedPreferences] file, resetting it **only** when the keyset
 * is genuinely undecryptable.
 *
 * `catch (Exception)` covers far more than the key invalidation the comments named. An
 * `IOException` from a full or momentarily unavailable data partition — which is routine, and which
 * happens during direct-boot to user-unlock transitions on several OEM builds — took the same
 * branch. The user's private key was deleted because the disk was full for a second.
 *
 * So: [GeneralSecurityException] (and Tink's `KeyStoreException` wrapper for it) means the keyset
 * cannot be decrypted and the file is genuinely unreadable forever — reset, and record that we did.
 * **Everything else propagates.** A transient failure must surface as a transient failure, not as
 * silent, permanent destruction of a credential.
 *
 * @param onReset invoked before the delete, with the failure, so the caller can log in its own
 *   voice. The durable marker is written here regardless.
 */
```

### `internal fun isUnrecoverableKeyset(failure: Throwable): Boolean =`
Replaced in source by: `/** True only when the keyset is gone or unparseable; transient storage failures are not. */`
```
/**
 * Whether [failure] means the keyset itself is gone or unparseable, as opposed to the storage
 * being briefly unavailable.
 *
 * Two shapes count:
 *
 * - a [GeneralSecurityException] anywhere in the cause chain: the master key can no longer decrypt
 *   the keyset (OS-level key invalidation, a restored backup);
 * - Tink's `InvalidProtocolBufferException`: the keyset bytes are not a valid protobuf at all, i.e.
 *   truncated or overwritten. It is itself an `IOException`, which is exactly why "IOException
 *   means transient" was too coarse. A store the app can never read again must reset, or the app
 *   cannot start at all.
 *
 * Everything else — a full disk, storage not yet mounted — rethrows, because destroying a
 * credential the user cannot get back is not an acceptable response to a transient failure.
 */
```

### `private fun Throwable.isProtobufParseFailure(): Boolean =`
Replaced in source by: `/** Walks the hierarchy: subclasses have their own simpleName, and the type is in shaded Tink. */`
```
/**
 * Whether this throwable is a protobuf parse failure, **including the subclasses**.
 *
 * `InvalidProtocolBufferException` has nested subclasses — `InvalidWireTypeException`,
 * `TruncatedMessageException`, `SizeLimitExceededException` — and a nested class's `simpleName` is
 * its own, not its parent's. So matching `javaClass.simpleName` directly recognised only the base
 * type, and every subclass fell through to "transient, rethrow".
 *
 * That was not cosmetic. Corrupting a keyset in a way that trips `InvalidWireTypeException` (which
 * is what happens on API 31, where the stored keyset's bytes differ from API 34's) left the store
 * permanently unreadable and never reset — so `AppLockStore.isLockEnabled()` threw, out of
 * `SecurityGraph`'s constructor, out of `LockedActivity.onCreate`, and the app could not start.
 * `AppLockStoreTest.corruptedKeyset_doesNotCrash_andTripsTheTripwire` asserts the recovery; it
 * passed on API 34 and failed on 31 for this reason, taking seventeen other suites down with it
 * because the corrupted store persisted across the whole instrumentation run.
 *
 * Walking the hierarchy rather than importing the type, because it lives in Tink's *shaded*
 * protobuf package — an implementation detail this file must not depend on by name.
 */
```

### `internal fun recordCredentialReset(context: Context, fileName: String) {`
```
/** The stores reset since the last time a screen acknowledged it, newest write wins. */
```

### `fun credentialResetsPending(context: Context): Set<String> =`
```
/** Which encrypted stores were reset out from under the user, for a screen to report. Empty when
 *  nothing was lost. */
```

### `fun acknowledgeCredentialResets(context: Context) {`
```
/** Called once the user has been told. */
```

## app/src/main/java/org/kysecurity/mail/security/EphemeralAttachmentProvider.kt

### `private const val MAX_CONCURRENT_WRITES = 8`
Replaced in source by: `/** Capped so a stalled viewer cannot wedge later opens; pairs with the pool's SynchronousQueue. */`
```
/**
 * Ceiling on *concurrent* pipe writes. One raw `Thread` per attachment was unbounded thread
 * creation driven by how fast the user can tap; a two-thread fixed pool replaced that with
 * head-of-line blocking, which is worse.
 *
 * A pipe holds 64 KB and `write()` blocks until the reader drains it, so a viewer app that opens
 * the descriptor and then stops reading — backgrounded, ANR'd, or sniffing only a MIME prefix —
 * parks its writer thread indefinitely. With a fixed pool of two and an unbounded queue, two such
 * viewers wedged every subsequent attachment open for the life of the process, with no timeout and
 * no error, on the one path whose entire purpose is that this is how you open an attachment under
 * Hostile Location Protection.
 *
 * The pool below pairs this cap with a [SynchronousQueue], so a write never waits behind a stalled
 * one: it either gets a thread immediately or is refused outright, and [EphemeralAttachmentProvider]
 * turns a refusal into an `IOException` the caller can see. Stalled writers still hold their thread
 * (nothing can safely interrupt a blocking write mid-stream without handing the viewer a truncated
 * file), but they can now only consume slots up to this bound.
 */
```

### `private const val MAX_PENDING_BYTES = org.kysecurity.mail.MemoryBudget.PENDING_ATTACHMENT_BYTES`
Replaced in source by: `/** Bounds retained plaintext; sized in MemoryBudget alongside the app's other heap ceilings. */`
```
/**
 * Ceiling on the total plaintext held awaiting a read.
 *
 * [MAX_CONCURRENT_WRITES] bounds writer *threads*; nothing bounded the map they read from. Each
 * registration parks a whole attachment — up to the 25 MB relay download limit — in the heap for
 * [ATTACHMENT_TTL_MILLIS], and the TTL only matters if the process lives that long. Tapping a
 * handful of large attachments and backing out of each chooser (which never calls `take`) put
 * hundreds of megabytes of decrypted mail in the heap, on the one path whose entire premise is
 * that this plaintext is short-lived.
 *
 * Set in [org.kysecurity.mail.MemoryBudget] rather than here: this is the only one of the app's
 * three heap ceilings whose bytes are *retained* rather than transient, so it is the term that
 * decides the realistic peak, and it cannot be sized without seeing the other two.
 */
```

### `internal class PendingAttachment(`
Replaced in source by: `/** Not a data class: identity equals over [bytes]. Enforced by `SourceRulesTest`. */`
```
/** **Not a `data class`**: identity `equals`/`hashCode` over [bytes] while advertising structural
 *  equality is the trap [WrappedSecret] and [PinHash] both refuse in their own KDoc, and this one
 *  is a map value, which is exactly where someone reaches for `==`. Enforced by `SourceRulesTest`. */
```

### `val displayName: String,`
```
    /** What a viewer app shows the user. See [EphemeralAttachmentProvider.query]. */
```

### `object EphemeralAttachmentBytes : org.kysecurity.mail.ProcessScopedState {`
Replaced in source by: `/** Attachment bytes awaiting a single ephemeral read; nothing here is ever written to disk. */`
```
/**
 * In-memory holder for attachment bytes awaiting a single ephemeral read, keyed by a one-time
 * token. Nothing here is ever written to disk — see [EphemeralAttachmentProvider], the
 * `ContentProvider` that serves these bytes to a viewer app.
 */
```

### `private val sweeper = Executors.newSingleThreadScheduledExecutor(daemonThreadFactory("ephemeral-attachment-sweeper"))`
Replaced in source by: `/** Expiry runs on a timer: a lazy sweep leaves bytes resident if nothing else registers. */`
```
    /**
     * Expiry runs on a timer, not lazily on the next [register].
     *
     * The lazy version only bounded the lifetime if another attachment was ever registered: view
     * one attachment, back out of the chooser so nothing calls [take], and those decrypted bytes
     * stayed in the heap for the life of the process. On the Hostile Location Protection path —
     * whose entire purpose is that attachment plaintext never persists — that is the failure the
     * feature exists to prevent, and the doc comment claiming it was bounded was simply wrong.
     */
```

### `internal val writeExecutor: ThreadPoolExecutor = ThreadPoolExecutor(`
Replaced in source by: `/** `SynchronousQueue` is load-bearing: with no free thread a write is refused, not queued. */`
```
    /** See [MAX_CONCURRENT_WRITES]. `SynchronousQueue` is load-bearing: it has no capacity, so a
     *  submission that finds every thread busy is rejected immediately instead of queueing behind
     *  a writer that may never finish. */
```

### `org.kysecurity.mail.ProcessState.register(this)`
Replaced in source by: `// Registered because relaunch no longer kills the process holding this plaintext.`
```
        // See [org.kysecurity.mail.ProcessScopedState]. This holder is the reason that registry exists:
        // it parks up to MAX_PENDING_BYTES of decrypted attachment plaintext in a process-scoped
        // object, and AppRestart.relaunch no longer kills the process — so a security wipe used to
        // run to completion, relaunch into the same JVM, and leave the plaintext readable in the
        // attacker's session. InMemoryPlaintext's own KDoc invited a future holder to register
        // here; this is that holder, and it did not.
```

### `override fun resetForNewSession() {`
Replaced in source by: `/** Zeroes rather than merely dropping: dropped plaintext stays readable in a heap dump. */`
```
    /**
     * Drops and zeroes every held attachment. See [org.kysecurity.mail.ProcessScopedState].
     *
     * Zeroes rather than merely dropping, for the same reason [purgeExpired] does: until the
     * collector runs — and possibly after, if a buffer was promoted — this plaintext is readable
     * in a heap dump, and a wipe runs precisely when the device is presumed hostile.
     */
```

### `fun register(bytes: ByteArray, mimeType: String, displayName: String): Uri? {`
```
    /**
     * Parks [bytes] for a single ephemeral read, or returns null when doing so would push the
     * held-plaintext total past [MAX_PENDING_BYTES].
     */
```

### `val authority = this.authority`
Replaced in source by: `// Nothing may be parked under an unknown authority; [configure] runs from attachInfo.`
```
        // Nothing may be parked under an unknown authority. [configure] runs from the provider's
        // attachInfo, and an empty authority produced `content:///token` — a malformed URI handed
        // to the chooser, resolving to nothing, with the plaintext left in the map until the
        // sweeper reached it. The caller already has a "cannot serve this" path; use it.
```

### `val removed = pending.remove(entry.key) ?: return@forEach`
Replaced in source by: `// The removal's return value decides ownership, since take() can win this race.`
```
            // The removal's own return value decides ownership of the bytes, rather than zeroing
            // the array this iteration happened to see. `take()` can win the race between the
            // filter above and this line — a user tapping an attachment moments before its TTL —
```

### `class EphemeralAttachmentProvider : ContentProvider() {`
Replaced in source by: `/** Serves registered bytes through a pipe, never a file; each token is single-use. */`
```
/**
 * Serves attachment bytes registered via [EphemeralAttachmentBytes.register] through a pipe, never
 * a file. Each token is single-use: [EphemeralAttachmentBytes.take] removes it from memory the
 * moment this provider starts serving it.
 */
```

### `if (mode != "r") {`
Replaced in source by: `// Checked BEFORE take(), which consumes the single-use token.`
```
        // Checked BEFORE take(), which consumes the single-use token. `mode` used to be accepted
        // and discarded, so a viewer opening "rw" or "w" got a read-only pipe end, an
        // incomprehensible failure downstream, and a token that was already gone by the time it
        // retried. There is nothing here to write to: these bytes are read once and zeroed.
```

### `android.util.Log.w(`
Replaced in source by: `// Benign: the viewer can close its read side early, giving a broken pipe.`
```
                    // Expected/benign, not a bug: the viewer app can close its read side before this
                    // finishes writing (user backs out of the app chooser, the viewer only reads a
                    // MIME-sniffing prefix, etc.), which surfaces here as a broken-pipe IOException.
```

### `Arrays.fill(attachment.bytes, 0)`
Replaced in source by: `// Every writer slot is held by a stalled viewer; fail loudly rather than queue.`
```
            // Every writer slot is held by a viewer that stopped reading (see MAX_CONCURRENT_WRITES).
            // Fail loudly and clean up rather than queueing: an attachment that never opens and
            // never errors is indistinguishable from a hung app, and the plaintext must not be left
            // sitting in the heap behind a write that will never run.
```

### `override fun query(`
Replaced in source by: `/** Must not return null (viewers refuse the URI) and must not consume the token. */`
```
    /**
     * `OpenableColumns` only — enough for a viewer to name and size the attachment.
     *
     * Returning null here was not a neutral "there is no table". Well-behaved viewers query
     * `DISPLAY_NAME` and `SIZE` before opening a `content://` URI; several treat a null cursor as
     * "this URI does not exist" and refuse outright, and the ones that do not showed the user their
     * decrypted attachment under a bare UUID with no extension. This is the one path whose entire
     * purpose is that attachments open without ever touching disk, so it has to actually open.
     *
     * Deliberately does NOT consume the token — that is [openFile]'s job, and a metadata query is
     * not a read.
     */
```

## app/src/main/java/org/kysecurity/mail/security/HostileLocationSettings.kt

### `enum class HostileLocationState {`
```
/**
 * What the protection flag can actually say, which is three things rather than two — the same shape
 * and the same reasoning as [TripwireState].
 */
```

### `class HostileLocationSettings(context: Context) {`
Replaced in source by: `/** Value plus HMAC under [KeystoreHlpKey]; tampering deliberately fails towards ENABLED. */`
```
/**
 * Whether Hostile Location Protection is on: no database file, no persisted push history, no
 * attachment ever written to disk.
 *
 * **Authenticated, because of what reads it.** This was a bare `Boolean` in a `MODE_PRIVATE`
 * preferences file — the exact primitive [KeystoreTripwireKey]'s KDoc spends a paragraph proving is
 * not a control — while being the single flag that decides whether the user's mail exists on disk
 * at all. The app-lock tripwire got a Keystore anchor over a much smaller claim; this one had
 * nothing, and its own test asserted only that the default is false and that it persists, because
 * there was nothing else to assert.
 *
 * The marker is now a value plus an HMAC under [KeystoreHlpKey], and the key's mere presence is the
 * durable half: deleting both preference files no longer silently downgrades the posture, and
 * writing `enabled=false` into the file no longer does either.
 *
 * **Tampering fails towards [HostileLocationState.ENABLED]**, the opposite of the app lock's
 * tripwire and for the mirror-image reason. There, failing towards "configured" would destroy data;
 * here, failing towards "disabled" would start writing plaintext to a disk the user believes is
 * empty. The cost of the safe answer is that cached mail is unavailable until it resolves.
 */
```

### `fun state(): HostileLocationState =`
Replaced in source by: `/** Mirrors [AppLockStore.tripwireState] but fails the opposite way; keep them separate. */`
```
    /**
     * The posture, or that it cannot be determined.
     *
     * Mirrors [AppLockStore.tripwireState] step for step; keep the two in sync by hand, because the
     * *directions they fail in are deliberately opposite* and a shared implementation would invite
     * someone to unify that away.
     */
```

### `fun isEnabled(): Boolean = state() != HostileLocationState.DISABLED`
Replaced in source by: `/** UNREADABLE answers true: callers decide where bytes go and have no wait-and-see. */`
```
    /**
     * [state] collapsed to the question every consumer actually asks.
     *
     * [HostileLocationState.UNREADABLE] answers **true** here. Every caller of this decides where
     * bytes go — an in-memory database or a file, an ephemeral pipe or shared Downloads — and there
     * is no "wait and see" available at those call sites. Answering true means the app is
     * temporarily less useful; answering false means it writes plaintext the user believes is not
     * being written. [LockedActivity] is what turns the unreadable case into something the user is
     * actually told about.
     */
```

### `fun setEnabled(enabled: Boolean) {`
Replaced in source by: `/** Key first when enabling, marker first when disabling, so an interruption leaves it ON. */`
```
    /**
     * Writes the flag, minting or destroying [KeystoreHlpKey] to match.
     *
     * **Key first when enabling**, exactly as [AppLockStore.enableLock] does: a marker written
     * before the key that authenticates it exists cannot be verified, and [state] reads an
     * unverifiable marker as tampering.
     *
     * **Marker first, key last when disabling.** Every interruption point then leaves protection
     * ON — after the clear, the key is still present with no marker beside it, which [state] reads
     * as tampering and answers ENABLED — so a process death during a disable is a retry rather than
     * a silent downgrade.
     *
     * Disabling deliberately writes no `enabled = false` marker on the way out. It cannot: MACing
     * one needs the key, and `setEnabled(false)` is reachable on a device that never enabled
     * protection at all — `SecuritySettingsActivity.disableLock` calls it unconditionally — where
     * [KeystoreHlpKey.mix] would throw [PepperUnavailableException]. It also would not buy
     * anything: "no key, no marker" already IS the disabled state, and it is the same state a fresh
     * install is in.
     */
```

### `@Volatile`
Replaced in source by: `/** Process-wide: one shared file. UNREADABLE is transient and never cached. */`
```
        /**
         * The resolved posture, cached **for the process**, not per instance.
         *
         * Cached at all because this is on hot paths that the old plain-boolean read was free on:
         * [org.kysecurity.mail.mail.MailCursorStore] consults it per cursor operation and
         * [org.kysecurity.mail.data.DataGraph] at construction, so a Keystore round trip each time
         * would be a real regression. Same precedent as
         * [org.kysecurity.mail.push.SecurePairingStore]'s cached TLS pin.
         *
         * **In the companion, because the state it caches is a single file shared by every
         * instance.** As a per-instance field this was a trap: `SecurityGraph`,
         * `DeviceContactsGraph`, `KeywordSettings`, `MailCursorStore` and `DeviceContactRepository`
         * each hold their own long-lived `HostileLocationSettings`, so `setEnabled` on a fresh
         * instance cleared exactly one memo and left the other five serving a stale answer. In
         * production that stayed invisible — every toggle is followed by [AppRestart.relaunch],
         * which rebuilds those graphs — and it surfaced as an instrumented test finding an
         * in-memory database where it had just asked for a disk-backed one. A cache of process-wide
         * state belongs in one place, invalidated once.
         *
         * [HostileLocationState.UNREADABLE] is deliberately NOT cached: it is a transient device
         * condition, and holding it would keep the app blocked past the keystore2 restart that
         * caused it.
         */
```

### `}`
Replaced in source by: `// No destroy(): SecurityWipe captures and restores the posture instead of tearing it down.`
```
    // Deliberately no `destroy()` teardown helper alongside the other security stores. SecurityWipe
    // does not tear this down: it captures the posture before wiping and RESTORES it afterwards,
    // because a wipe that runs because the device is presumed hostile must not switch off the
    // feature for that exact situation. `setEnabled(false)` is the only path that removes the key.
```

## app/src/main/java/org/kysecurity/mail/security/LockedActivity.kt

### `abstract class LockedActivity : AppCompatActivity() {`
```
/**
 * Base class for every screen that must not be reachable while the app lock is engaged.
 */
```

### `protected open val secureWindow: Boolean = true`
```
    /** Overridable only so a future screen with a genuine reason (e.g. a share/print preview) can
     *  opt out deliberately; no current screen does. */
```

### `protected fun isLocked(): Boolean = SecurityRuntime.graph(this).appLockManager.isLockedNow()`
Replaced in source by: `/** [AppLockManager.isLockedNow], not the flow value: the grace window may have expired. */`
```
    /** [AppLockManager.isLockedNow], not the flow's current value: a screen resumed after the
     *  background grace window expired must gate on the window having expired, not on whether
     *  anything happened to call `lockNow()` in the meantime. */
```

### `protected var redirectedToUnlock: Boolean = false`
```
    /**
     * True once this Activity has been redirected to the unlock screen, or is standing down for a
     * startup wipe verdict.
     *
     * Still readable by subclasses, because `onResume`, `onCreateOptionsMenu` and the async
     * callbacks they start legitimately need it. What it is no longer used for is gating
     * `onCreate` — see [onCreateUnlocked].
     */
```

### `protected abstract fun onCreateUnlocked(savedInstanceState: Bundle?)`
Replaced in source by: `/** Called only when the startup wipe verdict is in, not terminal, and the app is unlocked. */`
```
    /**
     * [onCreate], minus every state in which this screen must not run.
     *
     * **This replaces a convention with a signature.** The gate used to be three lines every
     * subclass had to remember to copy — `super.onCreate(...)`, a comment, `if (redirectedToUnlock)
     * return` — repeated verbatim in thirteen Activities. All thirteen got it right; the
     * fourteenth was one merge away from rendering the inbox behind the unlock screen, and no
     * compiler or test could have said so. Overriding this instead makes "do not run while locked"
     * a thing the type system enforces rather than a thing a comment asks for.
     *
     * Called only when: the startup wipe verdict is in and not terminal, and the app is unlocked.
     */
```

### `enableEdgeToEdge()`
Replaced in source by: `// enableEdgeToEdge must precede setContentView for its cutout mode to reach the window.`
```
        // Before any subclass content view exists: enableEdgeToEdge has to be called before
        // setContentView for the display-cutout mode it sets to reach the window. UnlockActivity
        // and MfaApprovalActivity are not subclasses and call it themselves.
```

### `@OptIn(ExperimentalCoroutinesApi::class)`
Replaced in source by: `/** Blocks until [SecurityWipe.enforceTripwire] has ruled; false means do nothing at all. */`
```
    /**
     * Blocks this screen until [SecurityWipe.enforceTripwire] has ruled on whether the local
     * database is about to be destroyed. Returns false when the caller must do nothing at all.
     */
```

### `val verdict = SecurityWipe.startupVerdict.getCompleted()`
Replaced in source by: `// First screen to observe a startup wipe relaunches; the CAS keeps it to exactly one.`
```
        // First screen to observe a startup wipe: tell the user, rebuild every graph (Mail and
        // Contacts still hold DAO handles on the database SecurityWipe just closed) and restart
        // into a coherent first-run state. The wipe reset the app lock, so MainActivity routes
        // straight to pairing — UnlockActivity would prompt for a PIN that no longer exists. The
        // CAS makes it exactly one screen: the others come up after the relaunch and carry on.
```

### `val lockTripwireUnreadable =`
Replaced in source by: `// Unreadable Keystore: neither answer is safe, so show nothing. Transient, not terminal.`
```
        // Before any verdict is acted on: the tripwire's durable half is a Keystore alias, and a
        // Keystore that cannot be consulted leaves "is the app lock still intact" genuinely
        // unanswered. Neither available answer is safe — see [TripwireState] — so the app answers
        // neither and shows nothing. Not terminal, unlike the abandoned wipe below: a keystore2
        // restart resolves on the next boot, so the user is told to restart rather than reinstall.
```

### `val protectionUnreadable = runCatching { HostileLocationSettings(this).state() }`
Replaced in source by: `// Checked here because isEnabled() resolves UNREADABLE to true, hiding it from callers.`
```
        // The protection flag's marker is anchored the same way and is unanswerable for the same
        // reason. It is checked here too because `HostileLocationSettings.isEnabled()` resolves
        // UNREADABLE to `true` — the only safe answer at a call site that has to decide where bytes
        // go — and that would otherwise present a silently empty mailbox as if it were the user's,
        // with no statement that the app could not read its own posture.
```

### `if (verdict is WipeResult.Incomplete && !verdict.willRetry) {`
Replaced in source by: `// Terminal, and checked before the one-shot below because this state is not one-shot.`
```
        // Terminal, and checked before the one-shot below because it is NOT one-shot: the wipe
        // gave up with steps still failing, so plaintext mail, contacts or attachments may be on
        // this device right now. Relaunching into a first-run screen — what the branch below does —
        // presents a clean, usable app over exactly that, which is the same false "your data is
        // gone" claim in a different form. There is nothing here it is safe to show, and only a
        // reinstall clears it, so every gated screen blocks on every launch until one happens.
```

### `val message = when (verdict) {`
```
            // Which message depends on whether the wipe actually finished. Announcing a completed
            // erasure over an incomplete one is the failure this branch used to have: it took a
            // bare `true` from enforceTripwire and always said "has been erased", including when
            // every step failed or when the security graph could not be built at all. In a coercive
            // hand-over that claim is what the user acts on.
```

### `private fun reportCredentialResets() {`
```
    /**
     * Tells the user, once, that an encrypted store had to be reset out from under them.
     */
```

### `val message = if (org.kysecurity.mail.data.DATABASE_NAME in reset) {`
Replaced in source by: `// Losing the database key costs the cached mail, not just a re-establishable credential.`
```
        // The database key's loss is not the same event as a pairing's. Every other reset store
        // costs a credential the user can re-establish; that one costs the cached mail itself, and
        // saying "no mail or contacts were deleted" over it is a false claim about their data.
```

### `private fun blockOnUnreadableTripwire() {`
Replaced in source by: `/** Transient device condition: asks for a restart, unlike [blockOnAbandonedWipe]. */`
```
    /**
     * The "the Keystore cannot be consulted" state: a non-dismissable notice over a blank window.
     *
     * Same shape as [blockOnAbandonedWipe] and for the same reason — there is nothing here it is
     * safe to show — but a different claim. That one is permanent and needs a reinstall; this one
     * is a transient device condition, so it says so and asks for a restart.
     */
```

### `private fun blockOnAbandonedWipe(failedSteps: List<String>) {`
Replaced in source by: `/** Posted because this runs from onCreate, before the window has a token for a dialog. */`
```
    /**
     * The permanent "wipe incomplete — manual recovery required" state: a non-dismissable notice
     * over a blank window, and the only way out is closing the app.
     *
     * Posted rather than shown inline because this runs from `onCreate`, before the window has a
     * token to attach a dialog to.
     */
```

### `val startupWipeHandled = java.util.concurrent.atomic.AtomicBoolean(false)`
Replaced in source by: `/** One-shot: later screens must not bounce the task again on the same verdict. */`
```
        /** One-shot across the process: the first screen to observe a startup wipe rebuilds the
         *  graphs and relaunches, and the screens that come up afterwards must not bounce the task
         *  again on the same verdict. */
```

## app/src/main/java/org/kysecurity/mail/security/LockoutPolicy.kt

### `object LockoutPolicy {`
Replaced in source by: `/** Attempts 1-2 are free; the delay ladder tops out at an hour, and the wipe is opt-out. */`
```
/**
 * Escalating-delay + optional-wipe lockout curve for wrong app-lock PIN attempts (see
 * "Require Unlock to Open" in the 2026-07-22 security-hardening spec). Attempts 1-2 are free
 * (typos happen); attempt 3 onward adds a growing delay before the next try is allowed; once
 * [wipeAfterAttempts] consecutive wrong attempts accumulate (no intervening correct PIN/biometric)
 * local data is wiped via [SecurityWipe].
 *
 * **The wipe is a user choice, and the ladder is long enough to be one.** It used to be a
 * hardcoded ten attempts with no way to turn it off, over a ladder summing to about eighty
 * minutes. That is not a defence — an attacker wants to read the mailbox, not delete it — but it
 * is a very effective denial of service: anyone who borrows the phone for an afternoon, or a child
 * who finds the PIN screen entertaining, destroys mail and contacts that `allowBackup="false"` and
 * `data_extraction_rules.xml` deliberately make unrecoverable. The ladder below tops out at an
 * hour per attempt so reaching the threshold takes most of a day rather than a lunch break, and
 * [AppLockSettings] lets the user pick the threshold or turn the wipe off entirely.
 */
```

### `val WIPE_THRESHOLD_CHOICES = listOf(10, 20, 30)`
```
    /** Offered in the settings UI. Null means "never wipe". */
```

### `const val DEFAULT_WIPE_THRESHOLD = 30`
```
    /** What a fresh install gets: on, and at the most forgiving end of the offered range. */
```

### `fun timeToWipeMillis(wipeAfterAttempts: Int): Long =`
```
    /** How long reaching [wipeAfterAttempts] actually takes, so the settings screen can state it
     *  rather than leaving the user to infer it from a number of attempts. */
```

## app/src/main/java/org/kysecurity/mail/security/PinField.kt

### `internal fun EditText.consumePin(): CharArray {`
Replaced in source by: `/** Clearing the Editable cannot scrub the TextView/IME copies, only the ones this app makes. */`
```
/**
 * Reads a PIN out of an [EditText] as a [CharArray] and clears the widget, so no `String` copy is
 * ever made.
 *
 * **Honest limit.** `Editable.clear()` truncates the widget's buffer, it does not scrub the
 * `char[]` behind it, and `TextView` keeps its own copies for layout and the IME. This removes the
 * copies this app makes; it cannot remove the ones the toolkit makes.
 */
```

### `internal suspend fun <T> CharArray.usePin(block: suspend (CharArray) -> T): T =`
```
/** Runs [block] with this PIN and zeroes it afterwards, whatever happens. */
```

## app/src/main/java/org/kysecurity/mail/security/PinGate.kt

### `suspend fun Activity.resolvePinAttempt(result: UnlockAttemptResult): Boolean = when (result) {`
Replaced in source by: `/** Route every result through here; no screen outside this file may test for Success. */`
```
/**
 * Turns an [UnlockAttemptResult] into "may this screen proceed?", handling the two outcomes that
 * are not about the PIN at all.
 *
 * Routing every caller through here is what makes that unrepresentable: the `when` below is
 * exhaustive over the sealed class, so a new outcome is a compile error rather than a silent
 * `false`. **No screen outside this file may test the result for `Success` directly.**
 *
 * Returns `true` only for [UnlockAttemptResult.Success]. On either wipe outcome it relaunches into
 * a fresh first-run state, so the caller's `false` branch runs against an Activity that is already
 * finishing — which is harmless, and simpler than making every caller understand the difference.
 */
```

### `Toast.makeText(applicationContext, R.string.security_verifier_unavailable, Toast.LENGTH_LONG).show()`
Replaced in source by: `// Not a wrong PIN, and it does not advance the wipe threshold.`
```
        // Not a wrong PIN, and the user must not be told it was one — the correct PIN will keep
        // "failing" until they reinstall, and every screen that shows "Incorrect PIN" here invites
        // them to burn the remaining attempts against a wipe threshold this outcome deliberately
        // does not advance. Say what actually happened.
```

### `val message =`
Replaced in source by: `// Retry is only promised while SecurityWipe still resumes; MAX_WIPE_RESUMES ends that.`
```
        // Two different messages: the wipe is only retried while SecurityWipe is still resuming it.
        // Once MAX_WIPE_RESUMES is reached nothing will re-run by itself, so promising a retry
        // there tells the user their data will be erased when it will not be. The relaunch below
        // then lands on LockedActivity's terminal block, which is where that state is enforced
        // rather than merely announced.
```

### `private suspend fun Activity.announceWipeAndRelaunch(messageRes: Int, failedSteps: List<String>?) {`
Replaced in source by: `/** App-context Toast: finishAffinity() follows and would drop one bound to this Activity. */`
```
/**
 * Tells the user their data is gone (or may not be) and rebuilds the process graphs.
 *
 * The Toast is built against the application context because [AppRestart.relaunch] calls
 * `finishAffinity()` immediately afterwards — a Toast bound to a finishing Activity's context can be
 * dropped, and this is the one message that must not be.
 *
 * Relaunching on the *incomplete* path too is deliberate: [SecurityWipe] leaves its in-progress
 * marker set, and [org.kysecurity.mail.KyPostApp] re-runs the whole wipe on the next start.
 */
```

## app/src/main/java/org/kysecurity/mail/security/PinHasher.kt

### `class PinHash(val salt: ByteArray, val hash: ByteArray)`
Replaced in source by: `/** Not a data class: compare only via [PinHasher.matches], which is constant time. */`
```
/**
 * [hash] is never the raw PIN — only this derived, salted value is ever persisted.
 *
 * **Not a `data class`.** Kotlin would generate identity `equals`/`hashCode` for the two
 * [ByteArray] fields while advertising structural equality, and this is a stored PIN verifier: an
 * `==` that silently means "same object" is the worst possible shape for it. Comparison goes
 * through [PinHasher.matches], which uses [java.security.MessageDigest.isEqual] and is constant
 * time; nothing else may compare these.
 */
```

### `object PinHasher {`
Replaced in source by: `/** The verifier is Keystore-peppered under its own alias, forcing brute force on-device. */`
```
/**
 * PBKDF2-based PIN hashing for the app-lock PIN (see "Require Unlock to Open" in the
 * 2026-07-22 security-hardening spec). [matches] uses [MessageDigest.isEqual], which is
 * documented as timing-attack-resistant, rather than `ByteArray.contentEquals` — a PIN
 * comparison is exactly the kind of check where short-circuiting on the first differing byte
 * would leak information to a timing attacker.
 *
 * The stored verifier is peppered with a non-exportable Keystore key, for the same reason
 * [CredentialCipher] peppers the wrapping key: PBKDF2 iterations cannot defend a 10^6..10^12
 * keyspace on their own, so an attacker who reads this file must be forced to brute-force *on the
 * device*, through the Keystore, rather than offline on a GPU. Leaving the verifier unpeppered
 * defeated the wrapping key's pepper too — both live in the same sandbox behind the same master
 * key, so whoever can read one can read the other, and recovering the PIN from the cheaper of the
 * two yields the wrapping key as well. A distinct pepper alias from [CredentialCipher]'s keeps the
 * two derivations non-interchangeable.
 */
```

### `fun hash(`
Replaced in source by: `/** Mints the pepper if missing; [matches] must not, or a correct PIN reads as wrong. */`
```
    /**
     * Derives a storable verifier, creating the Keystore pepper if this is the first one.
     *
     * The creation is here and **not** in [matches], because "no pepper key" means opposite things
     * on the two paths: setting a PIN legitimately establishes one, while verifying against a
     * missing one means the stored verifier can no longer be evaluated at all. Minting a key on the
     * verify path made every subsequent correct PIN read as wrong, and ten of those wipe the
     * device. See [PepperUnavailableException].
     */
```

### `fun matches(`
Replaced in source by: `/** Throws rather than returning false: a false here would count toward the wipe threshold. */`
```
    /**
     * Verifies [pin] against a stored verifier. Never creates a pepper key — see [hash].
     *
     * Throws [PepperUnavailableException] rather than returning false when the pepper is gone: a
     * `false` here is indistinguishable from a wrong PIN, and wrong PINs are counted toward
     * [AppLockState.wipeAfterAttempts].
     */
```

## app/src/main/java/org/kysecurity/mail/security/PinPolicy.kt

### `object PinPolicy {`
Replaced in source by: `/** Minimum 8, not 6: the Keystore pepper forces on-device guessing, but 10^6 is only hours. */`
```
/**
 * What counts as an acceptable app-lock PIN.
 *
 * The lock throttles and (optionally) wipes after a run of wrong attempts, so an attacker gets a
 * bounded number of guesses — which makes the handful of PINs that everybody picks a real risk
 * rather than a theoretical one. [WEAK_PINS] are the sequences and repeats that dominate every
 * published leaked-PIN dataset; a short guess budget would otherwise land inside this list.
 *
 * The minimum is 8, not 6, because iteration count cannot defend a small keyspace. Both the PIN
 * verifier and the wrapping key are peppered with a non-exportable Keystore HMAC, which forces any
 * brute force to run on-device — but 10^6 is still only minutes to an hour of Keystore calls,
 * whereas 10^8 is days. Existing shorter PINs keep working ([AppLockStore.verifyPin] does not
 * re-check length); the floor applies when setting or changing one.
 */
```

### `private val WEAK_PINS = setOf(`
Replaced in source by: `/** Runs of any length are caught by [isRun]; this covers repeat and date families it misses. */`
```
    /**
     * Sized for [MIN_LENGTH] and up. The list used to hold only 6-digit values, which the raised
     * minimum turned into dead code — `validate` checks length first, so every entry was already
     * rejected as TooShort before the set was consulted.
     *
     * Pure ascending/descending/constant runs of any length are caught by [isRun] instead, so this
     * covers the repeating- and dated-pattern families that a run check cannot see.
     */
```

### `pin.concatToString() in WEAK_PINS -> Result.TooCommon`
```
        // concatToString() here is a short-lived copy of a PIN that has already been rejected as
        // weak or is about to be accepted — the set lookup needs a String and there is no
        // CharArray-keyed equivalent worth building for 26 entries.
```

### `private fun isRun(pin: CharArray): Boolean {`
```
    /** Catches the longer ascending/descending runs the fixed [WEAK_PINS] list can't enumerate
     *  once PINs may be up to [MAX_LENGTH] digits (e.g. "23456789"). */
```

## app/src/main/java/org/kysecurity/mail/security/SecureDialogs.kt

### `fun <T : Dialog> T.showSecurely(): T {`
Replaced in source by: `/** FLAG_SECURE is per-window: a Dialog needs its own, and the touch filter needs onShow. */`
```
/**
 * Shows [this] with `FLAG_SECURE` set and overlays suppressed, so it is excluded from screenshots
 * and screen recordings exactly as the Activity behind it is, and cannot have its buttons covered
 * by another app.
 *
 * **`FLAG_SECURE` is a per-window flag and a Dialog creates its own window.** Setting it on the
 * Activity in [LockedActivity], [UnlockActivity] and
 * [org.kysecurity.mail.push.MfaApprovalActivity] therefore protects the Activity's window and nothing
 * else — every PIN this app asks for through an `AlertDialog` (set PIN, confirm PIN, change PIN,
 * disable lock, the credential-gate prompt, and the MFA fallback) was capturable by a screen
 * recorder or an overlay-capable app, while the identical field inlined in [UnlockActivity] was not.
 *
 * The same is true of [applyOverlayProtection], and it is the half that matters for a dialog that
 * asks the user to approve something: a consent prompt whose accept button can be covered is not a
 * consent prompt. The touch filter is re-applied to the dialog's whole view tree in
 * `setOnShowListener`, because the content view does not exist until then.
 *
 * Applies to both `android.app.AlertDialog` and `androidx.appcompat.app.AlertDialog`, which share
 * [Dialog] as a supertype. Use it for anything that renders a secret or asks for a decision; there
 * is no cost to using it for anything else.
 */
```

## app/src/main/java/org/kysecurity/mail/security/SecureWindow.kt

### `fun Window.applySecureFlag() {`
Replaced in source by: `/** Skipped only for BuildConfig.ALLOW_SCREENSHOTS: debug variant plus -PallowScreenshots. */`
```
/**
 * Single point at which `FLAG_SECURE` is applied, so the four windows that need it
 * ([LockedActivity], [UnlockActivity], [org.kysecurity.mail.push.MfaApprovalActivity] and every
 * dialog shown via [showSecurely]) cannot drift apart.
 *
 * The flag is skipped only when [BuildConfig.ALLOW_SCREENSHOTS] is set, which requires *both* a
 * debug variant and an explicit `-PallowScreenshots=true` on the Gradle invocation. It exists
 * because store and README screenshots have to be taken against a paired account, an emulator
 * cannot pair, and `FLAG_SECURE` is enforced below the app by SurfaceFlinger — so there is no
 * capture path on a real device without it. Release builds hardcode the field to false.
 */
```

### `fun Window.applyOverlayProtection() {`
Replaced in source by: `/** FLAG_SECURE does not stop overlays; filterTouches covers what setHideOverlayWindows misses. */`
```
/**
 * Refuses to render, and refuses to accept touches, while another app is drawing over this window.
 *
 * `FLAG_SECURE` is not this control. It stops the window being *captured*; it does nothing about a
 * `TYPE_APPLICATION_OVERLAY` drawn on top of it, which is the opposite direction and the one that
 * matters for a consent prompt. Every window in this app that takes an irreversible decision — the
 * pairing confirmation reached from a `BROWSABLE` deep link, the MFA approve/deny tiles, every PIN
 * field — was a bare `View` with default touch handling, so a co-installed app holding
 * `SYSTEM_ALERT_WINDOW` could position its own button over the accept target and collect the tap.
 *
 * Two mechanisms, because they cover different halves:
 * - [Window.setHideOverlayWindows] (API 31, this app's `minSdk`) asks the system to hide other
 *   apps' overlays for as long as this window is showing. It is the real fix, and it is free.
 * - `filterTouchesWhenObscured` makes the view discard any touch delivered while something is
 *   drawn over it. It is the fallback for the overlay types `setHideOverlayWindows` does not
 *   cover (notably accessibility overlays), and it is what actually fails closed.
 */
```

### `fun View.filterObscuredTouchesRecursively() {`
Replaced in source by: `/** The decorView flag misses Dialog content and views added after the window was created. */`
```
/**
 * [View.setFilterTouchesWhenObscured] on this view and, recursively, everything under it.
 *
 * The window-level flag on `decorView` does not reach a `Dialog`'s content, nor views added to a
 * container after the window was created — [org.kysecurity.mail.push.MfaApprovalActivity] builds its
 * number-match tiles at runtime, which is exactly the tap an overlay wants.
 */
```

## app/src/main/java/org/kysecurity/mail/security/SecurityGraph.kt

### `val appLockStore = AppLockStore(appContext)`
```
    /**
     * The single [AppLockStore] for the process.
     */
```

### `val hostileLocationSettings = HostileLocationSettings(appContext)`
```
    /** Likewise for the protection flag, which was constructed ten times over — including once
     *  per attachment chip inside a `forEach` in `EmailDetailActivity`. */
```

### `val biometricUnlockVault = BiometricUnlockVault(appContext)`
```
    /** Shared so [UnlockActivity]'s read of the sealed blob and [AppLockManager]'s write of it are
     *  the same object, rather than two views of one prefs file. */
```

### `val appLockManager: AppLockManager = AppLockManager(`
```
    // onWipe is a suspend lambda now: it used to be wrapped in runBlocking, which put a Room
    // teardown plus two Keystore-backed prefs commits on the main thread, reached from
    // UnlockActivity's click listener. AppLockManager.attemptPin is itself suspend, so the wipe
    // simply runs on the caller's IO context.
```

### `fun invalidate() = holder.invalidate()`
```
    /** See [org.kysecurity.mail.SingletonGraph.invalidate] — used by
     *  [org.kysecurity.mail.security.AppRestart]. */
```

## app/src/main/java/org/kysecurity/mail/security/SecuritySessionReset.kt

### `internal suspend fun runSecurityChangeThenReset(`
Replaced in source by: `/** Reset must run inside the NonCancellable block; code after withContext resumes cancellably. */`
```
/**
 * Runs a destructive security change and the session reset that completes it as **one**
 * non-cancellable unit.
 *
 * This exists because splitting the two is a silent correctness hole, and the split reads as
 * obviously fine:
 *
 * ```
 * lifecycleScope.launch {
 *     withContext(SecurityWork) { ...destroy...; settings.setEnabled(true) }
 *     AppRestart.relaunch(this@Activity)          // <-- never runs if the Activity died
 * }
 * ```
 *
 * `NonCancellable` protects the *block*, so the destruction and the flag commit both complete even
 * if the Activity is destroyed mid-operation. But the statement after `withContext` is an ordinary
 * cancellable continuation: it resumes through `resumeCancellableWith`, sees the cancelled parent
 * `Job`, and throws instead of running. The setting is committed and the reset is skipped.
 *
 * The behaviour depends on the dispatchers, which is what makes it easy to reason about wrongly —
 * with the *same* interceptor on both sides the continuation resumes undispatched and does run.
 * `lifecycleScope` is `Dispatchers.Main.immediate` and the security context is `Dispatchers.Default`,
 * so the failing case is the one that applied.
 *
 * What was actually skipped is [org.kysecurity.mail.ProcessState.resetAll] — the only call to it on that
 * path — leaving the outgoing session's decrypted attachment bytes, compose draft and notification
 * bookkeeping resident in a live process, under a Hostile Location Protection switch reading ON and
 * a confirmation dialog that had just promised nothing from before the toggle survives.
 *
 * [NonCancellable] is added here rather than taken from [workContext] so a caller cannot forget it
 * and quietly reintroduce the hole.
 */
```

## app/src/main/java/org/kysecurity/mail/security/SecuritySettingsActivity.kt

### `private val SecurityWork = Dispatchers.Default + NonCancellable`
```
/**
 * The context every security-critical background step in this screen runs on.
 */
```

### `internal fun tearDownEnrollmentForHostileLocation(context: android.content.Context) {`
Replaced in source by: `/** Top-level so the instrumented test drives the same code the toggle does. */`
```
/**
 * Destroys this device's enrollment and enqueues the correction, for the Hostile Location
 * Protection toggle.
 *
 * Top-level rather than a private method so the instrumented test drives the same code the toggle
 * does. A test that re-implemented the sequence would stay green after the toggle stopped calling
 * it — which is the failure mode this whole path exists to prevent.
 *
 * Unlike [SecurityWipe], this leaves the pairing alone: protection keeps push and sync working, and
 * only the ability to open the envelope goes away.
 *
 * A teardown that could not fully complete is logged rather than surfaced. The enqueued report is
 * the honest half — it probes live state, so if the envelope did survive, the server is told this
 * device is still enrolled rather than being told a comforting lie.
 */
```

### `class SecuritySettingsActivity : LockedActivity() {`
Replaced in source by: `/** Toggles 2 and 3 are disabled unless toggle 1 is on; enforced here, not just documented. */`
```
/**
 * "Security" settings: Require Unlock to Open, Hostile Location Protection, and the credential
 * PIN-gate. Toggles 2 and 3 are disabled unless toggle 1 is on; enforced here, not just documented.
 */
```

### `private data class SettingsSnapshot(`
Replaced in source by: `/** Read once, off the main thread: most of these come from the Keystore-backed store. */`
```
    /**
     * Every persisted value this screen renders, read in one pass.
     *
     * Read once, off the main thread, because seven of these come out of a Keystore-backed
     * `EncryptedSharedPreferences` — the store whose own KDoc says "[AppLockManager] keeps every
     * caller off the main thread so the durability can be afforded", while this screen read it
     * seven times from `onCreate` and wrote it with `commit()` from a click listener.
     */
```

### `setPadding(dpToPx(16), dpToPx(12), dpToPx(16), dpToPx(20))`
```
            // 16, not the previous 20: the cards carry their own 16dp inset now, and 20 + 16 put
            // content 36dp off the screen edge on a page that is mostly text.
```

### `val lockGraceSettings = SecurityRuntime.graph(this).appLockSettings`
```
        // How long backgrounding is tolerated before the lock re-engages. This existed only as a
        // hardcoded "immediately", which meant the attachment picker, the QR scanner and the
        // webmail handoff each destroyed the screen that launched them — see KyPostApp.onStop.
```

### `val secondaryActions = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }`
```
        // The two secondary actions share a row. They are peers — both open a picker, neither is the
        // thing you came here to do — and stacking them cost a full button height on a page that does
        // not fit a screen. 0dp width plus weight means "Lock after" simply takes the whole row when
        // "Change PIN" is GONE, which is its state whenever the lock is off.
```

### `wipeThresholdButton = Button(this).apply {`
```
        // The wipe threshold is a user choice and has to be visible: it decides whether repeated
        // wrong PINs destroy mail and contacts the app deliberately keeps no backup of.
```

### `AlertDialog.Builder(this)`
Replaced in source by: `// Confirmed: the most destructive control on the screen, and it relaunches the app.`
```
            // Confirmed, because this is the most destructive control on the screen and was the
            // only one without a prompt: it deletes every cached message, purges the contacts this
            // app wrote into the OS provider, removes the sync account and relaunches — on one
            // stray tap. Unpairing and pairing, both strictly less destructive, have confirmed for
            // some time.
```

### `notificationsCard.addViewSpaced(`
Replaced in source by: `// Always visible: the relay exposure exists whether or not this toggle is on.`
```
        // Always visible regardless of credentialGateSwitch's state: the push-relay exposure this
        // describes exists on every push delivery, on or off — this toggle only ever controlled
        // whether content is withheld while locked, not whether the relay sees it.
```

### `biometricSwitch.setOnCheckedChangeListener { _, checked ->`
Replaced in source by: `// commit()-backed Keystore write; a click listener may not do that on the main thread.`
```
        // commit()-backed write into the Keystore-backed store — an fsync plus AES-GCM, which is
        // not something a click listener may do on the main thread. Every other write on this
        // screen already goes through SecurityWork; this one had been missed.
```

### `if (!checked) {`
Replaced in source by: `// Switching it off destroys the sealed keys, not just the setting.`
```
                    // Switching it off destroys the sealed keys, rather than leaving a
                    // biometric-openable copy of the credential behind a disabled setting. The next
                    // PIN unlock re-seals if it is switched back on.
```

### `encryptionSectionLabel = TextView(this).apply {`
Replaced in source by: `// Built hidden and filled asynchronously: the row needs Keystore and network work.`
```
        // Encrypted mail. Built hidden and filled in asynchronously: deciding the row needs a
        // Keystore probe and (usually) one authenticated request, neither of which may run on the
        // main thread or block the rest of this screen from appearing.
        //
        // The eyebrow and the card are hidden together. A titled empty card on a screen that is
        // otherwise fully populated reads as something failing to load, which is exactly the wrong
        // impression for the one section whose absence is normal (unpaired devices never get it).
```

### `val bg = Color.parseColor(getStoredThemePalette(this).bg)`
Replaced in source by: `// Runs AFTER applyThemeToActivity, which repaints every ViewGroup flat `panel`.`
```
        // Everything below runs AFTER applyThemeToActivity, which walks the tree and overwrites
        // both of the things this screen's layout depends on. ComposeActivity solved the same
        // problem the same way; this is that precedent, not a new trick.
        //
        // 1. Every ViewGroup, root included, is repainted flat `panel`. Cards left at `panel` on a
        //    `panel` background are invisible, so the scroll surface is repainted `bg` and the cards
        //    keep the rounded `panel` fill — the contrast IS the card.
```

### `applyGhostButtonTheme(this, changePinButton)`
Replaced in source by: `// Ghost, not the accent-filled primary: these two are secondary actions.`
```
        // 2. Every Button is repainted with the accent-filled primary background. These two are
        //    secondary actions, and three solid accent buttons stacked down a settings page say
        //    everything is equally the thing to do next. Ghost is the style guide's answer.
```

### `private fun LinearLayout.addSection(titleRes: Int, bottomDp: Int = 10): LinearLayout {`
Replaced in source by: `/** An eyebrow label outside a panel card; radius fixed at 14dp by STYLE_GUIDE.md §3. */`
```
    /**
     * A section: an eyebrow label, then a panel card holding the controls.
     *
     * The page was a single flat column of switches, captions and accent buttons — every element at
     * the same visual weight, so nothing said which controls belong together or which one the others
     * depend on. Cards are what the rest of this app already uses for exactly that (Compose's
     * details/message cards, the inbox's keyword bar), and STYLE_GUIDE.md §3 fixes the radius at
     * 14dp across all four KyPost clients.
     *
     * The eyebrow sits OUTSIDE the card, matching web's `.sidebar-section-label` placement.
     */
```

### `private fun caption(text: CharSequence): TextView = TextView(this).apply {`
```
    /** A control's explanatory line: one step down from the switch it belongs to, never the same
     *  weight. 13sp matches the caption size the rest of this screen already used. */
```

### `private fun refreshEncryptionRow() {`
Replaced in source by: `/** Skips the identity request when a local fact decides the row; the network may be hostile. */`
```
    /**
     * Recomputes the encrypted-mail row.
     *
     * The identity request is skipped whenever a local fact already decides the row. That is not
     * only an optimisation: under Hostile Location Protection the user has just declared this
     * network hostile, and this screen must not answer that by making a request over it.
     */
```

### `val statusDecides = status == EnrollmentStatus.KEY_INVALIDATED ||`
Replaced in source by: `// SecurityWork, like the reads above: this pairing read is several decrypts plus AES.`
```
            // SecurityWork, like the reads above: check() calls pairingForAuthenticatedCall()
            // before its own withContext(Dispatchers.IO), and that pairing read is several
            // EncryptedSharedPreferences decrypts plus a CredentialCipher.unwrap AES operation —
```

### `private fun confirmRemoveEnrollment() {`
Replaced in source by: `/** Confirmed: destructive, and only reversible by another two-device ceremony. */`
```
    /**
     * Confirmed, because it is destructive and not obviously reversible from the user's side: the
     * envelope goes, and getting it back means another two-device ceremony.
     */
```

### `val leftBehind = withContext(SecurityWork) {`
Replaced in source by: `// clear() must be inside the block; code after withContext resumes cancellably.`
```
                    // SecurityWork, like every other destructive step on this screen: this is a
                    // Keystore deletion plus a commit()-backed prefs clear.
                    //
                    // EnrollmentSession.clear() lives INSIDE this block rather than as a statement
                    // after it, for the exact reason [runSecurityChangeThenReset]'s KDoc calls out
                    // (SecuritySessionReset.kt): NonCancellable protects the block's body, but a
                    // statement placed after `withContext` returns resumes through an ordinary
                    // cancellable continuation. If the Activity is destroyed while destroyAndReport
                    // is in flight, that resume throws CancellationException before ever reaching a
                    // clear() sitting out here — the teardown completes, the clear never runs, and
                    // the account's plaintext PGP private key survives on the heap in a process that
                    // finishing the Activity does not kill.
                    //
                    // try/finally, not a trailing statement, because destroyAndReport itself can
                    // throw: EnrollmentStateWorker.enqueue (reached via destroyAndReport) calls
                    // WorkManager.enqueueUniqueWork with no runCatching, unlike the two steps ahead
                    // of it in the chain. A throw there would otherwise skip the clear the same way
                    // a cancellation would — finally runs it (and lets leftBehind's exception
                    // propagate) unconditionally.
```

### `EnrollmentSession.clear()`
Replaced in source by: `// Not ProcessState.resetAll(): unenroll is not a session boundary.`
```
                            // The vault and the server-side record are gone, but this process may
                            // still be holding the account's plaintext private key from an earlier
                            // read (EnrollmentSession has exactly one production writer,
                            // VaultOpenerAndroid, and nothing before this cleared it on the unenroll
                            // path). Cleared directly rather than via ProcessState.resetAll():
                            // unenroll is not an account or session boundary — the same account
                            // stays paired — so it must not also discard an in-progress compose
                            // draft or ephemeral attachment plaintext the way a wipe, relaunch or
                            // unpair legitimately does.
```

### `runSecurityChangeThenReset(`
Replaced in source by: `// The relaunch is inside the non-cancellable unit; outside it, cancellation skips it.`
```
            // The relaunch is part of the non-cancellable unit, not a statement after it. It used
            // to sit outside, which made it an ordinary cancellable continuation: a Back press or a
            // rotation during the multi-second teardown killed lifecycleScope, the flag still
            // committed under NonCancellable, and the process reset was silently skipped — leaving
            // the previous session's decrypted attachments and draft resident under a switch
            // reading ON. See [runSecurityChangeThenReset].
```

### `SecurityWipe.closeAndDeleteDatabase(this@SecuritySettingsActivity)`
Replaced in source by: `// Both directions need a fresh on-disk kypost_mail.db afterward.`
```
                // Both directions need a fresh on-disk kypost_mail.db afterward: enabling must
                // not leave the pre-toggle disk cache behind, and this is a harmless no-op on
                // the disable path.
```

### `SecurityWipe.deletePlaintextMetadataStores(this@SecuritySettingsActivity)`
Replaced in source by: `// Also the metadata stores: push_state held 30 senders and subjects.`
```
                    // "Nothing from before the toggle survives" has to include the plaintext
                    // metadata stores, not just the database — push_state alone held sender and
                    // subject for the last 30 messages.
```

### `runCatching { DownloadedAttachmentLedger.deleteAll(this@SecuritySettingsActivity) }`
Replaced in source by: `// ...and attachments in shared Downloads, which sit OUTSIDE the sandbox.`
```
                    // ...and the attachments the user tapped while protection was off, which are
                    // written to shared Downloads with no prompt and sit OUTSIDE the sandbox. The
                    // confirmation the user just read says "No mail, contacts, or attachments are
                    // cached on this device... Turning this on immediately wipes what's cached now".
                    // The full wipe learned to clear these; this sibling path had not.
```

### `tearDownEnrollmentForHostileLocation(this@SecuritySettingsActivity)`
Replaced in source by: `// Before the flag flips: an interruption must not leave a readable envelope.`
```
                    // Before the flag flips, so every interruption point is safe: a process death
                    // after this leaves the flag off with the envelope already gone — honestly
                    // un-enrolled — rather than protection on with a readable envelope, which is
                    // the state this mode exists to prevent.
```

### `private fun promptWipeThreshold() {`
Replaced in source by: `/** Offers [LockoutPolicy.WIPE_THRESHOLD_CHOICES] plus "never"; the dialog states the cost. */`
```
    /**
     * Offers the thresholds in [LockoutPolicy.WIPE_THRESHOLD_CHOICES] plus "never".
     *
     * The dialog states the consequence in the message rather than leaving the user to infer it
     * from a number: the wipe deletes local mail, the synced OS contact rows and this device's
     * pairing, and none of that is recoverable — `allowBackup` and the device-transfer rules are
     * both closed, deliberately.
     */
```

### `private suspend fun disableAndPurgeDeviceContactSync() {`
Replaced in source by: `/** The synced rows live in the OS provider, which the in-memory database does not cover. */`
```
    /**
     * Turning Hostile Location Protection on has to undo any contact sync that already happened:
     * those rows live in the OS contacts provider, which protection's in-memory database does not
     * cover, so leaving them would keep publishing exactly what the feature promises to withhold.
     */
```

### `private fun revertLockSwitch(checked: Boolean) {`
```
    /**
     * Reverts [lockSwitch] to [checked] without re-firing its listener. Used whenever we undo the
     * user's toggle because the set-PIN or disable-lock flow was cancelled or failed.
     */
```

### `private fun promptEnterAndConfirmPin(onConfirmed: (CharArray) -> Unit, onCancelled: () -> Unit) {`
```
    /**
     * Shows a two-field "enter PIN, then confirm it" dialog — a typo in the single-entry flow this
     * replaced would permanently lock the PIN in with no recovery except 10 deliberate wrong
     * attempts (which wipes) or a reinstall, so every *new* PIN goes through enter+confirm.
     */
```

### `.create()`
Replaced in source by: `// FLAG_SECURE is per-window and a Dialog has its own. See [showSecurely].`
```
            // FLAG_SECURE lives on the Activity window and a Dialog has its own, so this PIN was
            // screenshot- and screen-recordable while the identical field on UnlockActivity was
            // not. See [showSecurely].
```

### `withContext(SecurityWork) {`
Replaced in source by: `// setPin runs PBKDF2 and two commit()-backed Keystore writes.`
```
                        // setPin runs PBKDF2 and two commit()-backed Keystore writes — see
                        // [SecurityWork] for why NonCancellable on its own did not move any of it
                        // off the main thread.
```

### `SecurityRuntime.graph(this@SecuritySettingsActivity)`
Replaced in source by: `// Seal now, so the biometric switch below has something to offer.`
```
                            // Seal now rather than at the first unlock, so turning the biometric
                            // switch on below actually offers a fingerprint the first time the app
                            // locks.
```

### `val ok = resolvePinAttempt(appLockManager.verifyPinThrottled(entered))`
Replaced in source by: `// resolvePinAttempt, not `is Success`: this runs the same wipe threshold.`
```
                // resolvePinAttempt, not `is Success`: this check runs the same wipe threshold as
                // the unlock screen, and collapsing Wiped into "wrong PIN" left the user in a
                // settings screen for an app whose data had just been destroyed. See [PinGate].
```

### `val changed = entered.usePin { old ->`
Replaced in source by: `// changePin needs the OLD PIN, so `entered` is held across dialogs.`
```
                                // Both arrays are zeroed here: `entered` has been held across the
                                // second dialog because changePin needs the OLD PIN to unwrap
                                // `deviceSecret` before the verifier is overwritten.
```

### `private suspend fun changePin(oldPin: CharArray, newPin: CharArray): Boolean = withContext(SecurityWork) {`
```
    /**
     * Rotates the PIN, re-wrapping `deviceSecret` in the same step when the credential gate is on.
     */
```

### `val hasPairingToProtect = gateEnabled && salt != null && securePairingStore.needsCredentialRewrap().not() &&`
Replaced in source by: `// ABORT BEFORE THE DESTRUCTIVE WRITE: a failed unwrap must not overwrite the PIN hash.`
```
        // ABORT BEFORE THE DESTRUCTIVE WRITE, not after it.
        //
        // The re-wrap below is skipped whenever `deviceSecret` comes back null — and the fix that
        // introduced this function only ever considered the case where there is no secret to
        // re-wrap. There is a second way to get null: the unwrap *failed* (the Keystore wrapping
        // key rotated, the ciphertext was damaged). Overwriting the PIN hash in that state leaves
        // ciphertext that nothing can ever open, `needsCredentialRewrap()` reports false because it
        // is present and current-versioned, so no repair path ever runs — and every authenticated
        // call 401s behind a UI still reading "Paired". Refuse instead, and leave the old PIN
        // working so the user still has a device they can use.
```

### `private fun promptDisableLock() {`
Replaced in source by: `/** `deriveAndCacheCredentialKeys`, not `verifyPinThrottled`: [disableLock] needs the key. */`
```
    /**
     * `deriveAndCacheCredentialKeys`, not `verifyPinThrottled`.
     *
     * Both run the identical throttled verification; only the former keeps the PIN-derived key. The
     * key is what [disableLock] needs to unwrap `deviceSecret` before the PIN goes away — and
     * verifying without it is precisely how this path ended up destroying the user's mailbox
     * instead: the PIN was checked, the keys were discarded a line later, and the code then
     * concluded the wrapped secret was unrecoverable and ran a full [SecurityWipe].
     */
```

### `private suspend fun disableLock() {`
Replaced in source by: `/** Nothing here wipes anything: a failed unwrap refuses the toggle instead. */`
```
    /**
     * Runs once the disabling user has re-verified their current PIN.
     *
     * **Nothing here wipes anything.** This used to run a full [SecurityWipe] whenever the
     * credential gate was on — deleting `kypost_mail.db`, the user's rows in the OS contacts
     * provider, the sealed OpenPGP key and the pairing — behind a dialog whose entire text was
     * "Enter your PIN to turn this off". The stated justification was that a PIN-wrapped
     * `deviceSecret` becomes unrecoverable once the PIN is gone, which is true and irrelevant: the
     * user has *just typed the PIN*, [promptDisableLock] now keeps the key it derives, and
     * [unwrapCurrentPairing] rewrites the secret in the clear before the verifier is cleared. That
     * is the same sequence [promptCredentialGatePin] has always used for the gate's own off-switch.
     *
     * If the unwrap cannot be done, the toggle is refused and nothing is destroyed. Losing access
     * to a credential is the user's problem to solve by re-pairing; it is never a reason for this
     * app to delete their mail.
     */
```

### `data class PriorState(val hostileLocation: Boolean, val credentialGate: Boolean)`
```
        // Named, not a Pair: these two flags select different teardown paths below, and `.first` /
        // `.second` at the branch points would say nothing about which is which.
```

### `val prior = withContext(SecurityWork) {`
Replaced in source by: `// commit()-backed and Keystore-opening, so they belong on [SecurityWork].`
```
        // Both reads and the write are commit()-backed, and one of them opens the Keystore-backed
        // store, so they belong on [SecurityWork] like every other write in this screen.
```

### `val unwrapped = withContext(SecurityWork) { unwrapCurrentPairing() }`
Replaced in source by: `// Unwrap BEFORE the verifier is cleared, or an interruption strands the secret.`
```
            // Unwrap BEFORE the verifier is cleared, using the key promptDisableLock just derived
            // from the PIN the user typed. Order matters for the same reason it does in
            // promptCredentialGatePin: reversed, an interruption leaves a wrapped secret that
            // nothing can ever unwrap again.
```

### `withContext(SecurityWork) { settings.setEnabled(prior.hostileLocation) }`
Replaced in source by: `// Refuse the toggle; a credential we cannot read is no reason to delete mail.`
```
                // Refuse the toggle and leave every setting as it was. The state reaching here is
                // "we could not read a credential", which is never a reason to delete the user's
                // mail and contacts — which is what this branch used to do.
```

### `private fun promptCredentialGatePin(enabling: Boolean) {`
Replaced in source by: `/** The PIN is re-entered so a fresh key is available to re-wrap or unwrap in the same step. */`
```
    /**
     * Both directions need the PIN re-entered here (not just "the app happens to be unlocked right
     * now") to guarantee a fresh PIN-derived key is available to actually re-wrap or unwrap the
     * current pairing's `deviceSecret` in the same step.
     */
```

### `appLockManager.dropCredentialKeys()`
Replaced in source by: `// Drop the keys: a later save would re-wrap behind a gate that is now off.`
```
                        // Drop the keys we just derived. Leaving them cached meant a pairing saved
                        // later in this same session got re-wrapped behind a gate that is now off,
                        // so no future unlock would ever cache a key to open it again.
```

### `private suspend fun unwrapCurrentPairing(): Boolean {`
Replaced in source by: `/** The inverse of [rewrapPairingIfNeeded]; "no pairing at all" counts as success. */`
```
    /**
     * The inverse of [rewrapPairingIfNeeded] — without this, turning the gate back off would leave
     * `deviceSecret` stored wrapped with no code path that ever unwraps it.
     *
     * "No pairing at all" counts as success: there is no secret to strand, so the gate can be
     * turned off freely.
     */
```

## app/src/main/java/org/kysecurity/mail/security/SecurityWipe.kt

### `private val DATASTORE_NAMES = listOf("push_state", "contacts_state", "mail_sync_state")`
Replaced in source by: `/** DataStore has no delete API, so the backing files go directly; a wipe always relaunches. */`
```
/** Every DataStore this app owns. DataStore has no "delete everything" API, so the backing files
 *  are removed directly — safe here because a wipe is always followed by [AppRestart.relaunch],
 *  which rebuilds the graphs that own them. */
```

### `private val PREFS_NAMES_RETAINED = setOf(`
Replaced in source by: `/** Retained because a later step still needs them: ordering, the wipe marker and the ledger. */`
```
/**
 * Files [deleteAllSharedPrefs] must NOT sweep, each because a named step owns it and needs it
 * *later* in the run: [AppLockStore.reset] (ordering), the wipe marker and the attachment ledger
 * (records of work still owed, so a resumed wipe has something to iterate), and the UnifiedPush
 * connector's file (holds the distributor selection `unifiedPushUnregister` reads).
 */
```

### `private val METADATA_PREFS_NAMES = listOf(org.kysecurity.mail.KeywordSettings.PREFS_NAME)`
Replaced in source by: `/** Plaintext mail metadata, no credentials; shared by the full wipe and the HLP enable path. */`
```
/**
 * Plaintext mail metadata, no credentials: folder cursors (whose *keys* are server folder paths),
 * contact cursors, the 30-entry sender/subject push history, and accumulated labels.
 *
 * Shared by the full wipe and Hostile Location Protection's enable path so the two cannot drift.
 */
```

### `private const val KEY_WIPE_ABANDONED = "wipe_abandoned"`
Replaced in source by: `/** Set when the wipe gives up. Must NOT clear [KEY_WIPE_IN_PROGRESS]; that marker outlives it. */`
```
/**
 * "Stop retrying by itself" — set once a wipe has exhausted [MAX_WIPE_RESUMES] with steps still
 * failing. Deliberately does **not** clear [KEY_WIPE_IN_PROGRESS]: that marker is the only durable
 * record that data may still be on disk, and it must survive until a run completes cleanly.
 */
```

### `private const val KEY_HOSTILE_LOCATION_WAS_ENABLED = "hostile_location_was_enabled"`
Replaced in source by: `/** Captured at wipe start: the sweep deletes the flag's own file, so a resume reads it here. */`
```
/**
 * The Hostile Location Protection posture as it was at the *start* of the wipe, stored in the one
 * preferences file the wipe retains — the `sharedPrefs` step deletes the flag's own file, so a
 * resumed run has to read it from here or it silently reverts the setting to `false`.
 */
```

### `private const val MAX_WIPE_RESUMES = 3`
Replaced in source by: `/** Enough to ride out a transient failure, few enough that a permanent one gets reported. */`
```
/**
 * How many times an incomplete wipe may be resumed at startup before the app stops retrying.
 *
 * Enough to ride out a transient failure (a file held open, a provider briefly unavailable), few
 * enough that a permanent one surfaces as a reported problem rather than an app that wipes itself
 * on every launch forever.
 */
```

### `private const val FCM_TEARDOWN_TIMEOUT_MS = 3_000L`
Replaced in source by: `/** Short: a hostile network must not be able to hold the wipe open. */`
```
/**
 * Ceiling on the Play Services token/installation teardown.
 *
 * Short for the same reason the deregister's is: this runs while an attacker may be holding the
 * device, and a hostile network must not be able to hold the wipe open.
 */
```

### `sealed class WipeResult {`
Replaced in source by: `/** Scoped to local destruction; the server deregister is logged, not reported here. */`
```
/**
 * Whether a wipe destroyed everything it set out to. [Incomplete] carries the step names so the
 * caller can refuse to tell the user their data is gone when it may not be.
 *
 * Scoped to **local destruction**. The best-effort server deregistration is reported in the log,
 * not here: an unreachable relay says nothing about whether the data on this device is gone, and
 * folding it in would both lie to an offline user and keep the resume marker set forever.
 */
```

### `data class Incomplete(`
Replaced in source by: `/** `willRetry = false` is terminal: gated screens stay blocked until a reinstall. */`
```
    /**
     * `willRetry = false` is **terminal**, not informational: the app has stopped resuming the wipe
     * by itself, [LockedActivity] blocks every gated screen on it, and the state survives launches
     * (see [KEY_WIPE_ABANDONED]) until a reinstall.
     */
```

### `object SecurityWipe {`
Replaced in source by: `/** Must never report [WipeResult.Complete] unless every step really ran. */`
```
/**
 * Full destructive reset: runs on the user's configured run of wrong PIN attempts, and when the
 * [AppLockStore] tripwire fires.
 *
 * Wider than the Room database on purpose — the push history holds senders and subjects, and the
 * synced contacts live in the OS provider, outside this sandbox. It must never report
 * [WipeResult.Complete] unless every step really ran.
 */
```

### `suspend fun wipeAndResetApp(context: Context): WipeResult = withContext(Dispatchers.IO + NonCancellable) {`
Replaced in source by: `/** [NonCancellable]: a half-finished wipe is worse than either outcome. */`
```
    /**
     * Performs the reset, then drops the graph holders. Follow with [AppRestart.relaunch].
     *
     * [NonCancellable]: every caller is a coroutine the wipe's own teardown may cancel, and a
     * half-finished wipe is worse than either outcome.
     */
```

### `suspend fun step(name: String, body: suspend () -> Unit) {`
Replaced in source by: `/** Records the failure in [failed]; no step below may catch its own exceptions. */`
```
        /**
         * Fault-isolates one step without silencing it: a failure is recorded in [failed], which is
         * what stops [WipeResult.Complete] being claimed over data that is still here.
         *
         * **Nothing below may catch its own exceptions** — a step that cannot fail cannot be
         * reported. Swallowing `CancellationException` is right here and nowhere else: this runs
         * under [NonCancellable], so it is never *our* job being cancelled.
         */
```

### `val currentlyEnabled = runCatching { HostileLocationSettings(appContext).isEnabled() }`
Replaced in source by: `// Captured before destruction and restored after; a wipe must not downgrade posture.`
```
        // Captured BEFORE the destruction and restored after: the sweep deletes this flag's file,
        // and a wipe that runs *because* the device is presumed hostile must not switch off the
        // feature for that exact situation. A wipe may destroy data; it must not downgrade posture.
        // Persisted by markWipeInProgress so a resumed run reads it from the retained file.
```

### `val hostileLocationWasEnabled = markWipeInProgress(appContext, currentlyEnabled)`
Replaced in source by: `// Makes an interrupted wipe resumable; commit(), before anything is destroyed.`
```
        // Makes an interrupted wipe resumable — force-stopping the app is one tap away in
        // Settings, and this runs while an attacker holds the device. commit(), before anything
        // is destroyed.
```

### `val pairingForDeregister = runCatching { PushRuntime.graph(appContext).repository.pairingForAuthenticatedCall() }`
Replaced in source by: `// Captured before sharedPrefs deletes the credential the deregister authenticates with.`
```
        // Captured BEFORE the sharedPrefs step deletes `push_pairing_secure`. The deregister runs
        // last (destroying plaintext must not wait on the network) but authenticates with a
        // credential that step removes, so it has to be read now.
```

### `val pinForDeregister = runCatching { PushRuntime.graph(appContext).repository.currentTlsPin() }`
Replaced in source by: `// The pin too: cleared state reads NeverPaired, which would send this request unpinned.`
```
        // The TLS pin, captured HERE for the same reason the pairing is: `clearPairingState` below
        // removes both the pin and its tripwire, and the deregister call happens after it.
        //
        // Without this the wipe's one outbound request — the one carrying
        // `X-Kypost-Device-Secret` — went out UNPINNED. `PinnedOrFallbackCallFactory` reads
        // `TlsPinState`, the cleared tripwire made that read `NeverPaired` rather than `Lost`, and
        // `NeverPaired` is the one state that legitimately falls back to bare system-CA trust. So
        // the guard built specifically to refuse a silent downgrade of a credential-bearing request
        // was routed around, during the operation whose entire premise is that the device is in
        // hostile hands and quite possibly on the attacker's network.
```

### `step("inMemoryPlaintext") {`
Replaced in source by: `// ORDER IS THE POINT: local plaintext first, network last. A force-stop must lose nothing.`
```
        // ORDER IS THE POINT: local plaintext first, network last. An attacker holding the device
        // can force-stop the app at any moment, so every step that blocks — above all the ~20s of
        // OkHttp timeouts in the deregister — has to come after the destruction, not before it.
        //
        // Leads because it needs no I/O and AppRestart relaunches into the same JVM: an uncleared
        // draft is restorable from the compose screen in the attacker's session.
```

### `val undeleted = DATASTORE_NAMES.map { name ->`
Replaced in source by: `// Checked, like every other step: `push_state` holds 30 sender/subject pairs.`
```
            // Checked, like every other step. Discarding `delete()`'s result meant this step could
            // not fail however badly it went — in a routine whose whole contract is that nothing
            // silently succeeds — and `push_state` holds the last 30 sender/subject pairs.
```

### `step("cancelNotifications") {`
Replaced in source by: `// Local push teardown BEFORE the network call; the connector DB holds the WebPush key.`
```
        // Local push teardown BEFORE the network call: the connector's SQLite database holds the
        // WebPush ECDH private key, and none of this needs the network, so none of it belongs
        // behind something that does.
```

### `if (!appContext.deleteSharedPreferences("unifiedpush.connector")) {`
Replaced in source by: `// `UnifiedPush.unregister` keeps the distributor selection; nothing else removes it.`
```
            // Explicit: `UnifiedPush.unregister` deliberately keeps the distributor selection for a
            // later re-register, so nothing else removes the record of which distributor this user
            // runs.
```

### `step("enrollmentTeardown") {`
Replaced in source by: `// Before the sharedPrefs sweep: creating the store would recreate its file and keyset.`
```
        // Before the sharedPrefs sweep below, so the vault deletes its own file rather than having
        // it removed underneath it and then recreated — EncryptedSharedPreferences.create rebuilds
        // both the file and a Tink keyset the moment it is touched.
        //
        // No state-report worker on this path: the wipe deregisters and clears the pairing, so the
        // device row goes away server-side and there is nothing left to correct.
```

### `val leftBehind = org.kysecurity.mail.pgp.EnrollmentTeardown.destroy(appContext)`
Replaced in source by: `// A named step, so a surviving key lands in the incomplete-wipe list.`
```
            // A named step so a failure lands in the incomplete-wipe list. It has to throw to get
            // there: `step` records a failure only when its body does, and a key surviving a wipe
            // nobody chose is exactly what the incomplete result exists to tell the user about.
```

### `step("biometricUnlockVault") {`
Replaced in source by: `// The sweep removes the sealed blob but not the Keystore alias.`
```
        // Same shape and same reason as enrollmentTeardown above: the sharedPrefs sweep removes the
        // sealed blob but not the Keystore alias, and a key surviving a wipe nobody chose is exactly
        // what the incomplete result exists to report.
```

### `step("authGateKey") {`
Replaced in source by: `// Same for the MFA gate key: a Keystore entry outliving a wipe must be reported.`
```
        // Same again for the MFA approval screen's gate key. It seals nothing, so what survives is
        // only an alias — but a Keystore entry outliving a wipe is exactly what the incomplete
        // result exists to report, whatever it holds.
```

### `step("databaseKey") {`
Replaced in source by: `// An encrypted database is only as destroyed as its key. Runs AFTER `database`.`
```
        // The database is encrypted at rest, so it is only as destroyed as its key. `database`
        // above deletes the file and reports if it could not; this makes any surviving copy of the
        // file unreadable as well, which is the property that matters when the file delete is the
        // step most likely to fail. Runs AFTER `database`, so the delete is not attempted against a
        // database whose key has already gone.
```

### `step("clearPairingState") { PushRuntime.graph(appContext).repository.clearPairing() }`
Replaced in source by: `// BEFORE the sharedPrefs sweep: clearPairing() writes, and would recreate the files.`
```
        // BEFORE the sharedPrefs sweep, not after. `PushRepository.clearPairing()` goes through
        // `SecurePairingStore`, which *writes* — so running it after the sweep had it recreate
        // `push_pairing_secure.xml` and a fresh Tink keyset moments after the sweep deleted them,
        // leaving files behind a step whose contract is that they are gone. That is the same
        // "removed underneath it and then recreated" ordering the `enrollmentTeardown` step above
        // is explicitly placed early to avoid; this one had it and the comment did not notice.
        //
        // The deregister below authenticates with `pairingForDeregister`, captured before any of
        // this ran, so clearing here does not disarm it. Clearing the in-memory pairing StateFlow
        // is the other half: anything still holding the graph sees "not paired" rather than a
        // stale pairing read before the file was deleted.
```

### `if (hostileLocationWasEnabled) {`
Replaced in source by: `// Re-assert the posture the deletions erased; after sharedPrefs or it is deleted again.`
```
        // Re-assert the protection posture the deletions above erased. Runs after the sharedPrefs
        // step on purpose — writing it earlier would just be deleted again. A step, not a bare
        // call, so a failure to restore it is reported rather than leaving the user believing
        // protection survived. Nothing is re-enabled that was not already on.
```

### `(top of file)`
Replaced in source by: `// Everything below touches the network; nothing below it destroys local data.`
```
        // ─── Everything below this line touches the network. Nothing below it destroys local
        // data, so an attacker who force-stops the app here has already lost. ───
```

### `step("fcmToken") {`
Replaced in source by: `// Network, so it belongs below that line; withTimeoutOrNull does bound Task.await().`
```
        // The FCM teardown is NETWORK, and it belongs here rather than up among the local steps.
        // Above, it sat before the sharedPrefs sweep, the OS contacts purge and the app-lock reset —
        // so an attacker holding the device only had to put it on a network that black-holes packets
        // (rather than refusing them), wait for Play Services to hang, and force-stop the app from
        // Settings. Everything below the hang survived. That is precisely the ordering the banner
        // above forbids, and this step was the exception to it.
        //
        // withTimeoutOrNull DOES bound these, unlike the deregister: `Task.await()` suspends on a
        // callback rather than blocking a thread in a socket read, so cancelling the continuation
        // actually stops the wait. It runs inside NonCancellable, whose children are still
        // cancellable by their own timeout.
```

### `val deregistered = runCatching {`
Replaced in source by: `// Network LAST, bounded by the client's own callTimeout; not folded into `failed`.`
```
        // Network LAST, bounded by the client's own `callTimeout` — coroutine cancellation cannot
        // interrupt a thread blocked in a socket read, so `withTimeoutOrNull` here would only skip
        // whatever came after it.
        //
        // Deliberately NOT folded into `failed`: [WipeResult.Incomplete] means "local data may
        // still be on disk", and an unreachable relay says nothing about local data — every byte of
        // which is gone by this line.
        //
        // The client is built HERE from [pinForDeregister], not taken from PushGraph. PushGraph's
        // resolves the pin per request, and by this line there is no pin left to resolve.
```

### `org.kysecurity.mail.push.DeregisterResult.Error(`
Replaced in source by: `// Fail closed: no captured pin is TlsPinState.Lost, which must not be downgraded.`
```
                // Fail closed. A pairing with no captured pin is `TlsPinState.Lost`, which the
                // ordinary request path already refuses; the wipe must refuse it too rather than
                // being the one caller that downgrades. The cost is a relay that keeps a revoked
                // device listed until the user removes it from the server's Security page, which is
                // logged below — strictly better than handing the credential to whoever is holding
                // the network.
```

### `val givingUp = wipeAttempts(appContext) >= MAX_WIPE_RESUMES`
Replaced in source by: `// Past the ceiling, stop auto-retrying — the marker and failed steps must persist.`
```
            // Past the ceiling, stop asking the app to re-wipe itself at every launch — that was a
            // brick, and it is why the ceiling exists. What must NOT happen alongside it is
            // clearing the marker: deletion failed, so the app has to keep knowing that. Fail
            // closed instead — [KEY_WIPE_ABANDONED] ends the automatic retries, the marker and the
            // failed step names persist, and [enforceTripwire] reports the same permanent
            // "incomplete, manual recovery required" verdict on every launch from here on.
```

### `internal fun pinnedDeregisterClient(`
Replaced in source by: `/** Bound to a pin captured before deletion, since the state a factory would read is gone. */`
```
    /**
     * A deregister client pinned to [pin], or null when there is nothing to pin to.
     *
     * Deliberately NOT [org.kysecurity.mail.push.PinnedOrFallbackCallFactory]: that type's whole
     * job is to answer "pin, fall back, or refuse" from *current* state, and by the time the wipe
     * reaches the network it has already destroyed the state that type would read. This binds one
     * client to one pin captured before the deletion started, so there is nothing left to get wrong.
     */
```

### `fun abandonedWipe(context: Context): WipeResult.Incomplete? {`
Replaced in source by: `/** The terminal state, or null while the wipe is still resumable — the two mean opposites. */`
```
    /**
     * The terminal state described in [KEY_WIPE_ABANDONED], or null while the wipe is still being
     * resumed (or has never run).
     *
     * Public so a screen can ask directly rather than inferring it from a bare `wipeInterrupted`,
     * which is true of both a resumable wipe and an abandoned one and means opposite things.
     */
```

### `fun blockedByAbandonedWipe(context: Context): Boolean = abandonedWipe(context) != null`
Replaced in source by: `/** Refuse-everything check for non-Activity entry points; one boolean, no graph or Keystore. */`
```
    /**
     * "Refuse to do anything at all", for the non-Activity entry points that cannot go through
     * [LockedActivity]'s terminal block. The pairing credential is often among what survived an
     * abandoned wipe, so push, lock-screen previews and MFA approval all stay reachable otherwise.
     *
     * One boolean from SharedPreferences: no graph, no coroutine, no Keystore, and independent of
     * [startupVerdict], which may not be complete when a push arrives.
     */
```

### `private fun recordFailedSteps(appContext: Context, failed: List<String>, abandoned: Boolean) {`
Replaced in source by: `/** commit(): the process may be killed at any point during a wipe. */`
```
    /** Persists what this run could not destroy, in the retained wipe-state file, alongside whether
     *  the app has stopped resuming it. `commit()` because the process may be killed at any point
     *  during a wipe — that is the whole premise of the marker. */
```

### `private fun markWipeInProgress(appContext: Context, hostileLocationEnabled: Boolean): Boolean {`
Replaced in source by: `/** Returns the posture the first run observed, sticky across resumes. */`
```
    /**
     * Marker, attempt count and protection posture in one `commit()`, before anything is destroyed.
     * Returns the posture the *first* run observed — sticky across resumes, because a resumed run
     * would otherwise read the settings file an interrupted run already deleted.
     */
```

### `val resuming = prefs.getBoolean(KEY_WIPE_IN_PROGRESS, false) &&`
Replaced in source by: `// The attempt counter belongs to one wipe episode, not to the install.`
```
        // The attempt counter belongs to ONE wipe episode, not to the install: a new episode gets
        // the full budget, or an install-lifetime counter would be spent before the wipe that
        // matters. An abandoned episode is over even though its marker is still set.
```

### `private fun clearWipeMarker(appContext: Context) {`
Replaced in source by: `/** Keeps [KEY_WIPE_ATTEMPTS]: clear() would reset the budget and unbound the ceiling. */`
```
    /**
     * Ends this wipe, **keeping** [KEY_WIPE_ATTEMPTS]. `clear()` would drop it, so reaching
     * [MAX_WIPE_RESUMES] would reset the budget and the ceiling would bound nothing. The count is
     * reset only by [markWipeInProgress], at episode start.
     */
```

### `suspend fun closeAndDeleteDatabase(context: Context) = withContext(Dispatchers.IO + NonCancellable) {`
Replaced in source by: `/** Drops [DataRuntime] too; shared with the Hostile Location Protection enable path. */`
```
    /**
     * Closes and deletes the database (plus its journal files) and drops [DataRuntime], so the next
     * access rebuilds rather than being handed the closed instance.
     *
     * Shared with Hostile Location Protection's toggle: enabling it must delete any on-disk cache
     * written before it was turned on.
     */
```

### `val settled = org.kysecurity.mail.MailBackgroundExecutor.quiesce()`
Replaced in source by: `// ORDER MATTERS: quiesce first, then take() — invalidate()+graph() would close a new DB.`
```
        // ORDER MATTERS. Quiesce first, or closing the database out from under an in-flight pool
        // thread is an uncaught exception on a non-UI thread — a process kill. Then `take()`, not
        // `invalidate()` + `graph()`: the latter builds a new database and closes *that*.
```

### `if (!deleted && appContext.getDatabasePath(org.kysecurity.mail.data.DATABASE_NAME).exists()) {`
Replaced in source by: `// Reported, not merely logged: a false return means the file is still there.`
```
        // Reported, not merely logged. `deleteDatabase` returns false when the file is still there,
        // which after an unquiesced teardown is exactly what "mail work is still holding it open"
        // looks like — and the cached message bodies are the single most sensitive thing a wipe is
        // supposed to destroy. The quiesce result is folded in so the cause is named rather than
        // guessed at from a bare "false".
```

### `suspend fun deletePlaintextMetadataStores(context: Context) = withContext(Dispatchers.IO + NonCancellable) {`
Replaced in source by: `/** Removes metadata written before Hostile Location Protection was turned on. */`
```
    /**
     * Deletes the plaintext metadata stores without touching the pairing or the app lock.
     *
     * Hostile Location Protection's contract is that nothing about the user's mail is on disk. The
     * Room swap and the push-history diversion only cover data written *after* the toggle, so the
     * enable path has to remove what is already there: `push_state`'s 30-entry sender/subject
     * history, `mail_sync_state`'s cursor keys (whose *names* are server folder paths, so they leak
     * the folder taxonomy the user has opened plus per-folder read timestamps), `contacts_state`,
     * and the accumulated keyword labels.
     */
```

### `private fun deleteAllSharedPrefs(appContext: Context) {`
Replaced in source by: `/** Throws on the first failure so [wipeAndResetApp] records the step as failed. */`
```
    /**
     * Every SharedPreferences file this app owns, minus [PREFS_NAMES_RETAINED].
     *
     * Throws on the first failure so [wipeAndResetApp] records the step as failed.
     */
```

### `val files = dir.listFiles { file -> file.name.endsWith(".xml") }`
Replaced in source by: `// Null means the directory could not be enumerated, which is not "nothing here".`
```
        // Null means the directory could not be enumerated, which is not the same as "there is
        // nothing here" — `.orEmpty()` alone turned "I cannot see what needs deleting" into a
        // clean pass.
```

### `private suspend fun clearWebViewState(appContext: Context) {`
Replaced in source by: `/** Nothing is caught: failures must reach `failed`. WebView statics must run on Main. */`
```
    /**
     * Clears Chromium's per-application profile. "Show images" makes the mail WebView fetch for
     * real, after which cookies, HSTS and alt-svc state under `app_webview` are a host-level record
     * of the servers contacted while reading mail.
     *
     * Nothing here is caught — a failure has to reach [wipeAndResetApp]'s `failed` list. The
     * WebView statics must run on Main; this is called from `Dispatchers.IO`.
     */
```

### `val profile = File(appContext.dataDir, "app_webview")`
Replaced in source by: `// app_webview holds the host-level record; deleteRecursively reports false, not throws.`
```
        // `app_webview` is the directory that actually holds the host-level record — cookies,
        // TransportSecurity, Network Persistent State — so a partial delete here is exactly the
        // state this must not call Complete. deleteRecursively() reports false rather than
        // throwing, hence the explicit check.
```

### `listOf(appContext.cacheDir, appContext.codeCacheDir).forEach { dir ->`
Replaced in source by: `// Logged rather than thrown: files are still being created underneath in a live process.`
```
        // Child by child, and logged rather than thrown: this runs in a live process where OkHttp,
        // WebView and ART are still creating files underneath, so a partial delete is routine and
        // must not brick the wipe. Nothing security-relevant is unique to these directories.
```

### `private fun deleteSyncedDeviceContactRows(context: Context) {`
Replaced in source by: `/** CALLER_IS_SYNCADAPTER makes the delete immediate; these rows live outside the sandbox. */`
```
    /**
     * Deletes the raw contacts this app wrote into the OS contacts provider.
     * `CALLER_IS_SYNCADAPTER` makes the delete immediate rather than a tombstone, which would keep
     * the data until a sync that will never happen for an account we are about to remove.
     *
     * Throws on failure, and is its own step, because this is the one thing a wipe destroys that
     * lives **outside this app's sandbox**.
     */
```

### `val deleted = org.kysecurity.mail.contacts.device.DeviceContactPurge.deleteSyncedRows(context)`
Replaced in source by: `// Via DeviceContactPurge: building a graph here would rebuild the deleted database.`
```
        // Shared with the unpair path via DeviceContactPurge, which does the provider delete without
        // constructing any graph — building DeviceContactsGraph here would rebuild the database this
        // wipe has already deleted.
```

### `if (deleted < 0) {`
Replaced in source by: `// Negative means the rows could not be reached; zero is legitimate, not assumed.`
```
        // A negative count is the provider reporting it did not act. Zero is legitimate (sync was
        // never enabled), so it is not an error — but it must not be *assumed*, which is what
        // discarding the return value did.
```

### `suspend fun enforceTripwire(context: Context): WipeResult? {`
Replaced in source by: `/** Fires when the encrypted app-lock file is empty while the marker says a lock was set. */`
```
    /**
     * Startup check for the [AppLockStore] tripwire: the encrypted app-lock file lost its contents
     * while the unencrypted marker still says a lock was configured. That means either OS-level
     * Keystore invalidation or someone deleting the keyset to disable the lock — and the old
     * behaviour of silently reporting "no lock configured" opened the inbox with every cached
     * message intact. Wipe instead, and let the user set the app up again.
     */
```

### `abandonedWipe(appContext)?.let {`
Replaced in source by: `// Resume first: the interrupted run may have deleted the state tripwireBroken() reads.`
```
        // A wipe that started and never finished is resumed before anything else, including the
        // tripwire check itself — the interrupted run may have deleted the app-lock state that
        // tripwireBroken() reads, so relying on the tripwire alone would let the rest of the wipe
        // stay undone forever. Re-running is safe: every step is idempotent.
        // Checked before the resume, and never cleared by anything but a clean run: past
        // MAX_WIPE_RESUMES the app stops re-running the destructive pass, but it does not stop
        // knowing that data may still be here. Every launch from now on lands on
        // `security_wipe_incomplete_final_notice` instead of a first-run screen that implies the
        // erasure succeeded.
```

### `val startupVerdict: kotlinx.coroutines.CompletableDeferred<WipeResult?> =`
Replaced in source by: `/** A gate: Application.onCreate cannot promise to run before the launcher Activity. */`
```
    /**
     * Completes once the startup tripwire check has finished, carrying whether it wiped.
     *
     * The check is a **gate**: `Application.onCreate` returns before the launcher Activity starts,
     * so it cannot promise to run first. [LockedActivity] awaits this before rendering anything.
     */
```

## app/src/main/java/org/kysecurity/mail/security/SpkiPinner.kt

### `object SpkiPinner {`
Replaced in source by: `/** TOFU: the server cert pin is captured at pairing time and enforced on every later connect. */`
```
/**
 * TOFU (trust-on-first-use) certificate pinning support — see "Certificate pinning" in the
 * 2026-07-22 security-hardening spec. kypost is self-hosted with a per-user server URL, so there
 * is no fixed certificate to hardcode; instead the server's certificate pin is captured once at
 * pairing time and enforced on every later connection. This wraps OkHttp's own
 * [CertificatePinner.pin] (which already computes the correct `sha256/BASE64` SPKI hash) purely
 * to give the operation a name specific to this feature, not because the computation itself
 * needs reimplementing.
 */
```

## app/src/main/java/org/kysecurity/mail/security/UnlockActivity.kt

### `class UnlockActivity : AppCompatActivity() {`
```
/**
 * Full-screen PIN gate shown whenever [AppLockManager.locked] is true. Biometric unlock layers on
 * top of this; the PIN field here is always present as the fallback.
 */
```

### `if (SecurityRuntime.graph(this).appLockStore.isBiometricEnabled()) {`
```
        // The credential gate is no longer a reason to refuse a fingerprint: biometric unlock now
        // opens the same PIN-derived keys the gate wants, so it is a complete unlock rather than a
        // partial one that has to be topped up with a PIN.
```

### `android.util.Log.e("UnlockActivity", "Wipe incomplete: ${result.failedSteps}")`
Replaced in source by: `// The wipe left its in-progress marker set, so KyPostApp retries it at start.`
```
                    // The wipe ran but did not finish, so local data may still be on disk. Say so
                    // rather than showing the same clean first-run screen as a successful wipe —
                    // and still relaunch, since SecurityWipe has left its in-progress marker set
                    // and KyPostApp will retry the whole wipe on the next start.
```

### `errorText.visibility = View.VISIBLE`
Replaced in source by: `// No PIN can match again, and this does not advance the wipe threshold.`
```
                    // The Keystore key behind the stored verifier is gone, so no PIN can ever match
                    // again. Saying "wrong PIN" would send the user round the loop until the wipe
                    // threshold — which this outcome deliberately does not advance — so name the
                    // real problem and the only real remedy.
```

### `private suspend fun completeUnlock() {`
Replaced in source by: `/** Shared by both unlock paths so each runs the rewrap and the enrollment report. */`
```
    /**
     * What a completed unlock owes the rest of the app, whichever credential produced it.
     *
     * Shared by the PIN and biometric paths deliberately. Both now yield the same credential keys,
     * so both can close the gap where a background FCM token rotation saved the pairing unwrapped
     * with nothing cached in this process, and both can migrate a pre-pepper wrap (see
     * [rewrapPairingIfNeeded]). While biometric derived nothing, this work hung off the PIN alone
     * and a user who only ever used the fingerprint reader never ran any of it.
     *
     * [org.kysecurity.mail.pgp.EnrollmentStateWorker] is unique work, so re-enqueueing is idempotent
     * and costs nothing when there is no report owed.
     */
```

### `private fun proceedIntoApp() {`
```
    /**
     * Every locked screen finishes itself when it redirects here, so on success there is nothing
     * left in the task to return to. Route through [MainActivity], which already decides between
     * the inbox and the pairing screen.
     */
```

### `private fun showBiometricPromptIfAvailable() {`
Replaced in source by: `/** prepareUnlock() is Keystore and disk work, hence the hop off the main thread. */`
```
    /**
     * Offers the fingerprint only when there is something for it to open.
     *
     * [BiometricUnlockVault.prepareUnlock] returns null on a device that has never completed a PIN
     * unlock since this feature landed, and on one whose key the OS destroyed because a biometric
     * was enrolled. Both leave the always-visible PIN field as the only route, and the next PIN
     * unlock re-seals — so the fallback repairs itself and needs no user-facing recovery step.
     *
     * The vault call is Keystore and disk work, hence the hop off the main thread.
     */
```

### `override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {`
```
                /**
                 * The authentication is *used*, not merely observed. The cipher handed back here is
                 * the one the Keystore refused to operate until the user authenticated, and the keys
                 * it opens are the same ones a PIN unlock derives — so there is no longer a version
                 * of this callback that grants access without producing a secret.
                 */
```

### `if (appLockManager.unlockWithBiometric(keys) !is UnlockAttemptResult.Success) {`
Replaced in source by: `// Rejected means an earlier lockout is still running; biometrics skip nothing.`
```
                    // Rejected means a lockout from earlier wrong PINs is still running; the
                    // fingerprint does not skip it. Rendered exactly like the PIN path's rejection
                    // so the two cannot say different things about the same ladder.
```

### `},`
Replaced in source by: `// Errors and failures need no handling: the PIN field is always the fallback.`
```
                // onAuthenticationError (includes the user tapping "Use PIN") and
                // onAuthenticationFailed both just leave the always-visible PIN field as the
                // fallback — no separate handling needed.
```

### `lifecycleScope.launch { AppRestart.relaunch(this@UnlockActivity) }`
Replaced in source by: `// SecurityWipe already ran; this only rebuilds the graphs, and the rebuild blocks.`
```
        // SecurityWipe already ran (inside AppLockManager.attemptPin's onWipe callback) by the
        // time UnlockAttemptResult.Wiped is returned — this just rebuilds the graphs and
        // relaunches so the app picks up the now-cleared state. Launched rather than called: the
        // rebuild blocks, and this is reached from a click listener.
```
