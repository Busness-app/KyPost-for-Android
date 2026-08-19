# Comment archive - main/pgp (A-F)

## app/src/main/java/org/kysecurity/mail/pgp/ArmoredKeyStream.kt

### `internal inline fun <T> CharArray.useArmoredStream(block: (InputStream) -> T): T`
```
/**
 * A stream over an armored key held as a [CharArray], without ever building a [String].
 *
 * The OpenPGP entry points take `CharArray` so [EnrollmentSession] never has to hand out an
 * unwipeable copy of the private key. Bouncy Castle wants an [InputStream], so a byte array is
 * unavoidable — but this one is ours, and [use] zeroes it the moment the caller is done rather
 * than leaving it for the collector.
 */
```

## app/src/main/java/org/kysecurity/mail/pgp/ClientEncryptedSender.kt

### `internal sealed class ClientSendOutcome`
```
/**
 * Every way a client-encrypted send can end. One per row of the compose screen's exit table.
 *
 * Separate objects rather than one error string because the UI shows a different sentence — and
 * sometimes a different button — for each. [Cancelled] in particular is not an error: the user
 * dismissed a prompt they raised, and the screen simply goes back to offering Send.
 */
```

### `internal class ClientEncryptedSender(`
```
/**
 * Encrypts and signs one message on this device, then hands the ciphertext to the relay.
 *
 * **No Android imports**, following [EncryptedMessageReader] — which is what lets the whole exit
 * table be a JVM test with fakes instead of an instrumented one.
 *
 * Nothing here decides whether the account *may* use this path; [pgpComposeStateOf] does that. This
 * runs only once that decision is made.
 */
```

### `val resolved = when (val result = resolver.resolve(addresses))`
```
        // Resolve BEFORE unlocking. A send that was going to be refused anyway must not interrupt
        // the user for a biometric they gain nothing from. (The web client prompts first; this is a
        // deliberate divergence, not an oversight.)
```

### `val changed = addresses.filter { ... }`
```
        // A broken pin outranks a missing key, and is checked first. `key_changed` means discovery
        // found a key whose fingerprint does not match the pinned one — which is what a rotation
        // looks like and also what interception looks like. Folding it into "no key on file" tells
        // the user nothing changed at the exact moment the one thing worth telling them did.
```

### `val ciphertexts = EnrollmentSession.withKey { privateKey -> ... }`
```
        // Every use of the private key is inside this one scope, so it stays the holder's wipeable
        // CharArray rather than an immortal String copy — see [EnrollmentSession.withKey]. Null
        // means the app locked between the unseal above and here, which lockNow() does by clearing
        // the holder.
```

### `private sealed class EncryptedBundle`
```
    /** Everything the private key is needed for, so [EnrollmentSession.withKey] can scope it to a
     *  single call rather than the whole send — the network round trip below needs no key. */
```

## app/src/main/java/org/kysecurity/mail/pgp/DeviceEnrollmentActivity.kt

### `class DeviceEnrollmentActivity : LockedActivity()`
```
/**
 * The enrollment ceremony's screen: renders [EnrollmentUiState] and owns the one piece the pure
 * orchestrator cannot — `BiometricPrompt`, which is Activity-bound.
 *
 * A dedicated Activity rather than a section of `SecuritySettingsActivity` (706 lines, and where the
 * `NonCancellable` continuation bug lived) or `PgpKeyActivity` (466). Neither should grow a
 * multi-minute stateful ceremony.
 */
```

### `private var created = false`
```
    /**
     * True once `onCreate` ran past [LockedActivity]'s gate — i.e. once [viewModel] has actually
     * been dereferenced and the sealer installed. Read by [onDestroy], which is the only method here
     * that must distinguish "this screen was never set up" from "this screen is going away".
     *
     * Deliberately **not** `redirectedToUnlock`, which `onCreate` and `onResume` use: that flag is
     * also set from `LockedActivity.onStart`, long after `onCreate` has run to completion, on the
     * ordinary "the app locked while this screen was backgrounded" exit. On that path the ViewModel
     * really does exist and a live `BiometricPrompt` really may need resolving, so keying
     * [onDestroy] off `redirectedToUnlock` would skip the seal resolution on a path that needs it —
     * leaving a `NonCancellable` continuation suspended forever with the armored private key never
     * zeroed. This flag is only ever false when `onCreate` itself bailed.
     */
```

### `private val sealExecutor = Executors.newSingleThreadExecutor()`
```
    /**
     * Where the AES-GCM `doFinal` and the `commit()`-backed store run.
     *
     * Not the main thread — `EnrollmentVault.store` is a Keystore round trip plus a synchronous
     * write into `EncryptedSharedPreferences`, which is exactly the work `SecuritySettingsActivity`'s
     * own KDoc records having wrongly run on the UI thread. Not `lifecycleScope` either: that is
     * cancelled when this Activity is destroyed, and a seal cancelled halfway leaves a continuation
     * nothing ever resumes, hanging the ceremony. A plain executor is independent of both.
     */
```

### `var committing: Boolean = false`
```
        /**
         * True once [sealExecutor] has been handed the `doFinal` + `vault.store` work — set inside
         * the same `synchronized(sealLock)` critical section that submits the task, so [onDestroy]
         * can never observe "the executor has it" and "committing is still false" as different
         * states. Only ever read or written while holding [sealLock].
         */
```

### `private var liveSeal: LiveSeal? = null`
```
    /**
     * The in-flight `BiometricPrompt` and the continuation waiting on it, if any.
     *
     * Exists because androidx.biometric 1.1.0 does **not** treat a configuration-change destroy the
     * way this screen needs it to: it resets its client callback to a no-op on `ON_DESTROY`
     * (`BiometricPrompt`'s internal `ResetCallbackObserver`), and on API ≥ Q it does not cancel the
     * system prompt when that destroy is a rotation — the dialog stays up and reconnects to the
     * activity-scoped `BiometricViewModel` that survives the recreation. Left alone, a user who
     * rotates while "Confirm it's you" is showing and then authenticates would see the prompt
     * dismiss with its result delivered to the now-no-op callback: the continuation this Activity
     * is holding would never be resumed, and the ceremony would hang on "Confirm it's you…"
     * forever. [onDestroy] resolves this itself instead of relying on the library — except when
     * [LiveSeal.committing] is true, in which case [sealExecutor] already owns delivering the true
     * outcome and [onDestroy] must leave the continuation alone; see [onDestroy]. `@Volatile`
     * because [resolveSeal] can run from [sealExecutor]'s thread as well as the main thread.
     */
```

### `private fun resolveSeal(continuation: ..., outcome: SealOutcome)`
```
    /**
     * Resolves [continuation] with [outcome] exactly once, racing safely against [onDestroy]
     * resolving the same wait from a different thread: whichever of the two clears [liveSeal]
     * first — inside the synchronized block, by continuation identity — is the one that actually
     * calls `resume`. Used only for outcomes [sealExecutor] itself produces or a failure to reach
     * it; [onDestroy]'s own cancel-on-destroy path resolves directly, because it must additionally
     * check [LiveSeal.committing] before deciding to resolve at all.
     */
```

### `private val vaultSealer = object : VaultSealer`
```
    /**
     * The `VaultSealer` handed to the ViewModel.
     *
     * An anonymous object rather than making this Activity implement the interface: `VaultSealer` is
     * `internal`, and a public class may not widen an internal supertype.
     */
```

### `val (ensured, cipher) = withContext(Dispatchers.IO)`
```
            // The authority on "is there a secure lock screen", and the point where a key is
            // legitimately generated. Off the main thread: ensureKey() is a Keystore round trip
            // that, on the generate path, attempts StrongBox key generation — hundreds of
            // milliseconds to seconds — with a TEE fallback, plus the lazy
            // EncryptedSharedPreferences/Tink construction behind prefs.edit().clear().commit().
            // Nothing upstream of VaultSealer switches dispatchers, so the ceremony's coroutine
            // runs on viewModelScope's Dispatchers.Main.immediate; without this it would block the
            // UI thread for that entire round trip. The BiometricPrompt itself must stay on main,
            // so this withContext ends before that begins.
```

### `return SealOutcome.Failed("The device key could not be created")`
```
                // ensureKey() returns false both when there is no secure lock screen AND when both
                // the StrongBox and TEE key-generation attempts fail for reasons that have nothing
                // to do with the lock screen — and sealAndReport already re-checked
                // hasSecureLockScreen() immediately before calling seal(), so by the time this
                // branch runs a lock screen is usually present. There is no SealOutcome.NoDeviceKey,
                // so this maps to the generic Failed rather than telling the user to fix something
                // that is not broken.
```

### `if (!lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED) || ...)`
```
                // A prompt requested after the FragmentManager has saved its state — the user hits
                // Home the instant the envelope arrives, landing here after onSaveInstanceState —
                // is silently dropped by BiometricPrompt.authenticateInternal: no exception, no
                // callback, ever. Caught here rather than left to orphan the continuation; the
                // envelope stays on the relay, so resolving as a cancel is recoverable via "Check
                // again" exactly like an ordinary dismissal.
```

### `val handoff = synchronized(sealLock) { ... }`
```
                            // Mark committing in the same critical section onDestroy claims
                            // liveSeal in, so the two decisions cannot interleave: either
                            // onDestroy's synchronized block already ran first and this no longer
                            // matches liveSeal (handoff below is false — nothing to commit to,
                            // the continuation is already resolved as Cancelled), or this marks
                            // first and onDestroy will then see committing == true and leave the
                            // continuation alone. Without this, onDestroy could resolve Cancelled
                            // over a write already handed to sealExecutor: the ceremony would zero
                            // the plaintext array while doFinal is still reading it, or report
                            // "cancelled" over a blob sealExecutor in fact stored — the exact lie
                            // EnrollmentVault's own KDoc says the enrollment marker must never
                            // tell, and the unsafe direction, since the user could then
                            // decommission the device that actually holds a working copy.
```

### `try { sealExecutor.execute { ... } }`
```
                            // Unreachable in practice once onDestroy has run: androidx.biometric
                            // resets this callback to a no-op on ON_DESTROY before it could ever
                            // fire again (see onDestroy and liveSeal's KDoc), and this dispatch,
                            // the handoff above, and sealExecutor.shutdown() all run on the main
                            // thread with no suspension between them, so they cannot interleave
                            // either. Kept as defence in depth. If it ever did fire post-shutdown,
                            // the right outcome is a cancel — nothing was written — not a
                            // destructive SealOutcome.Failed, which would tear down the agreement
                            // key via failAndDestroy.
```

### `override fun onAuthenticationError(errorCode: Int, errString: CharSequence)`
```
                        /** The user dismissing the prompt, or the library giving up on its own
                         *  (lockout, timeout). A configuration-change destroy does **not** land
                         *  here in androidx.biometric 1.1.0 — see [onDestroy], which resolves that
                         *  case itself because this callback never fires for it. */
```

### `val info = BiometricPrompt.PromptInfo.Builder()`
```
                // DEVICE_CREDENTIAL is allowed because the vault key itself allows it — see
                // EnrollmentVault's KDoc on why biometric-only would invalidate the key on every
                // fingerprint change. With DEVICE_CREDENTIAL in the set, setNegativeButtonText must
                // NOT be called: BiometricPrompt throws if both are given.
```

### `continuation.invokeOnCancellation { ... }`
```
                // Registered after authenticate(), not before: if the continuation were already
                // cancelled on entry, an earlier registration would fire this handler immediately
                // — clearing liveSeal and calling cancelAuthentication() on a prompt not yet shown
                // — and the authenticate() call above would then leave a system dialog nothing
                // will ever dismiss.
```

### `override fun onDestroy() — the `created` guard`
```
        // InboxActivity, EmailDetailActivity and ComposeActivity each note that their onDestroy
        // needs no guard, because it only touches property initializers, which exist even when
        // onCreate bailed. This one is different: it dereferences `viewModel`, and when onCreate
        // bailed at LockedActivity's gate nothing above ever has. `by viewModels()` resolves lazily,
        // so `viewModel.installSealer(null)` below would be the FIRST get on the store — and by then
        // ComponentActivity has already cleared it (on API >= 29 ON_DESTROY is dispatched from
        // dispatchActivityPreDestroyed(), before this method is even entered). ViewModelStore has no
        // "cleared" flag, so a get after clear() simply constructs a new ViewModel into a map
        // nothing will clear again: a whole DeviceEnrollmentViewModel whose init launches
        // ceremony.run(), with onCleared() — teardown()'s only caller — never running. With the
        // credential gate off (the default) that mints a P-256 agreement key and publishes its
        // public half to the relay with no screen, no user and no code ever shown, polls for five
        // minutes from a destroyed Activity, and exits at WaitingTimedOut, which by design KEEPS the
        // keypair. EnrollmentKeyStore's KDoc names exactly that outcome: the agreement key carries
        // no user-authentication requirement, justified solely by its life being one foreground
        // ceremony, so one that survives is a standing unauthenticated path to every envelope the
        // relay has retained. Reachable by backgrounding this screen, having the process reclaimed,
        // and returning past the lock grace — the restored task recreate()s for the startup
        // tripwire, and the second onCreate redirects and finishes.
        //
        // `created` and not `redirectedToUnlock` — see that property's KDoc. sealExecutor IS a
        // property initializer, so it exists here and must still be shut down or its thread leaks.
```

### `if (!isChangingConfigurations()) { viewModel.installSealer(null) }`
```
        // Only clear the slot if this Activity is still the one in it. On a rotation the new
        // Activity's onCreate runs BEFORE the old one's onDestroy, and isChangingConfigurations()
        // is true for exactly that case — so skipping the clear there is what stops an
        // unconditional null from uninstalling the incoming sealer and turning the next prompt
        // into a cancel. Every other path out of this screen (finish(), the app lock, the OS
        // reclaiming the process) is not a configuration change, so the clear still runs. This
        // guard is independent of the seal resolution below.
```

### `val (seal, shouldResolve) = synchronized(sealLock) { ... }`
```
        // Unconditionally — including on a configuration change — resolve any seal still waiting
        // on a live BiometricPrompt, UNLESS sealExecutor already has the doFinal + store work for
        // it (LiveSeal.committing — see onAuthenticationSucceeded, which sets it in the same
        // critical section this reads it in). See liveSeal's KDoc for why androidx.biometric will
        // not resolve the non-committing case on its own across a rotation: without this, the
        // continuation this Activity is holding would never be resumed, and the screen would sit
        // on "Confirm it's you…" forever with no prompt and no way forward except Cancel (which
        // destroys the agreement key). Resolving it here instead gives back exactly what
        // onAuthenticationError already gives an ordinary dismissal: the code back on screen,
        // envelope still on the relay for seven days, recoverable via "Check again".
        //
        // The committing case must NOT resolve, and this is not just belt-and-braces: sealExecutor
        // is deliberately independent of this Activity's lifetime and its running task is not
        // interrupted by shutdown() below, so the write proceeds regardless of what happens here.
        // If this resumed Cancelled anyway, the ceremony — on Dispatchers.Main.immediate — would
        // continue INLINE inside this call: sealAndReport's Cancelled branch runs, and
        // openAndSeal's finally zeroes the same plaintext array authenticated.doFinal(plaintext)
        // may still be reading on sealExecutor's thread, while the executor either stores a valid
        // blob the ceremony believes does not exist, or stores one built from a plaintext array
        // that is being zeroed out from under it mid-read. Leaving liveSeal in place instead means
        // sealExecutor's own resolveSeal call, once doFinal + store finish, is the only thing that
        // ever resumes this continuation — with the true outcome.
```

### `if (seal != null && shouldResolve) { ... }`
```
        // cancelAuthentication() is called only on the path that also resolves the wait. On the
        // committing path there is no live prompt left to cancel — authentication already
        // succeeded, the fragment already delivered its result to onAuthenticationSucceeded — so
        // the call buys nothing, and leaving it in would be a second door onto the same hazard
        // this round closed: it exists purely to dismiss a dialog, but it reads as "this is still
        // this Activity's prompt to manage," which is exactly the assumption committing exists to
        // retract.
```

### `val awaitingTheUser = ...`
```
        // FLAG_KEEP_SCREEN_ON wherever the ceremony is waiting on the user with a live keypair.
        // Without it the screen times out while the user is typing into their browser, which
        // backgrounds the app, which starts the lock grace — and the user comes back to an unlock
        // prompt with the ceremony destroyed.
        //
        // ReadyToFinish is in this set even though it shows no code: it is one tap from completing,
        // and it is where a user who stepped away to fetch a fingerprint lands. Letting the screen
        // sleep there would destroy a ceremony whose envelope had already arrived. It is the same
        // set as [offersCheckAgain] minus the transient states — both answer "is the ceremony
        // waiting on a person right now".
```

### `if (state is EnrollmentUiState.ShowingCode) { ... }`
```
        // The countdown runs only for ShowingCode. In WaitingTimedOut the poll loop has stopped, so
        // nothing refreshes this expiry: a ticking label would count a dead bucket down past zero
        // and then sit on "about to change" forever. That state's detail line sends the user to
        // "Check again" — which reopens a window and re-derives the code — rather than to the
        // stale value beside it.
```

### `private fun startCountdown(scope: CoroutineScope, expiresAtEpochMs: Long)`
```
    /**
     * Recomputes from the wall clock every second rather than counting down from a captured value,
     * so a screen that was backgrounded shows the truth when it comes back.
     *
     * Launched on [scope] — the CoroutineScope `repeatOnLifecycle(STARTED)` provides, cancelled on
     * STOP and relaunched on the next START — rather than on `lifecycleScope`, which lives until
     * DESTROYED. `lifecycleScope` would leave this ticking (and writing to [expiryText]) once a
     * second while the screen is backgrounded; render()'s own `countdown?.cancel()` cannot reach it
     * from there, because `repeatOnLifecycle`'s collector is suspended for the whole time the
     * screen is stopped, so render() itself does not run again until it resumes.
     */
```

## app/src/main/java/org/kysecurity/mail/pgp/DeviceEnrollmentCode.kt

### `private const val CODE_LENGTH = 14`
```
/**
 * Fourteen characters at five bits each — the first **70 bits** of the digest, MSB first.
 *
 * This was 10 characters (50 bits), and 50 bits is not enough. The comparison has **no commitment
 * step**: nothing the browser contributes enters this preimage, so every input is fixed, public, or
 * attacker-chosen and the search is entirely *offline* — a work factor, not a per-attempt
 * probability. An adversary who can write the relay's device table (explicitly in this design's
 * threat model — "a compromised database") grinds a key, or the `deviceId`, whose code collides with
 * the honest device's at a chosen future bucket, then waits for that bucket to arrive. At 50 bits
 * that is roughly 2^50 SHA-256 compressions: about 14 GPU-hours, five to seven dollars, per
 * 120-second window. The spec's original argument — "2^47 in 120 seconds, short of 2^50 with margin"
 * — assumed an online bound, but refusing *future* buckets does not prevent precomputing *into* one.
 *
 * 70 bits puts the same search at ~2^70, which is roughly a million GPU-years per window.
 *
 * The principled fix is a commitment, not a longer code: Matrix's SAS is *shorter* than this at
 * 36–39 bits and is sound, because `m.key.verification.accept` carries a required SHA-256 commitment
 * to the peer's ephemeral key, so the attacker gets exactly one online guess. That needs a
 * browser-to-device channel this protocol does not have yet — see the spec's "Decision 8". Until it
 * exists, length is what carries the property.
 *
 * Displayed as two groups of seven: `XXXXXXX-XXXXXXX`.
 */
```

### `internal fun deviceEnrollmentCode(rawPublicKey: ByteArray, deviceId: String, bucket: Long): String`
```
/**
 * The short authentication string shown during device enrollment.
 *
 * Derived from the public key in this device's own keystore — never from anything the server sent
 * back, and never from a cached copy of what was published. The browser compares its own derivation
 * (from the key the server handed it) against what the user reads off this screen; if this device
 * ever derived from a server-supplied value, the comparison would compare the server against itself
 * and the whole control would be decoration.
 *
 * [rawPublicKey] is the uncompressed SEC1 point, `0x04 ‖ X ‖ Y` with each coordinate left-padded to
 * 32 bytes — the raw 65 bytes, never their base64 text. [bucket] is `unixSeconds / 120`.
 *
 * [deviceId] is hashed as-is. It is **not** normalised, and must not be: the server bounds new ids
 * to `A-Z a-z 0-9 . _ : -`, every character of which is byte-identical under UTF-8, NFC and NFD, so
 * there is nothing to normalise. That bound exists precisely because an NFC/NFD disagreement
 * between two clients would surface to the user as a substituted key.
 */
```

## app/src/main/java/org/kysecurity/mail/pgp/DeviceEnrollmentViewModel.kt

### `internal class DeviceEnrollmentViewModel(application: Application)`
```
/**
 * Owns one ceremony for the lifetime of the screen, across rotations.
 *
 * No Activity in this app declares `configChanges`, so rotation destroys every screen. A ceremony
 * living in an Activity would, on rotation, mint and publish a *new* keypair and put a new code on
 * screen — invalidating the one the user had already started typing into their browser. The
 * ViewModel is what makes that survivable: it is created once and `run()` is started once.
 */
```

### `private var activitySealer: VaultSealer? = null`
```
    /**
     * The live Activity, or null between one being destroyed and the next installing itself.
     *
     * `@Volatile` because it is written from the main thread and read from whatever dispatcher the
     * ceremony is suspended on.
     */
```

### `sealer = object : VaultSealer { ... }`
```
        // A proxy, not the Activity itself: the ViewModel outlives the Activity, and a captured
        // reference would keep a destroyed one alive and prompt on a dead window. With none
        // installed, seal() resolves straight to Cancelled. On a configuration change, the
        // outgoing Activity's own onDestroy cancels its live prompt and resumes this call as
        // Cancelled itself — androidx.biometric resets its callback to a no-op on destroy, so the
        // library will not report the rotation on its own.
```

### `override fun onCleared()`
```
    /**
     * The "user leaves" row of the exit table.
     *
     * `viewModelScope` has been cancelled by the time this runs, but cancellation is cooperative, not
     * immediate: a suspended poll or a live `BiometricPrompt` may still be unwinding when `teardown()`
     * executes. That is fine to proceed through regardless — the agreement key must not survive the
     * screen either way, and deleting it cannot corrupt an in-flight seal, because the seal
     * authenticates against the vault key, which `teardown()` never touches. It is idempotent and
     * destroys nothing if the ceremony never minted anything, because `EnrollmentKeyStore.deleteKeyPair()`'s
     * boolean feeds a `SecurityWipe.step` elsewhere and a deletion that never happened must not be
     * reported.
     */
```

## app/src/main/java/org/kysecurity/mail/pgp/DeviceEnvelope.kt

### `private const val ENVELOPE_INFO = "kypost-device-envelope/v2"`
```
/**
 * The HKDF `info` string. Moves together with the version tag and the AAD prefix — changing one
 * alone strands every enrolled device.
 *
 * **v1 → v2 (2026-08-05):** the AAD stopped being pipe-delimited concatenation and became
 * length-prefixed. See [deviceEnvelopeAad].
 */
```

### `internal class DeviceEnvelopeFields(val epk: ByteArray, val iv: ByteArray, val ct: ByteArray)`
```
/** **Not a `data class`**: Kotlin would generate identity `equals`/`hashCode` over three
 *  [ByteArray] fields while advertising structural equality — the same trap
 *  [org.kysecurity.mail.security.WrappedSecret] and [org.kysecurity.mail.security.PinHash] refuse
 *  in their own KDoc. Nothing compares these; enforced by `SourceRulesTest`. */
```

### `internal fun parseDeviceEnvelope(json: String): DeviceEnvelopeFields?`
```
/**
 * Parses the envelope, returning null for anything malformed, unsupported, or wrong-sized. The
 * caller treats null as "re-run the ceremony", never as a retry.
 *
 * Parsed with kotlinx.serialization rather than `org.json`, deliberately. `org.json` on the unit-test
 * classpath resolves to the stubbed `android.jar`, and with `isReturnDefaultValues = true` every stub
 * method returns a default — so this function returned null for *every* input under test, including
 * well-formed envelopes, and all of its tests passed vacuously. Replacing the whole body with
 * `= null` left the suite green. This file is meant to be pure JVM; `org.json` was the one thing
 * making it not.
 */
```

### `internal fun deviceEnvelopeAad(deviceId: String, pgpFingerprint: String): ByteArray`
```
/**
 * Binds the sealing to this device and this identity, as **length-prefixed** fields.
 *
 * `info || uint16BE(len(deviceId)) || deviceId || uint16BE(len(fingerprint)) || fingerprint`
 */
```

### `internal fun openDeviceEnvelope(...)`
```
/**
 * Opens the envelope, or returns null if GCM authentication fails.
 *
 * A null here is **hostile or stale, never a retry**: the AAD binds the sealing to this device and
 * this identity, so a failure means the envelope was minted for someone else or under an identity
 * the account no longer advertises.
 *
 * [ownRawPublicKey] is the HKDF salt — this device's own raw 65-byte SEC1 point, not the ephemeral
 * one in the envelope.
 */
```

### `catch (e: java.security.GeneralSecurityException)`
```
        // A bare `catch (Exception) { null }` reported this identically to the tag failure above,
        // which is how "enrollment silently does nothing on this device" became undiagnosable.
```

## app/src/main/java/org/kysecurity/mail/pgp/EncryptedMessageReader.kt

### `internal interface PayloadSource`
```
/**
 * The ciphertext source, behind an interface so the orchestrator takes no dependency on OkHttp,
 * pairing credentials or a `Context`.
 */
```

### `internal sealed class ReadOutcome`
```
/**
 * Every way reading an encrypted message can end. One per row of the design spec's exit table.
 *
 * They are separate objects rather than one error string because the UI shows a different sentence,
 * and sometimes a different button, for each. [Cancelled] in particular is not an error: the user
 * dismissed a sheet they raised, and the screen simply goes back to offering the Decrypt button.
 */
```

### `internal class EncryptedMessageReader(`
```
/**
 * Reads one client-protected message: unseal if needed, fetch, decrypt, bind the signature, parse.
 *
 * **No Android imports**, following [EnrollmentCeremony] — which is what lets the whole exit table
 * be a JVM test with fakes instead of an instrumented one.
 *
 * The decrypted body is returned to the caller and never persisted. See the design spec's
 * non-negotiable rules: it must not reach Room, and must not reach `fetchedBodyHtml`.
 */
```

### `private val localSignerKeys: LocalSignerKeyLookup`
```
    /**
     * This device's own answer to "whose key is this". Defaults to holding none, which is what a
     * caller with no contact store (and every JVM fixture that does not care) gets: the verdict
     * then falls back to the relay's keys, capped below `VERIFIED_CONFIRMED`.
     */
```

### `sender: String`
```
        /** The sender exactly as displayed. Display context only — deliberately unread by this
         *  function. The signature binding is the SERVER's job: it narrows `payload.signerKeys` to
         *  the resolved sender before this ever runs (see the `offeredKeys` comment below), so this
         *  reader has no binding decision left to make with it. Do not "wire this up" to filter
         *  `signerKeys` — that reintroduces the client-side From parser an earlier task deleted
         *  after it diverged from the server's on 27 of 111 adversarial headers. Kept as a parameter
         *  because callers already have it and a future caller may want it for a purpose that is
         *  NOT the signature verdict (e.g. logging, or comparing against `resolvedSender` for
         *  display). */
```

### `if (!EnrollmentSession.isHeld()) return ReadOutcome.NeedsUnlock`
```
        //
```

### `val localKeys = runCatching { localSignerKeys.keysFor(payload.resolvedSender) }`
```
        // The local answer, resolved before any verdict is computed. `resolvedSender` is still the
        // server's parse of the From header — the client deliberately holds no parser of its own —
        // but what that address is used for has changed: it is now a lookup key into this device's
        // own contact store rather than a label to hang the server's own `verified` claim on. A
        // relay that lies about the address gets a lookup that misses, which produces KEY_CHANGED
        // or SIGNER_UNKNOWN, never a confirmation.
```

### `val offeredKeys = ...`
```
        // `payload.signerKeys` arrives ALREADY narrowed to the displayed sender by the server (Task
        // 14's `boundSignerKeysForSender`). Do not re-narrow here, and do not parse `sender` to do
        // it: a second parser deciding the same binding is exactly the defect an earlier task
        // removed — the client's own From parser diverged from the server's on 27 of 111
        // adversarial headers, including RFC 5322 comments, which let any contact forge a verified
        // badge for anyone.
        //
        // Conflicted keys are still dropped here: they carry no key material and must never be
        // offered to a signature check. They stay in `payload.signerKeys` so `signatureStateFor`
        // can report KEY_CHANGED.
        //
        // This filter cannot change today's ReadOutcome: signatureStateFor returns KEY_CHANGED for
        // any SIGNED message the moment ANY entry in `payload.signerKeys` has `conflict = true` —
        // checked after `!present -> NONE` and `signerKeys.isEmpty() -> SIGNER_UNKNOWN`, but still
        // before it ever looks at what got offered here or whether the signature matched — so no
        // test can observe this line doing anything (confirmed:
        // EncryptedMessageReaderTest.aConflictedKeyYieldsKeyChanged still passes with this filter
        // deliberately removed). It stays anyway, as defence-in-depth against exactly one plausible
        // future edit: someone reordering signatureStateFor so conflict no longer short-circuits
        // first. If that ever happens, offering a key that failed its TOFU pin would start to
        // matter, and deleting this filter now would make that future edit silently unsafe. Do not
        // delete this as "dead code" without re-checking signatureStateFor's precedence first.
        //
        // Locally-held keys go FIRST. PgpDecryptor resolves the verifying key by key id out of the
        // first ring that contains it, so when this device and the relay both hold a key for the
        // same id, the copy that was fingerprinted locally is the one the signature is checked
        // against. The relay's copies stay in the list because they are what makes a first-contact
        // message verifiable at all — and offering them is safe now that the verdict below will not
        // promote anything they support past VERIFIED_SEEN_BEFORE.
```

### `if (payload.encryptedPayload.isBlank())`
```
        // A signed-but-not-encrypted message arrives with a readable body and a detached
        // signature; there is nothing to decrypt.
        //
        // UNREACHABLE IN PRODUCTION TODAY. This function, attemptDecrypt(), is only invoked from
        // EmailDetailActivity's PgpMessageState.CLIENT_PROTECTED branch, and pgpMessageStateOf()
        // only reaches CLIENT_PROTECTED when the server's own pgpEncrypted flag is true — a
        // signed-only message never sets it, and the server keeps the two payloads mutually
        // exclusive (see signedOnlyBody in pgp_client_read.go, which zeroes the body whenever
        // encryptedPayload is non-empty and vice versa). So payload.encryptedPayload.isBlank() has
        // no live caller that can make it true.
        //
        // Do not delete it and do not try to make it work — reviving it is a design decision for
        // the owner, not a cleanup. If it IS revived: payload.body here is signedOnlyBody's
        // enmime-extracted DISPLAY body, not the canonical octets that were actually signed —
        // pgp_client_read.go's own comment on verifySignedOnlyMessageContent documents that a
        // canonicalization mismatch there is routine and just leaves PGPVerified false rather than
        // erroring. verifyDetached below has no such tolerance: a body that reads identically to a
        // human but differs byte-for-byte from what was signed fails verification outright, and
        // signatureStateFor maps a bound sender plus an unverifiable signature to INVALID — the
        // strongest accusation this app renders. Reviving this path with payload.body as-is would
        // therefore falsely accuse real correspondents of a bad signature on a routine, expected
        // mismatch. It would need the canonical signed octets, not the display body, before it can
        // safely run.
        //
        // The offered key is narrowed to the displayed sender here too. Taking "whichever
        // non-conflicted contact sorts first" would fail verification for a genuine
        // detached-signed message from anyone else — and signatureStateFor maps a bound sender
        // plus an unverifiable signature to INVALID, which tells the user to treat a legitimate
        // correspondent's message as untrusted. Same narrowing rule as the encrypted path above,
        // for the same reason.
```

### `?: PgpDecryptor.verifyDetached(armoredPublicKey = offeredKeys.firstOrNull().orEmpty(), ...)`
```
                // This IS "whichever non-conflicted contact sorts first" — it looks like the exact
                // thing the comment above forbids, but it is not the binding decision: nothing
                // that key id verified against feeds the verdict below. This fallback only exists
                // to produce a non-null RawSignature (present = true, valid = false, some
                // signerKeyId) when every real candidate above failed, so signatureStateFor can
                // still run its own key-id re-match against payload.signerKeys and land on
                // SIGNER_UNKNOWN or INVALID rather than crash on a null. The sender binding is
                // enforced there, not by which key was armored here.
```

## app/src/main/java/org/kysecurity/mail/pgp/EnrollmentCeremony.kt

### `private const val POLL_WINDOW_MS = 5 * 60 * 1_000L`
```
/**
 * How long one polling window lasts.
 *
 * **A background completion is impossible, not merely undesirable:** the re-seal uses a key with
 * `setUserAuthenticationRequired(true)` and per-use auth, so it needs a live `BiometricPrompt`. The
 * ceremony's tail requires the user present and the app foregrounded, which means an unbounded loop
 * would be a screen holding a published key and a spoken-aloud code until the process dies. Five
 * minutes also means the code has rotated at least twice, so the screen has had to refresh it anyway.
 */
```

### `internal class EnrollmentCeremony(`
```
/**
 * The device-enrollment state machine.
 *
 * **No Android imports, and none may be added.** The ceremony has more branches than any existing
 * call site in this app — identity missing, publish rejected, poll timeout, envelope 404, GCM open
 * failure, biometric cancelled, no lock screen, re-seal failure, report failure, user abandons — and
 * every one of them is something the user must be told about. Audit run-6's one unfixable finding
 * was that logic living in an Activity is logic no unit test can reach; splitting this out is what
 * makes each branch above a JVM test.
 *
 * [hostileLocationEnabled] and [hasSecureLockScreen] are lambdas rather than a port, following the
 * `elapsedRealtimeMs: () -> Long = SystemClock::elapsedRealtime` precedent in `AppLockManager`.
 *
 * [onState] rather than an owned `StateFlow`: the ViewModel owns the flow (it is what survives
 * rotation), and a callback lets a JVM test record the full transcript rather than sampling a
 * conflating flow.
 */
```

### `var isIdle: Boolean = true`
```
    /**
     * True whenever no polling window is running — the ceremony is finished, blocked, timed out, or
     * waiting for the user after a cancelled prompt.
     *
     * The Activity offers "Check again" on this, rather than on the state alone: `ShowingCode` means
     * two different things depending on whether a window is still open behind it.
     */
```

### `suspend fun run()`
```
    /**
     * Runs the ceremony from the gate to a terminal state.
     *
     * Every path out of this function is one row of the spec's exit table.
     */
```

### `keyPairLive = true`
```
        //
```

### `suspend fun checkAgain()`
```
    /**
     * Reopens a five-minute window against the **same** keypair.
     *
     * The key is not republished and `newKeyPair()` is not called again: a restart would rotate the
     * key, invalidating the code the user may already have typed into the browser. Leaving the
     * screen and re-entering is the restart, and that path does rotate.
     */
```

### `shownBucket = Long.MIN_VALUE`
```
        // Every window opens on a freshly derived code. [shownBucket] is instance state that
        // survives each exit from the loop below, so without this reset a window reopened after a
        // timeout — or after a cancelled prompt — would find the bucket unchanged, emit nothing, and
        // leave whatever code was last on screen sitting there while the browser has already moved
        // on to the next bucket. A code that outlived its bucket is not an inconvenience: the
        // browser refuses to seal on a mismatch, and a mismatch is this feature's one alarm, so a
        // stale code turns an entirely honest enrollment into the signal reserved for an attack.
        // Re-deriving costs one keystore read against a key that has not changed.
```

### `is EnrollmentCallResult.NotFound, RateLimited, Failed, Ok -> Unit`
```
                // 404 covers "never sealed" and "expired", indistinguishable by design and both
                // meaning keep waiting. A 429 or a dropped connection mid-window is not a reason to
                // tear down a ceremony the user is halfway through typing. `Ok` cannot occur on this
                // route.
```

### `val aad = runCatching { deviceEnvelopeAad(...) }`
```
        // The AAD is built from this device's id and the fingerprint the identity check returned —
        // never from anything in the envelope. deviceEnvelopeAad normalises and validates the
        // fingerprint itself; a throw here is a programming error, not a user condition, but it is
        // caught rather than crashed because the alternative is a crash on a security screen.
```

### `when (withContext(NonCancellable) { sealer.seal(plaintext) })`
```
        // NonCancellable around this one call, not around sealAndReport or openAndSeal: once
        // sealer.seal hands plaintext to a background thread (the Activity's own executor, which
        // this file cannot see and does not control), that thread reads it until doFinal returns.
        // Back, finish(), and the app lock all cancel viewModelScope, and — on
        // Dispatchers.Main.immediate — a cancellation while suspended here would resume inline and
        // unwind straight through openAndSeal's finally, running plaintext.fill(0) on the same
        // array the background thread may still be mid-read on: a blob built from partly-zeroed
        // plaintext would then get stored, and probeEnrollment cannot tell it apart from a real
        // one — Cipher.init on GCM touches no ciphertext — so EnrollmentStateWorker would report
        // encryptionEnrolled = true for a key nothing can open. See
        // SecuritySettingsActivity.SecurityWork for the same fix applied to the same class of bug.
        // The poll loop and report() stay outside this, and stay cancellable.
```

### `plaintext.fill(0)`
```
                // Zeroed here rather than waiting for openAndSeal's outer finally: it is durably
                // sealed by now and has no further reader, and report() is a suspending network
                // round trip that can run to a full timeout. Zeroing again in that finally is
                // harmless — it just covers the failure, cancel and throw paths this branch doesn't
                // take.
```

### `mailCache.clearServerDecryptedBodies()`
```
                // Before report(), which is a network round trip that can run to a full timeout or
                // fail outright. This device has just stopped depending on the server being able to
                // read this account's mail; anything cached that the server decrypted is plaintext
                // the new threat model does not account for, and queueing its removal behind a call
                // that may never succeed would leave it there for the 24 hours until the next full
                // snapshot — the delta path preserves bodies, so deltas never clear it.
```

### `emit(EnrollmentUiState.ReadyToFinish)`
```
                // NOT back to the code. Reaching here means fetchEnvelope already returned one, so
                // the browser has read the code and sealed: re-showing it would instruct a step the
                // user has finished, and would show a value that dies on the next bucket boundary
                // with no window left running to refresh it — a stale code is this feature's one
                // alarm fired at an entirely honest enrollment.
                //
                // The envelope stays on the relay for seven days, so "Check again" picks it straight
                // back up. Re-prompting from inside the poll loop instead would put the dialog back
                // three seconds after the user dismissed it, over and over, for the rest of the
                // window.
```

### `private suspend fun report()`
```
    /**
     * Tells the server this device is enrolled, and stops depending on the answer.
     *
     * A failed report is **not** a failed enrollment: the local seal is real, only the marker is
     * stale, and `EnrollmentStateWorker` re-probes live state and retries. The agreement key is spent
     * either way — its life is one ceremony.
     */
```

### `fun teardown()`
```
    /**
     * Destroys the agreement key, whatever state the ceremony was in.
     *
     * Called from the ViewModel's `onCleared` — the user leaving the screen, the app locking
     * mid-ceremony and the Activity being destroyed all land here. Idempotent: leaving a screen that
     * never minted anything must not report a deletion.
     */
```

## app/src/main/java/org/kysecurity/mail/pgp/EnrollmentClients.kt

### `internal class EnrollmentClients(`
```
/**
 * The three device-authenticated enrollment calls.
 *
 * Endpoints are built from the paired origin, never from a server-supplied URL — the same rule
 * `PgpKeyActivity.renderQr` follows, and for the same reason: a tampered response must not be able
 * to point an authenticated call at another host, outside the TLS pin.
 *
 * JSON goes through kotlinx.serialization, not `org.json`. Under this module's
 * `isReturnDefaultValues = true`, `org.json` resolves to the stubbed `android.jar` in unit tests and
 * every call returns a default — so a client built on it parses nothing, encodes nothing, and its
 * tests still pass. That trap already cost this plan one green-but-empty suite in `DeviceEnvelope`.
 */
```

## app/src/main/java/org/kysecurity/mail/pgp/EnrollmentCodeFormat.kt

### `private val CODE_GROUPS = intArrayOf(4, 3, 4, 3)`
```
/**
 * Group sizes for the displayed code: `5R9K-6FW-A18A-8YP`, not `5R9K6FW-A18A8YP`.
 */
```

### `internal fun formatEnrollmentCode(code: String): String`
```
/**
 * The code as the user reads it aloud.
 *
 * **Safe on the wire:** the browser's `normalizeEnrollmentCode` strips all whitespace and hyphens
 * (`/[\s-]/g`) and applies Crockford's decode rules before comparing, so grouping never reaches the
 * hash. The browser's `formatEnrollmentCode` groups identically; the two must move together.
 */
```

## app/src/main/java/org/kysecurity/mail/pgp/EnrollmentCountdown.kt

### `internal sealed class ExpiryCountdown`
```
/**
 * The countdown line's pure arithmetic, extracted so the wall-clock branch is a JVM test rather
 * than something only visible on a running screen. Kept free of Android imports for exactly that
 * reason — no `Context`, no `Resources`, nothing that needs an emulator to exercise.
 */
```

### `object Now : ExpiryCountdown()`
```
    /** The bucket has rolled, or is close enough that a one-second-granularity countdown cannot
     *  usefully distinguish it from having rolled. Covers the case a cancelled biometric prompt
     *  returns to a code whose expiry is already in the past: all of it renders "about to change"
     *  rather than a stale countdown or a negative number. */
```

### `internal fun expiryCountdown(expiresAtEpochMs: Long, nowMs: Long): ExpiryCountdown`
```
/**
 * [nowMs] is a parameter rather than `System.currentTimeMillis()` read internally, so this is a
 * pure function a JVM test can drive directly.
 *
 * Integer division truncates toward zero, so a remainder under one second already reads as [Now]
 * up to 999ms before the bucket actually rolls. That is not a new source of error — the countdown
 * only ever had one-second granularity to begin with — but it is why "exactly 0" is one of this
 * function's required test cases rather than an incidental one.
 */
```

## app/src/main/java/org/kysecurity/mail/pgp/EnrollmentKeyStore.kt

### `internal object EnrollmentKeyStore`
```
/**
 * This device's enrollment keypair: EC P-256, `PURPOSE_AGREE_KEY`, private half non-extractable.
 *
 * **No user-authentication requirement, deliberately.** This key only ever opens the server's
 * 7-day transport copy of the envelope, during a foreground ceremony with the user present.
 * Gating it would add a prompt that protects nothing durable — the durable protection is
 * [EnrollmentVault]'s re-seal key, which does carry the requirement. Conflating the two would
 * force the weaker requirement onto the key that matters.
 */
```

### `fun newKeyPair(): Boolean`
```
    /**
     * Mints a **fresh** keypair for one ceremony, destroying any previous one.
     *
     * - It contradicted the justification for this key carrying no authentication requirement. The
     *   claim is that it "only ever opens the server's transport copy, during a foreground ceremony
     *   with the user present" — but a key that outlives every ceremony is a standing, unauthenticated
     *   path to every envelope the relay has ever retained, which defeats [EnrollmentVault]'s
     *   per-use authentication via a parallel route. An attacker with the relay database and code
     *   execution under this app's UID could open the envelope with no prompt of any kind.
     * - It gave an attacker unbounded lead time to precompute against a known, stable public key,
     *   which is what makes grinding the enrollment code affordable at all.
     *
     * The design already publishes the public half at the start of *every* ceremony rather than once
     * at pairing, so rotating here costs nothing. Call [deleteKeyPair] on both the success and the
     * failure exit of a ceremony so the window is one ceremony, not one install.
     */
```

### `sec1UncompressedPoint(w.affineX, w.affineY)`
```
        // Encoding lives in Sec1Point.kt, pure and Android-free, so both padding branches are
        // unit-testable. A generated-key test here can only ever assert the overall length.
```

### `fun sharedSecret(epk: ByteArray): ByteArray?`
```
    /**
     * ECDH against the sender's ephemeral public key.
     *
     * **Validates the point before agreeing on it.** `parseDeviceEnvelope` checks that the blob is
     * 65 bytes starting `0x04`, which is a length-and-prefix check and says nothing about whether
     * (x, y) satisfies the curve equation. Feeding an off-curve point to ECDH is the precondition
     * for an invalid-curve attack, which recovers the private key from the residues of repeated
     * agreements — and the only thing standing in the way was whatever `KeyFactory` provider
     * happened to resolve at runtime, on a codebase that elsewhere refuses to depend on exactly
     * that (see [PgpDecryptor]'s note on Android's stripped-down BC provider).
     *
     * Per-ceremony key rotation ([newKeyPair]) already bounds the query budget. This makes the
     * defence something this file states and `EnrollmentKeyStoreTest` can assert, rather than
     * something a dependency might be doing.
     */
```

### `internal fun isOnCurve(point: ECPoint, params: ECParameterSpec): Boolean`
```
    /**
     * Whether [point] satisfies `y² = x³ + ax + b (mod p)` and lies in the field.
     *
     * The point at infinity is excluded by construction: it has no affine encoding, so a 65-byte
     * `0x04`-prefixed blob can never represent it. P-256 has prime order, so there is no small
     * subgroup to check for beyond this.
     */
```

### `fun deleteKeyPair(): Boolean`
```
    /**
     * Deletes the agreement keypair, reporting whether it is actually gone.
     *
     * The boolean is not decoration: [EnrollmentTeardown] feeds it to a `SecurityWipe.step(...)`,
     * and `step` records a failure only when its body signals one. Swallowing the outcome here —
     * as a bare `runCatching {}` did — would let a surviving key be reported as a completed wipe,
     * the same defect the audit fixed in [EnrollmentVault.destroy].
     */
```

## app/src/main/java/org/kysecurity/mail/pgp/EnrollmentPorts.kt

### `internal sealed class IdentityCheck`
```
/**
 * What the account's PGP identity is, as far as this device can tell.
 *
 * [CouldNotCheck] is a distinct case from [NoIdentity] on purpose — see [UnavailableReason].
 */
```

### `internal interface EnrollmentTransport`
```
/**
 * The three device-authenticated enrollment calls plus the durable fallback, with the pairing
 * resolved inside rather than threaded through the state machine.
 *
 * The real implementation **must** be built on `pinnedPairingCallFactory`. Every call here carries
 * the device bearer credential.
 */
```

### `internal interface EnrollmentKeys`
```
/**
 * The device's enrollment agreement keypair.
 *
 * A port rather than a direct call into [EnrollmentKeyStore] because "`deleteKeyPair()` on every
 * exit" is the property this design most needs a test for, and a Keystore object cannot be observed
 * from a JVM test.
 */
```

### `internal interface VaultSealer`
```
/**
 * The re-seal, requested through an interface because the orchestrator cannot call `BiometricPrompt`
 * — it is Activity-bound. This is the seam that keeps the state machine testable: "biometric
 * cancelled" is a JVM test with a fake rather than an instrumented one.
 */
```

### `internal interface DecryptedMailCache`
```
/**
 * The locally cached plaintext of mail the server decrypted.
 *
 * A port rather than a direct DAO call because [EnrollmentCeremony] has no Android imports and must
 * keep none — see its KDoc. This is the seam that makes "enrolling clears the old plaintext" a JVM
 * test instead of an instrumented one.
 *
 * **Why the ceremony owns this.** Enrolling is the moment this device stops depending on the server
 * being able to read the account's mail. Everything cached before it that the server decrypted is
 * plaintext the new threat model does not account for, and nothing else would remove it until the
 * next full snapshot — up to 24 hours later, because the delta path deliberately preserves bodies
 * (`reconcileFetchResult` merges "updated" entries over the existing body).
 */
```

### `internal interface EnrollmentClock`
```
/**
 * Time, and waiting.
 *
 * Two clocks because the two uses need different guarantees. [epochSeconds] is wall clock: the
 * 120-second bucket must agree with the browser's, so it has to be the same timebase. It is
 * therefore subject to the user changing the date, which costs a code mismatch and nothing worse.
 * [elapsedRealtimeMs] is monotonic, for the poll deadline, following the `elapsedRealtime` precedent
 * in `AppLockManager` and `AppLockStore` — a wall-clock deadline can be skipped past or never
 * reached at all.
 */
```

## app/src/main/java/org/kysecurity/mail/pgp/EnrollmentPortsAndroid.kt

### `internal class AndroidIdentitySource(context: Context) : IdentitySource`
```
/**
 * The identity check, from **one** `GET /api/pgp/bootstrap`.
 *
 * Bootstrap answers all three questions this port is defined by — is there an identity, is it
 * client-protected, and what is its fingerprint — so `hasPgpIdentity` is not called as well. A second
 * request could only ever agree or disagree with the first, and a disagreement has no resolution.
 *
 * The fingerprint is **hashed from the key bytes** by [ownFingerprintFromBootstrap], never read off
 * the response's own `fingerprint` field: that field is a claim sitting beside `publicKey` with no
 * cryptographic tie to it, and this value is about to be bound into an envelope's AAD.
 */
```

### `override suspend fun check(): IdentityCheck = withContext(Dispatchers.IO)`
```
    // withContext(IO) covers the whole body, not just the fetch: pairingForAuthenticatedCall() is
    // roughly eight EncryptedSharedPreferences decrypts plus a CredentialCipher.unwrap, and on the
    // first call it also forces the lazy EncryptedSharedPreferences/Tink construction and a MasterKey
    // Keystore round trip. The ceremony runs on viewModelScope's Dispatchers.Main.immediate, so
    // without this that lands on the UI thread. PgpBootstrapClient.fetch nests its own
    // withContext(IO), which costs nothing when we are already there. See SecuritySettingsActivity,
    // where the same call was wrapped for the same reason.
```

### `internal fun identityCheckFrom(result: PgpBootstrapResult): IdentityCheck`
```
/**
 * The pure "degrade, never guess" mapping from one bootstrap response to an [IdentityCheck].
 *
 * Pulled out of [AndroidIdentitySource.check] so the rule is testable on the JVM, without a network
 * fetch or a device — [pgpComposeStateOf] is a standalone pure function for exactly this reason, and
 * its own KDoc says why: "the rule is testable without instrumentation." A future edit that collapses
 * the `else` branch, or lets an unrecognised `protection` fall through to [IdentityCheck.ClientProtected],
 * must fail a test here rather than only being reachable through a real network round trip.
 */
```

### `internal class AndroidEnrollmentTransport(context: Context) : EnrollmentTransport`
```
/**
 * The three enrollment calls, with the pairing resolved per call rather than captured.
 *
 * Read at call time and never cached: the credential gate can drop the cached key when the app locks
 * mid-ceremony, and a captured secret would keep working from a state the user has left.
 */
```

### `private val clients = EnrollmentClients(callFactory = pinnedPairingCallFactory(appContext))`
```
    // callFactory has no default on EnrollmentClients precisely so this cannot be forgotten; see
    // d410827. The bare default was unpinned, on the one request carrying the device credential.
```

### `private fun pairing()`
```
    /**
     * Blocking, and never to be called from the main thread: one call is roughly eight
     * `EncryptedSharedPreferences` decrypts plus a `CredentialCipher.unwrap`, and the first one also
     * forces the lazy `EncryptedSharedPreferences`/Tink construction and a MasterKey Keystore round
     * trip. Every method below therefore opens with `withContext(Dispatchers.IO)` — the port is the
     * Android edge, and it is where this belongs.
     *
     * Wrapping only the client call underneath would not have been enough: the client switches to IO
     * *after* this has already run, so on the ceremony's `Dispatchers.Main.immediate` this landed on
     * the UI thread — from [fetchEnvelope] roughly a hundred times per five-minute window, on a
     * screen that also holds `FLAG_KEEP_SCREEN_ON` and runs a 1 Hz countdown. The clients' own
     * nested `withContext(IO)` costs nothing once we are already on IO.
     */
```

### `internal fun hasSecureLockScreen(context: Context): Boolean`
```
/**
 * Whether this device has a PIN, pattern or password.
 *
 * `KeyguardManager.isDeviceSecure` and **not** `EnrollmentVault.ensureKey()`, even though the vault
 * is the authority. `ensureKey()` mutates: on a key that no longer matches the spec it regenerates,
 * and generation clears the stored blob in the same breath. Using it as a read-only probe would mean
 * opening the ceremony screen could destroy an existing enrollment. The vault still has the final
 * word at the seal, where a mutation is expected.
 */
```

### `internal object SystemEnrollmentClock : EnrollmentClock`
```
/**
 * Wall clock for the bucket, monotonic for the deadline.
 *
 * `elapsedRealtime` for the deadline follows `AppLockManager` and `AppLockStore`, whose own comments
 * explain the choice: a wall-clock deadline can be stepped over or never reached when the user or
 * the network changes the date.
 */
```

### `internal class RoomDecryptedMailCache(private val appContext: Context) : DecryptedMailCache`
```
/**
 * [DecryptedMailCache] over Room.
 *
 * `withContext(Dispatchers.IO)` for the same reason every method in [AndroidEnrollmentTransport]
 * opens with it: the ceremony runs on `viewModelScope`'s `Dispatchers.Main.immediate`, so an
 * unwrapped DAO write would land a disk write on the main thread. `DataRuntime.graph` is resolved
 * inside the same block rather than in the constructor — building the graph opens the database, and
 * during a wipe that would rebuild the very database being destroyed. See `PushRepository`, which
 * documents the same hazard.
 */
```

## app/src/main/java/org/kysecurity/mail/pgp/EnrollmentRow.kt

### `internal sealed class EnrollmentRow`
```
/**
 * What the Security page's encrypted-mail row says, and what it offers.
 *
 * A type rather than a string so the decision is testable and the copy lives with the screen.
 */
```

### `internal fun enrollmentRowFor(...)`
```
/**
 * Decides the row.
 *
 * **Local facts before network facts.** The spec's row table lists `Enrolled` and `KEY_INVALIDATED`
 * last, after the identity branch. Ordered that way, a device with no connectivity renders as
 * "couldn't check your account" — which hides the one row whose entire job is to tell the user this
 * device can no longer open their mail, and hides "Remove from this device", a local security action
 * that must not require a working network. Both are facts about this device's own Keystore, so they
 * are answered from the Keystore first.
 *
 * Hostile Location Protection and the lock screen come before both, because under either of them the
 * `ENROLLED` probe is either a contradiction or impossible.
 */
```

## app/src/main/java/org/kysecurity/mail/pgp/EnrollmentSession.kt

### `internal object EnrollmentSession : ProcessScopedState`
```
/**
 * Holds the opened PGP private key for one unlock session.
 *
 * The plaintext lifetime is the real exposure, not how often BiometricPrompt appears — so it is
 * bound to the window the user already configured at "Lock after: …" rather than to a second
 * concept of its own.
 *
 * Held as a CharArray so [clear] can zero it. A String's backing array cannot be wiped, so one
 * would survive in the heap until GC and beyond, in a dump taken after the app locked.
 *
 * Registered with [ProcessState] as well, because the app lock is not the only session boundary.
 * A security wipe, `AppRestart.relaunch` and the unpair purge all reset through
 * [ProcessState.resetAll], and none of them calls `lockNow()`. Unregistered, this holder was not
 * merely missed by them — `resetAll()` reported no failure, so the wipe announced Complete with the
 * account's private key still in the heap of a process the relaunch deliberately does not kill.
 * That is the exact omission [ProcessScopedState]'s own KDoc says the registry exists to prevent.
 */
```

### `fun putUtf8(plaintext: ByteArray)`
```
    /**
     * Decodes UTF-8 [plaintext] straight into the held [CharArray], without ever building a
     * `String`.
     */
```

### `fun <T> withKey(block: (CharArray) -> T): T?`
```
    /**
     * Runs [block] against the held key, or returns null if none is held.
     *
     * **Scoped, and a [CharArray], because the whole point of this class is a key that can be
     * zeroed.** The accessor this replaces was `fun peek(): String? = held?.let { String(it) }` —
     * it minted a fresh, immutable, unwipeable copy of the OpenPGP private key on every call, and
     * its two callers are the read path and the send path, so ordinary use accumulated copies in
     * the heap that [clear] could not touch. The KDoc on [isHeld] named that exact hazard one line
     * above the method that committed it.
     *
     * The array handed to [block] is the live one. Do not retain it and do not mutate it; the PGP
     * entry points take `CharArray` precisely so nothing has to.
     */
```

## app/src/main/java/org/kysecurity/mail/pgp/EnrollmentState.kt

### `internal fun probeEnrollment(vault: EnrollmentVault): EnrollmentStatus`
```
/**
 * Whether this device can still open its local envelope — reported to the server as
 * `encryptionEnrolled`, and rendered by the browser as "this device can read your encrypted mail".
 *
 * Probes the **keystore**, not our own bookkeeping. A cached boolean would survive an app reinstall
 * or a biometric-enrollment change, both of which destroy the key without any code of ours running,
 * and the Security page would then tell the user a device can read their mail when it can read
 * nothing.
 *
 * Uses `Cipher.init`, which needs no user authentication: this runs from a background worker where
 * nothing can show a prompt. A key that is merely locked initialises fine; only a permanently
 * invalidated one throws.
 */
```

### `val stored = vault.stored()`
```
        // Inside the try: vault.stored() forces the lazy EncryptedSharedPreferences, and this
        // function's whole contract is that it reports rather than throws. It runs from a background
        // worker where a throw means the marker is never restated and freezes at its last value —
        // and a stale `true` is the specific lie the marker exists to prevent.
```

## app/src/main/java/org/kysecurity/mail/pgp/EnrollmentStateWorker.kt

### `internal const val MAX_REPORT_ATTEMPTS = 8`
```
/**
 * How many times a report may be retried before it is abandoned.
 *
 * WorkManager imposes no ceiling of its own — it only clamps the exponential backoff at five hours —
 * so a RETRY with no bound is a work item that never terminates. With the 30-second base delay this
 * spans roughly a day and a half of real attempts, which is generous for "the network came back"
 * and finite for "this relay is never answering again".
 */
```

### `internal fun enrollmentReportOutcome(...)`
```
/**
 * Whether a failed report is worth another attempt.
 *
 * Retry is the answer whenever the server's marker is wrong in the *unsafe* direction — the
 * Security page telling the user this device can read their mail after the envelope is gone. Give
 * up only where another attempt cannot change the answer: a credential the server refuses will not
 * start working, a device row that is gone will not come back, and past [MAX_REPORT_ATTEMPTS] the
 * evidence is that nothing is going to.
 */
```

### `internal class EnrollmentStateWorker(`
```
/**
 * Reports enrollment state durably.
 *
 * Enqueued before Hostile Location Protection's flag flips, so an interrupted teardown still
 * corrects the server: the Security page would otherwise show this device as protected in the
 * window between, which is the specific lie the marker exists to prevent. Offline is the expected
 * case — the user just declared they are somewhere hostile — so this retries rather than dropping.
 */
```

### `val pairing = PushRuntime.graph(...).repository.pairingForAuthenticatedCall()`
```
        //
```

### `return Result.success()`
```
            // Gated and currently locked, so the secret cannot be unwrapped in this run. Retrying
            // cannot help — only a PIN unlock can, and the unlock path re-enqueues us (see
            // UnlockActivity). Succeeding here releases the work slot instead of occupying it with
            // a job that can never make progress.
```

### `val clients = EnrollmentClients(callFactory = pinnedPairingCallFactory(applicationContext))`
```
        // The pinned factory, exactly as every other client that carries the device credential does.
        // The bare default was unpinned, which made this the only credentialed request in the app
        // outside the TOFU pin — and the only thing that triggers it is the user declaring the
        // network hostile, which is the worst possible moment to be trusting the system CA set.
```

## app/src/main/java/org/kysecurity/mail/pgp/EnrollmentTeardown.kt

### `internal object EnrollmentTeardown`
```
/**
 * Destroys everything that makes this device able to open its envelope.
 *
 * Two callers, both of which must survive interruption:
 *  - Enabling Hostile Location Protection. An envelope that survived that switch would leave the
 *    account's private key openable by device unlock on a device whose owner has just declared
 *    they are somewhere hostile — the exact disclosure the mode exists to prevent.
 *  - SecurityWipe, reached by too many wrong PIN attempts. A key surviving that would outlive a
 *    wipe nobody chose.
 *
 * The vault goes first. If the process dies between the two, what survives is the agreement key,
 * which opens only the relay's transport copy; the reverse order would leave the durable sealed
 * blob — the thing actually worth protecting — behind.
 */
```

### `fun destroyAndReport(context: Context): List<String>`
```
    /**
     * [destroy] plus the correction to the server, for the user-initiated "Remove from this device".
     *
     * `SecuritySettingsActivity.tearDownEnrollmentForHostileLocation` performs the same two steps
     * for the protection toggle. It is deliberately left alone rather than routed through here: it
     * is driven by an instrumented test that exists to keep the toggle and the teardown in step, and
     * a refactor of that path buys nothing this function needs.
     */
```

## app/src/main/java/org/kysecurity/mail/pgp/EnrollmentUiState.kt

### `internal enum class UnavailableReason`
```
/**
 * Why enrollment cannot be started at all. Distinct from [FailureReason]: nothing has been minted
 * or published yet, so there is nothing to clean up and nothing went wrong — the device is simply
 * not in a position to hold a key.
 */
```

### `COULD_NOT_CHECK,`
```
    /**
     * The identity check could not be answered — not paired for the purposes of an authenticated
     * call, a network failure, a server error.
     *
     * **"Could not check" is not "no."** The copy for this must never read as "your account doesn't
     * use encrypted mail": a user told that will go and create a second identity.
     */
```

### `internal enum class FailureReason`
```
/**
 * Why a started ceremony ended badly. A closed set, deliberately: the browser half enforces the same
 * rule so that an adversarial server's error string cannot select the alarming copy, and Android
 * matches. No server text is ever rendered from these.
 */
```

### `COULD_NOT_OPEN,`
```
    /**
     * GCM authentication failed.
     *
     * The only point at which the phone can detect the attack the ceremony exists to prevent, and
     * the only failure that gets its own copy. That copy **describes rather than accuses**: an
     * identity rotation mid-ceremony is indistinguishable by construction from a hostile
     * substitution, because both produce exactly this. Never a retry — the AAD binds device and
     * identity, so a failure means the envelope was sealed for someone else or under an identity the
     * account no longer advertises.
     */
```

### `NO_DEVICE_KEY,`
```
    /**
     * The Keystore would not mint or return the agreement keypair.
     *
     * Not in the spec's exit table, and not foldable into [PUBLISH_REJECTED]: nothing was published,
     * so telling the user their server refused the key would be false. `EnrollmentKeyStore` already
     * falls back from StrongBox to the TEE, so reaching this means neither worked.
     */
```

### `internal sealed class EnrollmentUiState`
```
/**
 * Every state the ceremony screen can be in.
 *
 * `Reporting` is deliberately absent. A failed report still means enrolled, so surfacing it as a
 * state would offer the user a distinction they must not act on.
 */
```

### `data class WaitingTimedOut(val code: String, val expiresAtEpochMs: Long)`
```
    /**
     * The five-minute polling window closed with no envelope.
     *
     * Carries the code because "Check again" **resumes rather than restarts**: it reopens a fresh
     * window against the same keypair, so the code on screen stays valid and the user does not have
     * to re-read it. This is the one exit that keeps the keypair.
     */
```

### `object ReadyToFinish : EnrollmentUiState()`
```
    /**
     * The prompt was dismissed with the envelope already in hand.
     *
     * Carries **no code, deliberately.** This state is only reachable after `fetchEnvelope` returned
     * one, which means the browser has already read the code and sealed — so re-showing it would
     * instruct a step the user has already completed, and would do it with a value that goes stale
     * on the next 120-second boundary with no window left running to refresh it. What is actually
     * outstanding is the fingerprint, and "Check again" is what asks for it: the envelope sits on the
     * relay for seven days, so resuming picks it straight back up.
     */
```

### `internal fun offersCheckAgain(state: EnrollmentUiState, idle: Boolean): Boolean`
```
/**
 * Whether the screen should offer "Check again".
 *
 * Pure, and tested on the JVM, because it is the only way forward from every state that stops with
 * the keypair still live. Omit a state that needs it and the user is stranded: the screen's only
 * other exit is Close, which tears the ceremony down and destroys the published key, turning a
 * dismissed fingerprint prompt into a full restart.
 *
 * Takes [idle] rather than reading the state alone because `ShowingCode` means two different things
 * depending on whether a polling window is still open behind it — see [EnrollmentCeremony.isIdle].
 */
```

## app/src/main/java/org/kysecurity/mail/pgp/EnrollmentVault.kt

### `internal class EnrollmentVault(context: Context)`
```
/**
 * The durable half: an AES-256-GCM Keystore key that requires the device lock screen, and the
 * envelope re-sealed under it.
 *
 * The allowed authenticators include `DEVICE_CREDENTIAL` on purpose, so the key **survives a
 * biometric enrollment change**. Biometric-only would invalidate it whenever a fingerprint is
 * added, costing every ordinary user a full re-enrollment ceremony; and enrolling a biometric
 * already requires the device credential, so the attacker it would exclude already holds what this
 * key accepts. It also keeps `encryptionEnrolled` from flapping false for benign reasons — a marker
 * that cries wolf is one users learn to dismiss.
 *
 * The strict posture is not a switch here. It is Hostile Location Protection, under which there is
 * no envelope at all.
 */
```

### `fun ensureKey(): Boolean`
```
    /**
     * False when the device has no secure lock screen. That is the honest outcome: the envelope's
     * protection *is* the lock screen, so a device without one cannot hold a meaningful one.
     */
```

### `private fun generate(strongBox: Boolean): Boolean`
```
    /**
     * Generates the vault key, and **clears any stored blob in the same breath**.
     *
     * A newly minted key can never open an envelope sealed under a previous one, so retaining the
     * blob across a regeneration is never correct — and it is actively harmful, because
     * [probeEnrollment] establishes only that *a* key exists and that *a* blob exists. `Cipher.init`
     * on GCM touches no ciphertext, so it succeeds against the wrong key, and the probe then reports
     * ENROLLED for a blob nothing in the world can decrypt. The server renders that to the user as
     * "this device can read your encrypted mail", which is the exact lie the marker exists to
     * prevent, and it is the unsafe direction: a user may decommission the device that actually
     * holds a working copy.
     *
     * Reachable whenever the OS destroys the key without any of our code running — the user removing
     * and re-adding the device lock screen is enough.
     */
```

### `prefs.edit().clear().commit()`
```
        // Before anything else: a blob sealed under a previous key is unopenable by the key we are
        // about to mint, and keeping it makes probeEnrollment report ENROLLED for a device that can
        // decrypt nothing. Clear it first so an interruption between here and generateKey leaves
        // "no key, no blob" rather than "new key, stale blob".
```

### `fun destroy(): List<String>`
```
    /**
     * Destroys the sealed blob and the vault key, and **reports what it could not destroy**.
     *
     * Its own prefs file, not `SecurePairingStore`'s, so this is a file delete plus one alias
     * removal — with no risk of clearing pairing state that Hostile Location Protection explicitly
     * preserves.
     */
```

### `private fun buildPrefs(): SharedPreferences`
```
    /**
     * Builds the encrypted store, resetting it if the Tink keyset can no longer be decrypted.
     *
     * `androidx.security-crypto` is deprecated precisely because `EncryptedSharedPreferences.create`
     * throws on an unreadable keyset — an OS-level key invalidation, a restored backup. Both siblings
     * in this codebase already handle it this way and say why: `SecurePairingStore.buildEncryptedPrefs`
     * and `AppLockStore.buildEncryptedPrefs`, the latter noting "an uncaught failure here crashes the
     * app on every launch". This store had none of it, so the one event the enrollment marker is
     * probed rather than cached *for* — the key going away without our code running — made the probe
     * throw instead of reporting.
     *
     * Failing closed is right here: a lost blob reads as "not enrolled", which is the safe direction.
     */
```
