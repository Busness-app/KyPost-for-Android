package com.urlxl.mail.pgp

import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.withContext

/** The code's validity window, and the browser's. `deviceEnrollmentCode`'s bucket is
 *  `unixSeconds / 120`; changing this alone strands every honest enrollment. */
private const val BUCKET_SECONDS = 120L

/** How often the phone asks whether the browser has sealed yet. There is no browser-to-device
 *  channel — the publish step is device-to-server POST only — so polling is the only discovery
 *  mechanism this protocol has. */
private const val POLL_INTERVAL_MS = 3_000L

/**
 * How long one polling window lasts.
 *
 * **A background completion is impossible, not merely undesirable:** the re-seal uses a key with
 * `setUserAuthenticationRequired(true)` and per-use auth, so it needs a live `BiometricPrompt`. The
 * ceremony's tail requires the user present and the app foregrounded, which means an unbounded loop
 * would be a screen holding a published key and a spoken-aloud code until the process dies. Five
 * minutes also means the code has rotated at least twice, so the screen has had to refresh it anyway.
 */
private const val POLL_WINDOW_MS = 5 * 60 * 1_000L

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
internal class EnrollmentCeremony(
    private val identity: IdentitySource,
    private val transport: EnrollmentTransport,
    private val keys: EnrollmentKeys,
    private val sealer: VaultSealer,
    private val clock: EnrollmentClock,
    private val hostileLocationEnabled: () -> Boolean,
    private val hasSecureLockScreen: () -> Boolean,
    private val onState: (EnrollmentUiState) -> Unit,
) {

    private var deviceId: String? = null
    private var fingerprint: String? = null

    /** Set once a keypair exists, so [teardown] knows whether there is anything to destroy and
     *  cannot report a deletion it never performed. */
    private var keyPairLive = false

    private fun emit(state: EnrollmentUiState) = onState(state)

    /**
     * True whenever no polling window is running — the ceremony is finished, blocked, timed out, or
     * waiting for the user after a cancelled prompt.
     *
     * The Activity offers "Check again" on this, rather than on the state alone: `ShowingCode` means
     * two different things depending on whether a window is still open behind it.
     */
    var isIdle: Boolean = true
        private set

    /**
     * Runs the ceremony from the gate to a terminal state.
     *
     * Every path out of this function is one row of the spec's exit table.
     */
    suspend fun run() {
        isIdle = false
        try {
            runInner()
        } finally {
            isIdle = true
        }
    }

    private suspend fun runInner() {
        emit(EnrollmentUiState.CheckingIdentity)

        // Local declarations first, and in this order. Hostile Location Protection means the user
        // has just said this network is hostile, so answering it must not require a request to a
        // server on that network.
        if (hostileLocationEnabled()) {
            emit(EnrollmentUiState.Unavailable(UnavailableReason.HOSTILE_LOCATION))
            return
        }
        if (!hasSecureLockScreen()) {
            emit(EnrollmentUiState.Unavailable(UnavailableReason.NO_SECURE_LOCK_SCREEN))
            return
        }

        val id = transport.deviceId()
        if (id.isNullOrBlank()) {
            emit(EnrollmentUiState.Unavailable(UnavailableReason.NOT_PAIRED))
            return
        }
        deviceId = id

        when (val check = identity.check()) {
            is IdentityCheck.ClientProtected -> fingerprint = check.fingerprint
            IdentityCheck.ServerHeld -> {
                emit(EnrollmentUiState.Unavailable(UnavailableReason.SERVER_HELD_KEY))
                return
            }
            IdentityCheck.NoIdentity -> {
                emit(EnrollmentUiState.Unavailable(UnavailableReason.NO_IDENTITY))
                return
            }
            IdentityCheck.CouldNotCheck -> {
                emit(EnrollmentUiState.Unavailable(UnavailableReason.COULD_NOT_CHECK))
                return
            }
        }

        publishAndPoll()
    }

    /** The code currently on screen, so [checkAgain] can resume without re-deriving from a bucket
     *  that has since moved — and so [EnrollmentUiState.WaitingTimedOut] can carry it. */
    private var shownCode: String = ""
    private var shownExpiresAtEpochMs: Long = 0L
    private var shownBucket: Long = Long.MIN_VALUE

    private suspend fun publishAndPoll() {
        emit(EnrollmentUiState.PublishingKey)

        // Mints a FRESH keypair, destroying any previous one. A key that outlives a ceremony is a
        // standing unauthenticated path to every envelope the relay has retained.
        //
        // Marked live BEFORE the check, not after. `newKeyPair()` deletes the previous key and then
        // generates — attempting StrongBox first and falling back to the TEE — so a `false` can
        // still leave something behind. Treating a failed mint as "nothing was created" is how a
        // half-generated key survives a ceremony.
        keyPairLive = true
        if (!keys.newKeyPair()) {
            failAndDestroy(FailureReason.NO_DEVICE_KEY)
            return
        }

        val encoded = keys.encodedPublicKey()
        if (encoded == null) {
            failAndDestroy(FailureReason.NO_DEVICE_KEY)
            return
        }

        when (transport.publishKey(encoded)) {
            is EnrollmentCallResult.Ok -> Unit
            is EnrollmentCallResult.Unauthorized -> return failAndDestroy(FailureReason.UNAUTHORIZED)
            is EnrollmentCallResult.RateLimited -> return failAndDestroy(FailureReason.RATE_LIMITED)
            // NotFound (the device row is gone), Failed, and an Envelope this route cannot send.
            // None is retryable, and all leave a minted key that must not survive.
            is EnrollmentCallResult.NotFound,
            is EnrollmentCallResult.Failed,
            is EnrollmentCallResult.Envelope,
            -> return failAndDestroy(FailureReason.PUBLISH_REJECTED)
        }

        poll()
    }

    /**
     * Reopens a five-minute window against the **same** keypair.
     *
     * The key is not republished and `newKeyPair()` is not called again: a restart would rotate the
     * key, invalidating the code the user may already have typed into the browser. Leaving the
     * screen and re-entering is the restart, and that path does rotate.
     */
    suspend fun checkAgain() {
        if (!keyPairLive) return
        isIdle = false
        try {
            poll()
        } finally {
            isIdle = true
        }
    }

    private suspend fun poll() {
        // Every window opens on a freshly derived code. [shownBucket] is instance state that
        // survives each exit from the loop below, so without this reset a window reopened after a
        // timeout — or after a cancelled prompt — would find the bucket unchanged, emit nothing, and
        // leave whatever code was last on screen sitting there while the browser has already moved
        // on to the next bucket. A code that outlived its bucket is not an inconvenience: the
        // browser refuses to seal on a mismatch, and a mismatch is this feature's one alarm, so a
        // stale code turns an entirely honest enrollment into the signal reserved for an attack.
        // Re-deriving costs one keystore read against a key that has not changed.
        shownBucket = Long.MIN_VALUE

        val deadline = clock.elapsedRealtimeMs() + POLL_WINDOW_MS

        while (clock.elapsedRealtimeMs() < deadline) {
            val bucket = clock.epochSeconds() / BUCKET_SECONDS
            if (bucket != shownBucket) {
                // Re-read from the keystore on every recomputation rather than caching the point.
                // The code must describe the key material actually in hand.
                val raw = keys.rawPublicKey()
                if (raw == null) {
                    failAndDestroy(FailureReason.NO_DEVICE_KEY)
                    return
                }
                shownBucket = bucket
                shownCode = deviceEnrollmentCode(raw, requireNotNull(deviceId), bucket)
                shownExpiresAtEpochMs = (bucket + 1) * BUCKET_SECONDS * 1_000L
                emit(EnrollmentUiState.ShowingCode(shownCode, shownExpiresAtEpochMs))
            }

            when (val result = transport.fetchEnvelope()) {
                is EnrollmentCallResult.Envelope -> {
                    openAndSeal(result.envelope)
                    return
                }
                // 401 is the one polling answer that cannot improve: the credential this device
                // holds is not accepted, and no amount of waiting changes that.
                is EnrollmentCallResult.Unauthorized -> return failAndDestroy(FailureReason.UNAUTHORIZED)
                // 404 covers "never sealed" and "expired", indistinguishable by design and both
                // meaning keep waiting. A 429 or a dropped connection mid-window is not a reason to
                // tear down a ceremony the user is halfway through typing. `Ok` cannot occur on this
                // route.
                is EnrollmentCallResult.NotFound,
                is EnrollmentCallResult.RateLimited,
                is EnrollmentCallResult.Failed,
                is EnrollmentCallResult.Ok,
                -> Unit
            }

            clock.sleep(POLL_INTERVAL_MS)
        }

        // The one exit that KEEPS the keypair — "Check again" resumes against it.
        emit(EnrollmentUiState.WaitingTimedOut(shownCode, shownExpiresAtEpochMs))
    }

    private fun failAndDestroy(reason: FailureReason) {
        teardown()
        emit(EnrollmentUiState.Failed(reason))
    }

    private suspend fun openAndSeal(envelopeJson: String) {
        emit(EnrollmentUiState.Opening)

        val fields = parseDeviceEnvelope(envelopeJson)
        if (fields == null) {
            failAndDestroy(FailureReason.ENVELOPE_MALFORMED)
            return
        }

        // The AAD is built from this device's id and the fingerprint the identity check returned —
        // never from anything in the envelope. deviceEnvelopeAad normalises and validates the
        // fingerprint itself; a throw here is a programming error, not a user condition, but it is
        // caught rather than crashed because the alternative is a crash on a security screen.
        val aad = runCatching {
            deviceEnvelopeAad(requireNotNull(deviceId), requireNotNull(fingerprint))
        }.getOrNull()
        if (aad == null) {
            failAndDestroy(FailureReason.ENVELOPE_MALFORMED)
            return
        }

        val ownPoint = keys.rawPublicKey()
        if (ownPoint == null) {
            failAndDestroy(FailureReason.NO_DEVICE_KEY)
            return
        }

        val sharedSecret = keys.sharedSecret(fields.epk)
        if (sharedSecret == null) {
            // The ECDH itself failed — a malformed peer point that got past the parse, or a key the
            // Keystore will no longer agree with. Indistinguishable from a hostile envelope from
            // here, and treated the same: no retry.
            failAndDestroy(FailureReason.COULD_NOT_OPEN)
            return
        }

        val plaintext = try {
            // ownPoint is the HKDF salt — this device's own point, not the ephemeral one in the
            // envelope.
            openDeviceEnvelope(sharedSecret, ownPoint, fields, aad)
        } finally {
            sharedSecret.fill(0)
        }
        if (plaintext == null) {
            failAndDestroy(FailureReason.COULD_NOT_OPEN)
            return
        }

        try {
            sealAndReport(plaintext)
        } finally {
            // The armored private key, zeroed in place on every path out — including the throw the
            // sealer is not supposed to produce. It never enters EnrollmentSession: that holder has
            // no reader until the deferred decryption work lands.
            plaintext.fill(0)
        }
    }

    private suspend fun sealAndReport(plaintext: ByteArray) {
        emit(EnrollmentUiState.AwaitingAuth)

        // Re-checked here as well as at the gate: the user can remove the lock screen between the
        // two, and EnrollmentVault.ensureKey() would then fail behind a prompt that never appears.
        if (!hasSecureLockScreen()) {
            failAndDestroy(FailureReason.NO_SECURE_LOCK_SCREEN)
            return
        }

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
        when (withContext(NonCancellable) { sealer.seal(plaintext) }) {
            is SealOutcome.Sealed -> {
                // Zeroed here rather than waiting for openAndSeal's outer finally: it is durably
                // sealed by now and has no further reader, and report() is a suspending network
                // round trip that can run to a full timeout. Zeroing again in that finally is
                // harmless — it just covers the failure, cancel and throw paths this branch doesn't
                // take.
                plaintext.fill(0)
                report()
            }
            is SealOutcome.NoSecureLockScreen -> failAndDestroy(FailureReason.NO_SECURE_LOCK_SCREEN)
            is SealOutcome.Failed -> failAndDestroy(FailureReason.SEAL_FAILED)
            is SealOutcome.Cancelled ->
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
                emit(EnrollmentUiState.ReadyToFinish)
        }
    }

    /**
     * Tells the server this device is enrolled, and stops depending on the answer.
     *
     * A failed report is **not** a failed enrollment: the local seal is real, only the marker is
     * stale, and `EnrollmentStateWorker` re-probes live state and retries. The agreement key is spent
     * either way — its life is one ceremony.
     */
    private suspend fun report() {
        if (transport.reportEnrolled(true) !is EnrollmentCallResult.Ok) {
            transport.enqueueDurableReport()
        }
        teardown()
        emit(EnrollmentUiState.Enrolled)
    }

    /**
     * Destroys the agreement key, whatever state the ceremony was in.
     *
     * Called from the ViewModel's `onCleared` — the user leaving the screen, the app locking
     * mid-ceremony and the Activity being destroyed all land here. Idempotent: leaving a screen that
     * never minted anything must not report a deletion.
     */
    fun teardown() {
        if (!keyPairLive) return
        keys.deleteKeyPair()
        keyPairLive = false
    }
}
