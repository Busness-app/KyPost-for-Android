package com.urlxl.mail.pgp

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
     * Runs the ceremony from the gate to a terminal state.
     *
     * Every path out of this function is one row of the spec's exit table.
     */
    suspend fun run() {
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

        // Task 4 replaces this line with publishAndPoll().
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
