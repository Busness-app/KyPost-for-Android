package com.urlxl.mail.pgp

/**
 * Why enrollment cannot be started at all. Distinct from [FailureReason]: nothing has been minted
 * or published yet, so there is nothing to clean up and nothing went wrong — the device is simply
 * not in a position to hold a key.
 */
internal enum class UnavailableReason {
    NOT_PAIRED,
    HOSTILE_LOCATION,
    NO_SECURE_LOCK_SCREEN,
    NO_IDENTITY,
    SERVER_HELD_KEY,

    /**
     * The identity check could not be answered — not paired for the purposes of an authenticated
     * call, a network failure, a server error.
     *
     * **"Could not check" is not "no."** The copy for this must never read as "your account doesn't
     * use encrypted mail": a user told that will go and create a second identity.
     */
    COULD_NOT_CHECK,
}

/**
 * Why a started ceremony ended badly. A closed set, deliberately: the browser half enforces the same
 * rule so that an adversarial server's error string cannot select the alarming copy, and Android
 * matches. No server text is ever rendered from these.
 */
internal enum class FailureReason {
    /** The server refused the enrollment key for a reason that is not 401 or 429. */
    PUBLISH_REJECTED,

    /** 401 on any call. This device's credential is not accepted; re-pairing is the fix. */
    UNAUTHORIZED,

    RATE_LIMITED,

    /** The envelope did not parse, or its fields were the wrong size. Never a retry. */
    ENVELOPE_MALFORMED,

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
    COULD_NOT_OPEN,

    /** Discovered at the seal rather than the gate — the lock screen was removed mid-ceremony. */
    NO_SECURE_LOCK_SCREEN,

    SEAL_FAILED,

    /**
     * The Keystore would not mint or return the agreement keypair.
     *
     * Not in the spec's exit table, and not foldable into [PUBLISH_REJECTED]: nothing was published,
     * so telling the user their server refused the key would be false. `EnrollmentKeyStore` already
     * falls back from StrongBox to the TEE, so reaching this means neither worked.
     */
    NO_DEVICE_KEY,
}

/**
 * Every state the ceremony screen can be in.
 *
 * `Reporting` is deliberately absent. A failed report still means enrolled, so surfacing it as a
 * state would offer the user a distinction they must not act on.
 */
internal sealed class EnrollmentUiState {
    object CheckingIdentity : EnrollmentUiState()

    data class Unavailable(val reason: UnavailableReason) : EnrollmentUiState()

    object PublishingKey : EnrollmentUiState()

    /** [expiresAtEpochMs] is the end of the current 120-second bucket, for the countdown. */
    data class ShowingCode(val code: String, val expiresAtEpochMs: Long) : EnrollmentUiState()

    /**
     * The five-minute polling window closed with no envelope.
     *
     * Carries the code because "Check again" **resumes rather than restarts**: it reopens a fresh
     * window against the same keypair, so the code on screen stays valid and the user does not have
     * to re-read it. This is the one exit that keeps the keypair.
     */
    data class WaitingTimedOut(val code: String, val expiresAtEpochMs: Long) : EnrollmentUiState()

    object Opening : EnrollmentUiState()

    object AwaitingAuth : EnrollmentUiState()

    object Enrolled : EnrollmentUiState()

    data class Failed(val reason: FailureReason) : EnrollmentUiState()
}
