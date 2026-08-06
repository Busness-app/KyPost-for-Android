package com.urlxl.mail.pgp

/**
 * What the account's PGP identity is, as far as this device can tell.
 *
 * [CouldNotCheck] is a distinct case from [NoIdentity] on purpose — see [UnavailableReason].
 */
internal sealed class IdentityCheck {
    /** The only case enrollment may proceed from. [fingerprint] is what the envelope's AAD binds;
     *  it is hashed from the key bytes by [ownFingerprintFromBootstrap], never read off a server
     *  field sitting beside them. */
    data class ClientProtected(val fingerprint: String) : IdentityCheck()

    object ServerHeld : IdentityCheck()
    object NoIdentity : IdentityCheck()
    object CouldNotCheck : IdentityCheck()
}

internal interface IdentitySource {
    suspend fun check(): IdentityCheck
}

/**
 * The three device-authenticated enrollment calls plus the durable fallback, with the pairing
 * resolved inside rather than threaded through the state machine.
 *
 * The real implementation **must** be built on `pinnedPairingCallFactory`. Every call here carries
 * the device bearer credential.
 */
internal interface EnrollmentTransport {
    /** This device's paired id — hashed into the code and bound into the envelope's AAD. Null when
     *  there is no usable pairing, which the ceremony reports as [UnavailableReason.NOT_PAIRED]. */
    suspend fun deviceId(): String?

    suspend fun publishKey(encodedPublicKey: String): EnrollmentCallResult

    suspend fun fetchEnvelope(): EnrollmentCallResult

    suspend fun reportEnrolled(enrolled: Boolean): EnrollmentCallResult

    /** Hands the report to [EnrollmentStateWorker], which re-probes live state and retries. Called
     *  when the direct report failed and the device is nonetheless enrolled. */
    fun enqueueDurableReport()
}

/**
 * The device's enrollment agreement keypair.
 *
 * A port rather than a direct call into [EnrollmentKeyStore] because "`deleteKeyPair()` on every
 * exit" is the property this design most needs a test for, and a Keystore object cannot be observed
 * from a JVM test.
 */
internal interface EnrollmentKeys {
    /** Mints a fresh keypair for one ceremony, destroying any previous one. */
    fun newKeyPair(): Boolean

    /** The uncompressed SEC1 point, `0x04 ‖ X ‖ Y`. **The code derives from this** — never from
     *  anything the server sent back, and never from a cached copy of what was published. */
    fun rawPublicKey(): ByteArray?

    /** The base64 of the same point, as published. */
    fun encodedPublicKey(): String?

    fun sharedSecret(epk: ByteArray): ByteArray?

    fun deleteKeyPair(): Boolean
}

internal sealed class SealOutcome {
    /** Sealed **and stored**. The sealer owns the ciphertext end to end so that no key material
     *  passes back through the state machine. */
    object Sealed : SealOutcome()

    /** The user dismissed the prompt, or the Activity hosting it was destroyed. Not a failure: the
     *  ceremony returns to the code and keeps polling, so the user can try again. */
    object Cancelled : SealOutcome()

    object NoSecureLockScreen : SealOutcome()

    data class Failed(val message: String) : SealOutcome()
}

/**
 * The re-seal, requested through an interface because the orchestrator cannot call `BiometricPrompt`
 * — it is Activity-bound. This is the seam that keeps the state machine testable: "biometric
 * cancelled" is a JVM test with a fake rather than an instrumented one.
 */
internal interface VaultSealer {
    suspend fun seal(plaintext: ByteArray): SealOutcome
}

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
internal interface EnrollmentClock {
    fun epochSeconds(): Long
    fun elapsedRealtimeMs(): Long

    /** Injected rather than calling `delay` directly so a JVM test runs the five-minute polling
     *  window in microseconds without a test dispatcher — this module has no
     *  `kotlinx-coroutines-test` on the classpath. */
    suspend fun sleep(millis: Long)
}
