package org.kysecurity.mail.pgp

/**
 * The result of unsealing the device envelope.
 *
 * [Opened] carries **no key material**, mirroring [VaultSealer]: the plaintext goes straight into
 * [EnrollmentSession] and the caller is told only that it worked, so no key material passes back
 * through the state machine.
 *
 * [Cancelled] is not a failure — the user dismissed the prompt, or the hosting Activity went away.
 * The reader returns to offering the Decrypt button and says nothing.
 */
internal sealed class OpenOutcome {
    object Opened : OpenOutcome()
    object Cancelled : OpenOutcome()

    /** No sealed envelope on this device: never enrolled, or torn down by a wipe, an unpair or
     *  Hostile Location Protection. */
    object NotEnrolled : OpenOutcome()

    object NoSecureLockScreen : OpenOutcome()

    /** The envelope exists and could not be opened — typically a Keystore key the OS invalidated,
     *  which needs a fresh enrollment rather than a retry. */
    data class Failed(val message: String) : OpenOutcome()
}

/**
 * The unseal, behind an interface because `BiometricPrompt` is Activity-bound and the orchestrator
 * must stay free of Android imports. That seam is what makes "the user dismissed the prompt" a JVM
 * test with a fake rather than an instrumented one.
 */
internal interface VaultOpener {
    /** On [OpenOutcome.Opened], and only then, the armored private key is in [EnrollmentSession]. */
    suspend fun open(): OpenOutcome
}
