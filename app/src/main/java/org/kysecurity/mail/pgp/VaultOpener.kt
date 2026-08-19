package org.kysecurity.mail.pgp

/** [Opened] carries no key material — the plaintext goes straight into [EnrollmentSession]. */
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

internal interface VaultOpener {
    /** On [OpenOutcome.Opened], and only then, the armored private key is in [EnrollmentSession]. */
    suspend fun open(): OpenOutcome
}
