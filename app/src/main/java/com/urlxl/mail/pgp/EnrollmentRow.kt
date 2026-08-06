package com.urlxl.mail.pgp

/**
 * What the Security page's encrypted-mail row says, and what it offers.
 *
 * A type rather than a string so the decision is testable and the copy lives with the screen.
 */
internal sealed class EnrollmentRow {
    /** Not paired: there is no account to hold a key for. */
    object Hidden : EnrollmentRow()

    object HostileLocation : EnrollmentRow()
    object NoSecureLockScreen : EnrollmentRow()

    /** The vault key is gone — a biometric enrollment change, a Keystore invalidation. Offers the
     *  ceremony again. */
    object KeyInvalidated : EnrollmentRow()

    /** This device holds a key. Offers removal. */
    object Enrolled : EnrollmentRow()

    /** The account's key is held by the server. Offers webmail — this is the retirement nudge. */
    object ServerHeldKey : EnrollmentRow()

    /** The account has no PGP identity yet. Offers webmail, where one can be made. */
    object NoIdentity : EnrollmentRow()

    /** The account could not be reached. Offers nothing, and says so without implying "no". */
    object CouldNotCheck : EnrollmentRow()

    /** A client-protected key this device does not hold yet. Offers the ceremony. */
    object NotEnrolled : EnrollmentRow()
}

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
internal fun enrollmentRowFor(
    paired: Boolean,
    hostileLocation: Boolean,
    hasSecureLockScreen: Boolean,
    status: EnrollmentStatus,
    identity: IdentityCheck,
): EnrollmentRow = when {
    !paired -> EnrollmentRow.Hidden
    hostileLocation -> EnrollmentRow.HostileLocation
    !hasSecureLockScreen -> EnrollmentRow.NoSecureLockScreen

    // Local, and both unsafe to withhold.
    status == EnrollmentStatus.KEY_INVALIDATED -> EnrollmentRow.KeyInvalidated
    status == EnrollmentStatus.ENROLLED -> EnrollmentRow.Enrolled

    else -> when (identity) {
        is IdentityCheck.ServerHeld -> EnrollmentRow.ServerHeldKey
        is IdentityCheck.NoIdentity -> EnrollmentRow.NoIdentity
        is IdentityCheck.CouldNotCheck -> EnrollmentRow.CouldNotCheck
        is IdentityCheck.ClientProtected -> EnrollmentRow.NotEnrolled
    }
}
