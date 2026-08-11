package com.urlxl.mail.pgp

/** The two `protection` values this app understands. Anything else degrades to "not server". */
internal const val PROTECTION_SERVER = "server"
internal const val PROTECTION_CLIENT = "client"

/**
 * Which PGP controls the compose screen offers, as a pure function of what
 * `GET /api/pgp/bootstrap` said.
 *
 * Kept out of the Activity for the same reason as [PgpMessageState]: the rule is testable without
 * instrumentation, and the view only picks widgets.
 */
data class PgpComposeState(
    val canEncrypt: Boolean,
    val canSign: Boolean,
    /** Show "Continue in webmail" instead of the toggles: this account's key is held only by the
     *  user, and this device is not enrolled, so neither the server nor this app can encrypt on its
     *  behalf. */
    val handoffToWebmail: Boolean,
    /** The encryption happens **here**, and the send goes to `/api/mail/send-pgp` rather than
     *  `/api/mail/send`. True only for a client-custody account on an enrolled device.
     *
     *  A single flag rather than leaving the Activity to re-derive the combination: getting it
     *  wrong means posting encrypt/sign flags to the endpoint that answers 409 for precisely this
     *  account type. */
    val clientSide: Boolean = false,
)

/**
 * [hasIdentity] and [protection] are null when bootstrap could not be reached. Unknown hides
 * everything: guessing "server" offers a toggle that 409s, and guessing "client" sends people to
 * webmail for no reason.
 *
 * An unrecognized non-null [protection] is treated as "not server" — degrade, never guess.
 *
 * [deviceEnrolled] is whether this device still holds the account's private key
 * ([probeEnrollment]). It is a `Boolean` rather than an `EnrollmentStatus` because that enum is
 * `internal` and this function is part of the public surface.
 *
 * [accountAddress] is `suggestedUserIDs[0]` from bootstrap. Blank means no mail account is
 * configured, so no delivery `From` can be built — an enrolled client-custody account still falls
 * back to the handoff rather than offering a Send the relay is certain to refuse.
 */
fun pgpComposeStateOf(
    hasIdentity: Boolean?,
    protection: String?,
    deviceEnrolled: Boolean = false,
    accountAddress: String = "",
): PgpComposeState = when {
    protection == null || hasIdentity != true ->
        PgpComposeState(canEncrypt = false, canSign = false, handoffToWebmail = false)
    // An enrolled device holds the key the browser sealed to it, so it can do the crypto itself.
    // This is the case the earlier "this device never holds the account's private key" contract
    // ruled out; the device enrollment ceremony replaced that contract.
    protection == PROTECTION_CLIENT && deviceEnrolled && accountAddress.isNotBlank() ->
        PgpComposeState(canEncrypt = true, canSign = true, handoffToWebmail = false, clientSide = true)
    protection == PROTECTION_CLIENT ->
        PgpComposeState(canEncrypt = false, canSign = false, handoffToWebmail = true)
    protection == PROTECTION_SERVER ->
        PgpComposeState(canEncrypt = true, canSign = true, handoffToWebmail = false)
    else -> PgpComposeState(canEncrypt = false, canSign = false, handoffToWebmail = false)
}
