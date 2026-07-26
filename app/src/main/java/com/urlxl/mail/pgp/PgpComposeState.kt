package com.urlxl.mail.pgp

/** The two `protection` values this app understands. Anything else degrades to "not server". */
private const val PROTECTION_SERVER = "server"
private const val PROTECTION_CLIENT = "client"

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
    /** Show "Continue in webmail" instead of the toggles: this account's key is unwrapped only in
     *  the browser, from a password this device never learns, so neither the server nor this app
     *  can encrypt on its behalf. */
    val handoffToWebmail: Boolean,
)

/**
 * [hasIdentity] and [protection] are null when bootstrap could not be reached. Unknown hides
 * everything: guessing "server" offers a toggle that 409s, and guessing "client" sends people to
 * webmail for no reason.
 *
 * An unrecognized non-null [protection] is treated as "not server" — degrade, never guess.
 */
fun pgpComposeStateOf(hasIdentity: Boolean?, protection: String?): PgpComposeState = when {
    protection == null || hasIdentity != true ->
        PgpComposeState(canEncrypt = false, canSign = false, handoffToWebmail = false)
    protection == PROTECTION_CLIENT ->
        PgpComposeState(canEncrypt = false, canSign = false, handoffToWebmail = true)
    protection == PROTECTION_SERVER ->
        PgpComposeState(canEncrypt = true, canSign = true, handoffToWebmail = false)
    else -> PgpComposeState(canEncrypt = false, canSign = false, handoffToWebmail = false)
}
