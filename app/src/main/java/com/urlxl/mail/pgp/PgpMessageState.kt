package com.urlxl.mail.pgp

/**
 * What this app can actually do with a message's OpenPGP content.
 *
 * Kept as a pure function of the three relay fields so the decision is unit-testable without
 * instrumentation — the Activity only picks views, it does not re-derive the rule.
 */
enum class PgpMessageState {
    /** No OpenPGP content: render normally. */
    NONE,

    /**
     * Encrypted, and the server deliberately did not decrypt it because the account's key is
     * end-to-end protected. There is no body and this app holds no private key, so the only
     * route to the content is webmail.
     */
    CLIENT_PROTECTED,

    /** Encrypted, and the server tried to decrypt and failed. There is a real error to show. */
    DECRYPT_FAILED,

    /**
     * Encrypted, and the server decrypted it for us. Worth surfacing rather than rendering
     * silently: the user should be able to tell that the server read their mail.
     */
    DECRYPTED_BY_SERVER,

    /**
     * Encrypted, but we do not have this message cached and cannot tell which of the states above
     * applies. Distinct from [CLIENT_PROTECTED] on purpose: an absent body is not evidence of
     * client-side protection, and conflating the two made the app assert the *stronger* privacy
     * property exactly when the weaker one held — concealing the fact that the server had read the
     * mail. Under Hostile Location Protection this is the normal state of every cold process.
     */
    BODY_UNAVAILABLE,
}

/**
 * The ordering matters. A non-empty [pgpDecryptError] is checked before the body, because the
 * server populates the error and leaves the body empty — reading it as CLIENT_PROTECTED would
 * tell the user to go to webmail for a message that will fail there too, for a reason we were
 * already told.
 */
fun pgpMessageStateOf(
    pgpEncrypted: Boolean,
    pgpDecryptError: String,
    body: String?,
    /** True when the body could not be read at all (no cached row), as opposed to the server
     *  having delivered the message with no body. See [PgpMessageState.BODY_UNAVAILABLE]. */
    bodyUnavailable: Boolean = false,
): PgpMessageState = when {
    !pgpEncrypted -> PgpMessageState.NONE
    pgpDecryptError.isNotBlank() -> PgpMessageState.DECRYPT_FAILED
    !body.isNullOrBlank() -> PgpMessageState.DECRYPTED_BY_SERVER
    bodyUnavailable -> PgpMessageState.BODY_UNAVAILABLE
    else -> PgpMessageState.CLIENT_PROTECTED
}

/**
 * Marker for an inbox row, or null for no marker.
 *
 * Only the two states that yield no readable content are marked. DECRYPTED_BY_SERVER is
 * deliberately unmarked: the row opens and reads normally, so a marker there would be a symbol on
 * most rows in a server-mode mailbox carrying no information the user can act on — and the detail
 * view already discloses that the server decrypted it.
 */
fun pgpRowMarker(state: PgpMessageState): String? = when (state) {
    PgpMessageState.CLIENT_PROTECTED -> "🔒"
    PgpMessageState.DECRYPT_FAILED -> "⚠"
    // BODY_UNAVAILABLE is unmarked: we do not know which state applies, and a lock glyph would be
    // the very claim we cannot substantiate.
    PgpMessageState.NONE, PgpMessageState.DECRYPTED_BY_SERVER, PgpMessageState.BODY_UNAVAILABLE -> null
}
