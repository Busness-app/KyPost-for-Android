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
 * Whether the screen would otherwise render **nothing at all**: no body, no preview text, and no
 * PGP notice explaining the absence.
 *
 * This is the one combination the state machine above cannot speak for. [PgpMessageState.NONE] means
 * "no OpenPGP content, render normally", and rendering normally is correct — right up to the point
 * where there is nothing to render, at which case the user gets a blank screen with no explanation.
 *
 * It is reachable, and not rare. `pgpEncrypted` is `omitempty` server-side and defaults to `false`
 * here, so **an encrypted message the server has not warmed yet is indistinguishable on the wire from
 * an unencrypted one** — it arrives with the flag clear and no body, and lands in [NONE]. The sibling
 * `hasAttachments` field already carries a comment saying it reads `false` until the server warms the
 * message; the PGP flags have the same caveat and it was never written down.
 *
 * Nothing here guesses which case it is. The client genuinely cannot tell an unwarmed encrypted
 * message from a genuinely empty one, and inventing a lock glyph for the first would repeat the
 * mistake [PgpMessageState.BODY_UNAVAILABLE] exists to prevent — asserting the stronger privacy
 * property on evidence that does not support it. It only says that *something* should be on screen.
 */
fun rendersNothing(state: PgpMessageState, body: String?, preview: String): Boolean =
    state == PgpMessageState.NONE && body.isNullOrBlank() && preview.isBlank()

/**
 * Whether the relay could tie this message's OpenPGP signature to the sender.
 *
 * Kept separate from [PgpMessageState], which answers "can this content be read here?" — a message
 * can be perfectly readable and still be signed by someone other than who it claims to be from, and
 * that is precisely the case worth surfacing.
 *
 * The relay computes this and returns `pgpSigned`/`pgpVerified`/`pgpSignerFingerprint` per message.
 * All three were parsed off the wire, mapped into [com.urlxl.mail.Email], and persisted to Room
 * behind their own schema migration — and then never rendered anywhere on Android. An attacker who
 * fetched the victim's published key, encrypted to it, signed with their own key and forged the
 * `From` header got a message that displayed as ordinary encrypted mail, while the same message in
 * webmail read "signature does not match sender".
 */
enum class PgpSignatureState {
    /** Not signed, or no opinion was expressed. Nothing to say. */
    NONE,

    /** Signed by a key bound to the sender, and the user confirmed that key out of band — by
     *  eyeballing the fingerprint or scanning a QR code. The only state that claims identity. */
    VERIFIED_CONFIRMED,

    /**
     * Signed by a key bound to the sender that still matches its TOFU pin, but which nobody ever
     * confirmed. This claims **continuity**, not identity: the same key as last time.
     *
     * Distinct from [VERIFIED_CONFIRMED] because most keys arrive by Autocrypt harvest, so one flat
     * "verified" badge would assert the stronger property on the weaker evidence for nearly every
     * message — and a badge that over-claims on the common case is one users learn to ignore.
     */
    VERIFIED_SEEN_BEFORE,

    /** Signed, but no key we hold is bound to this sender. Not an accusation: the ordinary state
     *  for a correspondent who is not in the address book yet. */
    SIGNER_UNKNOWN,

    /**
     * A key IS bound to this sender and it no longer matches its TOFU pin.
     *
     * Under trust-on-first-use this is the one alarm worth raising. It used to be indistinguishable
     * from [SIGNER_UNKNOWN], because the server dropped a pin-mismatched contact entirely — so an
     * active key substitution displayed as the most routine message in the app.
     */
    KEY_CHANGED,

    /** Signed, and it does **not** verify against the key bound to the sender. */
    INVALID,
}

/**
 * The relay's verdict, for accounts whose key the **server** holds.
 *
 * Two booleans cannot express six states, and they cannot distinguish a fingerprint-confirmed key
 * from an Autocrypt-harvested one, so `pgpVerified` maps to the weaker of the two positive claims.
 * [PgpSignatureState.VERIFIED_CONFIRMED], [PgpSignatureState.SIGNER_UNKNOWN] and
 * [PgpSignatureState.KEY_CHANGED] are reachable only through [signatureStateFor], from a local
 * decrypt against a locally-held key.
 */
fun pgpSignatureStateOf(pgpSigned: Boolean, pgpVerified: Boolean): PgpSignatureState = when {
    !pgpSigned -> PgpSignatureState.NONE
    pgpVerified -> PgpSignatureState.VERIFIED_SEEN_BEFORE
    else -> PgpSignatureState.INVALID
}

/**
 * Marker for an inbox row, or null for no marker.
 *
 * Only the two states that yield no readable content are marked. DECRYPTED_BY_SERVER is
 * deliberately unmarked: the row opens and reads normally, so a marker there would be a symbol on
 * most rows in a server-mode mailbox carrying no information the user can act on — and the detail
 * view already discloses that the server decrypted it.
 */
fun pgpRowMarker(
    state: PgpMessageState,
    /** A failed signature or a changed key outranks every readability marker: the row is
     *  readable, and that is exactly what makes an unflagged impersonation dangerous.
     *  SIGNER_UNKNOWN deliberately does not mark — see [PgpSignatureState.SIGNER_UNKNOWN]. */
    signature: PgpSignatureState = PgpSignatureState.NONE,
): String? = when (signature) {
    PgpSignatureState.INVALID, PgpSignatureState.KEY_CHANGED -> "⚠"
    else -> pgpReadabilityMarker(state)
}

private fun pgpReadabilityMarker(state: PgpMessageState): String? = when (state) {
    PgpMessageState.CLIENT_PROTECTED -> "🔒"
    PgpMessageState.DECRYPT_FAILED -> "⚠"
    // BODY_UNAVAILABLE is unmarked: we do not know which state applies, and a lock glyph would be
    // the very claim we cannot substantiate.
    PgpMessageState.NONE, PgpMessageState.DECRYPTED_BY_SERVER, PgpMessageState.BODY_UNAVAILABLE -> null
}
