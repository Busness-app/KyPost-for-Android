package com.urlxl.mail.pgp

/**
 * One address-bound contact key as the server ships it.
 *
 * [addresses] is the binding the **server's** address book computed. The client must not re-derive
 * it from the key's own User IDs: one key can self-assert two User IDs, so a binding taken from the
 * key material is forgeable, and re-deriving it with a second parser is how a client can end up
 * vouching for a key the server's own binding rejects.
 *
 * [conflict] means the stored key no longer matches its TOFU pin. Such an entry carries no
 * [publicKey] and is never offered to a signature check — it exists so the reader can say the key
 * changed instead of silently reporting an unknown signer.
 */
internal data class SignerKey(
    val addresses: List<String>,
    val publicKey: String,
    val verified: Boolean,
    val source: String,
    val conflict: Boolean,
)

/**
 * Extracts the bare addr-spec from a From header value.
 *
 * The relay sends the RAW header, which renders as `Name <addr>` whenever a display name is
 * present. Comparing that against a bare address matched nothing, so the binding silently returned
 * no keys for every correspondent who has a display name — while a bare `From: bob@example.com`,
 * the form an attacker controls and therefore always chooses, went on matching. A binding that only
 * ever fires for the attacker is worse than no binding. This mirrors the server's `senderAddrSpec`.
 */
internal fun senderAddrSpec(sender: String): String {
    val raw = sender.trim()
    if (raw.isEmpty()) return ""
    val open = raw.lastIndexOf('<')
    if (open >= 0) {
        val close = raw.indexOf('>', open + 1)
        if (close >= 0) return raw.substring(open + 1, close).trim().lowercase()
    }
    return raw.lowercase()
}

/**
 * The signature verdict for a message being displayed as being from [senderAddress].
 *
 * A signature is accepted only from a key the address book binds to that sender. The signing key's
 * own claim about who it belongs to is never consulted.
 */
internal fun signatureStateFor(
    signature: RawSignature,
    senderAddress: String,
    signerKeys: List<SignerKey>,
): PgpSignatureState {
    if (!signature.present) return PgpSignatureState.NONE

    val address = senderAddrSpec(senderAddress)
    if (address.isEmpty()) return PgpSignatureState.SIGNER_UNKNOWN

    val bound = signerKeys.filter { key -> key.addresses.any { it.trim().lowercase() == address } }
    if (bound.isEmpty()) return PgpSignatureState.SIGNER_UNKNOWN

    // A conflict outranks a good key for the same sender. Two entries for one address means one of
    // them is a key that changed, and reporting the survivor as verified would hide precisely the
    // event worth reporting.
    if (bound.any { it.conflict }) return PgpSignatureState.KEY_CHANGED

    if (!signature.valid) return PgpSignatureState.INVALID

    return if (bound.any { it.verified }) {
        PgpSignatureState.VERIFIED_CONFIRMED
    } else {
        PgpSignatureState.VERIFIED_SEEN_BEFORE
    }
}
