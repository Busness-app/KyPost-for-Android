package com.urlxl.mail.pgp

import org.bouncycastle.openpgp.PGPPublicKeyRingCollection
import org.bouncycastle.openpgp.PGPUtil
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator

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
 * The key ids [armoredPublicKey] can sign with: its primary key plus every subkey it contains.
 *
 * A one-pass signature is ordinarily made with a dedicated signing subkey, whose id differs from
 * the primary key's, so matching only the primary key's id would silently reject every normally
 * signed message. Returns an empty set — never throws — on a key that fails to parse: an
 * unparseable bound key must never grant a pass, only ever shrink the candidate set.
 */
internal fun signerKeyIdsOf(armoredPublicKey: String): Set<Long> = runCatching {
    val rings = PGPPublicKeyRingCollection(
        PGPUtil.getDecoderStream(armoredPublicKey.byteInputStream(Charsets.UTF_8)),
        BcKeyFingerprintCalculator(),
    )
    rings.keyRings.asSequence()
        .flatMap { it.publicKeys.asSequence() }
        .map { it.keyID }
        .toSet()
}.getOrDefault(emptySet())

/**
 * The signature verdict for a message being displayed as being from [senderAddress].
 *
 * A signature is accepted only from a key the address book binds to that sender, AND only when the
 * key that actually produced the signature ([RawSignature.signerKeyId]) is one of that bound key's
 * own key ids. The second check is not redundant with the first: [PgpDecryptor] resolves the
 * signature against every non-conflicted key offered to it, so a signature made by some other
 * contact's key still comes back `valid = true` — it verifies, just not against this sender's key.
 * Without this check, any contact in the address book could forge this sender's `From` header, sign
 * with their own harvested key, and have the message attributed to whoever they named. A mismatch
 * reads as [PgpSignatureState.SIGNER_UNKNOWN], not [PgpSignatureState.INVALID]: it means "signed by
 * somebody, but not this sender," and no key for whoever it actually was is held here.
 *
 * The signing key's own claim about who it belongs to is never consulted.
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

    val signedByABoundKey = bound.any { signature.signerKeyId in signerKeyIdsOf(it.publicKey) }
    if (!signedByABoundKey) return PgpSignatureState.SIGNER_UNKNOWN

    if (!signature.valid) return PgpSignatureState.INVALID

    return if (bound.any { it.verified }) {
        PgpSignatureState.VERIFIED_CONFIRMED
    } else {
        PgpSignatureState.VERIFIED_SEEN_BEFORE
    }
}
