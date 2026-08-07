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
 * Every key id present in [armoredPublicKey]: its primary key plus every subkey, regardless of that
 * subkey's usage flags — an encryption-only subkey's id is returned exactly like a signing subkey's.
 *
 * A one-pass signature is ordinarily made with a dedicated signing subkey, whose id differs from
 * the primary key's, so matching only the primary key's id would silently reject every normally
 * signed message. Revocation is **not** checked here: a signature made with a subkey whose signing
 * capability has since been revoked still matches by id. Returns an empty set — never throws — on
 * a key that fails to parse: an unparseable bound key must never grant a pass, only ever shrink the
 * candidate set.
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
 * The signature verdict for a message being displayed as being from a sender the **server** has
 * already resolved.
 *
 * [signerKeys] arrives narrowed to that sender by `boundSignerKeysForSender`. This function does
 * not know the sender's address and must not learn it: the client used to parse the raw `From`
 * header itself, and a differential harness over 111 adversarial headers found 27 divergences from
 * the server's parser — most seriously RFC 5322 comments, where `Bob (Eve <eve@evil>) <bob@x>` is
 * valid, the server binds `bob@x`, and the client bound `eve@evil`, letting any contact forge a
 * verified badge for anyone. Three fix rounds each closed one construct and opened another.
 *
 * A second parser deciding the same binding is the defect. Do not reintroduce one.
 */
internal fun signatureStateFor(
    signature: RawSignature,
    signerKeys: List<SignerKey>,
): PgpSignatureState {
    if (!signature.present) return PgpSignatureState.NONE
    if (signerKeys.isEmpty()) return PgpSignatureState.SIGNER_UNKNOWN
    if (signerKeys.any { it.conflict }) return PgpSignatureState.KEY_CHANGED

    val signedBy = signerKeys.filter { signature.signerKeyId in signerKeyIdsOf(it.publicKey) }
    if (signedBy.isEmpty()) return PgpSignatureState.SIGNER_UNKNOWN
    if (!signature.valid) return PgpSignatureState.INVALID

    return if (signedBy.any { it.verified }) {
        PgpSignatureState.VERIFIED_CONFIRMED
    } else {
        PgpSignatureState.VERIFIED_SEEN_BEFORE
    }
}
