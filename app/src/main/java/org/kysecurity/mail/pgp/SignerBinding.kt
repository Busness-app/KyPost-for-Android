package org.kysecurity.mail.pgp

import org.bouncycastle.openpgp.PGPPublicKeyRingCollection
import org.bouncycastle.openpgp.PGPUtil
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator
import java.util.Date

/**
 * One address-bound contact key as the server ships it.
 *
 * [addresses] is the binding the **server's** address book computed. The client must not re-derive
 * it from the key's own User IDs: one key can self-assert two User IDs, so a binding taken from the
 * key material is forgeable, and re-deriving it with a second parser is how a client can end up
 * vouching for a key the server's own binding rejects.
 */
internal data class SignerKey(
    val addresses: List<String>,
    val publicKey: String,
    /**
     * The relay's claim that the user confirmed this key.
     *
     * **Read by nothing that decides a verdict**, and that is deliberate — see [signatureStateFor].
     * It is the server asserting the strongest trust state in the app about a key the same response
     * supplied. Kept on the type because the wire format still carries it and dropping the field
     * would silently discard it on a round trip; do not reintroduce a read of it.
     */
    val verified: Boolean,
    val source: String,
    val conflict: Boolean,
)

/**
 * Every **currently usable** key id in [armoredPublicKey]: its primary key plus every subkey,
 * regardless of that subkey's usage flags — an encryption-only subkey's id is returned exactly like
 * a signing subkey's.
 *
 * This is the only place revocation and expiry are enforced. [signatureStateFor] answers
 * SIGNER_UNKNOWN for a signature whose key id is not in this set, so a key dropped here can never
 * render as VERIFIED however cleanly its signature verifies — which is what makes the omission
 * below matter.
 *
 * **A ring is dropped whole when its primary key is revoked or expired.** Per-key filtering alone
 * checked each subkey's own revocation signature and never the primary's, so revoking a compromised
 * *primary* — which is what a user does when their key is stolen, and which every other OpenPGP
 * implementation treats as revoking the whole certificate — left every unrevoked signing subkey
 * under it still trusted. A thief holding the stolen subkey kept a green VERIFIED badge in this
 * client after the owner had published the revocation.
 */
internal fun signerKeyIdsOf(armoredPublicKey: String, now: Date = Date()): Set<Long> = runCatching {
    val rings = PGPPublicKeyRingCollection(
        PGPUtil.getDecoderStream(armoredPublicKey.byteInputStream(Charsets.UTF_8)),
        BcKeyFingerprintCalculator(),
    )
    rings.keyRings.asSequence()
        .filter { it.publicKey.isUsableAt(now) }
        .flatMap { ring ->
            val primary = ring.publicKey
            ring.publicKeys.asSequence()
                .filter { it.isUsableAt(now) }
                // A subkey counts only if the PRIMARY key vouches for it. BouncyCastle's
                // PGPPublicKeyRing constructor stores subkeys without ever verifying their binding
                // signatures, so an attacker who supplies the armored blob — and on the
                // client-protected read path the relay does supply it, see PgpPayloadClient — could
                // append an arbitrary subkey to a genuine contact's key. Its key id then landed in
                // this set, PgpDecryptor.verifyOnePass looked the signer up by that same id in the
                // same blob, found the grafted key, and the signature verified: a message signed by
                // the attacker, attributed to a contact whose primary fingerprint the user had
                // compared in person.
                //
                // PgpFingerprint.compute has enforced exactly this since it was written, and its
                // KDoc says why. Two functions in one package answering "is this subkey part of
                // this key" differently is how the gap survived; they now share one implementation.
                .filter { it.isMasterKey || hasValidBindingSignature(primary, it) }
                // And it must be a key that may sign at all. A signature verifying under an
                // encryption-only subkey is not a signature from that identity.
                .filter { it.canSign(primary) }
        }
        .map { it.keyID }
        .toSet()
}.getOrDefault(emptySet())

private fun org.bouncycastle.openpgp.PGPPublicKey.isUsableAt(now: Date): Boolean =
    !hasRevocation() && !isExpiredAt(now)

/**
 * Whether this key advertises a signing capability, per key flags [primary] asserted.
 *
 * `PGPPublicKey.isEncryptionKey()` is BouncyCastle's algorithm-level question and is the wrong one:
 * it answers "can this algorithm encrypt", not "did the owner authorise this key to sign". The key
 * flags in the self/binding signature are where that is stated, so they are what is read — and a
 * key with no key-flags subpacket at all falls back to the algorithm, which is the pre-RFC4880
 * behaviour every other client uses for old keys.
 */
private fun org.bouncycastle.openpgp.PGPPublicKey.canSign(
    primary: org.bouncycastle.openpgp.PGPPublicKey,
): Boolean {
    val flags = keyFlagsAssertedBy(primary)
    if (flags != 0) {
        return flags and org.bouncycastle.bcpg.sig.KeyFlags.SIGN_DATA != 0
    }
    // No key flags asserted at all: fall back to what the algorithm can do.
    return isEncryptionKey.not() || isMasterKey
}

/**
 * The OR of every key-flags subpacket [primary] asserted about this key, or 0 if it asserted none.
 *
 * Two filters, both load-bearing:
 *
 * - **Signatures made by [primary] only.** `PGPPublicKey.signatures` yields third-party
 *   certifications too, and anyone can append one to an armored blob. Reading flags out of those
 *   would let whoever supplies the key material assert that an encryption-only key may sign, which
 *   is the capability check this function exists to perform.
 * - **Hashed subpackets only.** An unhashed area is not covered by the signature, so a flag placed
 *   there is editable without invalidating anything and must not grant a capability.
 */
private fun org.bouncycastle.openpgp.PGPPublicKey.keyFlagsAssertedBy(
    primary: org.bouncycastle.openpgp.PGPPublicKey,
): Int {
    var flags = 0
    val signatures = signatures
    while (signatures.hasNext()) {
        val signature = signatures.next() as? org.bouncycastle.openpgp.PGPSignature ?: continue
        if (signature.keyID != primary.keyID) continue
        val vectors = signature.hashedSubPackets ?: continue
        if (vectors.hasSubpacket(org.bouncycastle.bcpg.SignatureSubpacketTags.KEY_FLAGS)) {
            flags = flags or vectors.keyFlags
        }
    }
    return flags
}

private fun org.bouncycastle.openpgp.PGPPublicKey.isExpiredAt(now: Date): Boolean {
    val validSeconds = getValidSeconds()
    if (validSeconds <= 0) return false
    val createdAt = creationTime.time
    if (validSeconds > (Long.MAX_VALUE - createdAt) / 1_000L) return false
    return createdAt + validSeconds * 1_000L <= now.time
}

/**
 * A signer key this device holds **itself**, out of its own contact store.
 *
 * The distinction from [SignerKey] is provenance and it is the whole point: a [SignerKey] arrives
 * in the relay's HTTP response, one field away from the ciphertext; a [LocalSignerKey] came out of
 * Room, where it got there through contact sync and had its fingerprint computed locally by
 * [PgpFingerprint.compute].
 *
 * [confirmed] means the user compared this exact fingerprint out of band — the QR ceremony — and
 * neither of the two local alarms is outstanding against it. It is the **only** input that can
 * produce [PgpSignatureState.VERIFIED_CONFIRMED]. Nothing on the wire can.
 */
internal data class LocalSignerKey(val publicKey: String, val confirmed: Boolean)

/**
 * Resolves the keys this device holds for an address, so the verdict does not have to take the
 * relay's word for who a sender is.
 *
 * A `fun interface` with no Android types, for the same reason [PayloadSource] is one: it keeps
 * [EncryptedMessageReader] free of Room and of a `Context`, so the exit table stays a JVM test.
 */
internal fun interface LocalSignerKeyLookup {
    /** Empty when this device holds no key for [address] — including when [address] is blank. */
    suspend fun keysFor(address: String): List<LocalSignerKey>
}

/**
 * The signature verdict, resolved **locally first**.
 *
 * ## What changed and why
 *
 * This function used to take only [serverKeys], and those arrive in the same JSON body as the
 * ciphertext: the relay chose the armored key, the address it is bound to, AND the `verified`
 * boolean. So a compromised or hostile relay signed a message with a key of its own, shipped that
 * key with `verified = true`, and this app rendered "✅ signature confirmed" beside a
 * `resolvedSender` the same response had also chosen. That is the exact adversary the
 * client-protected read path exists for, and the badge asserting the strongest claim in the app was
 * the one thing still delegated to it. Meanwhile `ContactEntity.pgpKeyFingerprint` — computed on
 * this device, from the key's own bytes, precisely so a server-supplied fingerprint is never
 * trusted — was sitting unread.
 *
 * ## The rule
 *
 * - **This device holds a key for the sender** ([localKeys] non-empty): the relay gets no say.
 *   The signature either matches a locally-held key or it does not, and if it does not while we
 *   hold one, that is [PgpSignatureState.KEY_CHANGED] — the sender rotated, or someone else signed.
 *   Both deserve the same "do not act on this yet" treatment, and the two are not locally
 *   distinguishable.
 * - **It does not** ([localKeys] empty): fall back to [serverKeys], which is still worth something
 *   — it is how a first-contact message says anything at all — but the verdict is **capped at
 *   [PgpSignatureState.VERIFIED_SEEN_BEFORE]**. `verified` off the wire is ignored outright.
 *
 * The cap is the part that must not be softened later. "Seen before" claims continuity, which a
 * relay-supplied key can honestly support; "confirmed" claims identity, which only the user's own
 * out-of-band comparison can.
 */
internal fun signatureStateFor(
    signature: RawSignature,
    serverKeys: List<SignerKey>,
    localKeys: List<LocalSignerKey> = emptyList(),
): PgpSignatureState {
    if (!signature.present) return PgpSignatureState.NONE

    if (localKeys.isNotEmpty()) {
        val signedBy = localKeys.filter { signature.signerKeyId in signerKeyIdsOf(it.publicKey) }
        // We hold a key for this sender and the message was not signed with it. Not
        // SIGNER_UNKNOWN: "we have no opinion" is false here, we have one and it disagrees.
        if (signedBy.isEmpty()) return PgpSignatureState.KEY_CHANGED
        return verdictFor(signature, confirmed = signedBy.any { it.confirmed })
    }

    if (serverKeys.isEmpty()) return PgpSignatureState.SIGNER_UNKNOWN

    // A conflict outranks a good key for the same sender. Two entries for one address means one of
    // them is a key that changed, and reporting the survivor as verified would hide precisely the
    // event worth reporting.
    if (serverKeys.any { it.conflict }) return PgpSignatureState.KEY_CHANGED

    val signedBy = serverKeys.filter { signature.signerKeyId in signerKeyIdsOf(it.publicKey) }
    if (signedBy.isEmpty()) return PgpSignatureState.SIGNER_UNKNOWN

    // Capped. `SignerKey.verified` is read nowhere in this branch, deliberately — see the KDoc, and
    // note that `confirmed = false` is passed unconditionally rather than read from anything.
    return verdictFor(signature, confirmed = false)
}

/**
 * The verdict once the signing key has been matched to the sender, for a key whose out-of-band
 * confirmation status is [confirmed].
 *
 * Matches on [RawSignature]'s type rather than on its `valid` boolean, which is the whole reason
 * that type stopped being a pair of booleans. [RawSignature.NoSuchKey] must never reach
 * [PgpSignatureState.INVALID]: nothing was checked, so there is nothing to accuse anyone of.
 * Reaching it here means the key id matched a key we hold while the decryptor was not offered that
 * key — unreachable today, since [EncryptedMessageReader] offers local keys first, and reported
 * honestly rather than assumed away.
 */
private fun verdictFor(signature: RawSignature, confirmed: Boolean): PgpSignatureState =
    when (signature) {
        is RawSignature.Absent -> PgpSignatureState.NONE
        is RawSignature.NoSuchKey -> PgpSignatureState.SIGNER_UNKNOWN
        is RawSignature.Checked -> when {
            !signature.verified -> PgpSignatureState.INVALID
            confirmed -> PgpSignatureState.VERIFIED_CONFIRMED
            else -> PgpSignatureState.VERIFIED_SEEN_BEFORE
        }
    }
