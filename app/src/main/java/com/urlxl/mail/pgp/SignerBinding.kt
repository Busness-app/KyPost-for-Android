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
 * Extracts the bare addr-spec of the FIRST mailbox from a From header value.
 *
 * The relay sends the RAW header, which renders as `Name <addr>` whenever a display name is
 * present, and can list more than one mailbox (`Bob <bob@example.com>, Eve <eve@evil.com>`). The
 * server's own `senderAddrSpec` (backend/internal/api/pgp_receive.go) always binds the FIRST
 * mailbox — it tries `mail.ParseAddressList` and only falls back to an angle-addr scan. An earlier
 * version of this function took the LAST `<...>` in the whole header instead, so a `From` that
 * *leads* with a real contact and trails with the actual sender's own address bound the signature
 * to the leading name — and the inbox row's single-line, ellipsizing `TextView` shows exactly that
 * leading name to the user. This finds the first top-level comma (outside quotes, outside angle
 * brackets) to isolate the first mailbox, then extracts its addr-spec. Any input this cannot parse
 * confidently returns "" (which yields [PgpSignatureState.SIGNER_UNKNOWN]) rather than guessing.
 */
internal fun senderAddrSpec(sender: String): String {
    val raw = sender.trim()
    if (raw.isEmpty()) return ""
    return addrSpecFromMailbox(firstMailboxText(raw))
}

/** The header text up to (not including) the first comma that is outside a quoted string and
 *  outside an angle-addr — i.e. the first mailbox in a possibly multi-address header. */
private fun firstMailboxText(raw: String): String {
    var angleDepth = 0
    var inQuotes = false
    for (i in raw.indices) {
        val c = raw[i]
        when {
            c == '"' && (i == 0 || raw[i - 1] != '\\') -> inQuotes = !inQuotes
            inQuotes -> Unit
            c == '<' -> angleDepth++
            c == '>' -> if (angleDepth > 0) angleDepth--
            c == ',' && angleDepth == 0 -> return raw.substring(0, i)
        }
    }
    return raw
}

/** Extracts the addr-spec from a single mailbox (`Name <addr>` or a bare `addr`). Returns "" if
 *  the candidate does not look like a confidently-parsed address, rather than guessing. */
private fun addrSpecFromMailbox(mailbox: String): String {
    val trimmed = mailbox.trim()
    if (trimmed.isEmpty()) return ""
    val open = trimmed.indexOf('<')
    val candidate = if (open >= 0) {
        val close = trimmed.indexOf('>', open + 1)
        if (close < 0) return "" // unterminated angle-addr: fail closed
        trimmed.substring(open + 1, close).trim()
    } else {
        trimmed
    }
    return if (looksLikeAddrSpec(candidate)) candidate.lowercase() else ""
}

/** A conservative addr-spec check: no whitespace/quote/bracket/comma leftovers (which would mean
 *  the extraction above swallowed more than one mailbox or a malformed fragment), and exactly one
 *  '@' that is neither the first nor the last character. */
private fun looksLikeAddrSpec(s: String): Boolean {
    if (s.any { it.isWhitespace() || it == '"' || it == '<' || it == '>' || it == ',' }) return false
    val at = s.indexOf('@')
    return at > 0 && at == s.lastIndexOf('@') && at < s.length - 1
}

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
 * The signature verdict for a message being displayed as being from [senderAddress].
 *
 * A signature is accepted only from a key the address book binds to that sender, AND only when the
 * key that actually produced the signature ([RawSignature.signerKeyId]) is one of that specific
 * bound key's own key ids. The second check is not redundant with the first: [PgpDecryptor] resolves
 * the signature against every non-conflicted key offered to it, so a signature made by some other
 * contact's key still comes back `valid = true` — it verifies, just not against this sender's key.
 * Without this check, any contact in the address book could forge this sender's `From` header, sign
 * with their own harvested key, and have the message attributed to whoever they named.
 *
 * [PgpSignatureState.SIGNER_UNKNOWN] is returned whenever this app cannot point at a specific key it
 * holds for [senderAddress] that produced this signature — whether because the header did not parse,
 * no key is bound to the address at all, or a bound key's ids simply do not contain the signer's.
 * All three are locally indistinguishable from one another (and from an ordinary correspondent not
 * yet in the address book, a key rotated before the new one was harvested, or an impersonation), so
 * this state deliberately asserts nothing beyond "not any key held for this sender" — see
 * [PgpSignatureState.SIGNER_UNKNOWN].
 *
 * Once a specific bound key is identified as the signer, [SignerKey.verified] is read from THAT key
 * — never from "any key bound to this address." Two keys can be bound to one address whenever two
 * contacts list it (contact address lists are attacker-influenceable, see
 * `pgp_qr_bind_confirm_body`), so reading verified from the wrong one of two non-conflicted keys
 * could let a message signed by an Autocrypt-harvested key read as [PgpSignatureState.VERIFIED_CONFIRMED]
 * on the strength of an unrelated confirmed key that never touched this message.
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

    // The key(s) that actually produced this signature — not just "some key bound to this address".
    val signedBy = bound.filter { signature.signerKeyId in signerKeyIdsOf(it.publicKey) }
    if (signedBy.isEmpty()) return PgpSignatureState.SIGNER_UNKNOWN

    if (!signature.valid) return PgpSignatureState.INVALID

    return if (signedBy.any { it.verified }) {
        PgpSignatureState.VERIFIED_CONFIRMED
    } else {
        PgpSignatureState.VERIFIED_SEEN_BEFORE
    }
}
