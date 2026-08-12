package org.kysecurity.mail.pgp

/** The compose screen's three recipient fields, split and de-overlapped. */
internal data class RecipientFields(
    val to: List<String>,
    val cc: List<String>,
    val bcc: List<String>,
)

/**
 * Splits the compose screen's comma-joined recipient fields, keeping each field distinct.
 *
 * **Not [org.kysecurity.mail.splitAddresses].** That one flattens all three fields into a single deduped
 * list, which is correct for the preflight — the question there is "which addresses need a key", and
 * asking twice about one person is only noise. Reusing it here would collapse a BCC recipient into
 * the To bucket, putting someone the sender marked blind into a header every other recipient reads.
 *
 * Overlap is resolved by precedence rather than kept: an address already in To is dropped from CC
 * and BCC, and one already in CC is dropped from BCC. Keeping it would build that person a second,
 * redundant delivery *and* leave the sender believing the extra copy was blind when the To header
 * already names them. First spelling wins, since that is the one the user typed and will see named
 * back to them.
 */
internal fun splitRecipientFields(to: String, cc: String, bcc: String): RecipientFields {
    val seen = mutableSetOf<String>()
    fun take(field: String): List<String> = field.split(',')
        .map { it.trim() }
        .filter { it.isNotEmpty() }
        .filter { seen.add(it.lowercase()) }

    // Evaluation order is the precedence: To first, then CC, then BCC.
    val toList = take(to)
    val ccList = take(cc)
    return RecipientFields(to = toList, cc = ccList, bcc = take(bcc))
}
