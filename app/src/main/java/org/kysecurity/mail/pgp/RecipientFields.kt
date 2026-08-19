package org.kysecurity.mail.pgp

/** The compose screen's three recipient fields, split and de-overlapped. */
internal data class RecipientFields(
    val to: List<String>,
    val cc: List<String>,
    val bcc: List<String>,
)

/** Not `splitAddresses`, which flattens — that would put a BCC recipient into the To header. */
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
