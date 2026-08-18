package org.kysecurity.mail.pgp

/**
 * Group sizes for the displayed code: `5R9K-6FW-A18A-8YP`, not `5R9K6FW-A18A8YP`.
 */
private val CODE_GROUPS = intArrayOf(4, 3, 4, 3)

/**
 * The code as the user reads it aloud.
 *
 * **Safe on the wire:** the browser's `normalizeEnrollmentCode` strips all whitespace and hyphens
 * (`/[\s-]/g`) and applies Crockford's decode rules before comparing, so grouping never reaches the
 * hash. The browser's `formatEnrollmentCode` groups identically; the two must move together.
 */
internal fun formatEnrollmentCode(code: String): String {
    val parts = mutableListOf<String>()
    var index = 0
    for (size in CODE_GROUPS) {
        if (index >= code.length) break
        parts += code.substring(index, minOf(index + size, code.length))
        index += size
    }
    if (index < code.length) parts += code.substring(index)
    return parts.joinToString("-")
}
