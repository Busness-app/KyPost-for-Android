package org.kysecurity.mail.pgp

/**
 * Group sizes for the displayed code: `5R9K-6FW-A18A-8YP`, not `5R9K6FW-A18A8YP`.
 *
 * Derived from nothing — these are a display choice, not a function of [deviceEnrollmentCode]'s
 * width — but the tail rule below means a width change cannot silently truncate.
 */
private val CODE_GROUPS = intArrayOf(4, 3, 4, 3)

/**
 * The code as the user reads it aloud.
 *
 * **Safe on the wire:** the browser's `normalizeEnrollmentCode` strips all whitespace and hyphens
 * (`/[\s-]/g`) and applies Crockford's decode rules before comparing, so grouping never reaches the
 * hash. The browser's `formatEnrollmentCode` groups identically; the two must move together.
 *
 * Anything left over after the last group is appended rather than dropped. A hardcoded slice is
 * exactly how the browser's version silently truncated the code when its width grew from 10 to 14,
 * and because the short code is a prefix of the long one the result looked entirely plausible.
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
