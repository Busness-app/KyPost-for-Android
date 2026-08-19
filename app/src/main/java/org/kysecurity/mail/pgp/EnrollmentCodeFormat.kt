package org.kysecurity.mail.pgp

private val CODE_GROUPS = intArrayOf(4, 3, 4, 3)

/** Display grouping only — the browser strips it before comparing, but the two must agree. */
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
