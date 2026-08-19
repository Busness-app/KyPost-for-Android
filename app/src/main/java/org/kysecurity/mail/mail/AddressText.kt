package org.kysecurity.mail.mail

// The LAST angle-addr is the real address (RFC 5322); rule shared verbatim with webmail/Linux.
fun addressFromHeader(raw: String): String {
    val value = raw.trim()
    if (value.isEmpty()) return ""
    val close = value.lastIndexOf('>')
    val open = if (close == -1) -1 else value.lastIndexOf('<', close)
    val candidate = if (open != -1 && close > open) {
        value.substring(open + 1, close).trim()
    } else {
        value
    }
    return if (candidate.contains('@')) candidate else ""
}
