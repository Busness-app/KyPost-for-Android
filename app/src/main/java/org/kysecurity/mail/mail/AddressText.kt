package org.kysecurity.mail.mail

/**
 * The real address out of a raw From/To/Cc header value.
 *
 * A display name is attacker-controlled and is authenticated by nothing: DKIM,
 * SPF and DMARC all validate the domain a message was sent from, never the
 * human-readable label in front of it. So this arrives intact and aligned:
 *
 *     From: "Bob <bob@corp.com>" <evil@attacker.tld>
 *
 * The previous rule took the *first* `<...>` group, which resolved that to Bob
 * when the mail genuinely came from the attacker. Reply, Reply All and Forward
 * all carry the quoted original, so a wrong answer here sends a thread to
 * someone who never sent it.
 *
 * The rule, shared verbatim with the webmail and Linux clients: the real address
 * is the LAST angle-addr, because RFC 5322 puts display-name first and addr-spec
 * last. A bare value is the address itself. Anything without an "@" is not an
 * address and yields "" rather than being passed through as a pseudo-recipient.
 *
 * Deliberately not `android.text.util.Rfc822Tokenizer`: it is framework code and
 * would push these cases into an instrumented test, where they would drift out
 * of step with the other two clients' plain unit tests. The rule is small enough
 * that having all three implement it identically, against the same vectors, is
 * worth more than delegating one of them to a platform parser.
 */
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
