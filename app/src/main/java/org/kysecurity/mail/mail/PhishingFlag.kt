package org.kysecurity.mail.mail

/**
 * The IMAP keyword the server sets on inbound mail that impersonates KyPost itself — see
 * `backend/internal/processor/phish_scan.go`.
 *
 * `$Phishing` is the reserved RFC 8621 keyword, so other mail clients understand it too. The message
 * is flagged in place: it stays in the inbox, stays unread, and keeps its body. Nothing here moves
 * or hides mail.
 *
 * A mirrored literal rather than a shared constant — the other clients are TypeScript and QML, with
 * no cross-repo artifact to share it through. The keyword string itself is the contract.
 */
const val PHISHING_KEYWORD = "\$Phishing"

fun isFlaggedPhishing(keywords: Set<String>): Boolean =
    keywords.any { it.trim().equals(PHISHING_KEYWORD, ignoreCase = true) }
