package org.kysecurity.mail.mail

import org.kysecurity.mail.Email

/**
 * The message a notification tap referred to, or null.
 *
 * Exact id first. The fallback exists because a push id is not always an inbox id — a pull payload
 * carrying no `messageId` is given a synthesised `pull-<seq>` that no row can ever hold. It
 * identifies, it does not guess: sender and subject must both be present, and the candidate must be
 * UNIQUE. Two matches is ambiguity, and resolving ambiguity by opening the first match shows
 * private mail the notification never referred to. Ambiguous means not found.
 */
fun notifiedMessage(emails: List<Email>, id: String, sender: String?, subject: String?): Email? {
    emails.find { it.id == id }?.let { return it }
    val senderHint = sender?.takeIf { it.isNotBlank() } ?: return null
    val subjectHint = subject?.takeIf { it.isNotBlank() } ?: return null
    return emails.singleOrNull {
        it.sender.contains(senderHint, ignoreCase = true) && it.subject == subjectHint
    }
}
