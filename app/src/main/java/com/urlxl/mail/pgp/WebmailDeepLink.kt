package com.urlxl.mail.pgp

import okhttp3.HttpUrl.Companion.toHttpUrlOrNull

private const val INBOX = "INBOX"

/**
 * Builds the webmail URL that opens one specific message.
 *
 * The route already exists and is what a web push notification click uses: ReadPage reads
 * `?message=<id>` (optionally `&tab=`) alongside `?mailbox=`, opens that message once its tab has
 * loaded, then strips both params from the address bar. `tab` is omitted here — without it
 * ReadPage searches every tab, which is what we want since the relay's tab names and the web's
 * are not guaranteed to line up.
 *
 * INBOX is sent as an absent `mailbox` param rather than the literal string, matching the links
 * the web app builds for itself (its own Inbox link is a bare `/read`, and it treats an empty
 * mailbox as the default).
 *
 * Returns null when [serverUrl] isn't a usable absolute URL, which callers render as "no button"
 * rather than a dead one.
 */
fun webmailMessageUrl(serverUrl: String, mailbox: String, messageId: String): String? {
    if (messageId.isBlank()) return null
    val base = "${serverUrl.trimEnd('/')}/read".toHttpUrlOrNull() ?: return null
    return base.newBuilder()
        .apply {
            if (mailbox.isNotBlank() && !mailbox.equals(INBOX, ignoreCase = true)) {
                addQueryParameter("mailbox", mailbox)
            }
        }
        .addQueryParameter("message", messageId)
        .build()
        .toString()
}
