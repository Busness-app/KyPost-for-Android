package com.urlxl.mail.pgp

import okhttp3.HttpUrl.Companion.toHttpUrlOrNull

private const val INBOX = "INBOX"
private const val DRAFTS = "Drafts"

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

/**
 * The webmail URL that opens the Drafts mailbox, used after handing a client-custody composition
 * off to the browser.
 *
 * It targets the mailbox rather than one specific draft because `POST /api/mail/draft` answers with
 * a bare `{ok: true}` and no UID — there is nothing to deep-link to. The draft the user just saved
 * is the newest one there.
 *
 * Unlike INBOX in [webmailMessageUrl], Drafts is passed explicitly: an absent mailbox means INBOX
 * to the web app's read page.
 */
fun webmailDraftsUrl(serverUrl: String): String? {
    val base = "${serverUrl.trimEnd('/')}/read".toHttpUrlOrNull() ?: return null
    return base.newBuilder().addQueryParameter("mailbox", DRAFTS).build().toString()
}

/**
 * The account's webmail home.
 *
 * Used by the Security page's "open webmail" actions, where the destination is "your account in the
 * browser" rather than one message — creating a PGP identity and choosing client custody are both
 * web-session-only actions on the backend.
 *
 * The path is replaced rather than appended: the stored `serverUrl` is the pairing's origin, but a
 * value carrying a path would otherwise produce `…/read/` and land nowhere. `isFirstPartyWebmailUrl`
 * still gates the launch on the origin.
 *
 * The query and fragment are cleared alongside the path: `encodedPath` alone leaves any `?...` or
 * `#...` on the input untouched, so a stored URL carrying one (there is no reason one would, but
 * nothing rules it out) would otherwise survive into the handoff target the same way a path would.
 */
fun webmailHomeUrl(serverUrl: String): String? =
    serverUrl.toHttpUrlOrNull()?.newBuilder()?.encodedPath("/")?.query(null)?.fragment(null)
        ?.build()?.toString()
