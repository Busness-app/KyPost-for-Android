package org.kysecurity.mail.pgp

import okhttp3.HttpUrl
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull

/** Compares the whole origin; [HttpUrl] also refuses `javascript:` and `data:` outright. */
fun isFirstPartyWebmailUrl(serverUrl: String, candidateUrl: String): Boolean {
    val server = serverUrl.toHttpUrlOrNull() ?: return false
    val candidate = candidateUrl.toHttpUrlOrNull() ?: return false
    return server.scheme == candidate.scheme &&
        server.host == candidate.host &&
        server.port == candidate.port
}

/** How to open a webmail URL, in preference order. */
enum class WebmailLaunchMode {
    /** Offer the URL to a non-browser app — in practice the webmail PWA. Ranked first. */
    NATIVE_APP,

    /** A plain `ACTION_VIEW`: "attempt it and catch the failure", not "a handler exists". */
    EXTERNAL_BROWSER,

    /** Refuse. The URL is not this account's webmail. */
    NONE,
}

fun webmailLaunchOrder(isFirstParty: Boolean): List<WebmailLaunchMode> =
    if (!isFirstParty) emptyList()
    else listOf(WebmailLaunchMode.NATIVE_APP, WebmailLaunchMode.EXTERNAL_BROWSER)
