package org.kysecurity.mail.pgp

import okhttp3.HttpUrl
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull

/**
 * Whether [candidateUrl] belongs to the same origin as the paired server.
 *
 * The gate on the webmail handoff. Every caller builds its URL from the pairing's own `serverUrl`,
 * and this refuses anything else rather than trusting that: the handoff is the one place the app
 * tells the user "this is your mail, sign in here", so an attacker-chosen URL reaching it is a
 * credential-harvest primitive. Compares the whole origin — scheme, host and port — not the host
 * alone.
 *
 * Uses OkHttp's [HttpUrl] rather than `android.net.Uri` so it is unit-testable on a plain JVM,
 * matching [webmailMessageUrl] in `WebmailDeepLink.kt`. [HttpUrl] additionally refuses any
 * non-http(s) scheme outright, so `javascript:` and `data:` never reach the comparison.
 */
fun isFirstPartyWebmailUrl(serverUrl: String, candidateUrl: String): Boolean {
    val server = serverUrl.toHttpUrlOrNull() ?: return false
    val candidate = candidateUrl.toHttpUrlOrNull() ?: return false
    return server.scheme == candidate.scheme &&
        server.host == candidate.host &&
        server.port == candidate.port
}

/** How to open a webmail URL, in preference order. */
enum class WebmailLaunchMode {
    /**
     * Offer the URL to a non-browser app — in practice the webmail PWA.
     *
     * Ranked first because it is the best experience available: a standalone window with the
     * session it holds, and no browser chrome.
     */
    NATIVE_APP,

    /**
     * A plain `ACTION_VIEW` intent — the user's browser, in the browser's own task.
     *
     * Whether *any* handler exists cannot be determined in advance — see the note on
     * `resolveActivity` in this plan's constraints — so this mode means "attempt it and catch
     * the failure", not "a handler is known to exist".
     */
    EXTERNAL_BROWSER,

    /** Refuse. The URL is not this account's webmail. */
    NONE,
}

/**
 * The modes to try, best first, until one of them actually launches.
 */
fun webmailLaunchOrder(isFirstParty: Boolean): List<WebmailLaunchMode> =
    if (!isFirstParty) emptyList()
    else listOf(WebmailLaunchMode.NATIVE_APP, WebmailLaunchMode.EXTERNAL_BROWSER)
