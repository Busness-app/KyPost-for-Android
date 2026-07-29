package com.urlxl.mail.pgp

import okhttp3.HttpUrl
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull

/**
 * Whether [candidateUrl] belongs to the same origin as the paired server.
 *
 * The gate on opening a URL in a Custom Tab. Unlike an external browser, a Custom Tab renders
 * inside this app's task with this app's toolbar colour, so a page opened in one reads to the
 * user as part of the app. Handing an attacker-chosen URL to that is a phishing primitive, which
 * is why this compares the whole origin — scheme, host and port — and not merely the host.
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
     * A non-browser app claims this URL — in practice the webmail PWA.
     *
     * Ranked above [CUSTOM_TAB] because it is already the best experience available: a standalone
     * window with the session it holds, and no browser chrome. A Custom Tab targets a browser and
     * does not honour verified app links, so preferring one here would take the PWA away from the
     * users who currently have the smoothest path.
     */
    NATIVE_APP,

    /** In-app Custom Tab: shares the browser's session, no task switch. */
    CUSTOM_TAB,

    /**
     * A plain `ACTION_VIEW` intent, for a device with no Custom Tabs-capable browser.
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
 * Picks the launch mode.
 *
 * [hasNativeHandler] and [customTabsPackage] are both probed by the caller — see `WebmailTab.kt` —
 * rather than read here, so this stays a pure function with no Android dependency and the
 * precedence order itself is unit-testable.
 *
 * A non-first-party URL is [WebmailLaunchMode.NONE] rather than
 * [WebmailLaunchMode.EXTERNAL_BROWSER] on purpose: every caller of this builds its URL from the
 * pairing's own `serverUrl`, so a failure here is a programming error, not a user situation to
 * degrade gracefully around. Silently opening it elsewhere would hide the bug.
 */
fun webmailLaunchMode(
    isFirstParty: Boolean,
    hasNativeHandler: Boolean,
    customTabsPackage: String?,
): WebmailLaunchMode = when {
    !isFirstParty -> WebmailLaunchMode.NONE
    hasNativeHandler -> WebmailLaunchMode.NATIVE_APP
    customTabsPackage != null -> WebmailLaunchMode.CUSTOM_TAB
    else -> WebmailLaunchMode.EXTERNAL_BROWSER
}
