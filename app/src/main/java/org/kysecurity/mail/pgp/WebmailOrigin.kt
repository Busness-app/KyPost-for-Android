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
     * *Attempted*, not detected. Nothing here knows whether such an app exists: the launch carries
     * `FLAG_ACTIVITY_REQUIRE_NON_BROWSER` and the system throws when only browsers would have
     * taken it, so the caller finds out by trying and falls through to the next mode. An earlier
     * revision tried to predict it by diffing `queryIntentActivities`, which could never fire —
     * see `launchNonBrowser` in `WebmailTab.kt` for why package-visibility filtering made the PWA
     * invisible on every device.
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
 *
 * An ordered list and not a single verdict because [WebmailLaunchMode.NATIVE_APP] cannot be
 * predicted, only attempted — see its KDoc. A function that returned one mode would have to claim
 * knowledge of an installed PWA that no in-process query can honestly supply, which is exactly the
 * bug this replaced: the probe it used could never return true, so the PWA preference was dead code
 * on every device. Handing the caller a fallback chain lets the system answer the question at
 * launch time, where it is the only party that can.
 *
 * A non-first-party URL yields an empty list — refuse, in the sense of [WebmailLaunchMode.NONE] —
 * rather than degrading to [WebmailLaunchMode.EXTERNAL_BROWSER]: every caller of this builds its
 * URL from the pairing's own `serverUrl`, so a failure here is a programming error, not a user
 * situation to degrade gracefully around. Silently opening it elsewhere would hide the bug. It is
 * also what keeps the guard ahead of the launch attempts, so a refused URL is never handed to the
 * system at all.
 */
fun webmailLaunchOrder(isFirstParty: Boolean): List<WebmailLaunchMode> =
    if (!isFirstParty) emptyList()
    else listOf(WebmailLaunchMode.NATIVE_APP, WebmailLaunchMode.EXTERNAL_BROWSER)
