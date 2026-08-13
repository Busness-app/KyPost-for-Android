package org.kysecurity.mail.pgp

import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.util.Log

private const val TAG = "WebmailTab"

/**
 * Opens one of this account's own webmail URLs in a **separate task**: the installed PWA if there
 * is one, otherwise whatever browser the device has. [webmailLaunchOrder] owns that order; this
 * walks it and stops at the first mode that actually launched.
 *
 * It is not an in-app WebView, and that is deliberate — the user's real browser carries the
 * session cookies webmail already holds, so there is no second login, and this app cannot read its
 * contents or its account-password field.
 *
 * **There is no Custom Tab path, and that is the security property.** A Custom Tab is the
 * browser's activity launched into *this* app's task, and `FLAG_SECURE` is a per-window flag: the
 * blanket one [org.kysecurity.mail.security.LockedActivity] sets on every KyPost window does not
 * reach the browser's. The Recents card for the KyPost task would then show decrypted message
 * content, on the one app whose every other screen is blank there — while the user's own choice of
 * browser, and whatever Recents posture it keeps, is the boundary they already accepted. The tab
 * bought one thing: a back gesture returning here instead of a task switch. That is not worth
 * paying for with plaintext in a task preview, so it is gone rather than shipped unverified.
 *
 * Only ever called with a URL built from the pairing's own `serverUrl`; [isFirstPartyWebmailUrl]
 * enforces that rather than trusting it.
 *
 * @return true if something was launched. False means the caller should tell the user it could not
 *   open, and is *not* the same as the user dismissing the browser.
 */
fun openWebmail(activity: Activity, serverUrl: String, url: String): Boolean {
    val order = webmailLaunchOrder(isFirstParty = isFirstPartyWebmailUrl(serverUrl, url))
    if (order.isEmpty()) {
        // A programming error, not a user condition: every caller builds this URL from the
        // pairing. Logged loudly so it surfaces rather than looking like a dead button. Nothing
        // below runs, so a refused URL never reaches the system at all.
        Log.e(TAG, "Refused to open a URL that is not this account's webmail")
        return false
    }
    // First success wins — `any` stops there. Every launcher reports failure instead of throwing,
    // so the fallback chain is walked in order and a device that can open the URL no way at all
    // ends up back at the caller with false rather than a crash.
    return order.any { mode ->
        when (mode) {
            WebmailLaunchMode.NATIVE_APP -> launchNonBrowser(activity, url)
            WebmailLaunchMode.EXTERNAL_BROWSER -> launchExternalBrowser(activity, url)
            WebmailLaunchMode.NONE -> false
        }
    }
}

/**
 * `ACTION_VIEW` + `CATEGORY_BROWSABLE` — a *web intent* in the platform's sense, which is what
 * makes firing it implicitly safe.
 *
 * The category is the security control here, not decoration. Android's domain-verification gate
 * applies **only** to web intents: an app that declares `<data android:scheme="https"
 * android:host="<the paired server>"/>` with no verified `assetlinks.json` is excluded from
 * resolution only when the intent carries BROWSABLE. Without it, any installed app may claim the
 * paired server's host and answer this handoff with a convincing fake webmail login — a credential
 * harvest aimed at the one screen a client-custody account has no alternative to. `openExternally`
 * in `EmailDetailActivity` adds the category for the same reason, and a browser gets it too.
 *
 * It costs nothing on the PWA path an earlier comment here worried about. A WebAPK's VIEW filter,
 * like any app link's, is *required* to declare BROWSABLE, and an intent's categories only ever
 * narrow the match to filters that declare them — so adding it can exclude only components that
 * never declared it, which is precisely the set that must be excluded.
 */
private fun webIntent(url: String): Intent =
    Intent(Intent.ACTION_VIEW, Uri.parse(url)).addCategory(Intent.CATEGORY_BROWSABLE)

/**
 * [WebmailLaunchMode.NATIVE_APP]: offer the URL to the webmail PWA, and fail if only browsers want
 * it.
 *
 * `FLAG_ACTIVITY_REQUIRE_NON_BROWSER` (API 30; this app is `minSdk 31`) is what makes the
 * preference real instead of a guess. The system resolves it at launch time and throws
 * `ActivityNotFoundException` when every candidate is a browser, so a miss costs one caught
 * exception and falls through to the browser.
 *
 * It replaces a `queryIntentActivities` probe that could not have worked. The manifest `<queries>`
 * entry declared `https` with no authority, so the synthesised visibility-match intent had a null
 * host, and `IntentFilter.matchDataAuthority` returns no match against a filter that declares one —
 * which a WebAPK always does. The PWA was invisible through that grant, this mode never fired on
 * any device, and no amount of testing the pure decision function would have shown it. Asking the
 * system at launch time sidesteps package visibility entirely and needs no `<queries>` grant.
 */
private fun launchNonBrowser(activity: Activity, url: String): Boolean =
    runCatching {
        activity.startActivity(webIntent(url).addFlags(Intent.FLAG_ACTIVITY_REQUIRE_NON_BROWSER))
    }.onFailure { Log.d(TAG, "No non-browser app claims the webmail URL; falling through", it) }
        .isSuccess

/**
 * [WebmailLaunchMode.EXTERNAL_BROWSER]: the last resort, and the previous behaviour of this handoff
 * minus the `resolveActivity` guard.
 *
 * Same web intent as [launchNonBrowser] without the non-browser flag, so a browser — the thing the
 * flag exists to exclude — is exactly what answers it.
 *
 * The dropped guard was a false-negative trap. With `minSdk 31` and package-visibility filtering,
 * `resolveActivity` returns null for an implicit https intent even when a browser is installed,
 * so the read path could report "no webmail" to a user who had one — stalling the only route a
 * client-custody account has to an encrypted message. `ComposeActivity` documented this and
 * avoided it; this path did not. Attempt the launch, catch the genuine no-handler case.
 */
private fun launchExternalBrowser(activity: Activity, url: String): Boolean =
    runCatching { activity.startActivity(webIntent(url)) }
        .onFailure { Log.w(TAG, "No app on this device could open the webmail URL", it) }
        .isSuccess
