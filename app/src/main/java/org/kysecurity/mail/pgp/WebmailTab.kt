package org.kysecurity.mail.pgp

import android.app.Activity
import android.content.Intent
import android.graphics.Color
import android.net.Uri
import android.util.Log
import androidx.browser.customtabs.CustomTabColorSchemeParams
import androidx.browser.customtabs.CustomTabsClient
import androidx.browser.customtabs.CustomTabsIntent
import org.kysecurity.mail.getStoredThemePalette

private const val TAG = "WebmailTab"

/**
 * Opens one of this account's own webmail URLs: the installed PWA if there is one, otherwise an
 * in-app Custom Tab, otherwise whatever browser the device has. [webmailLaunchOrder] owns that
 * order; this walks it and stops at the first mode that actually launched.
 *
 * A Custom Tab is **not** an in-app WebView, and the distinction is the whole point. It is the
 * user's real browser rendering in a real browser process: it carries the session cookies webmail
 * already holds, so there is no second login, and this app cannot read its contents or its form
 * fields. The older comments at these call sites ruled out a WebView on exactly those two grounds
 * — no shared session, and an account-password field inside the app — and neither objection
 * applies here.
 *
 * What it buys is the removal of the task switch: the tab opens over this activity and a back
 * gesture returns to it, instead of the user landing in a separate browser app.
 *
 * Only ever called with a URL built from the pairing's own `serverUrl`; [isFirstPartyWebmailUrl]
 * enforces that rather than trusting it.
 *
 * @return true if a tab or a browser was launched. False means the caller should tell the user
 *   it could not open, and is *not* the same as the user dismissing the tab.
 */
fun openWebmail(activity: Activity, serverUrl: String, url: String): Boolean {
    val customTabsPackage = CustomTabsClient.getPackageName(activity, null)
    val order = webmailLaunchOrder(
        isFirstParty = isFirstPartyWebmailUrl(serverUrl, url),
        customTabsPackage = customTabsPackage,
    )
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
            WebmailLaunchMode.CUSTOM_TAB ->
                customTabsPackage != null && launchCustomTab(activity, url, customTabsPackage)
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
 * exception and falls through to the Custom Tab.
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
 * [WebmailLaunchMode.CUSTOM_TAB]: the browser [customTabsPackage] named by
 * `CustomTabsClient.getPackageName`, rendering over this activity.
 *
 * **Recents exposure — unverified, and deliberately not fixed here.** A Custom Tab is the
 * browser's activity launched into *this* app's task, and `FLAG_SECURE` is a per-window flag: the
 * blanket one [org.kysecurity.mail.security.LockedActivity] sets on every KyPost window does not reach
 * the browser's. So the Recents card for this task may show decrypted message content, on the one
 * app whose every other screen is blank there. This has not been checked on hardware — step 6b of
 * `docs/superpowers/plans/2026-07-29-webmail-custom-tabs.md` is that check — and the launch is left
 * exactly as it is until it has been, because the plausible remedies (a separate task, no tab at
 * all) each trade away something this change exists to deliver.
 */
private fun launchCustomTab(activity: Activity, url: String, customTabsPackage: String): Boolean {
    val builder = CustomTabsIntent.Builder().setShowTitle(true)
    // Match the app's theme so the tab reads as a continuation rather than a jump. Guarded
    // because the palette is stored as hex strings and a bad one must cost the colour, not the
    // whole handoff — which is the only path a client-custody account has to its own mail.
    runCatching {
        val palette = getStoredThemePalette(activity)
        builder.setDefaultColorSchemeParams(
            CustomTabColorSchemeParams.Builder()
                .setToolbarColor(Color.parseColor(palette.panel))
                .build(),
        )
    }.onFailure { Log.w(TAG, "Could not apply the theme colour to the Custom Tab", it) }

    val customTabsIntent = builder.build()
    // Explicit, not implicit: getPackageName has already chosen this browser, so name it rather
    // than letting the system re-resolve an https VIEW intent and possibly land somewhere else.
    customTabsIntent.intent.setPackage(customTabsPackage)

    // launchUrl throws ActivityNotFoundException if the browser vanished between the
    // getPackageName check and here (an uninstall, or a work-profile change).
    return runCatching { customTabsIntent.launchUrl(activity, Uri.parse(url)) }
        .onFailure { Log.w(TAG, "Custom Tab launch failed; no tab was opened", it) }
        .isSuccess
}

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
