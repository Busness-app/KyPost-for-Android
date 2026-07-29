package com.urlxl.mail.pgp

import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.Color
import android.net.Uri
import android.util.Log
import androidx.browser.customtabs.CustomTabColorSchemeParams
import androidx.browser.customtabs.CustomTabsClient
import androidx.browser.customtabs.CustomTabsIntent
import com.urlxl.mail.getStoredThemePalette

private const val TAG = "WebmailTab"

/**
 * Opens one of this account's own webmail URLs, preferring an in-app Custom Tab.
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
fun openWebmail(activity: Activity, serverUrl: String, url: String): Boolean =
    when (webmailLaunchMode(
        isFirstParty = isFirstPartyWebmailUrl(serverUrl, url),
        hasNativeHandler = nonBrowserHandlerExists(activity, url),
        customTabsPackage = CustomTabsClient.getPackageName(activity, null),
    )) {
        // Plain ACTION_VIEW, exactly as before this change: the system routes it to the verified
        // app-link handler, which is how an installed PWA gets its own window.
        WebmailLaunchMode.NATIVE_APP -> launchExternalBrowser(activity, url)
        WebmailLaunchMode.CUSTOM_TAB -> launchCustomTab(activity, url)
        WebmailLaunchMode.EXTERNAL_BROWSER -> launchExternalBrowser(activity, url)
        WebmailLaunchMode.NONE -> {
            // A programming error, not a user condition: every caller builds this URL from the
            // pairing. Logged loudly so it surfaces rather than looking like a dead button.
            Log.e(TAG, "Refused to open a URL that is not this account's webmail")
            false
        }
    }

/**
 * Whether some app that is **not** a browser claims [url] — in practice the webmail PWA.
 *
 * Works by difference: every browser answers `VIEW`/`BROWSABLE` for an arbitrary https URL, so
 * anything that answers for *this* URL but not for a throwaway one is a host-specific handler.
 *
 * **Known limitation.** Under `minSdk 31` package-visibility filtering this can return a false
 * negative: the manifest `<queries>` filter declares `https` with no host, and an app whose own
 * filter requires a specific host may not be visible through it. A false negative costs the PWA
 * user a Custom Tab instead of their PWA — the behaviour we would have had without this check at
 * all — so it degrades in the safe direction. Verify on a device with the PWA installed
 * (see the manual verification section) rather than assuming either way.
 */
private fun nonBrowserHandlerExists(activity: Activity, url: String): Boolean = runCatching {
    val pm = activity.packageManager
    fun handlersOf(target: String): Set<String> = pm.queryIntentActivities(
        Intent(Intent.ACTION_VIEW, Uri.parse(target)).addCategory(Intent.CATEGORY_BROWSABLE),
        PackageManager.MATCH_DEFAULT_ONLY,
    ).map { it.activityInfo.packageName }.toSet()

    // A domain reserved by RFC 6761 for exactly this: it resolves nowhere, so only apps claiming
    // https in general — browsers — can answer for it.
    val browsers = handlersOf("https://invalid.")
    (handlersOf(url) - browsers).isNotEmpty()
}.onFailure { Log.w(TAG, "Could not probe for a native handler; assuming none", it) }
    .getOrDefault(false)

private fun launchCustomTab(activity: Activity, url: String): Boolean {
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

    // launchUrl throws ActivityNotFoundException if the browser vanished between the
    // getPackageName check and here (an uninstall, or a work-profile change).
    return runCatching { builder.build().launchUrl(activity, Uri.parse(url)) }
        .onFailure { Log.w(TAG, "Custom Tab launch failed; no tab was opened", it) }
        .isSuccess
}

/**
 * Serves both [WebmailLaunchMode.NATIVE_APP] and [WebmailLaunchMode.EXTERNAL_BROWSER]: the
 * previous behaviour, minus the `resolveActivity` guard.
 *
 * One function for two modes because the intent is identical — the difference is only *why* we
 * chose it, and the system does the routing either way. `CATEGORY_BROWSABLE` is deliberately
 * **not** added: it would narrow resolution to browsers and shut out the very PWA the
 * `NATIVE_APP` mode exists to reach. (`openExternally` in `EmailDetailActivity` does add it, for
 * the opposite reason — those URLs come from senders.)
 *
 * The dropped guard was a false-negative trap. With `minSdk 31` and package-visibility filtering,
 * `resolveActivity` returns null for an implicit https intent even when a browser is installed,
 * so the read path could report "no webmail" to a user who had one — stalling the only route a
 * client-custody account has to an encrypted message. `ComposeActivity` documented this and
 * avoided it; this path did not. Attempt the launch, catch the genuine no-handler case.
 */
private fun launchExternalBrowser(activity: Activity, url: String): Boolean =
    runCatching { activity.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url))) }
        .onFailure { Log.w(TAG, "No app on this device could open the webmail URL", it) }
        .isSuccess
