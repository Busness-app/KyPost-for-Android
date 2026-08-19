package org.kysecurity.mail.pgp

import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.util.Log

private const val TAG = "WebmailTab"

/** No Custom Tab path: `FLAG_SECURE` is per-window, so Recents would show decrypted content. */
fun openWebmail(activity: Activity, serverUrl: String, url: String): Boolean {
    val order = webmailLaunchOrder(isFirstParty = isFirstPartyWebmailUrl(serverUrl, url))
    if (order.isEmpty()) {
        // A programming error, not a user condition: every caller builds this URL from the pairing.
        Log.e(TAG, "Refused to open a URL that is not this account's webmail")
        return false
    }
    // First success wins. Every launcher reports failure instead of throwing, so the chain is
    // walked in order and a device that cannot open the URL at all returns false rather than crashing.
    return order.any { mode ->
        when (mode) {
            WebmailLaunchMode.NATIVE_APP -> launchNonBrowser(activity, url)
            WebmailLaunchMode.EXTERNAL_BROWSER -> launchExternalBrowser(activity, url)
            WebmailLaunchMode.NONE -> false
        }
    }
}

/** `CATEGORY_BROWSABLE` is the security control: domain verification applies only to web intents. */
private fun webIntent(url: String): Intent =
    Intent(Intent.ACTION_VIEW, Uri.parse(url)).addCategory(Intent.CATEGORY_BROWSABLE)

/** `FLAG_ACTIVITY_REQUIRE_NON_BROWSER` throws when every candidate is a browser; we fall through. */
private fun launchNonBrowser(activity: Activity, url: String): Boolean =
    runCatching {
        activity.startActivity(webIntent(url).addFlags(Intent.FLAG_ACTIVITY_REQUIRE_NON_BROWSER))
    }.onFailure { Log.d(TAG, "No non-browser app claims the webmail URL; falling through", it) }
        .isSuccess

/** No `resolveActivity` guard — package-visibility filtering makes it null even with a browser. */
private fun launchExternalBrowser(activity: Activity, url: String): Boolean =
    runCatching { activity.startActivity(webIntent(url)) }
        .onFailure { Log.w(TAG, "No app on this device could open the webmail URL", it) }
        .isSuccess
