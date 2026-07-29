# Webmail Custom Tabs Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Open the two first-party webmail handoffs in a Chrome Custom Tab instead of throwing the user out to an external browser, removing the app-switch friction for client-custody PGP accounts without building any on-device crypto.

**Architecture:** A pure, JVM-testable origin guard decides whether a URL is genuinely this account's webmail; a pure decision function picks Custom Tab vs external browser vs give-up; a thin Android launcher applies the verdict. The two call sites (`EmailDetailActivity`'s PGP bar and `ComposeActivity`'s draft handoff) delegate to it. Sender-controlled links from mail bodies keep going out to an external browser, untouched.

**Tech Stack:** Kotlin, `androidx.browser` (Custom Tabs), OkHttp `HttpUrl` for origin parsing, plain JUnit for unit tests.

## Global Constraints

- `minSdk = 31`, `targetSdk = 36`, `compileSdk` per `app/build.gradle.kts`.
- Unit tests in `app/src/test` run on the **plain JVM — there is no Robolectric**. Anything referencing an Android framework type (`Uri`, `Intent`, `Context`) cannot be unit-tested. Follow the existing pattern: extract pure logic and test that (`pgpMessageStateOf`, `webmailMessageUrl`, `buildEmailBodyHtml`).
- Use OkHttp `HttpUrl`, **not** `android.net.Uri`, in any code that needs a unit test. `WebmailDeepLink.kt` already does this and `WebmailDeepLinkTest` is why.
- **Never** call `Intent.resolveActivity` for an implicit `https` intent. With `minSdk 31` and package-visibility filtering it returns null even when a browser is present. `ComposeActivity.showHandoffDialog` documents this; `EmailDetailActivity` currently has the bug. Attempt the launch and catch `ActivityNotFoundException`.
- Custom Tabs are for **first-party webmail URLs only** — URLs whose origin equals the paired server's. Sender-controlled links must never open in a Custom Tab: it renders inside the app's task and would lend app trust to an attacker-chosen page.
- Dependencies go through `gradle/libs.versions.toml`, never a raw coordinate in `build.gradle.kts`, unless the file already does so for that library.
- New user-facing strings go in `app/src/main/res/values/strings.xml`.

---

### Task 1: First-party origin guard

The guard that decides whether a URL may be trusted to a Custom Tab. Pure Kotlin so it can be unit-tested, and written before anything that uses it.

**Files:**
- Create: `app/src/main/java/com/urlxl/mail/pgp/WebmailOrigin.kt`
- Test: `app/src/test/java/com/urlxl/mail/pgp/WebmailOriginTest.kt`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `fun isFirstPartyWebmailUrl(serverUrl: String, candidateUrl: String): Boolean`
  - `enum class WebmailLaunchMode { NATIVE_APP, CUSTOM_TAB, EXTERNAL_BROWSER, NONE }`
  - `fun webmailLaunchMode(isFirstParty: Boolean, hasNativeHandler: Boolean, customTabsPackage: String?): WebmailLaunchMode`

**Why `NATIVE_APP` comes first:** both current call sites hand out a bare `ACTION_VIEW` *without* `CATEGORY_BROWSABLE`, and the comment at `EmailDetailActivity.kt:399` says why — "so an installed PWA or the user's browser opens it with the session it already has". If the user has the webmail PWA installed, today the link opens the PWA. `CustomTabsIntent.launchUrl` targets a browser and does not honour verified app links, so a straight swap to Custom Tabs would *downgrade* exactly the users who currently have the least friction. A native handler therefore outranks a Custom Tab.

- [ ] **Step 1: Write the failing test**

Create `app/src/test/java/com/urlxl/mail/pgp/WebmailOriginTest.kt`:

```kotlin
package com.urlxl.mail.pgp

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Covers the guard that decides whether a URL may be opened in a Custom Tab.
 *
 * A Custom Tab renders inside this app's task, so opening an attacker-chosen URL in one would
 * lend the app's trust to a phishing page. Only URLs whose origin equals the paired server's
 * are eligible; everything else falls back to an external browser or is refused.
 */
class WebmailOriginTest {

    private val server = "https://mail.example.com"

    @Test
    fun `accepts a url on the same origin`() {
        assertTrue(isFirstPartyWebmailUrl(server, "https://mail.example.com/read?message=5"))
    }

    @Test
    fun `accepts the server url with a trailing slash`() {
        assertTrue(isFirstPartyWebmailUrl("https://mail.example.com/", "https://mail.example.com/read"))
    }

    @Test
    fun `rejects a different host`() {
        assertFalse(isFirstPartyWebmailUrl(server, "https://evil.example.com/read?message=5"))
    }

    @Test
    fun `rejects a lookalike subdomain`() {
        assertFalse(isFirstPartyWebmailUrl(server, "https://mail.example.com.evil.test/read"))
    }

    @Test
    fun `rejects a different port`() {
        assertFalse(isFirstPartyWebmailUrl("https://mail.example.com:8443", "https://mail.example.com/read"))
    }

    @Test
    fun `rejects a downgrade to http`() {
        assertFalse(isFirstPartyWebmailUrl(server, "http://mail.example.com/read"))
    }

    @Test
    fun `rejects a non-http scheme`() {
        assertFalse(isFirstPartyWebmailUrl(server, "javascript:alert(1)"))
    }

    @Test
    fun `rejects a malformed candidate`() {
        assertFalse(isFirstPartyWebmailUrl(server, "not a url"))
    }

    @Test
    fun `rejects a blank candidate`() {
        assertFalse(isFirstPartyWebmailUrl(server, ""))
    }

    @Test
    fun `rejects a malformed server url`() {
        assertFalse(isFirstPartyWebmailUrl("not a url", "https://mail.example.com/read"))
    }

    @Test
    fun `prefers an installed native handler over a custom tab`() {
        assertEquals(
            WebmailLaunchMode.NATIVE_APP,
            webmailLaunchMode(
                isFirstParty = true,
                hasNativeHandler = true,
                customTabsPackage = "com.android.chrome",
            ),
        )
    }

    @Test
    fun `picks a custom tab when a capable browser is installed and no native handler is`() {
        assertEquals(
            WebmailLaunchMode.CUSTOM_TAB,
            webmailLaunchMode(
                isFirstParty = true,
                hasNativeHandler = false,
                customTabsPackage = "com.android.chrome",
            ),
        )
    }

    @Test
    fun `falls back to an external browser when no capable browser is found`() {
        assertEquals(
            WebmailLaunchMode.EXTERNAL_BROWSER,
            webmailLaunchMode(isFirstParty = true, hasNativeHandler = false, customTabsPackage = null),
        )
    }

    @Test
    fun `prefers a native handler even when no custom tabs browser exists`() {
        assertEquals(
            WebmailLaunchMode.NATIVE_APP,
            webmailLaunchMode(isFirstParty = true, hasNativeHandler = true, customTabsPackage = null),
        )
    }

    @Test
    fun `refuses a url that is not first party even when a custom tab is available`() {
        assertEquals(
            WebmailLaunchMode.NONE,
            webmailLaunchMode(
                isFirstParty = false,
                hasNativeHandler = false,
                customTabsPackage = "com.android.chrome",
            ),
        )
    }

    @Test
    fun `refuses a url that is not first party even when a native handler claims it`() {
        assertEquals(
            WebmailLaunchMode.NONE,
            webmailLaunchMode(isFirstParty = false, hasNativeHandler = true, customTabsPackage = null),
        )
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./gradlew :app:testDebugUnitTest --tests "com.urlxl.mail.pgp.WebmailOriginTest"`

Expected: FAIL — compilation error, `isFirstPartyWebmailUrl` / `WebmailLaunchMode` / `webmailLaunchMode` unresolved.

- [ ] **Step 3: Write minimal implementation**

Create `app/src/main/java/com/urlxl/mail/pgp/WebmailOrigin.kt`:

```kotlin
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `./gradlew :app:testDebugUnitTest --tests "com.urlxl.mail.pgp.WebmailOriginTest"`

Expected: PASS, 16 tests.

- [ ] **Step 5: Commit**

```bash
git add app/src/main/java/com/urlxl/mail/pgp/WebmailOrigin.kt \
        app/src/test/java/com/urlxl/mail/pgp/WebmailOriginTest.kt
git commit -m "feat(pgp): add the first-party origin guard for webmail Custom Tabs"
```

---

### Task 2: The launcher, the dependency, and the read-path call site

Adds `androidx.browser`, the manifest `<queries>` block it needs to see browsers at all, the launcher itself, and rewires `EmailDetailActivity` — which also removes the `resolveActivity` false negative.

**Files:**
- Modify: `gradle/libs.versions.toml`
- Modify: `app/build.gradle.kts:117-150` (the `dependencies` block)
- Modify: `app/src/main/AndroidManifest.xml:2-8` (add `<queries>` after the `<uses-permission>` entries)
- Create: `app/src/main/java/com/urlxl/mail/pgp/WebmailTab.kt`
- Modify: `app/src/main/java/com/urlxl/mail/EmailDetailActivity.kt:390-412` (the `CLIENT_PROTECTED` branch of `renderPgpBar`)

**Interfaces:**
- Consumes: `isFirstPartyWebmailUrl`, `webmailLaunchMode`, `WebmailLaunchMode` from Task 1.
- Produces: `fun openWebmail(activity: Activity, serverUrl: String, url: String): Boolean` — true if something was launched, false if the caller should tell the user it could not be.

- [ ] **Step 1: Add the dependency**

In `gradle/libs.versions.toml`, add to `[versions]` (alphabetical neighbours: after `biometric`):

```toml
browser = "1.8.0"
```

and to `[libraries]`:

```toml
androidx-browser = { group = "androidx.browser", name = "browser", version.ref = "browser" }
```

In `app/build.gradle.kts`, add alongside the other `libs.` entries (next to `libs.androidx.biometric`):

```kotlin
    implementation(libs.androidx.browser)
```

- [ ] **Step 2: Add the manifest `<queries>` block**

`CustomTabsClient.getPackageName` enumerates installed browsers. Under `minSdk 31` package-visibility filtering it sees nothing without an explicit declaration, so it would return null on every device and the Custom Tab path would be dead code.

In `app/src/main/AndroidManifest.xml`, insert between the last `<uses-permission>` and `<application>`:

```xml
    <!--
      Package visibility for browsers only, so CustomTabsClient.getPackageName can find a
      Custom Tabs-capable one. Without this, minSdk 31's filtering hides every browser and the
      Custom Tab path silently degrades to an external-browser launch on all devices.

      Deliberately an <intent> filter and not QUERY_ALL_PACKAGES: this grants sight of apps that
      answer VIEW/BROWSABLE for https, which is the question being asked, and nothing else.
    -->
    <queries>
        <intent>
            <action android:name="android.intent.action.VIEW" />
            <category android:name="android.intent.category.BROWSABLE" />
            <data android:scheme="https" />
        </intent>
    </queries>
```

- [ ] **Step 3: Verify the project still builds**

Run: `./gradlew :app:assembleDebug`

Expected: BUILD SUCCESSFUL. If `androidx.browser:browser:1.8.0` fails to resolve, check the version exists rather than dropping the version catalog entry.

- [ ] **Step 4: Write the launcher**

Create `app/src/main/java/com/urlxl/mail/pgp/WebmailTab.kt`:

```kotlin
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
```

- [ ] **Step 5: Rewire the read path**

In `app/src/main/java/com/urlxl/mail/EmailDetailActivity.kt`, replace the `CLIENT_PROTECTED` branch body of `renderPgpBar` (currently lines ~390-412) with:

```kotlin
            PgpMessageState.CLIENT_PROTECTED -> {
                if (webmailUrl == null) {
                    pgpText.text = getString(R.string.email_pgp_client_protected) +
                        "\n" + getString(R.string.email_pgp_no_webmail)
                } else {
                    pgpText.text = getString(R.string.email_pgp_client_protected)
                    btnOpenInWebmail.visibility = View.VISIBLE
                    // A Custom Tab where one is available: the user's real browser, with the
                    // session webmail already holds, rendered over this activity so a back
                    // gesture comes straight back to the message list. See WebmailTab for why
                    // this is not the in-app WebView the old comment here ruled out.
                    btnOpenInWebmail.setOnClickListener {
                        val serverUrl = pairedServerUrl
                        if (serverUrl == null || !openWebmail(this, serverUrl, webmailUrl)) {
                            Toast.makeText(this, R.string.email_pgp_no_webmail, Toast.LENGTH_LONG).show()
                        }
                    }
                }
            }
```

`openWebmail` needs the server URL, which the existing code already reads off the pairing to *build* `webmailUrl` but then discards. Capture it. In the body-loading callback (around line 276), change:

```kotlin
        val webmailUrl = if (pgpState == PgpMessageState.CLIENT_PROTECTED) {
            PushRuntime.graph(this).repository.pairingForAuthenticatedCall()?.serverUrl
                ?.let { webmailMessageUrl(it, emailFolder, emailId) }
        } else {
            null
        }
```

to:

```kotlin
        // Resolved off the main thread with the URL it builds — pairingForAuthenticatedCall
        // reads Keystore-backed EncryptedSharedPreferences, which is disk I/O. Both are kept:
        // openWebmail re-derives the origin from serverUrl to check the URL it is handed.
        val serverUrl = if (pgpState == PgpMessageState.CLIENT_PROTECTED) {
            PushRuntime.graph(this).repository.pairingForAuthenticatedCall()?.serverUrl
        } else {
            null
        }
        val webmailUrl = serverUrl?.let { webmailMessageUrl(it, emailFolder, emailId) }
```

Add a field alongside the other render-state fields (near `lastRenderedHtml`):

```kotlin
    /** The paired server's URL, captured with the webmail link so the Custom Tab launcher can
     *  re-check the link's origin without another disk read on the main thread. */
    private var pairedServerUrl: String? = null
```

and set it in the `runOnUiThread` block next to `lastRenderedHtml = htmlContent`:

```kotlin
            pairedServerUrl = serverUrl
```

Add the import:

```kotlin
import com.urlxl.mail.pgp.openWebmail
```

- [ ] **Step 6: Verify it builds and the existing tests still pass**

Run: `./gradlew :app:assembleDebug :app:testDebugUnitTest`

Expected: BUILD SUCCESSFUL, all existing tests pass. `EmailDetailActivityTest` and `PgpMessageStateTest` cover the pure helpers and must be unaffected.

- [ ] **Step 7: Commit**

```bash
git add gradle/libs.versions.toml app/build.gradle.kts \
        app/src/main/AndroidManifest.xml \
        app/src/main/java/com/urlxl/mail/pgp/WebmailTab.kt \
        app/src/main/java/com/urlxl/mail/EmailDetailActivity.kt
git commit -m "feat(pgp): open a client-protected message's webmail link in a Custom Tab

Also drops the resolveActivity guard on this path, which under minSdk 31
package-visibility filtering returns null even when a browser is installed —
reporting no webmail to users who had one."
```

---

### Task 3: The compose draft handoff — writing email

The second and last first-party handoff, and the write-side counterpart to Task 2: a client-custody account cannot encrypt or sign on device, so composing ends with the draft saved over the paired credentials and the user sent to webmail to press send.

Reading (Task 2) and writing (this task) get **the same treatment through the same `openWebmail` entry point** — Custom Tab where available, external browser otherwise, no `resolveActivity`. `grep -rn "webmailDraftsUrl\|webmailMessageUrl" app/src/main/java/` returns exactly these two call sites, so after this task every first-party webmail handoff in the app is converted.

**Files:**
- Modify: `app/src/main/java/com/urlxl/mail/ComposeActivity.kt:685-707` (`showHandoffDialog`)

**Interfaces:**
- Consumes: `openWebmail` from Task 2.
- Produces: nothing new.

- [ ] **Step 1: Pass the server URL through to the dialog**

The caller already has it: `val url = serverUrl?.let { webmailDraftsUrl(it) }` at line 660. `serverUrl` is a local `val`, so restructuring the null check lets Kotlin smart-cast both to non-null in the `else` branch.

At lines 674-678, replace:

```kotlin
                        url == null -> {
                            webmailChip.isEnabled = true
                            Toast.makeText(this, R.string.compose_handoff_no_webmail, Toast.LENGTH_LONG).show()
                        }
                        else -> showHandoffDialog(url)
```

with:

```kotlin
                        serverUrl == null || url == null -> {
                            webmailChip.isEnabled = true
                            Toast.makeText(this, R.string.compose_handoff_no_webmail, Toast.LENGTH_LONG).show()
                        }
                        else -> showHandoffDialog(serverUrl, url)
```

- [ ] **Step 2: Rewire the dialog**

Change the signature at line 685 to `private fun showHandoffDialog(serverUrl: String, url: String)` and replace the positive-button body with:

```kotlin
            .setPositiveButton(R.string.compose_handoff_dialog_confirm) { _, _ ->
                // Prefers an in-app Custom Tab, which carries the browser session webmail
                // already holds, so the user is not asked to log in again just to press send.
                // Falls back to an external browser where no Custom Tabs-capable browser
                // exists. Still no resolveActivity: see WebmailTab.launchExternalBrowser.
                if (openWebmail(this, serverUrl, url)) {
                    finish()
                } else {
                    Toast.makeText(this, R.string.compose_handoff_no_handler, Toast.LENGTH_LONG).show()
                }
            }
```

Add the import:

```kotlin
import com.urlxl.mail.pgp.openWebmail
```

Delete the `import android.content.ActivityNotFoundException` at line 3. The `catch` at line 701 is its only use in this file and the replacement above removes it — confirm with `grep -n "ActivityNotFoundException" app/src/main/java/com/urlxl/mail/ComposeActivity.kt`, which should return nothing afterwards.

Leave the `setOnDismissListener { webmailChip.isEnabled = true }` exactly as it is.

- [ ] **Step 3: Verify it builds and tests pass**

Run: `./gradlew :app:assembleDebug :app:testDebugUnitTest`

Expected: BUILD SUCCESSFUL, all tests pass.

- [ ] **Step 4: Commit**

```bash
git add app/src/main/java/com/urlxl/mail/ComposeActivity.kt
git commit -m "feat(pgp): open the client-custody draft handoff in a Custom Tab"
```

---

### Task 4: Confirm the sender-link path is untouched, and record the boundary

The one thing this change must not do is route attacker-controlled URLs through a Custom Tab. This task proves it and writes the reason down where the next person will look.

**Files:**
- Modify: `app/src/main/java/com/urlxl/mail/EmailDetailActivity.kt:598-611` (`openExternally` — comment only)

**Interfaces:**
- Consumes: nothing.
- Produces: nothing.

- [ ] **Step 1: Verify no sender-controlled path calls the launcher**

Run: `grep -rn "openWebmail" app/src/main/java/`

Expected: exactly three hits — the definition in `WebmailTab.kt`, the `CLIENT_PROTECTED` branch in `EmailDetailActivity.kt`, and the handoff dialog in `ComposeActivity.kt`. Any hit inside `openExternally`, the `WebViewClient`, or an attachment path is a defect — remove it.

- [ ] **Step 2: Record the boundary in the code**

Append to the KDoc on `openExternally` in `EmailDetailActivity.kt`:

```kotlin
     *  Deliberately NOT a Custom Tab, unlike the webmail handoff in renderPgpBar. A Custom Tab
     *  renders inside this app's task wearing this app's toolbar colour, so a page opened in one
     *  reads to the user as part of the app. That is the right frame for the user's own webmail
     *  and precisely the wrong one for a URL chosen by whoever sent the email. Sender-controlled
     *  links go to a separate browser app, where the address bar and the app switch are the
     *  cues that this is somewhere else.
```

- [ ] **Step 3: Verify it builds**

Run: `./gradlew :app:assembleDebug`

Expected: BUILD SUCCESSFUL.

- [ ] **Step 4: Commit**

```bash
git add app/src/main/java/com/urlxl/mail/EmailDetailActivity.kt
git commit -m "docs(mail): record why sender links do not get a Custom Tab"
```

---

### Task 5: Amend the design spec

`docs/superpowers/specs/2026-07-29-on-device-pgp-decryption-design.md` (commit `e499aaa`) currently reads as "build the on-device crypto". That is no longer the immediate recommendation, and leaving it unqualified will send the next reader down the expensive path.

**Files:**
- Modify: `docs/superpowers/specs/2026-07-29-on-device-pgp-decryption-design.md`

- [ ] **Step 1: Add a status note directly under the title**

```markdown
> **Status (2026-07-29): deferred behind a cheaper step.** The context-switch
> friction this spec targets is being addressed first with in-app Custom Tabs
> (`docs/superpowers/plans/2026-07-29-webmail-custom-tabs.md`), which removes the
> app switch and the re-login for a fraction of the cost and no new cryptography.
> Build what follows only if measured friction survives that change.
>
> Two corrections to the reasoning below, found while planning that work:
>
> - On-device decryption is **not** an offline win. Ciphertext is fetched per
>   message from `/api/mail/pgp-payload`, so it needs the network regardless.
> - It may **increase** passphrase prompts rather than reduce them. The web vault
>   holds the unwrapped key for the life of the page; an Android vault clears on
>   app lock, `onTrimMemory` and process death.
```

- [ ] **Step 2: Correct the Lever C paragraph**

Under "Lever C — a separate PGP passphrase", replace "The largest posture win available, and it is a *server* change." with:

```markdown
The largest posture win available. It is a **browser** change plus a small server
flag — not server cryptography. The server holds only a scrypt hash of the
password and cannot derive the wrapping key, so it cannot rewrap anything;
`frontend/src/lib/keyVault.ts` does the wrapping and `POST /api/pgp/identity/rewrap`
merely stores the resulting blob. That endpoint is `withAuth` (session only) and
`run4_security_fixes_test.go:334` asserts a paired device cannot call it, so
rewrapping from the phone is closed off by design.

Worth doing on its own merits regardless of Android: `E2E_PGP.md` lists "admin
password reset destroys the key" as an inherent cost of the model. It is inherent
only because the wrapping secret *is* the account password. Under a separate
passphrase, a password reset stops touching the key.
```

- [ ] **Step 3: Commit**

```bash
git add docs/superpowers/specs/2026-07-29-on-device-pgp-decryption-design.md
git commit -m "docs: defer on-device PGP decryption behind the Custom Tabs step"
```

---

## Manual verification

Custom Tabs cannot be meaningfully unit-tested — the pure decision logic is covered in Task 1, and the launch itself needs a device. Run all of this on real hardware with a **client-custody** account:

1. **The read path.** Open an encrypted message showing 🔒. Tap "Open in webmail". Expect a tab over the app, the app's panel colour in its toolbar, webmail already logged in, and the message opening. Press back: expect the message list, not the launcher.
2. **The session claim.** The point of this change is no second login. If webmail asks you to log in, confirm you are logged in to the same server in your default browser first — if you are, and it still asks, the Custom Tab is not sharing the session and this whole approach needs re-examining before Tasks 3-5 are worth keeping.
3. **The compose path.** Compose to a recipient from a client-custody account, trigger the handoff, confirm the dialog, expect a tab on the Drafts view with your draft present.
4. **The fallback.** On a device or emulator image with no Custom Tabs-capable browser, expect both paths to open an external browser rather than toasting "no webmail". This is the `resolveActivity` regression under test.
4a. **PWA precedence — the check that this change does not downgrade anyone.** Install the webmail PWA ("Add to Home screen" from webmail in Chrome), then use both handoffs. Expect the **PWA**, in its own window, not a Custom Tab. Then uninstall it and repeat: expect a Custom Tab. If the PWA case opens a Custom Tab instead, the `FLAG_ACTIVITY_REQUIRE_NON_BROWSER` attempt in `WebmailTab.launchNonBrowser` is throwing — check logcat for its debug line, and confirm the WebAPK really is verified for the webmail host. That is a safe-direction failure, not a crash, but it means PWA users lose their PWA, so decide deliberately whether to ship it before merging rather than treating it as a detail. (The original probe-based version of this preference could never fire at all; see that function's KDoc.)
5. **Sender links are unchanged.** Open a message containing an ordinary http link. Tap it. Expect a separate browser app with a visible address bar — *not* an in-app tab.
6. **Hostile Location Protection.** Enable HLM, then open the webmail handoff. Note honestly: the Custom Tab's cookies and history live in the **browser's** profile, which `SecurityWipe.clearWebViewState` cannot reach — it clears this app's `app_webview` directory only. That is unchanged from the current external-browser behaviour and is not a regression, but HLM's "nothing about your mail is on disk" claim has never covered the external browser and still does not. Do not describe this change as improving it.
6b. **The Recents card — the one open question this change ships with.** Open a client-protected message, tap "Open in webmail" and let the tab load the message. Swipe to Recents *without* leaving the tab, and report exactly what the KyPost card shows: the message content, a blank card, or the message list underneath. A Custom Tab is the browser's activity inside this app's task and `FLAG_SECURE` is per-window, so the blanket flag `LockedActivity` sets on every KyPost window does not cover it — decrypted mail may be visible in Recents on the one app where every other screen is blank there. Nothing has been changed to prevent this yet; the answer to this check decides whether it needs to be. Do the same on the compose handoff (step 3) and report both.
