# Security/Keyword Spacing + Push Data-Leak Warning Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give the Security and Keyword settings screens real breathing room (they're currently laid out with raw-pixel padding that reads as ~8dp on real devices), and add an always-visible warning under "Require unlock to receive push/MFA" explaining that push notifications relay message metadata through a third-party server regardless of that toggle's state.

**Architecture:** Both target screens (`SecuritySettingsActivity`, `KeywordSettingsActivity`) build their view tree by hand in Kotlin (no XML/Compose). Add a small, testable pixel-scaling helper plus a warning-callout theme helper to the shared `AppTheme.kt` (same file both activities already read from — `applyThemeToActivity`, `applyTopInsetWithHeader`, etc. all live there), then use them in both activities to convert padding to real dp and add margins between sibling controls, and to style the new warning `TextView`.

**Tech Stack:** Kotlin, Android Views (`LinearLayout`/`ScrollView`/`Switch`/`TextView`), JUnit (plain, no Robolectric — this project has no Android-framework test harness for view code; confirmed no `Robolectric` dependency and no `AppThemeTest`/`AboutDialogTest`/etc. exist for any existing view-construction code).

## Global Constraints

- Match the existing local `dp()`-closure pattern already used in `AboutDialog.kt` conceptually, but since the same conversion is needed in two new files, factor it into one shared, testable function in `AppTheme.kt` instead of duplicating a private closure — see spec's "Spacing" section.
- No Robolectric/Espresso in this project; do not add test infra as part of this plan (out of scope per spec). The one piece of genuinely testable new logic (the dp→px arithmetic) gets a plain-JUnit test; the Activity view-tree changes are verified by building + a manual on-device check, matching how every other hand-built screen in this codebase (`AboutDialog.kt`, `PushPairingActivity.kt`, etc.) is verified today.
- Warning copy is exactly: "Push always sends the sender and subject through Google/UnifiedPush relay servers, even with this on. For zero leakage, ask your server admin to switch this device to Pull mode instead." (confirmed with user).
- Reuse the existing `COLOR_WARNING` semantic color family (`STYLE_GUIDE.md` §1) rather than introducing a new palette; extend it with border/fill/text variants mirroring the existing `COLOR_DANGER_ACTION_*` triplet's naming and alpha values exactly.
- The new warning is always visible under the credential-gate toggle, regardless of the toggle's on/off state (not gated on `isChecked`).

---

## File Structure

- Modify `app/src/main/java/com/urlxl/mail/AppTheme.kt` — add `scalePxByDensity` (pure, tested), `dpToPx` (wraps it with the file's existing `density` snapshot), `LinearLayout.addViewSpaced` (extension used by both activities to add margins), `COLOR_WARNING_ACTION_BORDER`/`COLOR_WARNING_ACTION_FILL`/`COLOR_WARNING_ACTION_TEXT` constants, `warningCalloutBackground()`, and `applyWarningCalloutTheme(context, textView)`.
- Create `app/src/test/java/com/urlxl/mail/AppThemeScalingTest.kt` — unit test for `scalePxByDensity`.
- Modify `app/src/main/res/values/strings.xml` — add `security_credential_gate_leak_warning`.
- Modify `app/src/main/java/com/urlxl/mail/security/SecuritySettingsActivity.kt` — use `dpToPx`/`addViewSpaced` for spacing, add the warning `TextView`.
- Modify `app/src/main/java/com/urlxl/mail/KeywordSettingsActivity.kt` — use `dpToPx`/`addViewSpaced` for spacing.

---

### Task 1: Add `scalePxByDensity`/`dpToPx`/`addViewSpaced`/warning-callout theme to `AppTheme.kt`

**Files:**
- Modify: `app/src/main/java/com/urlxl/mail/AppTheme.kt:60-66` (constants), `:206-212` (near `applyDangerButtonTheme`), `:538` (near `density`), `:583-590` (near `dangerButtonBackground`)
- Test: `app/src/test/java/com/urlxl/mail/AppThemeScalingTest.kt`

**Interfaces:**
- Produces: `internal fun scalePxByDensity(value: Int, density: Float): Int`, `fun dpToPx(value: Int): Int`, `fun LinearLayout.addViewSpaced(view: View, topDp: Int = 0, bottomDp: Int = 0)`, `fun applyWarningCalloutTheme(context: Context, textView: TextView)`, `const val COLOR_WARNING_ACTION_BORDER`, `const val COLOR_WARNING_ACTION_FILL`, `const val COLOR_WARNING_ACTION_TEXT` — all consumed by Task 2 and Task 3.

- [ ] **Step 1: Write the failing test**

Create `app/src/test/java/com/urlxl/mail/AppThemeScalingTest.kt`:

```kotlin
package com.urlxl.mail

import org.junit.Assert.assertEquals
import org.junit.Test

class AppThemeScalingTest {

    @Test
    fun scalePxByDensity_scalesByDensity() {
        assertEquals(20, scalePxByDensity(20, 1.0f))
        assertEquals(30, scalePxByDensity(20, 1.5f))
        assertEquals(60, scalePxByDensity(20, 3.0f))
    }

    @Test
    fun scalePxByDensity_truncatesFractionalPixels() {
        // 7 * 1.75 = 12.25 -> truncates to 12, matching the existing (value * density).toInt()
        // pattern used elsewhere in AppTheme.kt (e.g. dangerButtonBackground's stroke width).
        assertEquals(12, scalePxByDensity(7, 1.75f))
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./gradlew :app:testDebugUnitTest --tests "com.urlxl.mail.AppThemeScalingTest"`
Expected: FAIL — compile error, `scalePxByDensity` is unresolved.

- [ ] **Step 3: Add the constants**

In `app/src/main/java/com/urlxl/mail/AppTheme.kt`, replace lines 60-66:

```kotlin
const val COLOR_DANGER = "#ff5f5f"
const val COLOR_DANGER_ACTION_BORDER = "#66FFB4AB" // rgba(255,180,171,.4)
const val COLOR_DANGER_ACTION_FILL = "#1FFFB4AB" // rgba(255,180,171,.12)
const val COLOR_DANGER_ACTION_TEXT = "#ffd8d3"
const val COLOR_WARNING = "#ffd64d"
const val COLOR_WARNING_ACTION_BORDER = "#66FFD64D" // rgba(255,214,77,.4)
const val COLOR_WARNING_ACTION_FILL = "#1FFFD64D" // rgba(255,214,77,.12)
const val COLOR_WARNING_ACTION_TEXT = "#fff0b8"
const val COLOR_SUCCESS_BORDER = "#7bbf7b"
const val COLOR_SUCCESS_TEXT = "#a5dca5"
```

- [ ] **Step 4: Add `applyWarningCalloutTheme`**

In `app/src/main/java/com/urlxl/mail/AppTheme.kt`, directly after `applyDangerButtonTheme` (after line 212, i.e. after its closing `}`), insert:

```kotlin
/** Stroke + 12%-fill warning panel for non-interactive informational callouts — same stroke+fill
 *  shape as [applyDangerButtonTheme] (STYLE_GUIDE.md §4's danger-button pattern), but with the
 *  fixed warning yellow (STYLE_GUIDE.md §1) and applied to a TextView since callouts aren't
 *  buttons. Caller sets its own padding/margins; this only sets background + text color. */
fun applyWarningCalloutTheme(context: Context, textView: TextView) {
    textView.background = warningCalloutBackground()
    textView.setTextColor(Color.parseColor(COLOR_WARNING_ACTION_TEXT))
}
```

- [ ] **Step 5: Add `scalePxByDensity`, `dpToPx`, and `addViewSpaced`**

In `app/src/main/java/com/urlxl/mail/AppTheme.kt`, directly after the `density` declaration at line 538, insert:

```kotlin
private val density: Float get() = android.content.res.Resources.getSystem().displayMetrics.density

/** Pure dp->px math, factored out of [dpToPx] so it's unit-testable without the Android
 *  framework (this project has no Robolectric setup) — [dpToPx] is the entry point every caller
 *  should use directly. */
internal fun scalePxByDensity(value: Int, density: Float): Int = (value * density).toInt()

/** Converts a dp value to raw device pixels using the system-wide [density] snapshot — for raw
 *  View APIs (setPadding, LayoutParams margins) that take pixels, not dp. */
fun dpToPx(value: Int): Int = scalePxByDensity(value, density)

/** Adds [view] with vertical breathing room ([topDp]/[bottomDp], converted via [dpToPx]) instead
 *  of the zero-margin default plain `addView(view)` produces — the Security/Keyword settings
 *  screens build their layout by hand and need real gaps between sibling controls. */
fun LinearLayout.addViewSpaced(view: View, topDp: Int = 0, bottomDp: Int = 0) {
    val params = LinearLayout.LayoutParams(
        LinearLayout.LayoutParams.WRAP_CONTENT,
        LinearLayout.LayoutParams.WRAP_CONTENT,
    ).apply {
        topMargin = dpToPx(topDp)
        bottomMargin = dpToPx(bottomDp)
    }
    addView(view, params)
}
```

(Leave the original `private val density: Float get() = ...` line in place — this step only adds new code after it, it does not change that line.)

- [ ] **Step 6: Add `warningCalloutBackground`**

In `app/src/main/java/com/urlxl/mail/AppTheme.kt`, directly after `dangerButtonBackground()` (after line 590, i.e. after its closing `}`), insert:

```kotlin
private fun warningCalloutBackground(): GradientDrawable {
    return GradientDrawable().apply {
        shape = GradientDrawable.RECTANGLE
        cornerRadius = 10f * density
        setColor(Color.parseColor(COLOR_WARNING_ACTION_FILL))
        setStroke((1 * density).toInt(), Color.parseColor(COLOR_WARNING_ACTION_BORDER))
    }
}
```

- [ ] **Step 7: Run test to verify it passes**

Run: `./gradlew :app:testDebugUnitTest --tests "com.urlxl.mail.AppThemeScalingTest"`
Expected: PASS (2 tests)

- [ ] **Step 8: Commit**

```bash
git add app/src/main/java/com/urlxl/mail/AppTheme.kt app/src/test/java/com/urlxl/mail/AppThemeScalingTest.kt
git commit -m "android: add dp-scaling and warning-callout helpers to AppTheme"
```

---

### Task 2: Space out `SecuritySettingsActivity` and add the push data-leak warning

**Files:**
- Modify: `app/src/main/java/com/urlxl/mail/security/SecuritySettingsActivity.kt:39-139` (the `onCreate` body)
- Modify: `app/src/main/res/values/strings.xml:272` (insert new string after `security_credential_gate_intro`)

**Interfaces:**
- Consumes: `dpToPx(value: Int): Int`, `LinearLayout.addViewSpaced(view: View, topDp: Int = 0, bottomDp: Int = 0)`, `applyWarningCalloutTheme(context: Context, textView: TextView)` from Task 1.

- [ ] **Step 1: Add the new string resource**

In `app/src/main/res/values/strings.xml`, directly after line 272 (`security_credential_gate_intro`), insert:

```xml
    <string name="security_credential_gate_leak_warning">Push always sends the sender and subject through Google/UnifiedPush relay servers, even with this on. For zero leakage, ask your server admin to switch this device to Pull mode instead.</string>
```

- [ ] **Step 2: Replace the `onCreate` body**

In `app/src/main/java/com/urlxl/mail/security/SecuritySettingsActivity.kt`, replace lines 39-139 (the entire `override fun onCreate(savedInstanceState: Bundle?) { ... }` method) with:

```kotlin
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.setFlags(android.view.WindowManager.LayoutParams.FLAG_SECURE, android.view.WindowManager.LayoutParams.FLAG_SECURE)
        appLockStore = AppLockStore(this)
        setTitle(R.string.security_settings_title)

        val scrollView = ScrollView(this)
        val container = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dpToPx(20), dpToPx(20), dpToPx(20), dpToPx(20))
        }
        applyTopInsetWithHeader(this, scrollView)

        lockSwitch = Switch(this).apply {
            text = getString(R.string.security_require_unlock_title)
            isChecked = appLockStore.isLockEnabled()
        }
        container.addViewSpaced(lockSwitch, bottomDp = 4)
        container.addViewSpaced(
            TextView(this).apply {
                text = getString(R.string.security_require_unlock_intro)
                textSize = 13f
            },
            bottomDp = 20,
        )

        // "A 'Change PIN' action appears once enabled" (spec) — only ever visible while lock is
        // on; toggling lock off/on elsewhere in this file must keep this in sync (see
        // promptSetPin/disableLock).
        changePinButton = Button(this).apply {
            text = getString(R.string.security_change_pin_button)
            visibility = if (appLockStore.isLockEnabled()) View.VISIBLE else View.GONE
            setOnClickListener { promptChangePin() }
        }
        container.addViewSpaced(changePinButton, bottomDp = 16)

        biometricSwitch = Switch(this).apply {
            text = getString(R.string.security_use_biometric_title)
            isChecked = appLockStore.isBiometricEnabled()
            isEnabled = appLockStore.isLockEnabled()
        }
        container.addViewSpaced(biometricSwitch, bottomDp = 20)

        val hostileLocationSettings = HostileLocationSettings(this)
        hostileLocationSwitch = Switch(this).apply {
            text = getString(R.string.security_hostile_location_title)
            isChecked = hostileLocationSettings.isEnabled()
            isEnabled = appLockStore.isLockEnabled()
        }
        container.addViewSpaced(hostileLocationSwitch, bottomDp = 4)
        hostileLocationIntro = TextView(this).apply {
            text = if (appLockStore.isLockEnabled()) {
                getString(R.string.security_hostile_location_intro)
            } else {
                getString(R.string.security_hostile_location_requires_lock)
            }
            textSize = 13f
        }
        container.addViewSpaced(hostileLocationIntro, bottomDp = 20)
        hostileLocationSwitch.setOnCheckedChangeListener { _, checked ->
            lifecycleScope.launch {
                // Both directions need a fresh on-disk kypost_mail.db afterward: enabling must not
                // leave the pre-toggle disk cache behind ("nothing from before the toggle
                // survives" — see the spec's "Toggling on" section), and this is a harmless
                // safety-net no-op on the disable path, since the in-memory DB it's replacing
                // never wrote to this file in the first place. See SecurityWipe.closeAndDeleteDatabase.
                SecurityWipe.closeAndDeleteDatabase(this@SecuritySettingsActivity)
                hostileLocationSettings.setEnabled(checked)
                AppRestart.relaunch(this@SecuritySettingsActivity)
            }
        }

        credentialGateSwitch = Switch(this).apply {
            text = getString(R.string.security_credential_gate_title)
            isChecked = appLockStore.isCredentialPinGateEnabled()
            isEnabled = appLockStore.isLockEnabled()
        }
        container.addViewSpaced(credentialGateSwitch, bottomDp = 4)
        container.addViewSpaced(
            TextView(this).apply {
                text = getString(R.string.security_credential_gate_intro)
                textSize = 13f
            },
            bottomDp = 8,
        )
        // Always visible regardless of credentialGateSwitch's state: the push-relay exposure
        // this describes exists on every push delivery, on or off — this toggle only ever
        // controlled whether content is withheld while locked, not whether the relay sees it.
        container.addViewSpaced(
            TextView(this).apply {
                text = getString(R.string.security_credential_gate_leak_warning)
                textSize = 13f
                setPadding(dpToPx(12), dpToPx(10), dpToPx(12), dpToPx(10))
                applyWarningCalloutTheme(this@SecuritySettingsActivity, this)
            },
            bottomDp = 16,
        )
        credentialGateSwitch.setOnCheckedChangeListener { _, checked ->
            if (suppressCredentialGateListener) return@setOnCheckedChangeListener
            if (checked) confirmEnableCredentialGate() else confirmDisableCredentialGate()
        }

        lockSwitch.setOnCheckedChangeListener { _, checked ->
            if (suppressLockToggleListener) return@setOnCheckedChangeListener
            onLockToggle(checked)
        }
        biometricSwitch.setOnCheckedChangeListener { _, checked -> appLockStore.setBiometricEnabled(checked) }

        scrollView.addView(container)
        setContentView(scrollView)
        applyThemeToActivity(this)
    }
```

- [ ] **Step 3: Build to verify it compiles**

Run: `./gradlew :app:compileDebugKotlin`
Expected: BUILD SUCCESSFUL

- [ ] **Step 4: Manual on-device verification**

No Robolectric/Espresso harness exists in this project for Activity view trees (confirmed: no test touches `SecuritySettingsActivity`'s layout), so this step is a manual visual check, same as every other hand-built screen in this codebase.

Run:
```bash
./gradlew :app:installDebug
adb shell am start -n com.urlxl.mail/com.urlxl.mail.security.SecuritySettingsActivity
adb exec-out screencap -p > /tmp/security-settings-screenshot.png
```
Expected: screen shows visible vertical gaps between each switch/button/text block (not flush against each other), and a yellow-bordered warning callout with the leak-warning text appears directly under the "Require unlock to receive push/MFA" intro text, visible whether that switch is on or off. Open `/tmp/security-settings-screenshot.png` to confirm.

- [ ] **Step 5: Commit**

```bash
git add app/src/main/java/com/urlxl/mail/security/SecuritySettingsActivity.kt app/src/main/res/values/strings.xml
git commit -m "android: space out Security settings and warn about push metadata relay"
```

---

### Task 3: Space out `KeywordSettingsActivity`

**Files:**
- Modify: `app/src/main/java/com/urlxl/mail/KeywordSettingsActivity.kt:14-60` (the `onCreate` body)

**Interfaces:**
- Consumes: `dpToPx(value: Int): Int`, `LinearLayout.addViewSpaced(view: View, topDp: Int = 0, bottomDp: Int = 0)` from Task 1.

- [ ] **Step 1: Replace the `onCreate` body**

In `app/src/main/java/com/urlxl/mail/KeywordSettingsActivity.kt`, replace lines 14-60 (the entire `override fun onCreate(savedInstanceState: Bundle?) { ... }` method) with:

```kotlin
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        keywordSettings = KeywordSettings(this)
        setTitle(R.string.keyword_settings_title)

        val scrollView = ScrollView(this)
        val container = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dpToPx(20), dpToPx(20), dpToPx(20), dpToPx(20))
        }

        applyTopInsetWithHeader(this, scrollView)

        val intro = TextView(this).apply {
            text = getString(R.string.keyword_settings_intro)
            textSize = 14f
        }
        container.addViewSpaced(intro, bottomDp = 16)

        val allKeywords = keywordSettings.getAllKeywords().sorted()
        if (allKeywords.isEmpty()) {
            val emptyView = TextView(this).apply {
                text = getString(R.string.keyword_settings_empty)
                textSize = 14f
            }
            applyEmptyStateBackground(this, emptyView)
            container.addViewSpaced(emptyView, bottomDp = 12)
        } else {
            allKeywords.forEach { keyword ->
                val checkbox = CheckBox(this).apply {
                    text = keyword
                    isChecked = keywordSettings.isKeywordVisible(keyword)
                    textSize = 15f
                    setOnCheckedChangeListener { _, isChecked ->
                        keywordSettings.setKeywordVisible(keyword, isChecked)
                    }
                }
                container.addViewSpaced(checkbox, bottomDp = 12)
            }
        }

        scrollView.addView(container)
        setContentView(scrollView)
        applyThemeToActivity(this)
    }
```

- [ ] **Step 2: Build to verify it compiles**

Run: `./gradlew :app:compileDebugKotlin`
Expected: BUILD SUCCESSFUL

- [ ] **Step 3: Manual on-device verification**

Run:
```bash
./gradlew :app:installDebug
adb shell am start -n com.urlxl.mail/com.urlxl.mail.KeywordSettingsActivity
adb exec-out screencap -p > /tmp/keyword-settings-screenshot.png
```
Expected: visible vertical gaps between the intro text and the first checkbox, and between each checkbox row (not flush against each other). Open `/tmp/keyword-settings-screenshot.png` to confirm.

- [ ] **Step 4: Commit**

```bash
git add app/src/main/java/com/urlxl/mail/KeywordSettingsActivity.kt
git commit -m "android: space out Keyword settings checkboxes"
```

---

## Self-Review Notes

- **Spec coverage:** "give them room to breathe" → Tasks 2 & 3 (spacing). "warning about that to prevent data leaks... turn on pull notifications" → Task 2 (warning callout, text-only per user's confirmed choice, always visible per user's confirmed choice). Both spec sections covered.
- **Placeholders:** none — every step has literal code/commands, no TBD/"add appropriate X".
- **Type consistency:** `dpToPx(Int): Int`, `addViewSpaced(View, Int, Int)`, `applyWarningCalloutTheme(Context, TextView)` are defined once in Task 1 and used with matching signatures in Tasks 2 and 3.
- **Scope:** single cohesive change (2 screens + 1 shared helper file), no unrelated refactors pulled in.
