# Foldable and Large-Screen Support Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Show two-pane, rail-navigated layouts on displays 600dp and wider, and fall back to today's phone layouts automatically when the device folds.

**Architecture:** Resource qualifiers (`layout-w600dp`) do the layout switching; Jetpack Activity Embedding does the master-detail pairing without touching the detail Activities; the default configuration-change recreate is the switching mechanism, so no Activity gains `android:configChanges`. State that must cross a live resize goes in a saved-state Bundle, except contact PII, which goes in a process-scoped in-memory cache.

**Tech Stack:** Kotlin, Android Views (no Compose), Material Components 1.10.0, `androidx.window` 1.5.1, `androidx.startup` 1.1.1, JUnit 4, Espresso/AndroidX Test.

**Spec:** `docs/superpowers/specs/2026-08-14-foldable-support-design.md`

## Global Constraints

- **Breakpoint is `w600dp`.** One qualifier, no `w840dp` tier.
- **No Activity may declare `android:configChanges`.** The recreate is the switching mechanism.
- **A saved-state Bundle may carry identifiers and view positions only** — folder names, tab enums, scroll indices, message ids. Never a decrypted body, never attachment bytes, never draft content, never contact PII.
- **Message and contact plaintext lives only in `ProcessState`-registered holders**, cleared by `ProcessState.resetAll()`.
- **A screen close that trips the app lock lands the user on the inbox** with no context restored. Do not add a holder to work around this.
- `minSdk` is 31; Activity Embedding splits require API 32. On 31 the app must behave exactly as it does today.
- JVM tests in `app/src/test` are Android-framework-free (no Robolectric). Anything needing a `Bundle`, `Context`, or Activity lifecycle belongs in `app/src/androidTest`.
- Build check: `./gradlew :app:assembleDebug`. JVM tests: `./gradlew :app:testDebugUnitTest`. Instrumented: `./gradlew :app:connectedDebugAndroidTest` (needs a running emulator).

## Deviations from the spec, with reasons

Two changes were forced by details found while writing this plan. Both are narrower than what the spec proposed.

**1. `ui/FormFactor.kt` is dropped; `R.bool.nav_is_rail` replaces it.** The spec assumed Kotlin would compute the form factor from `displayMetrics`. Two problems: nothing consumes it (layout selection is the resource system's job), and a hand-computed dp value can disagree with the qualifier that actually resolved — in multi-window, with insets, or at a rounding boundary — leaving code and layout inconsistent. A bool resource under the same `w600dp` qualifier cannot disagree with the layout, because the framework resolves both the same way. The spec's JVM test of `formFactorFor` boundaries goes away with the function; the layout/bool pairing is verified instrumented in Task 1 instead.

**2. The markRead guard is instance state, tested instrumented, not a pure JVM predicate.** The spec asked for a pure predicate so it could be JVM-tested. The guard reduces to `if (!markReadAlreadySent)`, and a JVM test of that is a tautology that asserts nothing about the behaviour anyone cares about. The property worth testing — "a recreate does not re-fire the mutation" — is a Bundle round-trip and only exists under a real lifecycle, so it is an instrumented test in Task 3.

---

### Task 1: Navigation rail on large screens

Swaps `BottomNavigationView` for `NavigationRailView` above 600dp. `InboxActivity` keeps one code path because Material 1.10.0 has both types extending `NavigationBarView`.

`InboxActivity.kt:114` calls `applyBottomInset(bottomNav)`, which pads the bottom by the system-bar inset. A rail spans the full height at the start edge, so it needs top, bottom, and start insets instead. This is the only place in the app that must know which form factor rendered.

**Files:**
- Create: `app/src/main/res/values/bools.xml`
- Create: `app/src/main/res/values-w600dp/bools.xml`
- Create: `app/src/main/res/layout-w600dp/activity_inbox.xml`
- Modify: `app/src/main/java/org/kysecurity/mail/AppTheme.kt` (add `applyRailInsets` after `applyBottomInset`, which ends at :164)
- Modify: `app/src/main/java/org/kysecurity/mail/InboxActivity.kt:22` (import), `:43` (field type), `:114` (inset call)
- Test: `app/src/androidTest/java/org/kysecurity/mail/ui/InboxRailTest.kt`

**Interfaces:**
- Consumes: nothing.
- Produces: `R.bool.nav_is_rail` (false by default, true at `w600dp`); `applyRailInsets(view: View)` in `org.kysecurity.mail`; `layout-w600dp/activity_inbox.xml` exposing every id the phone layout does.

- [ ] **Step 1: Add the bool resources**

`app/src/main/res/values/bools.xml`:

```xml
<?xml version="1.0" encoding="utf-8"?>
<resources>
    <!-- True only where layout-w600dp resolved, so code and layout cannot disagree about which
         navigation widget was inflated. Read it instead of recomputing a width in Kotlin. -->
    <bool name="nav_is_rail">false</bool>
</resources>
```

`app/src/main/res/values-w600dp/bools.xml`:

```xml
<?xml version="1.0" encoding="utf-8"?>
<resources>
    <bool name="nav_is_rail">true</bool>
</resources>
```

- [ ] **Step 2: Add the rail inset helper**

Append to `app/src/main/java/org/kysecurity/mail/AppTheme.kt`, directly after `applyBottomInset` (which ends at line 164):

```kotlin
/**
 * The rail equivalent of [applyBottomInset]. A vertical rail spans the full height at the start
 * edge, so the bottom-only padding that suits a bottom bar leaves its top item under the status bar
 * and its first icon under the gesture handle.
 */
fun applyRailInsets(view: View) {
    val basePaddingStart = view.paddingStart
    val basePaddingTop = view.paddingTop
    val basePaddingBottom = view.paddingBottom
    ViewCompat.setOnApplyWindowInsetsListener(view) { v, insets ->
        val bars = insets.getInsets(WindowInsetsCompat.Type.systemBars())
        val startInset = if (v.layoutDirection == View.LAYOUT_DIRECTION_RTL) bars.right else bars.left
        v.setPaddingRelative(
            basePaddingStart + startInset,
            basePaddingTop + bars.top,
            v.paddingEnd,
            basePaddingBottom + bars.bottom,
        )
        insets
    }
    ViewCompat.requestApplyInsets(view)
}
```

- [ ] **Step 3: Create the large-screen inbox layout**

`app/src/main/res/layout-w600dp/activity_inbox.xml`. Every id from the phone layout is present and unchanged — `InboxActivity` binds all of them:

```xml
<?xml version="1.0" encoding="utf-8"?>
<FrameLayout xmlns:android="http://schemas.android.com/apk/res/android"
    xmlns:app="http://schemas.android.com/apk/res-auto"
    android:id="@+id/inboxRoot"
    android:layout_width="match_parent"
    android:layout_height="match_parent">

    <LinearLayout
        android:layout_width="match_parent"
        android:layout_height="match_parent"
        android:orientation="horizontal">

        <com.google.android.material.navigationrail.NavigationRailView
            android:id="@+id/bottomNavigation"
            android:layout_width="wrap_content"
            android:layout_height="match_parent"
            android:elevation="12dp"
            app:labelVisibilityMode="labeled"
            app:itemTextAppearanceActive="@style/TextAppearance.KyPost.BottomNavLabel"
            app:itemTextAppearanceInactive="@style/TextAppearance.KyPost.BottomNavLabel"
            app:itemIconSize="24dp"
            app:menu="@menu/bottom_nav_menu" />

        <LinearLayout
            android:layout_width="0dp"
            android:layout_height="match_parent"
            android:layout_weight="1"
            android:orientation="vertical">

            <TextView
                android:id="@+id/headerFolderTitle"
                android:layout_width="match_parent"
                android:layout_height="wrap_content"
                android:paddingStart="24dp"
                android:paddingEnd="24dp"
                android:paddingTop="16dp"
                android:paddingBottom="16dp"
                android:textSize="22sp"
                android:textStyle="bold" />

            <LinearLayout
                android:id="@+id/inboxContent"
                android:layout_width="match_parent"
                android:layout_height="0dp"
                android:layout_weight="1"
                android:orientation="vertical"
                android:paddingTop="8dp"
                android:paddingStart="24dp"
                android:paddingEnd="24dp"
                android:paddingBottom="16dp">

                <HorizontalScrollView
                    android:id="@+id/keywordChipScroll"
                    android:layout_width="match_parent"
                    android:layout_height="wrap_content"
                    android:scrollbars="none"
                    android:paddingHorizontal="8dp"
                    android:paddingVertical="6dp">

                    <com.google.android.material.chip.ChipGroup
                        android:id="@+id/keywordChipGroup"
                        android:layout_width="wrap_content"
                        android:layout_height="wrap_content"
                        app:singleLine="true"
                        app:singleSelection="true"
                        app:selectionRequired="true"
                        app:chipSpacingHorizontal="6dp" />

                </HorizontalScrollView>

                <androidx.swiperefreshlayout.widget.SwipeRefreshLayout
                    android:id="@+id/inboxSwipeRefresh"
                    android:layout_width="match_parent"
                    android:layout_height="0dp"
                    android:layout_weight="1"
                    android:layout_marginTop="8dp">

                    <androidx.recyclerview.widget.RecyclerView
                        android:id="@+id/recyclerViewInbox"
                        android:layout_width="match_parent"
                        android:layout_height="match_parent"
                        android:clipToPadding="false"
                        android:paddingBottom="8dp" />

                </androidx.swiperefreshlayout.widget.SwipeRefreshLayout>

            </LinearLayout>

        </LinearLayout>

    </LinearLayout>

    <LinearLayout
        android:id="@+id/loadingOverlay"
        android:layout_width="wrap_content"
        android:layout_height="wrap_content"
        android:layout_gravity="center"
        android:orientation="vertical"
        android:gravity="center"
        android:visibility="gone">

        <ProgressBar
            android:id="@+id/loadingSpinner"
            android:layout_width="wrap_content"
            android:layout_height="wrap_content" />

        <TextView
            android:id="@+id/loadingStatus"
            android:layout_width="wrap_content"
            android:layout_height="wrap_content"
            android:layout_marginTop="8dp"
            android:text="@string/loading_emails"
            android:textColor="?android:attr/textColorSecondary"
            android:visibility="gone" />

        <Button
            android:id="@+id/cancelLoading"
            style="@style/Widget.MaterialComponents.Button.TextButton"
            android:layout_width="wrap_content"
            android:layout_height="wrap_content"
            android:layout_marginTop="8dp"
            android:text="@string/cancel"
            android:visibility="gone" />
    </LinearLayout>

</FrameLayout>
```

- [ ] **Step 4: Widen the field type in InboxActivity**

Replace the import at `InboxActivity.kt:22`:

```kotlin
import com.google.android.material.navigation.NavigationBarView
```

Replace the field declaration at `:43`:

```kotlin
    private lateinit var bottomNav: NavigationBarView
```

Every existing call site already uses `NavigationBarView` API — `backgroundTintList`, `setBackgroundColor`, `itemTextColor`, `itemIconTintList`, `itemRippleColor`, `itemActiveIndicatorColor` (`:236`–`:247`), `setOnItemSelectedListener` (`:622`), `setOnItemReselectedListener` (`:645`), `selectedItemId` (`:652`). None of them change.

- [ ] **Step 5: Branch the inset call**

Replace `InboxActivity.kt:114`:

```kotlin
        if (resources.getBoolean(R.bool.nav_is_rail)) applyRailInsets(bottomNav) else applyBottomInset(bottomNav)
```

- [ ] **Step 6: Build**

Run: `./gradlew :app:assembleDebug`
Expected: BUILD SUCCESSFUL.

- [ ] **Step 7: Add the explicit AndroidX Test dependency**

Instrumented tests from here on use `ActivityScenario`. It arrives transitively through `androidx.test.ext:junit`, but depending on that transitively is fragile. Add to `gradle/libs.versions.toml` under `[versions]`:

```toml
testCore = "1.5.0"
```

under `[libraries]`:

```toml
androidx-test-core = { group = "androidx.test", name = "core", version.ref = "testCore" }
```

and to `app/build.gradle.kts` in `dependencies`, beside the other `androidTestImplementation` entries:

```kotlin
    androidTestImplementation(libs.androidx.test.core)
```

- [ ] **Step 8: Write the failing instrumented test**

`app/src/androidTest/java/org/kysecurity/mail/ui/InboxRailTest.kt`:

```kotlin
package org.kysecurity.mail.ui

import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.google.android.material.navigation.NavigationBarView
import com.google.android.material.navigationrail.NavigationRailView
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.kysecurity.mail.InboxActivity
import org.kysecurity.mail.R

/**
 * The bool resource and the layout resolve through the same qualifier, so they can never disagree.
 * This asserts exactly that pairing: wherever nav_is_rail is true a NavigationRailView was
 * inflated, and wherever it is false one was not. It therefore passes on a phone and on a tablet
 * without the test knowing which it is running on.
 */
@RunWith(AndroidJUnit4::class)
class InboxRailTest {

    @Test
    fun navWidgetMatchesTheBoolResource() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val expectRail = context.resources.getBoolean(R.bool.nav_is_rail)

        ActivityScenario.launch(InboxActivity::class.java).use { scenario ->
            scenario.onActivity { activity ->
                val nav = activity.findViewById<NavigationBarView>(R.id.bottomNavigation)
                assertEquals(expectRail, nav is NavigationRailView)
                assertEquals(3, nav.menu.size())
            }
        }
    }

    @Test
    fun railSurvivesRecreate() {
        ActivityScenario.launch(InboxActivity::class.java).use { scenario ->
            scenario.recreate()
            scenario.onActivity { activity ->
                val nav = activity.findViewById<NavigationBarView>(R.id.bottomNavigation)
                assertTrue(nav.selectedItemId == R.id.nav_inbox)
            }
        }
    }
}
```

- [ ] **Step 9: Run the test**

Run: `./gradlew :app:connectedDebugAndroidTest --tests "org.kysecurity.mail.ui.InboxRailTest"`
Expected: PASS on a phone emulator (asserting the bottom bar) and PASS on a `w600dp`+ emulator (asserting the rail). If the app lock is configured on the test device, the launch redirects to `UnlockActivity` and this fails — run it on a freshly installed emulator with no PIN set.

- [ ] **Step 10: Commit**

```bash
git add app/src/main/res/values/bools.xml app/src/main/res/values-w600dp/bools.xml \
        app/src/main/res/layout-w600dp/activity_inbox.xml \
        app/src/main/java/org/kysecurity/mail/AppTheme.kt \
        app/src/main/java/org/kysecurity/mail/InboxActivity.kt \
        app/src/androidTest/java/org/kysecurity/mail/ui/InboxRailTest.kt \
        gradle/libs.versions.toml app/build.gradle.kts
git commit -m "feat(ui): navigation rail and wide inbox layout above 600dp"
```

---

### Task 2: Inbox state across a live resize

`InboxActivity` implements no `onSaveInstanceState`, so a fold resets the folder to `INBOX`, the tab to `ALL`, and the scroll to the top. Rotation always did this; folding will do it constantly.

**Files:**
- Modify: `app/src/main/java/org/kysecurity/mail/InboxActivity.kt` (`currentFolder` at `:56`, `selectedTab` at `:59`)
- Test: `app/src/androidTest/java/org/kysecurity/mail/ui/InboxStateRestoreTest.kt`

**Interfaces:**
- Consumes: `R.bool.nav_is_rail` from Task 1 (build dependency only).
- Produces: `InboxActivity` restoring `currentFolder`, `selectedTab`, and first-visible item index across a recreate.

- [ ] **Step 1: Write the failing instrumented test**

`app/src/androidTest/java/org/kysecurity/mail/ui/InboxStateRestoreTest.kt`:

```kotlin
package org.kysecurity.mail.ui

import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith
import org.kysecurity.mail.InboxActivity

/**
 * A live resize (unfolding while the app is in the foreground) is a configuration change, so the
 * Activity is destroyed and recreated. recreate() reproduces exactly that path.
 */
@RunWith(AndroidJUnit4::class)
class InboxStateRestoreTest {

    @Test
    fun folderAndTabSurviveRecreate() {
        ActivityScenario.launch(InboxActivity::class.java).use { scenario ->
            scenario.onActivity { it.setFolderForTest("Archive", "Finance") }

            scenario.recreate()

            scenario.onActivity {
                assertEquals("Archive", it.currentFolderForTest())
                assertEquals("Finance", it.selectedTabForTest())
            }
        }
    }
}
```

- [ ] **Step 2: Run it to confirm it fails**

Run: `./gradlew :app:connectedDebugAndroidTest --tests "org.kysecurity.mail.ui.InboxStateRestoreTest"`
Expected: FAIL to compile — `setFolderForTest` is unresolved.

- [ ] **Step 3: Add the test seams and the state constants**

In `InboxActivity`, beside the existing `private companion object` members, add:

```kotlin
    @androidx.annotation.VisibleForTesting
    internal fun setFolderForTest(folder: String, tab: String) {
        currentFolder = folder
        selectedTab = tab
    }

    @androidx.annotation.VisibleForTesting
    internal fun currentFolderForTest(): String = currentFolder

    @androidx.annotation.VisibleForTesting
    internal fun selectedTabForTest(): String = selectedTab
```

- [ ] **Step 4: Save and restore the state**

Add to `InboxActivity`:

```kotlin
    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        if (redirectedToUnlock) return
        // Identifiers and positions only. No subjects, senders or bodies: this Bundle is
        // system-managed storage outside the app's control.
        outState.putString(STATE_FOLDER, currentFolder)
        outState.putString(STATE_TAB, selectedTab)
        val layoutManager = recyclerView.layoutManager as? LinearLayoutManager
        outState.putInt(STATE_SCROLL, layoutManager?.findFirstVisibleItemPosition() ?: 0)
    }
```

In `onCreate`, immediately after the `if (redirectedToUnlock) return` guard:

```kotlin
        savedInstanceState?.let { state ->
            currentFolder = state.getString(STATE_FOLDER, currentFolder)
            selectedTab = state.getString(STATE_TAB, selectedTab)
            pendingScrollPosition = state.getInt(STATE_SCROLL, 0)
        }
```

Add the backing field beside the other `private var` declarations:

```kotlin
    private var pendingScrollPosition: Int = 0
```

Add to the existing `private companion object`:

```kotlin
        const val STATE_FOLDER = "inbox_folder"
        const val STATE_TAB = "inbox_tab"
        const val STATE_SCROLL = "inbox_scroll"
```

- [ ] **Step 5: Apply the restored scroll position**

At the end of `renderFilteredEmails()`, after the adapter has its items:

```kotlin
        if (pendingScrollPosition > 0) {
            val target = pendingScrollPosition.coerceAtMost(adapter.itemCount - 1)
            pendingScrollPosition = 0
            if (target >= 0) recyclerView.scrollToPosition(target)
        }
```

- [ ] **Step 6: Run the test**

Run: `./gradlew :app:connectedDebugAndroidTest --tests "org.kysecurity.mail.ui.InboxStateRestoreTest"`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add app/src/main/java/org/kysecurity/mail/InboxActivity.kt \
        app/src/androidTest/java/org/kysecurity/mail/ui/InboxStateRestoreTest.kt
git commit -m "fix(inbox): keep folder, tab and scroll across a configuration change"
```

---

### Task 3: Stop markRead re-firing on every fold

`EmailDetailActivity.kt:209` submits `mailRepository.markRead(emailId, emailFolder)` from `onCreate`. Every recreate re-fires an authenticated network mutation. Reopening the message after the task was cleared is a genuine new open and must still mark it read.

**Files:**
- Modify: `app/src/main/java/org/kysecurity/mail/EmailDetailActivity.kt:209`
- Test: `app/src/androidTest/java/org/kysecurity/mail/ui/MarkReadOnceTest.kt`

**Interfaces:**
- Consumes: nothing.
- Produces: `EmailDetailActivity` exposing `markReadSentForTest(): Boolean`; `markRead` submitted at most once per Activity instance chain.

- [ ] **Step 1: Write the failing instrumented test**

`app/src/androidTest/java/org/kysecurity/mail/ui/MarkReadOnceTest.kt`:

```kotlin
package org.kysecurity.mail.ui

import android.content.Intent
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith
import org.kysecurity.mail.EmailDetailActivity

@RunWith(AndroidJUnit4::class)
class MarkReadOnceTest {

    @Test
    fun markReadIsNotResubmittedOnRecreate() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val intent = Intent(context, EmailDetailActivity::class.java).apply {
            putExtra("emailId", "test-message-1")
            putExtra("folder", "INBOX")
        }

        ActivityScenario.launch<EmailDetailActivity>(intent).use { scenario ->
            scenario.onActivity { assertEquals(1, it.markReadSubmitCountForTest()) }
            scenario.recreate()
            scenario.onActivity { assertEquals(1, it.markReadSubmitCountForTest()) }
        }
    }
}
```

Confirm the two intent extra keys against the constants `EmailDetailActivity` already declares before running — use those constants rather than the string literals above if their names differ.

- [ ] **Step 2: Run it to confirm it fails**

Run: `./gradlew :app:connectedDebugAndroidTest --tests "org.kysecurity.mail.ui.MarkReadOnceTest"`
Expected: FAIL to compile — `markReadSubmitCountForTest` is unresolved.

- [ ] **Step 3: Guard the submit**

Replace `EmailDetailActivity.kt:209`:

```kotlin
        if (!markReadSubmitted) {
            markReadSubmitted = true
            markReadSubmitCount++
            MailBackgroundExecutor.submit { mailRepository.markRead(emailId, emailFolder) }
        }
```

Add the fields beside the other `private var` declarations:

```kotlin
    /** A configuration-change recreate is not a new open. Reopening after the task was cleared is,
     *  and that path builds a fresh instance with no saved state, so it marks read again. */
    private var markReadSubmitted = false
    private var markReadSubmitCount = 0

    @androidx.annotation.VisibleForTesting
    internal fun markReadSubmitCountForTest(): Int = markReadSubmitCount
```

- [ ] **Step 4: Carry the flag and the counter across the recreate**

Add to `EmailDetailActivity`:

```kotlin
    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        if (redirectedToUnlock) return
        outState.putBoolean(STATE_MARK_READ_SUBMITTED, markReadSubmitted)
        outState.putInt(STATE_MARK_READ_COUNT, markReadSubmitCount)
    }
```

In `onCreate`, immediately after the `if (redirectedToUnlock) return` guard at `:133` and before the `markRead` block at `:209`:

```kotlin
        savedInstanceState?.let { state ->
            markReadSubmitted = state.getBoolean(STATE_MARK_READ_SUBMITTED, false)
            markReadSubmitCount = state.getInt(STATE_MARK_READ_COUNT, 0)
        }
```

Add to the class's `companion object`:

```kotlin
        private const val STATE_MARK_READ_SUBMITTED = "mark_read_submitted"
        private const val STATE_MARK_READ_COUNT = "mark_read_count"
```

- [ ] **Step 5: Run the test**

Run: `./gradlew :app:connectedDebugAndroidTest --tests "org.kysecurity.mail.ui.MarkReadOnceTest"`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add app/src/main/java/org/kysecurity/mail/EmailDetailActivity.kt \
        app/src/androidTest/java/org/kysecurity/mail/ui/MarkReadOnceTest.kt
git commit -m "fix(mail): mark a message read once per open, not once per recreate"
```

---

### Task 4: Two-column compose layout

`ComposeActivity` already owns the header fields and the body editor, so this is a layout variant only. No Kotlin changes.

**Files:**
- Create: `app/src/main/res/layout-w600dp/activity_compose.xml`
- Read first: `app/src/main/res/layout/activity_compose.xml` (252 lines)

**Interfaces:**
- Consumes: nothing.
- Produces: a `w600dp` compose layout exposing every id the phone layout does.

- [ ] **Step 1: Inventory the ids the Activity binds**

Run: `grep -n "findViewById" app/src/main/java/org/kysecurity/mail/ComposeActivity.kt`

Every id returned must exist in the new layout with the same type. A missing id is a crash on the first large-screen launch, not a compile error — this step is the check that prevents it. The layout below carries all 23 ids from the phone variant; use this grep to confirm none has been added since.

- [ ] **Step 2: Create the variant**

`app/src/main/res/layout-w600dp/activity_compose.xml`.

Two structural changes from the phone layout, both deliberate:

**The outer `NestedScrollView` is gone.** It exists so a focused field can scroll above the keyboard in a single tall column. Side by side there are two independently sized columns, and a single outer scroller would fight both. The left column gets its own `NestedScrollView` instead.

**The body editor moves from a fixed `320dp` to `0dp`+weight.** The phone layout's comment at `:207`–`:211` pins a concrete height because `RichHtmlEditorWebView` overwrites its own `layoutParams.height`, and `fillViewport` only re-stretches when the scroll view is measured `EXACTLY` — which the *outer* scroller never did. Here the right column is a `LinearLayout` of `match_parent` height, so `0dp`+`layout_weight="1"` produces exactly that `EXACTLY` spec. The original constraint is satisfied, not ignored. **Verify this in Step 4** — a blank body box means the measurement assumption is wrong and the editor needs a concrete height here too.

```xml
<?xml version="1.0" encoding="utf-8"?>
<!-- Two columns above 600dp: form on the left, editor on the right. No outer NestedScrollView —
     see the plan's Task 4 for why the editor's height strategy differs from the phone layout. -->
<LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
    xmlns:app="http://schemas.android.com/apk/res-auto"
    android:id="@+id/composeRoot"
    android:layout_width="match_parent"
    android:layout_height="match_parent"
    android:orientation="horizontal"
    android:padding="16dp">

    <androidx.core.widget.NestedScrollView
        android:layout_width="0dp"
        android:layout_height="match_parent"
        android:layout_weight="2"
        android:layout_marginEnd="16dp"
        android:fillViewport="true">

        <LinearLayout
            android:layout_width="match_parent"
            android:layout_height="wrap_content"
            android:orientation="vertical">

            <LinearLayout
                android:id="@+id/composeDetailsCard"
                android:layout_width="match_parent"
                android:layout_height="wrap_content"
                android:orientation="vertical"
                android:padding="16dp"
                android:layout_marginBottom="16dp">

                <org.kysecurity.mail.RecipientInputView
                    android:id="@+id/composeToInput"
                    android:layout_width="match_parent"
                    android:layout_height="wrap_content"
                    android:layout_marginBottom="12dp" />

                <View
                    android:id="@+id/composeDetailsDivider1"
                    android:layout_width="match_parent"
                    android:layout_height="1dp"
                    android:layout_marginBottom="12dp" />

                <org.kysecurity.mail.RecipientInputView
                    android:id="@+id/composeCcInput"
                    android:layout_width="match_parent"
                    android:layout_height="wrap_content"
                    android:layout_marginBottom="12dp" />

                <View
                    android:id="@+id/composeDetailsDivider2"
                    android:layout_width="match_parent"
                    android:layout_height="1dp"
                    android:layout_marginBottom="12dp" />

                <org.kysecurity.mail.RecipientInputView
                    android:id="@+id/composeBccInput"
                    android:layout_width="match_parent"
                    android:layout_height="wrap_content"
                    android:layout_marginBottom="12dp" />

                <View
                    android:id="@+id/composeDetailsDivider3"
                    android:layout_width="match_parent"
                    android:layout_height="1dp"
                    android:layout_marginBottom="12dp" />

                <LinearLayout
                    android:layout_width="match_parent"
                    android:layout_height="wrap_content"
                    android:orientation="horizontal">

                    <TextView
                        android:layout_width="wrap_content"
                        android:layout_height="wrap_content"
                        android:text="@string/compose_subject"
                        android:textSize="12sp"
                        android:gravity="center_vertical"
                        android:layout_marginEnd="8dp" />

                    <EditText
                        android:id="@+id/composeSubjectField"
                        android:layout_width="0dp"
                        android:layout_height="wrap_content"
                        android:layout_weight="1"
                        android:hint="Email subject" />

                </LinearLayout>

            </LinearLayout>

            <com.google.android.material.chip.ChipGroup
                android:id="@+id/composeAttachmentsCard"
                android:layout_width="match_parent"
                android:layout_height="wrap_content"
                android:padding="12dp"
                android:layout_marginBottom="8dp"
                android:visibility="gone"
                app:chipSpacingHorizontal="6dp" />

        </LinearLayout>

    </androidx.core.widget.NestedScrollView>

    <LinearLayout
        android:id="@+id/composeMessageCard"
        android:layout_width="0dp"
        android:layout_height="match_parent"
        android:layout_weight="3"
        android:orientation="vertical"
        android:padding="12dp">

        <LinearLayout
            android:layout_width="match_parent"
            android:layout_height="wrap_content"
            android:orientation="horizontal"
            android:gravity="center_vertical"
            android:layout_marginBottom="12dp">

            <com.google.android.material.chip.ChipGroup
                android:layout_width="0dp"
                android:layout_height="wrap_content"
                android:layout_weight="1"
                app:chipSpacingHorizontal="6dp">

                <com.google.android.material.chip.Chip
                    android:id="@+id/composeBold"
                    style="@style/Widget.KyPost.IconOnlyChip"
                    android:checkable="true"
                    app:chipIcon="@drawable/ic_bold"
                    android:contentDescription="@string/compose_format_bold" />

                <com.google.android.material.chip.Chip
                    android:id="@+id/composeItalic"
                    style="@style/Widget.KyPost.IconOnlyChip"
                    android:checkable="true"
                    app:chipIcon="@drawable/ic_italic"
                    android:contentDescription="@string/compose_format_italic" />

                <com.google.android.material.chip.Chip
                    android:id="@+id/composeUnderline"
                    style="@style/Widget.KyPost.IconOnlyChip"
                    android:checkable="true"
                    app:chipIcon="@drawable/ic_underline"
                    android:contentDescription="@string/compose_format_underline" />

                <com.google.android.material.chip.Chip
                    android:id="@+id/composeLink"
                    style="@style/Widget.KyPost.IconOnlyChip"
                    android:checkable="true"
                    app:chipIcon="@drawable/ic_link"
                    android:contentDescription="@string/compose_format_link" />

            </com.google.android.material.chip.ChipGroup>

            <com.google.android.material.chip.Chip
                android:id="@+id/composeAttachButton"
                android:layout_width="wrap_content"
                android:layout_height="wrap_content"
                android:checkable="false"
                app:chipIcon="@drawable/ic_attach"
                app:chipIconSize="18dp"
                android:text="@string/compose_attach"
                android:layout_marginStart="4dp" />

        </LinearLayout>

        <com.google.android.material.chip.ChipGroup
            android:id="@+id/composePgpChips"
            android:layout_width="match_parent"
            android:layout_height="wrap_content"
            android:visibility="gone"
            android:layout_marginBottom="12dp"
            app:chipSpacingHorizontal="6dp">

            <com.google.android.material.chip.Chip
                android:id="@+id/composeEncryptChip"
                android:layout_width="wrap_content"
                android:layout_height="wrap_content"
                android:checkable="true"
                android:visibility="gone"
                android:text="@string/compose_pgp_encrypt" />

            <com.google.android.material.chip.Chip
                android:id="@+id/composeSignChip"
                android:layout_width="wrap_content"
                android:layout_height="wrap_content"
                android:checkable="true"
                android:visibility="gone"
                android:text="@string/compose_pgp_sign" />

            <com.google.android.material.chip.Chip
                android:id="@+id/composeWebmailChip"
                android:layout_width="wrap_content"
                android:layout_height="wrap_content"
                android:checkable="false"
                android:visibility="gone"
                android:text="@string/compose_pgp_webmail" />

        </com.google.android.material.chip.ChipGroup>

        <TextView
            android:id="@+id/composeKeylessWarning"
            android:layout_width="match_parent"
            android:layout_height="wrap_content"
            android:visibility="gone"
            android:padding="12dp"
            android:layout_marginBottom="12dp" />

        <View
            android:id="@+id/composeMessageDivider"
            android:layout_width="match_parent"
            android:layout_height="1dp"
            android:layout_marginBottom="12dp" />

        <androidx.core.widget.NestedScrollView
            android:layout_width="match_parent"
            android:layout_height="0dp"
            android:layout_weight="1"
            android:fillViewport="true">

            <FrameLayout
                android:layout_width="match_parent"
                android:layout_height="wrap_content">

                <com.infomaniak.lib.richhtmleditor.RichHtmlEditorWebView
                    android:id="@+id/composeBodyEditor"
                    android:layout_width="match_parent"
                    android:layout_height="match_parent" />

                <TextView
                    android:id="@+id/composeBodyPlaceholder"
                    android:layout_width="wrap_content"
                    android:layout_height="wrap_content"
                    android:layout_margin="4dp"
                    android:text="@string/compose_body_hint"
                    android:textSize="16sp" />

            </FrameLayout>
        </androidx.core.widget.NestedScrollView>

    </LinearLayout>

</LinearLayout>
```

- [ ] **Step 3: Build**

Run: `./gradlew :app:assembleDebug`
Expected: BUILD SUCCESSFUL.

- [ ] **Step 4: Verify on a large-screen emulator**

Launch compose on a `w600dp`+ emulator. Confirm:

1. The form sits left and the editor right.
2. **The body editor is visible and fills its column** — a blank or one-line-tall box means the `0dp`+weight measurement assumption from Step 2 is wrong. Fall back to a concrete `android:layout_height="480dp"` on that `NestedScrollView` and note it in the commit message.
3. Typing in the body does not push the form off-screen; `windowSoftInputMode="adjustResize"` (manifest `:58`) still resizes rather than pans.
4. Attaching a file still reveals `composeAttachmentsCard` in the left column.

- [ ] **Step 5: Commit**

```bash
git add app/src/main/res/layout-w600dp/activity_compose.xml
git commit -m "feat(compose): two-column layout above 600dp"
```

---

### Task 5: Contacts list and detail on large screens

**Files:**
- Create: `app/src/main/res/layout-w600dp/activity_contacts_list.xml`
- Modify: `app/src/main/java/org/kysecurity/mail/contacts/ContactsListActivity.kt`
- Modify: `app/src/main/java/org/kysecurity/mail/contacts/ContactDetailActivity.kt`
- Test: `app/src/androidTest/java/org/kysecurity/mail/ui/ContactsListStateRestoreTest.kt`

**Interfaces:**
- Consumes: nothing.
- Produces: `ContactsListActivity` and `ContactDetailActivity` restoring scroll position across a recreate; a `w600dp` contacts layout.

- [ ] **Step 1: Create the variant**

`app/src/main/res/layout-w600dp/activity_contacts_list.xml` — the phone layout at `app/src/main/res/layout/activity_contacts_list.xml` with wider gutters. Ids `contactsRoot`, `contactsContent`, `contactsEmptyText`, `recyclerViewContacts` and `btnAddContact` are unchanged:

```xml
<?xml version="1.0" encoding="utf-8"?>
<FrameLayout xmlns:android="http://schemas.android.com/apk/res/android"
    android:id="@+id/contactsRoot"
    android:layout_width="match_parent"
    android:layout_height="match_parent">

    <LinearLayout
        android:id="@+id/contactsContent"
        android:layout_width="match_parent"
        android:layout_height="match_parent"
        android:orientation="vertical"
        android:paddingStart="24dp"
        android:paddingEnd="24dp"
        android:paddingTop="16dp">

        <TextView
            android:id="@+id/contactsEmptyText"
            android:layout_width="match_parent"
            android:layout_height="wrap_content"
            android:layout_marginTop="48dp"
            android:gravity="center"
            android:text="@string/contacts_empty"
            android:visibility="gone" />

        <androidx.recyclerview.widget.RecyclerView
            android:id="@+id/recyclerViewContacts"
            android:layout_width="match_parent"
            android:layout_height="match_parent"
            android:clipToPadding="false"
            android:paddingBottom="80dp" />

    </LinearLayout>

    <com.google.android.material.floatingactionbutton.FloatingActionButton
        android:id="@+id/btnAddContact"
        android:layout_width="wrap_content"
        android:layout_height="wrap_content"
        android:layout_gravity="bottom|end"
        android:layout_margin="24dp"
        android:contentDescription="@string/contacts_add"
        android:src="@android:drawable/ic_input_add" />

</FrameLayout>
```

- [ ] **Step 2: Write the failing instrumented test**

`app/src/androidTest/java/org/kysecurity/mail/ui/ContactsListStateRestoreTest.kt`:

```kotlin
package org.kysecurity.mail.ui

import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith
import org.kysecurity.mail.contacts.ContactsListActivity

@RunWith(AndroidJUnit4::class)
class ContactsListStateRestoreTest {

    @Test
    fun scrollPositionSurvivesRecreate() {
        ActivityScenario.launch(ContactsListActivity::class.java).use { scenario ->
            scenario.onActivity { it.setPendingScrollForTest(4) }
            scenario.recreate()
            scenario.onActivity { assertEquals(4, it.pendingScrollForTest()) }
        }
    }
}
```

- [ ] **Step 3: Run it to confirm it fails**

Run: `./gradlew :app:connectedDebugAndroidTest --tests "org.kysecurity.mail.ui.ContactsListStateRestoreTest"`
Expected: FAIL to compile — `setPendingScrollForTest` is unresolved.

- [ ] **Step 4: Save and restore the scroll position**

Add to `ContactsListActivity`, using the RecyclerView field name the class already declares:

```kotlin
    private var pendingScrollPosition: Int = 0

    @androidx.annotation.VisibleForTesting
    internal fun setPendingScrollForTest(position: Int) { pendingScrollPosition = position }

    @androidx.annotation.VisibleForTesting
    internal fun pendingScrollForTest(): Int = pendingScrollPosition

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        if (redirectedToUnlock) return
        // A position, not a contact. No names, addresses or numbers reach this Bundle.
        val layoutManager = recyclerView.layoutManager as? androidx.recyclerview.widget.LinearLayoutManager
        val visible = layoutManager?.findFirstVisibleItemPosition() ?: 0
        outState.putInt(STATE_SCROLL, if (pendingScrollPosition > 0) pendingScrollPosition else visible)
    }
```

In `onCreate`, immediately after the `if (redirectedToUnlock) return` guard:

```kotlin
        pendingScrollPosition = savedInstanceState?.getInt(STATE_SCROLL, 0) ?: 0
```

Add a `private companion object` if the class has none, or extend the existing one:

```kotlin
    private companion object {
        const val STATE_SCROLL = "contacts_scroll"
    }
```

Where the adapter's items are set, apply and clear it:

```kotlin
        if (pendingScrollPosition > 0) {
            val target = pendingScrollPosition.coerceAtMost(adapter.itemCount - 1)
            pendingScrollPosition = 0
            if (target >= 0) recyclerView.scrollToPosition(target)
        }
```

- [ ] **Step 5: Run the test**

Run: `./gradlew :app:connectedDebugAndroidTest --tests "org.kysecurity.mail.ui.ContactsListStateRestoreTest"`
Expected: PASS.

- [ ] **Step 6: Do the same for the detail screen**

`ContactDetailActivity` rebuilds its content from the contact uid in its intent, so a recreate restores the data but drops the scroll position. Add the same three pieces, using the scrolling view the class already binds (a `ScrollView` or `RecyclerView` — check which before writing this):

```kotlin
    private var pendingScrollY: Int = 0

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        if (redirectedToUnlock) return
        // A scroll offset. No names, addresses, numbers or PGP keys reach this Bundle.
        outState.putInt(STATE_SCROLL_Y, detailScrollView.scrollY)
    }

    private companion object {
        const val STATE_SCROLL_Y = "contact_detail_scroll_y"
    }
```

In `onCreate`, after the `if (redirectedToUnlock) return` guard:

```kotlin
        pendingScrollY = savedInstanceState?.getInt(STATE_SCROLL_Y, 0) ?: 0
```

Once the detail content is populated:

```kotlin
        if (pendingScrollY > 0) {
            val target = pendingScrollY
            pendingScrollY = 0
            detailScrollView.post { detailScrollView.scrollTo(0, target) }
        }
```

If the class already declares a `companion object`, extend it rather than adding a second one.

- [ ] **Step 7: Build**

Run: `./gradlew :app:assembleDebug`
Expected: BUILD SUCCESSFUL.

- [ ] **Step 8: Commit**

```bash
git add app/src/main/res/layout-w600dp/activity_contacts_list.xml \
        app/src/main/java/org/kysecurity/mail/contacts/ContactsListActivity.kt \
        app/src/main/java/org/kysecurity/mail/contacts/ContactDetailActivity.kt \
        app/src/androidTest/java/org/kysecurity/mail/ui/ContactsListStateRestoreTest.kt
git commit -m "feat(contacts): wide list layout and scroll restore across a configuration change"
```

---

### Task 6: Contact edit draft cache

`ContactEditActivity` has roughly thirty fields plus six repeatable lists. Its contents are the user's contact PII, which the Bundle rule keeps out of system-managed storage — so it needs the same treatment `ComposeDraftCache` gives a message draft.

The house pattern already exists: `mergedContactDto` at `ContactEditActivity.kt:581` was pulled out of `save()` for exactly this kind of testability, and `ContactEditActivityTest.kt` already covers it. This task extracts the two remaining halves — reading the form and writing the form — so a draft can round-trip through the same code the save and load paths use.

**Files:**
- Create: `app/src/main/java/org/kysecurity/mail/contacts/ContactEditDraftCache.kt`
- Modify: `app/src/main/java/org/kysecurity/mail/contacts/ContactEditActivity.kt` (`loadExisting` at `:400`, `save` at `:463`)
- Test: `app/src/test/java/org/kysecurity/mail/contacts/ContactEditDraftCacheTest.kt`
- Test: `app/src/androidTest/java/org/kysecurity/mail/ui/ContactEditDraftTest.kt`

**Interfaces:**
- Consumes: `ContactDto` from `contacts/ContactSyncModels.kt:7`; `mergedContactDto(...)` at `ContactEditActivity.kt:581`; `ProcessScopedState` / `ProcessState` from `ProcessScopedState.kt`.
- Produces: `ContactEditDraftCache.save(ContactDto)`, `.take(): ContactDto?`, `.clear()`; `ContactEditActivity.currentFormDto(fn: String): ContactDto` and `.populateForm(dto: ContactDto)`.

- [ ] **Step 1: Write the failing JVM test**

`app/src/test/java/org/kysecurity/mail/contacts/ContactEditDraftCacheTest.kt`:

```kotlin
package org.kysecurity.mail.contacts

import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * Mirrors ComposeDraftCacheTest's contract: a draft survives Activity destruction, a take() hands
 * ownership to the caller, and a clear() seals the cache against a late write from the session
 * that was just wiped.
 */
class ContactEditDraftCacheTest {

    @After
    fun tearDown() = ContactEditDraftCache.clear()

    @Test
    fun takeReturnsTheSavedDraftAndClearsIt() {
        ContactEditDraftCache.save(ContactDto(fn = "Ada Lovelace"))

        assertEquals("Ada Lovelace", ContactEditDraftCache.take()?.fn)
        assertNull(ContactEditDraftCache.take())
    }

    @Test
    fun anEmptyDraftIsNotWorthKeeping() {
        ContactEditDraftCache.save(ContactDto())

        assertNull(ContactEditDraftCache.take())
    }

    @Test
    fun clearSealsAgainstALateWrite() {
        ContactEditDraftCache.clear()

        ContactEditDraftCache.save(ContactDto(fn = "Late Arrival"))

        assertNull(ContactEditDraftCache.take())
    }

    @Test
    fun takeUnsealsForTheNextSession() {
        ContactEditDraftCache.clear()
        ContactEditDraftCache.take()

        ContactEditDraftCache.save(ContactDto(fn = "Grace Hopper"))

        assertEquals("Grace Hopper", ContactEditDraftCache.take()?.fn)
    }

    @Test
    fun resetForNewSessionDropsEverything() {
        ContactEditDraftCache.save(ContactDto(fn = "Ada Lovelace"))

        ContactEditDraftCache.resetForNewSession()

        assertNull(ContactEditDraftCache.take())
    }
}
```

- [ ] **Step 2: Run it to confirm it fails**

Run: `./gradlew :app:testDebugUnitTest --tests "org.kysecurity.mail.contacts.ContactEditDraftCacheTest"`
Expected: FAIL to compile — `ContactEditDraftCache` is unresolved.

- [ ] **Step 3: Write the cache**

`app/src/main/java/org/kysecurity/mail/contacts/ContactEditDraftCache.kt`:

```kotlin
package org.kysecurity.mail.contacts

import org.kysecurity.mail.ProcessScopedState
import org.kysecurity.mail.ProcessState

/**
 * The in-progress contact edit, held for the life of the process so a fold cannot destroy it.
 *
 * Unfolding a device is a configuration change, which destroys and recreates the Activity. This
 * screen carries the user's contact PII across roughly thirty fields, and discarding it because
 * someone opened their phone is data loss on a casual gesture.
 *
 * A saved-state Bundle is the wrong home for it: that is system-managed storage written outside
 * this app's control, and [ComposeDraftCache][org.kysecurity.mail.ComposeDraftCache] already
 * documents why message plaintext stays out of it. This holds the same line for contact plaintext —
 * in memory, process-scoped, and registered with [ProcessState] so a security wipe clears it.
 */
object ContactEditDraftCache : ProcessScopedState {

    @Volatile
    private var draft: ContactDto? = null

    /** Refuses writes until the next [take] — see ComposeDraftCache.sealed for the resurrection
     *  this prevents: a wipe clears the cache, and a write already queued lands afterwards. */
    @Volatile
    private var sealed: Boolean = false

    init {
        ProcessState.register(this)
    }

    fun save(draft: ContactDto) {
        if (sealed) return
        // An untouched form is not worth restoring, and caching it would blank a later edit's
        // prefilled fields.
        this.draft = draft.takeIf { it.fn.isNotBlank() }
    }

    fun take(): ContactDto? {
        val current = draft
        draft = null
        sealed = false
        return current
    }

    fun clear() {
        draft = null
        sealed = true
    }

    override fun resetForNewSession() = clear()
}
```

If `ContactDto.fn` is not a non-null `String`, adjust the `takeIf` predicate to match its declared type in `contacts/ContactSyncModels.kt:7` — check before writing this file.

- [ ] **Step 4: Run the JVM test**

Run: `./gradlew :app:testDebugUnitTest --tests "org.kysecurity.mail.contacts.ContactEditDraftCacheTest"`
Expected: PASS.

- [ ] **Step 5: Extract `populateForm` from `loadExisting`**

In `ContactEditActivity`, move the body of `loadExisting` from `loadedDto = dto` (`:404`) through the final `setItemCount` call (`:461`) into a new method, leaving the database read behind:

```kotlin
    private fun loadExisting(uid: String) {
        lifecycleScope.launch {
            val entity = DataRuntime.graph(this@ContactEditActivity).database.contactDao().getByUid(uid) ?: return@launch
            populateForm(entity.toDto())
        }
    }

    /** Writes a [ContactDto] into the form. Shared by the database load and the draft restore, so
     *  a restored draft cannot drift from a loaded contact. */
    private suspend fun populateForm(dto: ContactDto) {
        // ...the moved body, unchanged, including `loadedDto = dto` and `existingRev = dto.rev`...
    }
```

`loadedDto` must be assigned inside `populateForm`: a draft is produced by `.copy()` off the loaded contact, so restoring it as the merge base preserves every field the form does not show. `populateForm` stays `suspend` because the moved body calls `hasPgpIdentity(this@ContactEditActivity)`.

- [ ] **Step 6: Extract `currentFormDto` from `save`**

Move the `mergedContactDto(...)` call at `:469`–`:496` into its own method and have `save()` call it:

```kotlin
    /** Reads the form into a DTO, merged onto [loadedDto] so unshown fields survive. Shared by the
     *  save path and the draft stash. */
    private fun currentFormDto(fn: String): ContactDto = mergedContactDto(
        loaded = loadedDto,
        uid = existingUid,
        rev = existingRev,
        fn = fn,
        // ...the remaining arguments, moved verbatim from save()...
    )

    private fun save() {
        val fn = fnField.text.toString().trim()
        if (fn.isBlank()) {
            Toast.makeText(this, R.string.contacts_name_required, Toast.LENGTH_SHORT).show()
            return
        }
        val dto = currentFormDto(fn)

        lifecycleScope.launch {
            // ...unchanged...
        }
    }
```

- [ ] **Step 7: Stash on stop, restore on create**

Add to `ContactEditActivity`:

```kotlin
    override fun onStop() {
        super.onStop()
        // Not gated on isChangingConfigurations: the app lock finishes this screen too, and that
        // is the case ComposeDraftCache was built for.
        if (redirectedToUnlock || isFinishing) return
        ContactEditDraftCache.save(currentFormDto(fnField.text.toString().trim()))
    }
```

At the end of `onCreate`, after the form is wired and after any `loadExisting` call:

```kotlin
        ContactEditDraftCache.take()?.let { draft ->
            lifecycleScope.launch { populateForm(draft) }
        }
```

`take()` runs after `loadExisting` dispatches, and both write through `populateForm`, so the draft is the last writer and wins. `isFinishing` keeps a successful save — which calls `finish()` — from stashing a draft that was just written to the database.

- [ ] **Step 8: Write the failing instrumented test**

`app/src/androidTest/java/org/kysecurity/mail/ui/ContactEditDraftTest.kt`:

```kotlin
package org.kysecurity.mail.ui

import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith
import org.kysecurity.mail.contacts.ContactEditActivity
import org.kysecurity.mail.contacts.ContactEditDraftCache

@RunWith(AndroidJUnit4::class)
class ContactEditDraftTest {

    @After
    fun tearDown() = ContactEditDraftCache.clear()

    @Test
    fun typedNameSurvivesRecreate() {
        ActivityScenario.launch(ContactEditActivity::class.java).use { scenario ->
            scenario.onActivity { it.setNameForTest("Ada Lovelace") }

            scenario.recreate()

            scenario.onActivity { assertEquals("Ada Lovelace", it.nameForTest()) }
        }
    }
}
```

Add the seams to `ContactEditActivity`:

```kotlin
    @androidx.annotation.VisibleForTesting
    internal fun setNameForTest(name: String) = fnField.setText(name)

    @androidx.annotation.VisibleForTesting
    internal fun nameForTest(): String = fnField.text.toString()
```

- [ ] **Step 9: Run both suites**

Run: `./gradlew :app:testDebugUnitTest --tests "org.kysecurity.mail.contacts.*"`
Expected: PASS, including the pre-existing `ContactEditActivityTest`, which must not regress — the extraction changed where `mergedContactDto` is called from, not what it does.

Run: `./gradlew :app:connectedDebugAndroidTest --tests "org.kysecurity.mail.ui.ContactEditDraftTest"`
Expected: PASS.

- [ ] **Step 10: Commit**

```bash
git add app/src/main/java/org/kysecurity/mail/contacts/ContactEditDraftCache.kt \
        app/src/main/java/org/kysecurity/mail/contacts/ContactEditActivity.kt \
        app/src/test/java/org/kysecurity/mail/contacts/ContactEditDraftCacheTest.kt \
        app/src/androidTest/java/org/kysecurity/mail/ui/ContactEditDraftTest.kt
git commit -m "feat(contacts): keep an in-progress edit across a configuration change"
```

---

### Task 7: Activity Embedding for master-detail

Pairs each list Activity with its detail Activity so the system renders them side by side above 600dp and stacks them below. The detail Activities are not modified.

**Files:**
- Modify: `gradle/libs.versions.toml`
- Modify: `app/build.gradle.kts`
- Create: `app/src/main/res/xml/split_config.xml`
- Create: `app/src/main/java/org/kysecurity/mail/ui/SplitInitializer.kt`
- Modify: `app/src/main/AndroidManifest.xml`
- Modify: `app/proguard-rules.pro`

**Interfaces:**
- Consumes: nothing.
- Produces: split behaviour for `InboxActivity`→`EmailDetailActivity` and `ContactsListActivity`→`ContactDetailActivity`/`ContactEditActivity`.

- [ ] **Step 1: Add the dependencies**

`gradle/libs.versions.toml`, under `[versions]`:

```toml
window = "1.5.1"
startupRuntime = "1.1.1"
```

under `[libraries]`:

```toml
androidx-window = { group = "androidx.window", name = "window", version.ref = "window" }
androidx-startup-runtime = { group = "androidx.startup", name = "startup-runtime", version.ref = "startupRuntime" }
```

`app/build.gradle.kts`, in `dependencies` beside the other `implementation` entries:

```kotlin
    implementation(libs.androidx.window)
    implementation(libs.androidx.startup.runtime)
```

- [ ] **Step 2: Write the split rules**

`app/src/main/res/xml/split_config.xml`. `splitMinWidthDp="600"` matches the layout breakpoint, so the split and the rail appear together:

```xml
<?xml version="1.0" encoding="utf-8"?>
<resources xmlns:window="http://schemas.android.com/apk/res-auto">

    <!-- finishPrimaryWithSecondary="never": closing a message must not close the inbox.
         finishSecondaryWithPrimary="always": the detail pane cannot outlive its list. -->
    <SplitPairRule
        window:splitRatio="0.4"
        window:splitLayoutDirection="locale"
        window:splitMinWidthDp="600"
        window:finishPrimaryWithSecondary="never"
        window:finishSecondaryWithPrimary="always"
        window:clearTop="true">
        <SplitPairFilter
            window:primaryActivityName=".InboxActivity"
            window:secondaryActivityName=".EmailDetailActivity" />
    </SplitPairRule>

    <SplitPairRule
        window:splitRatio="0.4"
        window:splitLayoutDirection="locale"
        window:splitMinWidthDp="600"
        window:finishPrimaryWithSecondary="never"
        window:finishSecondaryWithPrimary="always"
        window:clearTop="true">
        <SplitPairFilter
            window:primaryActivityName=".contacts.ContactsListActivity"
            window:secondaryActivityName=".contacts.ContactDetailActivity" />
        <SplitPairFilter
            window:primaryActivityName=".contacts.ContactsListActivity"
            window:secondaryActivityName=".contacts.ContactEditActivity" />
        <SplitPairFilter
            window:primaryActivityName=".contacts.ContactDetailActivity"
            window:secondaryActivityName=".contacts.ContactEditActivity" />
    </SplitPairRule>

</resources>
```

- [ ] **Step 3: Write the initializer**

`app/src/main/java/org/kysecurity/mail/ui/SplitInitializer.kt`:

```kotlin
package org.kysecurity.mail.ui

import android.content.Context
import androidx.startup.Initializer
import androidx.window.embedding.RuleController
import org.kysecurity.mail.R

/**
 * Loads the split rules before the first Activity is created.
 *
 * Rules must be registered before the pair they describe is launched, and androidx.startup runs
 * this from the content-provider phase — earlier than Application.onCreate's own work and earlier
 * than any screen. On API 31, where embedding is unsupported, the rules are simply never applied.
 */
class SplitInitializer : Initializer<RuleController> {

    override fun create(context: Context): RuleController =
        RuleController.getInstance(context).apply {
            setRules(RuleController.parseRules(context, R.xml.split_config))
        }

    override fun dependencies(): List<Class<out Initializer<*>>> = emptyList()
}
```

- [ ] **Step 4: Wire the manifest**

In `app/src/main/AndroidManifest.xml`, add the `tools` namespace to the root element at `:2`:

```xml
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    xmlns:tools="http://schemas.android.com/tools">
```

Inside `<application>`, beside the existing `<meta-data>` block:

```xml
        <!-- Required by androidx.window 1.1.0-alpha06 and later; without it the system ignores
             every split rule and the app renders exactly as it did before. -->
        <property
            android:name="android.window.PROPERTY_ACTIVITY_EMBEDDING_SPLITS_ENABLED"
            android:value="true" />

        <provider
            android:name="androidx.startup.InitializationProvider"
            android:authorities="${applicationId}.androidx-startup"
            android:exported="false"
            tools:node="merge">
            <meta-data
                android:name="org.kysecurity.mail.ui.SplitInitializer"
                android:value="androidx.startup" />
        </provider>
```

- [ ] **Step 5: Keep the initializer through R8**

The release build enables R8, and `SplitInitializer` is referenced only from manifest metadata — a string, not a code reference. Add to `app/proguard-rules.pro`:

```proguard
# Referenced only by name from AndroidManifest metadata, so R8 cannot see the reference and would
# strip it — leaving splits silently dead in release while they work in debug.
-keep class org.kysecurity.mail.ui.SplitInitializer { *; }
```

- [ ] **Step 6: Build both variants**

Run: `./gradlew :app:assembleDebug :app:assembleRelease`
Expected: BUILD SUCCESSFUL for both. The release build is the one that proves the keep rule parses; if `keystore.properties` is absent and the release task fails on signing, run `./gradlew :app:assembleDebug` and note that the R8 path is verified in Task 8's manual pass instead.

- [ ] **Step 7: Verify the split on a large-screen emulator**

On a `w600dp`+ emulator: open the inbox, tap a message, and confirm the list stays visible on the left with the message on the right. Press back and confirm the message closes while the inbox remains. Repeat for contacts → contact detail → edit.

Then on a phone emulator: confirm messages open full-screen exactly as before.

- [ ] **Step 8: Commit**

```bash
git add gradle/libs.versions.toml app/build.gradle.kts \
        app/src/main/res/xml/split_config.xml \
        app/src/main/java/org/kysecurity/mail/ui/SplitInitializer.kt \
        app/src/main/AndroidManifest.xml app/proguard-rules.pro
git commit -m "feat(ui): master-detail via activity embedding above 600dp"
```

---

### Task 8: Prove the app lock still holds

Embedding makes two `LockedActivity` instances visible at once — a code path that has never existed in this app. Both redirect when the lock engages. `UnlockActivity` is `singleInstance` (manifest `:171`), so the two `startActivity` calls should collapse into one prompt, but that is a security claim and gets a test.

The three properties below are the ones the spec refused to assert without evidence.

**Files:**
- Test: `app/src/androidTest/java/org/kysecurity/mail/security/FoldLockBehaviourTest.kt`
- Modify: `docs/superpowers/specs/2026-08-14-foldable-support-design.md` (record the manual pass result)

**Interfaces:**
- Consumes: everything from Tasks 1–7.
- Produces: evidence for the spec's verification list.

- [ ] **Step 1: Write the lock tests**

`app/src/androidTest/java/org/kysecurity/mail/security/FoldLockBehaviourTest.kt`:

```kotlin
package org.kysecurity.mail.security

import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.kysecurity.mail.InboxActivity

/**
 * The two halves of the foldable lock contract. A live resize must not lock; a close-and-lock must.
 * Neither is assumed anywhere in this feature — both are asserted here.
 */
@RunWith(AndroidJUnit4::class)
class FoldLockBehaviourTest {

    private val appLockManager
        get() = SecurityRuntime.graph(
            InstrumentationRegistry.getInstrumentation().targetContext,
        ).appLockManager

    @Test
    fun aLiveResizeDoesNotEngageTheAppLock() {
        ActivityScenario.launch(InboxActivity::class.java).use { scenario ->
            scenario.recreate()

            assertFalse(
                "A configuration-change recreate must not lock the app — every unfold would prompt for a PIN.",
                appLockManager.isLockedNow(),
            )
        }
    }

    @Test
    fun lockNowStillGatesTheInbox() {
        ActivityScenario.launch(InboxActivity::class.java).use { scenario ->
            appLockManager.lockNow()

            scenario.recreate()

            scenario.onActivity { activity ->
                assertTrue(
                    "A locked app must finish a gated screen rather than leave it under the prompt.",
                    activity.isFinishing || activity.isDestroyed,
                )
            }
        }
    }
}
```

Check `AppLockManager`'s and `SecurityRuntime`'s visibility before running; if `lockNow()` is not reachable from the test source set, drive the lock through the same entry point the existing `androidTest/security` suites use.

- [ ] **Step 2: Run the lock tests**

Run: `./gradlew :app:connectedDebugAndroidTest --tests "org.kysecurity.mail.security.FoldLockBehaviourTest"`
Expected: PASS. A failure on the first test is a release blocker, not a test bug — it means every unfold prompts for a PIN. A failure on the second is worse: the lock no longer gates a recreated screen.

- [ ] **Step 3: Run the whole suite**

Run: `./gradlew :app:testDebugUnitTest`
Expected: PASS, no regressions.

Run: `./gradlew :app:connectedDebugAndroidTest`
Expected: PASS, no regressions — in particular the pre-existing `androidTest/security` suites.

- [ ] **Step 4: Manual pass on a foldable emulator**

Nothing above drives a real hinge. Create a `7.6" Fold-in with outer display` AVD (API 34+) and walk these, recording the result of each:

1. Open the app unfolded → rail on the left, two panes once a message is open.
2. Fold while reading a message → phone layout, message full-screen, list behind it.
3. Unfold again within the 30s grace → returns to two panes, no PIN prompt.
4. Fold, wait past the grace window, unfold → PIN prompt, then the inbox at defaults. **This is the intended behaviour, not a bug.**
5. Type a contact name, unfold mid-edit → the typed name is still there.
6. Type a message body, fold and unfold → the draft is still there.
7. With two panes open, lock the app → **one** unlock prompt, no pane visible behind it.

Toggle the hinge with `adb shell cmd device_state state 0` (folded) and `adb shell cmd device_state state 1` (unfolded); confirm the ids with `adb shell cmd device_state print-states` on the AVD, as they vary by device profile.

- [ ] **Step 5: Record the outcome in the spec**

Append a "Verification results" section to `docs/superpowers/specs/2026-08-14-foldable-support-design.md` recording what passed, what failed, and anything the manual pass found that the tests missed. Write what actually happened, including failures.

- [ ] **Step 6: Commit**

```bash
git add app/src/androidTest/java/org/kysecurity/mail/security/FoldLockBehaviourTest.kt \
        docs/superpowers/specs/2026-08-14-foldable-support-design.md
git commit -m "test(security): assert the app lock holds across fold transitions"
```

---

## Notes for the executor

**The riskiest task is 6, not 7.** Task 7 adds a library and a config file; if embedding misbehaves, deleting `split_config.xml` restores today's behaviour. Task 6 restructures two methods inside a 449-line form. Run the existing `ContactEditActivityTest` before and after the extraction and compare — `mergedContactDto` must behave identically.

**If a `w600dp` layout crashes on first launch**, the cause is almost always an id the Activity binds that the variant omits. `grep -n "findViewById" <Activity>.kt` and diff the id list against the new layout.

**Do not add `android:configChanges` to silence a recreate.** If a screen misbehaves on recreate, fix the state handling. Suppressing the recreate keeps the wrong layout inflated and breaks the whole feature.

**Emulator coverage:** Tasks 1–3 and 5–6 need one phone AVD and one `w600dp`+ AVD. Task 8 needs a foldable AVD specifically.
