# Foldable and large-screen support

**Date:** 2026-08-14
**Repo:** `kypost-android`

The app renders one layout at every size. On the inner display of a Galaxy Fold 8 that means a phone
column stretched across a tablet screen: a single-column inbox with a bottom navigation bar sized for
a thumb on a 350dp phone, and a whole second screen's worth of empty space beside it.

This spec adds large-screen layouts that appear only on displays wide enough to earn them, and
switch back automatically when the device folds. It changes no security control. Where a control and
a layout disagree, the control wins and this document says so explicitly.

---

## Scope

**In:** the inbox and other mailboxes, reading a message, composing, the contacts list, and reading
and editing a contact.

**Out:** every screen reachable from the settings menu. Those are short forms and lists that read
correctly at any width; a two-pane settings screen would be work spent on a screen nobody dwells in.
Also out: the pairing screen, the unlock screen, and the MFA approval screen — each is a single
centred task, and widening them is a visual change with no gain.

---

## The breakpoint

One qualifier: `w600dp`.

The Fold's cover display sits near 350dp wide; the inner display is comfortably past 600dp. A single
breakpoint separates them, and every ordinary phone plus the cover screen keeps today's layouts
unchanged — not "recalculated to the same result", but the same resource files, untouched.

No second breakpoint until a screen actually needs one. A `w840dp` tier is easy to add later and
impossible to justify now.

---

## Three mechanisms, matched to what each screen already is

The screens in scope are not the same shape as each other, and forcing one mechanism across all of
them is what would make this expensive.

### Compose — a layout variant

`ComposeActivity` already owns both the recipient/subject fields and the body editor. A new
`res/layout-w600dp/activity_compose.xml` puts the header fields in a left column and the editor on
the right, reusing every view id from the phone layout. `ComposeActivity.kt` is not modified.

### Inbox and contacts master-detail — Activity Embedding

The detail screens are separate Activities, and large ones: `EmailDetailActivity.kt` is 86 KB.
Hand-rolling a two-pane layout means lifting that logic out of its Activity so `InboxActivity` can
host it, in code that carries `FLAG_SECURE`, the app-lock gate, and ephemeral attachment handling.
That is a structural refactor through the most security-sensitive code in the app, bought for a
layout change.

Jetpack Activity Embedding (`androidx.window`) asks the system to render two Activities side by side
when the window is wide and stack them when it is narrow. A split rule in `res/xml/split_config.xml`
pairs `InboxActivity` → `EmailDetailActivity` and `ContactsListActivity` →
`ContactDetailActivity`/`ContactEditActivity`. Both Activities stay exactly as they are.
`startActivity` calls, result contracts, and the `EXTRA_REMOVED_EMAIL_ID` round-trip keep working,
because the system is only deciding *where* to draw the second Activity.

`minSdk` is 31 and embedding is fully supported from Android 12L (API 32). On API 31 the split never
activates and the app behaves as it does today. The devices this feature targets ship far newer.

### Navigation rail — a widened type

`res/layout-w600dp/activity_inbox.xml` replaces `BottomNavigationView` with `NavigationRailView`,
reusing `@menu/bottom_nav_menu` and keeping the id `bottomNavigation`. Material 1.10.0 has both
extending `NavigationBarView`, so `InboxActivity` widens its field type and runs identical logic —
including the `suppressFolderPickerReentry` guard, which is `NavigationBarView` reselection
behaviour, not a bottom-nav quirk.

The rail anchors to `start`, so the detail pane keeps the opposite edge and RTL mirrors both
together. A rail on the trailing edge would collide with the detail pane and land in the middle of
the screen.

---

## Transitions

No Activity declares `android:configChanges`, and none gains one. A size change destroys and
recreates the Activity, and that recreate re-resolves `layout-w600dp` — the recreate *is* the
switch. Suppressing it would keep the stale layout inflated and defeat the design.

Folding is two different events, and conflating them is how this goes wrong.

### Class A — live resize

The app stays in the foreground: unfolding while using the cover screen, multi-window, rotation.
A configuration change, a recreate, a layout swap, and instance state restores what the user was
looking at.

No screen in scope implements `onSaveInstanceState` today — `MainActivity` and `MfaApprovalActivity`
do, the rest do not. Rotation always could have reset them; folding will do it constantly. So this
work adds it:

| Screen        | Restored across a live resize                   |
| ------------- | ----------------------------------------------- |
| Inbox         | `currentFolder`, `selectedTab`, scroll position |
| Email detail  | message id, markRead-already-sent flag          |
| Contacts list | selected contact id, scroll position            |
| Contact edit  | in-progress field values, via a process-scoped cache |
| Compose       | nothing new — `ComposeDraftCache` already does it |

`ContactEditActivity` needs the cache rather than a Bundle. Its fields are the user's contact PII —
names, addresses, phone numbers — which the rule below keeps out of system-managed storage, and
discarding a half-typed contact because someone opened their phone is data loss on a casual gesture.
`ContactEditDraftCache` mirrors `ComposeDraftCache` exactly: in-memory, process-scoped, registered
with `ProcessState`, sealed on clear. A pattern already carrying message drafts through this same
lifecycle is a better answer than a second, weaker mechanism.

`EmailDetailActivity.kt:209` fires `markRead` from `onCreate`. Without a guard, every fold re-fires
an authenticated network mutation. The guard covers recreates only: reopening a message after the
task was cleared is a genuine new open, and marking it read again is correct.

### Class B — close-and-lock

Closing the fold turns the screen off. `KyPostApp.onStop` arms the grace window (default 30s) through
`ProcessLifecycleOwner`. Past that window `LockedActivity` finishes the screen and routes to
`UnlockActivity`, which relaunches `MainActivity` with `FLAG_ACTIVITY_CLEAR_TASK`.

| Away for  | On return                                                        |
| --------- | ---------------------------------------------------------------- |
| **< 30s** | Grace cancels the lock. The Activity resizes to the cover screen. |
| **≥ 30s** | Lock engages → PIN → task cleared → **inbox at defaults**.        |

**If a screen close causes a lock event, the user gets the inbox.** No instance state survives
`finish()` plus `CLEAR_TASK`, and this design adds nothing to work around that. Restoring someone
into a sensitive folder or an open message on a cover screen they may be holding in public is not a
convenience worth buying, and a process-scoped "last folder" holder to smuggle context past the lock
would be exactly that purchase.

`ComposeDraftCache` remains the one exception. It predates this work, exists because the app lock
finishes the compose screen during a file-picker round trip, and is deliberately in-memory so it
never writes message plaintext to disk.

---

## What may enter a saved-state Bundle

Identifiers and view positions only. Folder names, tab enums, scroll indices, message ids.

Never a decrypted body, never attachment bytes, never draft content. The saved-state Bundle is
system-managed storage written outside this app's control, and `ComposeDraftCache` already documents
why message plaintext stays off disk — Hostile Location Protection exists to prevent exactly that.
Folding must not become a side door around it.

Message plaintext keeps living only in the process-scoped holders that register with `ProcessState`
and are cleared at session boundaries by `ProcessState.resetAll()`.

---

## Files

**New**

| Path                                     | Purpose                                          |
| ---------------------------------------- | ------------------------------------------------ |
| `ui/FormFactor.kt`                       | Pure `formFactorFor(widthDp)` + Context wrapper   |
| `contacts/ContactEditDraftCache.kt`      | In-memory contact-edit draft, `ProcessState`-registered |
| `res/layout-w600dp/activity_inbox.xml`   | Rail instead of bottom nav, wider list            |
| `res/layout-w600dp/activity_compose.xml` | Header column left, editor right                  |
| `res/layout-w600dp/activity_contacts_list.xml` | Wider list, rail-aware padding             |
| `res/xml/split_config.xml`               | Activity Embedding pair rules                     |

**Modified**

`InboxActivity.kt` (field → `NavigationBarView`, `onSaveInstanceState`), `EmailDetailActivity.kt`
(markRead guard, saved state), `ContactsListActivity.kt` and `ContactDetailActivity.kt` (saved
state), `ContactEditActivity.kt` (stash to and take from the draft cache),
`AndroidManifest.xml` (embedding property), `app/build.gradle.kts` and
`gradle/libs.versions.toml` (`androidx.window`).

---

## Edge cases

**API 31.** Embedding inactive, behaviour identical to today.

**RTL.** The rail anchors to `start` and mirrors with the detail pane.

**Cover screen.** The `w600dp` variants never resolve; today's layouts are what render.

**Fold closed mid-compose.** Class B. The draft lands in `ComposeDraftCache` and is taken back on the
next open, attachments included.

---

## Verification

The module has no Robolectric — JVM tests here are deliberately Android-framework-free — so what can
be tested where is a real constraint, not a preference.

**JVM tests.** `formFactorFor` at the 599/600/601dp boundaries and across densities; the markRead
guard, extracted as a pure predicate so it needs no Activity. This follows the `AppLockManager`
precedent of keeping security-relevant logic Context-free precisely so it can be tested.

**Instrumented tests.** `ActivityScenario.recreate()` for the layout swap, rail presence, and state
restore. In `androidTest/security`:

1. A live resize must **not** engage the app lock.
2. Close-and-lock past the grace window **must** still lock. This control cannot regress on
   foldables.
3. Two embedded panes locking at once must produce **one** unlock prompt, with no pane left alive
   underneath it. `UnlockActivity` is `singleInstance`, so the two `startActivity` calls should
   collapse — but two `LockedActivity` instances visible simultaneously is a code path that has
   never existed in this app, so it is tested rather than assumed.
4. The compose draft survives both transition classes, attachments included.
5. A contact edit in progress survives a live resize, and is cleared by `ProcessState.resetAll()`
   like every other plaintext holder.

**Manual, on a foldable emulator.** The physical hinge event (`adb shell cmd device_state`). No
automated test in this plan drives a real fold, and none is claimed to.

---

## Out of scope, with reasons

**Refactoring the detail Activities into fragments.** Activity Embedding gets the same two-pane
result without touching them. A fragment migration would move `FLAG_SECURE`, the app-lock gate and
attachment handling onto a new lifecycle for no user-visible gain.

> **Reason gate.** Revisit if a pane needs to communicate with its sibling beyond what
> `startActivityForResult` already carries — for example, live-updating the list as the detail pane
> edits a contact.

**A `w840dp` tier and desktop-class layouts.** One breakpoint answers the question this spec was
written for. Adding tiers for hardware nobody has reported using is cost without a case.

**Drag-and-drop between panes, and multi-window drag targets.** Genuinely useful on large screens and
genuinely its own design: it touches attachment handling, which is where `EphemeralAttachmentProvider`
and the download ledger live.

**Restoring deep context after an app lock.** Refused above, on purpose. Recorded here so a later
reader does not implement it as a missing feature.

---

## Verification results

Recorded 2026-08-15, at the end of Task 8, updated the same day after fix round 1 added the missing
third lock test and a JVM test for `ComposeDraftCache`. **Nothing in this section may be read as
"the fold behaviour works."** It has not been observed working, on any device, by anyone, at any
point in this plan. What follows is a precise account of what ran, what only compiles, and what was
never written.

### Environment limits, established before anything else

Instrumented tests do not execute on this machine. The API 37 emulator boots and runs system apps,
but cannot launch this app's own Activities — `am start` reports "Activity class does not exist" even
with the package installed for user 0 and the activity present in the resolver table, and Gradle's
`connectedDebugAndroidTest` run resolves the intent against the `.test` package instead of the app's.
This is environmental, not a defect in any code this plan touches.

The only AVD on this machine is `Pixel_10`, a phone at 411dp wide. There is no large-screen or
foldable AVD, `avdmanager`/`sdkmanager` are not on `PATH` to create one, and `adb shell cmd
device_state` has no foldable device to drive. The manual pass in Task 8's Step 4 could not be
attempted for want of a device to run it on, not skipped for lack of time.

Both limits pre-date and are independent of this task's code.

### The spec's five instrumented items

1. **A live resize must not engage the app lock.**
   **Written, unverified.** `FoldLockBehaviourTest.aLiveResizeDoesNotEngageTheAppLock()`
   (`app/src/androidTest/java/org/kysecurity/mail/security/FoldLockBehaviourTest.kt`) launches
   `InboxActivity`, calls `scenario.recreate()`, and asserts `appLockManager.isLockedNow()` is false.
   It compiles and packages — `:app:assembleDebugAndroidTest` succeeded, which exercises
   `compileDebugAndroidTestKotlin` against this file — but it has never run.

2. **Close-and-lock past the grace window must still lock.**
   **Written, partial, unverified.** `FoldLockBehaviourTest.lockNowStillGatesTheInbox()` calls
   `appLockManager.lockNow()` directly, then recreates `InboxActivity` and asserts the Activity is
   finishing or destroyed. This is a proxy for "once the app is locked, a gated screen does not
   survive a recreate" — it does not drive the real close → 30s grace window elapses → reopen path
   through `KyPostApp`/`ProcessLifecycleOwner`. No test anywhere in this plan does. It compiles.
   It has never run.

3. **Two embedded panes locking at once must produce exactly one unlock prompt.**
   **Written (fix round 1), unverified.**
   `FoldLockBehaviourTest.lockingTwoEmbeddedPanesProducesExactlyOneUnlockPrompt()` launches
   `InboxActivity` as the primary pane and `EmailDetailActivity` as the secondary, locks the app,
   recreates both, and asserts two things: neither pane survives (`isFinishing`/`isDestroyed`, the
   same proxy item 2 uses), and — the property's actual point — an `Application.ActivityLifecycleCallbacks`
   registered process-wide observed exactly **one** `onActivityCreated` call for `UnlockActivity`.
   That count is a direct assertion of `UnlockActivity`'s `singleInstance` launch mode: a second
   `startActivity` against an already-running `singleInstance` Activity is delivered as
   `onNewIntent`, not a fresh `onCreate`, so a count of 1 is what the manifest's contract predicts
   and a count of 2 would mean the two panes had stacked two prompts. It compiles
   (`:app:assembleDebugAndroidTest` succeeded). It has never run, for the same emulator reason as
   items 1 and 2 — this environment cannot launch this app's Activities at all, so the launch-mode
   collapse this test depends on has not been observed here either.

4. **The compose draft survives both transition classes, attachments included.**
   **Partially written (fix round 1), the JVM half verified.**
   `app/src/test/java/org/kysecurity/mail/ComposeDraftCacheTest.kt` — 7 JVM tests covering
   `save`/`take` ownership transfer, that `hasContent()` rejects an untouched draft, that a lone
   attachment with no text anywhere is still worth keeping (the spec's own "attachments included"
   case), that `clear()` seals against a late write, that `take()` unseals for the next session, and
   that `resetForNewSession()` drops everything. **This part genuinely ran**: `./gradlew
   :app:testDebugUnitTest` — all 7 pass, 0 failures. It is Android-framework-free, so unlike
   everything else in this section it needed no emulator. What it does **not** cover, and what
   remains entirely unwritten, is the actual transition behaviour — an `ActivityScenario.recreate()`
   or a real fold/close-and-lock proving `ComposeActivity` actually stashes into and restores from
   this cache. The cache's own contract is now proven; whether `ComposeActivity` honours it under a
   real transition is not.

5. **A contact edit in progress survives a live resize, and is cleared by `ProcessState.resetAll()`
   like every other plaintext holder.**
   **Partially written, unverified.** `ContactEditDraftTest.typedNameSurvivesRecreate()`
   (`app/src/androidTest/java/org/kysecurity/mail/ui/ContactEditDraftTest.kt`, from an earlier task
   in this plan) covers the live-resize-survives half. No test asserts the cache is cleared by
   `ProcessState.resetAll()`. What exists has never run.

### What did run

`./gradlew :app:testDebugUnitTest` — **BUILD SUCCESSFUL**, 822 tests, 0 failures, 0 errors, 0 skipped
(815 before fix round 1, +7 from the new `ComposeDraftCacheTest`). No regressions. This is the one
genuinely executed piece of foldable-specific coverage in this whole plan — everything else below is
either unrun instrumented code or a manual pass that never happened.

`./gradlew :app:assembleDebug` — **BUILD SUCCESSFUL**.

`./gradlew :app:assembleDebugAndroidTest` — **BUILD SUCCESSFUL**. `compileDebugAndroidTestKotlin`
executed and succeeded, which is the proof that `FoldLockBehaviourTest.kt` — now three tests —
compiles and its symbols (`SecurityRuntime.graph`, `AppLockManager.lockNow`/`isLockedNow`,
`InboxActivity`, `EmailDetailActivity`, `UnlockActivity`, `Application.ActivityLifecycleCallbacks`)
resolve. This is compilation evidence only — it is not execution evidence.

### Manual foldable pass (Step 4) — not performed

Not attempted, for the environment reasons above. The seven checks are outstanding for whoever next
has real hardware or can provision a foldable/large-screen AVD:

1. Open the app unfolded → rail on the left, two panes once a message is open.
2. Fold while reading a message → phone layout, message full-screen, list behind it.
3. Unfold again within the 30s grace → returns to two panes, no PIN prompt.
4. Fold, wait past the grace window, unfold → PIN prompt, then the inbox at defaults.
5. Type a contact name, unfold mid-edit → the typed name is still there.
6. Type a message body, fold and unfold → the draft is still there.
7. With two panes open, lock the app → **one** unlock prompt, no pane visible behind it.

### Bottom line

All three app-lock security properties this task exists to check now have a test written against
them. **None has ever run.** The two-panes-one-prompt test is a genuine assertion of
`UnlockActivity`'s `singleInstance` contract via a process-wide `ActivityLifecycleCallbacks` count,
not a placeholder — but it is exactly as unexecuted as the other two, for the same environmental
reason. Separately, `ComposeDraftCache`'s own contract (save/take/clear/reseal, attachments included)
is now covered by 7 JVM tests that **did** run and pass — the one piece of foldable-adjacent
verification in this entire plan that is not an unrun promise. It proves the cache; it does not prove
`ComposeActivity` uses it correctly under a real transition, which remains untested.

The large-screen and fold behaviour described throughout this spec has not been observed working, on
any device, at any point in this plan. A reader relying on this document for a release decision should
treat every layout, embedding, and state-restore claim above as design intent, not as demonstrated
fact — the one exception, noted explicitly above, is `ComposeDraftCache`'s own in-memory contract.
