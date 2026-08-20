# Handoff — making `SecurityWipe`'s step ordering structural

**Status:** Not started. Deliberately deferred on 2026-08-19 at the end of the hostile-review fix pass.
**Owner:** unassigned
**Target file:** `app/src/main/java/org/kysecurity/mail/security/SecurityWipe.kt`
**Risk:** High. This is the routine that destroys the user's mailbox. Read all of §3 before editing.

---

## 1. Why this exists

A hostile review of the repo raised, under "Code Quality Failures":

> `SecurityWipe.kt` is 522 lines and roughly a third of it is prose defending the other two thirds.
> [CLAUDE.md] rule 2: **"Code needing a paragraph to defend why it isn't wrong, is wrong. Fix the
> code."** […] That comment is defending an ordering constraint that is invisible in the code. The
> fix is not a shorter comment — it's making the constraint structural.

Every other finding from that review was fixed and verified in the same pass. This one was not, for
a reason that has not changed and that you should weigh before starting:

**The ordering is currently correct, guarded by instrumented tests, and a refactor that reorders
steps is the single most dangerous edit available in this codebase.** The payoff is legibility and
regression-resistance, not a behaviour fix. There is no known bug here. If you are under time
pressure, closing this ticket as "won't do" is a defensible outcome — see §5 for the minimal
version that captures most of the value for a fraction of the risk.

### What already changed on 2026-08-19

Do not re-derive these; they are shipped and tested.

- `wipeAndResetApp` now takes a `Mutex` (`wipeGate`) and delegates to a private `runWipe`.
  Concurrent wipes previously raced each other's `deleteSharedPreferences` and produced spurious
  failed steps. Guarded by `ConcurrentWipeTest`.
- The stranded-downloads count on the throwing path is the ledger's real size
  (`DownloadedAttachmentLedger.recordedCount`), not a placeholder list's `.size`.
- `recordStrandedDownloads`' KDoc now matches its `maxOf` implementation (high-water mark, not a
  running total).
- `enforceTripwire` handles the new tri-state `AppLockStore.tripwireBroken()`, and publishes
  `SecurityWipe.lockStoreUnreadable` for `LockedActivity`.

---

## 2. The actual invariants

There are **22 `step(...)` calls** plus **three deliberate non-steps**. Line numbers are as of
commit `8396d0f` + the 2026-08-19 working tree and *will* drift — grep for the step name.

### 2.1 Step order as it stands

```
 1 inMemoryPlaintext            12 pullWorker
 2 database                     13 deviceContactWorker
 3 datastores                   14 clearPairingState
 4 cancelNotifications          15 sharedPrefs
 5 unifiedPushUnregister        16 webViewState
 6 unifiedPushDatabase          17 deviceContactRows
 7 unifiedPushPrefs             18 deviceContactAccount
 8 enrollmentTeardown           19 appLock
 9 biometricUnlockVault         20 credentialPeppers
10 authGateKey                  21 restoreHostileLocationProtection  (conditional)
11 databaseKey                  22 androidxMasterKey
```

### 2.2 The constraints that are currently comments

Each of these is a real dependency. **A phase enum alone does not express any of them** — see §4.

| # | Constraint | Why | Currently defended by |
|---|---|---|---|
| C1 | `database` before `databaseKey` | An encrypted DB is only as destroyed as its key; deleting the key first leaves a file nothing can even prove is gone | comment at `databaseKey` |
| C2 | `unifiedPushUnregister` before `unifiedPushDatabase` **and** `unifiedPushPrefs` | Reversed, the unregister has no registration records left to unsubscribe with and the device stays subscribed server-side | comment at `unifiedPushUnregister` |
| C3 | all three unifiedPush steps before `sharedPrefs` | `UnifiedPush.unregister` reads the distributor selection out of `unifiedpush.connector`, which the mid-wipe sweep retains only because this ordering holds | comment at `sharedPrefs`; `PREFS_NAMES_RETAINED` |
| C4 | `enrollmentTeardown` before `sharedPrefs` | Constructing the enrollment store recreates its file *and its Tink keyset*; after the sweep that is a resurrected artefact | comment at `enrollmentTeardown` |
| C5 | `clearPairingState` before `sharedPrefs` | `clearPairing()` writes, and a write recreates the files the sweep just removed | comment at `clearPairingState` |
| C6 | `appLock` after `sharedPrefs` | `app_lock_secure` / `app_lock_tripwire` are in `PREFS_NAMES_RETAINED` precisely so the verifier survives the mid-wipe sweep long enough for this step to evaluate it | `PREFS_NAMES_RETAINED` |
| C7 | `credentialPeppers` after `appLock` | `appLock` is the last thing that can still need to evaluate the PIN verifier the peppers key | comment at `credentialPeppers` |
| C8 | `restoreHostileLocationProtection` after `sharedPrefs` | Otherwise the sweep deletes the flag this step just re-asserted | comment at the call |
| C9 | Nothing after the network phase may destroy local data | A force-stop mid-network must not lose anything a resume needs | banner comment `// Everything below touches the network…` |
| C10 | `androidxMasterKey` is **absolutely last** | The deregister ends in `clearPairing()`, which writes to an encrypted store and thereby recreates both the prefs file *and* the master key alias. Destroying the alias any earlier is undone on every wipe that reaches the relay | 3-paragraph comment at `androidxMasterKey` |
| C11 | Pairing + TLS pin captured **before** `sharedPrefs` | The deregister authenticates with a credential the sweep deletes; a cleared pin reads `NeverPaired` and would send the device secret unpinned | comments at the two `runCatching` captures |
| C12 | `markWipeInProgress` before anything is destroyed | An interruption before this point erases the evidence a wipe was ever started | comment at the call |

**C10 is the load-bearing one and the easiest to break.** It is the only constraint where the
correct position is "after a phase that is not a `step` at all".

### 2.3 The three deliberate non-steps

These must **not** become steps. Each was a step once and each bricked the app:

1. **`DownloadedAttachmentLedger.deleteAll`** — rows live in a provider this app does not own. A row
   it can never delete failed the wipe on every resume until `MAX_WIPE_RESUMES` (3) marked it
   abandoned, permanently blocking the app over a file the user can delete in ten seconds.
   Reported via `recordStrandedDownloads`, guarded by
   `WipeResurrectionTest.wipe_completesButReportsAttachmentsItCouldNotRemove`.
2. **FCM teardown** — needs a reachable Firebase. As a step it bricked offline devices.
3. **Server deregister** — same argument; reports rather than fails.

A refactor that "tidies these into the step list for consistency" re-introduces three separate
app-bricking regressions. Any new abstraction must make the non-step path *expressible and obvious*,
not awkward.

---

## 3. Hazards

1. **Step names are persisted and asserted on.** They are written to
   `KEY_WIPE_FAILED_STEPS` (`org.kysecurity.mail.wipe_state`), survive across launches and app
   upgrades, and are read back by `abandonedWipe()`. Nothing in production *branches* on a name —
   they are logged (`PinGate`, `UnlockActivity`, `LockedActivity`) and displayed only as a generic
   string — so a rename is not a correctness break, but it does mean a device upgrading mid-abandoned-wipe
   shows old names. **Tests do branch on literal names:**
   - `SecurityWipeTest.kt:205` — `"sharedPrefs"`
   - `WipeResurrectionTest.kt:171` — `"sharedPrefs"`
   - `ConcurrentWipeTest.kt` — `raceSensitiveSteps` = `sharedPrefs, datastores, unifiedPushPrefs, androidxMasterKey, database`

   Prefer keeping every existing name. If you must rename, update all three suites in the same commit.

2. **`step()` is a local closure over `failed`.** Any extraction to a class must preserve that a
   step's failure is recorded and *does not* abort the remaining steps. A wipe that stops at the
   first failure is strictly worse than today's.

3. **These tests only run on an emulator.** `ci-emulator` (API 31 / 34 / 36). There is no JVM
   coverage of ordering at all. If you change ordering and only run `testDebugUnitTest`, you have
   verified nothing.

4. **`FoldLockBehaviourTest.lockingTwoEmbeddedPanesProducesExactlyOneUnlockPrompt` fails on a local
   emulator on an unmodified tree.** Confirmed 2026-08-19 by running it in a clean `git worktree` at
   HEAD. Do not chase it; do not count it as your regression. Establish your own baseline the same
   way before believing any instrumented failure.

---

## 4. Why a bare phase enum is not enough

The review's phrasing — "a phase enum" — is the right *instinct* and the wrong *mechanism*, and this
is the most important thing in this document.

A phase enum expresses C9 and C10 (coarse: "network last", "final sweep after network"). It
expresses **none** of C1–C8, C11, C12, which are pairwise dependencies *within* what would be a
single `LOCAL_DESTRUCTION` phase. Shipping a phase enum and deleting the comments it does not
replace would leave eight real constraints defended by nothing at all — strictly worse than today,
and with the appearance of rigour. **Do not do that.**

### Option A — declared dependencies (recommended)

Keep the linear list exactly as it is. Give each step an `after` set, and have the runner assert
every named predecessor has already run.

```kotlin
private class WipeRun(private val appContext: Context) {
    val failed = mutableListOf<String>()
    private val ran = mutableSetOf<String>()

    /** [after] is the ordering contract, checked rather than described. A step naming a
     *  predecessor that has not run is a programming error, not a wipe failure: it means the list
     *  below was reordered, and the wipe would silently under-destroy. */
    suspend fun step(name: String, after: Set<String> = emptySet(), body: suspend () -> Unit) {
        val missing = after - ran
        check(missing.isEmpty()) { "wipe step '$name' runs before $missing" }
        ran += name
        runCatching { body() }.onFailure {
            failed += name
            android.util.Log.e(TAG, "Wipe step failed: $name", it)
        }
    }
}
```

Call sites become e.g.:

```kotlin
run.step("databaseKey", after = setOf("database")) { … }
run.step("sharedPrefs", after = setOf("unifiedPushPrefs", "enrollmentTeardown", "clearPairingState")) { … }
run.step("credentialPeppers", after = setOf("appLock")) { … }
run.step("androidxMasterKey", after = setOf("sharedPrefs", "credentialPeppers")) { … }
```

- Converts C1–C8 from prose into machine-checked data. Each `after` replaces a paragraph.
- **Reorders nothing.** The diff is additive; the execution order is byte-identical.
- `ran` records steps that ran, not steps that *succeeded* — a failed step still satisfies its
  dependents, which is correct: the wipe deliberately continues past failures.
- C9/C10 still need a comment, because "the network phase" is not a step. Accept that, or add a
  single `run.phaseBoundary("network")` marker that later steps can name in `after`.

**Cost:** ~40 lines added, ~60 lines of comment removed, no behavioural change.

### Option B — phases *and* dependencies

Option A plus a `WipePhase` enum threaded through `step`, with a monotonic-advance check. Buys a
machine-checked C9/C10 at the cost of a second concept. Only worth it if C9 has actually been
violated at some point; as of 2026-08-19 it has not.

### Option C — do nothing, tighten the comments

Legitimate. The comments are accurate and the tests pass. If you pick this, say so in the ticket and
delete this file, rather than leaving it open forever.

---

## 5. If you only do one thing

Do **Option A, for C1, C4, C5, C7 and C10 only** — the five where the ordering is non-obvious from
reading the list top to bottom. That is roughly fifteen lines of change, removes the four longest
comments in the file, reorders nothing, and is verifiable in one emulator run.

Leave C6, C11, C12 as comments: they are constraints about *data captured before a sweep*, not about
step order, and forcing them into an `after` set would misrepresent them.

---

## 6. Verification recipe

Ordering changes are not verifiable by unit tests. All three of these must pass.

```bash
# The local toolchain picks up a VS Code JRE with no `jlink` and fails the JdkImageTransform.
# Pin a real JDK 21 explicitly, or the build dies before compiling anything:
export JAVA_HOME=/home/yoshi/.gradle/jdks/eclipse_adoptium-21-amd64-linux.2

./gradlew :app:testDebugUnitTest -Dorg.gradle.java.home="$JAVA_HOME"   # expect 933 pass, 0 fail
./gradlew :app:lint             -Dorg.gradle.java.home="$JAVA_HOME"    # expect BUILD SUCCESSFUL

# The emulator needs a secure lock screen (EnrollmentVault refuses without one) and a
# dismissed keyguard, or unrelated suites fail for reasons that are not your change:
adb shell locksettings set-pin 1234
adb shell locksettings verify --old 1234      # must say "verified successfully"
adb shell svc power stayon true
adb shell wm dismiss-keyguard
adb shell input swipe 540 1600 540 400        # API 36 needs the swipe; keyevent 82 is not enough
adb shell dumpsys activity activities | grep -m1 mKeyguardShowing   # must be false

./gradlew :app:connectedDebugAndroidTest -Dorg.gradle.java.home="$JAVA_HOME"
# Expect 198 tests. Expect exactly ONE pre-existing failure:
#   FoldLockBehaviourTest.lockingTwoEmbeddedPanesProducesExactlyOneUnlockPrompt
```

**Establish a baseline before believing any failure**, in a worktree so your tree is never at risk:

```bash
git worktree add /tmp/kypost-baseline HEAD
cp local.properties /tmp/kypost-baseline/ && cp app/google-services.json /tmp/kypost-baseline/app/
( cd /tmp/kypost-baseline && ./gradlew :app:connectedDebugAndroidTest -Dorg.gradle.java.home="$JAVA_HOME" )
# …compare failure sets, then:
git worktree remove --force /tmp/kypost-baseline
```

### The test that should exist and does not

Whichever option you pick, add a JVM test asserting the dependency declarations are internally
consistent — that every name in an `after` set is a real step, and that the declared graph is a
subsequence of the actual call order. That is the only part of this work that is testable without an
emulator, and it is what stops the `after` sets rotting into decoration.

---

## 7. Definition of done

- [ ] Ordering constraints C1, C4, C5, C7, C10 expressed as `after` declarations, not prose.
- [ ] The comments those declarations replace are **deleted**, not merely shortened.
- [ ] No step renamed, or all three test suites in §3.1 updated in the same commit.
- [ ] The three non-steps in §2.3 are still non-steps.
- [ ] Execution order byte-identical to before — verify with a `log()` of `ran` on both trees.
- [ ] JVM consistency test added (§6).
- [ ] Unit + lint + instrumented all green against a freshly-taken baseline.
- [ ] `app/AGENTS.md` updated if the wipe's verification contract changed.
