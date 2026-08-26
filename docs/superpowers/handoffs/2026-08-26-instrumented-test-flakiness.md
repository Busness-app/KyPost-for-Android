# Handoff: the instrumented suite flakes, and it gates every merge

Written 2026-08-26 from the session that landed section D of the launch plan.
Every claim carries a citation and was checked against the file or the CI log it
names. Where something is a hypothesis rather than a finding, it says so.

**Scope:** `connected<Flavor>DebugAndroidTest` — the `ci-emulator` legs. Unit
tests are not implicated.

---

## The problem

Two instrumented failures during one afternoon, on changes that provably could
not have caused them. A third, older instance of a *different* class is already
recorded in `ci.yml` — see "What this is NOT" below.

| PR | Leg | Test that failed |
| --- | --- | --- |
| #91 | `ci-emulator (34)` | `KeywordSettingsBoundsTest.rememberKeywords_writesNothingUnderHostileLocationProtection` |
| #94 | `ci-emulator (31, Play)` | `DeviceContactVisibilityTest.ungroupedSyncedContact_isVisibleOnceTheAccountOptsIn` |

Both passed on re-run of the **identical commit**. For #94 that is conclusive:
its entire diff is two Markdown files under `docs/`, and no change to a Markdown
file can break an instrumented contacts test.

Every emulator leg is required and `fail-fast: false`, so each flake blocks a
merge until a human notices and re-runs it, at roughly 7 minutes a leg.

## What this is NOT

The repo already documents a flake class and has mitigated it at length: the
emulator's keyguard re-arming mid-run, producing

    Activity never becomes requested state "[RESUMED]"

`ci.yml` carries a keyguard watchdog and a long comment about it
(`.github/workflows/ci.yml:470-500`), including a previous instance — *"eight red
UI tests on a tree whose only change was to encrypted-prefs recovery, green on a
rerun of the identical commit."*

**These two failures are a different class.** Neither test launches an Activity;
both are state assertions. `KeywordSettingsBoundsTest` failed with a plain
`java.lang.AssertionError`, not a lifecycle timeout. The keyguard watchdog cannot
help here, and reading these as "the known keyguard flake" would send the next
person down a road that has already been walked.

## The structural cause

**There is no test isolation.** All 56 instrumented classes run in one process
against one device:

- no Android Test Orchestrator, no `clearPackageData`, no
  `testInstrumentationRunnerArguments` — `app/build.gradle.kts` `testOptions`
  configures unit tests only;
- no `@FixMethodOrder` or custom sorter anywhere in `app/src/androidTest`, so
  **class order is not pinned**.

That last point explains why the failures move: which test runs immediately
before which is not stable between runs, so a pollution-sensitive pair only
sometimes lands adjacently.

The shared state these tests contend over is not ordinary app state. It is
*system* state that outlives the process:

- **CP2**, the system contacts provider — survives even app death;
- **AccountManager** accounts;
- SharedPreferences and DataStore;
- WorkManager, which this app really uses (`DeviceContactSyncWorker`,
  `PullWorker`).

## The contacts failure has a concrete, evidence-backed hypothesis

Read the CI log ordering, not just the failure. Immediately before the failing
test, on the same runner thread:

    12:38:58.768 I DeviceContactPurge: ... ContentProviderHelper.getContentProvider
    12:38:58.776 I TestRunner: finished: deleteSyncedRows_withNoAccount_isNotAFailure
                                (DeviceContactAccountTeardownTest)
    12:38:58.778 I TestRunner: started:  ungroupedSyncedContact_isVisibleOnceTheAccountOptsIn
                                (DeviceContactVisibilityTest)

**Two milliseconds apart.** And the test that just finished exists to remove the
account: `DeviceContactAccountTeardownTest.deleteSyncedRows_withNoAccount_isNotAFailure`
calls `accounts.removeAccountBlocking()` at line 42, and the class `@After`
(line 18-20) removes it again.

The next test then does, in `@Before`, `accounts.ensureAccount()`
(`DeviceContactVisibilityTest.kt:32,37`), and inserts a probe raw contact
(`:46`).

**Hypothesis:** `removeAccountBlocking()` returns once AccountManager has dropped
the account record, but CP2 deletes the raw contacts and the `Settings` row
belonging to a removed account **asynchronously**. If that cleanup lands after
the next test has recreated the account and inserted its probe, it takes the
probe or the `UNGROUPED_VISIBLE` row with it — which is exactly the pair of
assertions that failed:

```kotlin
assertEquals("the account must be opted in to showing ungrouped contacts", 1, ungroupedVisible())
assertEquals(..., 1, inVisibleGroup(contactId))
```

There is a second, independent sharp edge in the same file regardless of the
race. `insertUngroupedRawContact` looks the contact up by **account type only**,
taking the first row it finds, never by the display name it just wrote
(`DeviceContactVisibilityTest.kt:73`). Any residue from another test in the
same account picks up the wrong `CONTACT_ID`.

**Not reproduced.** This is inference from log adjacency plus the source; nobody
has watched it happen.

## The keyword failure has a weaker one

`KeywordSettingsBoundsTest` clears state in `@Before` with
`context.deleteSharedPreferences(KeywordSettings.PREFS_NAME)` and
`HostileLocationSettings(context).setEnabled(false)` (`:21-23`).

Two candidate mechanisms, neither confirmed:

1. `KeywordSettings` holds `private val prefs = context.getSharedPreferences(...)`
   (`KeywordSettings.kt:7`), so an instance is live whenever one exists.
   `deleteSharedPreferences` is documented as unsafe against a
   SharedPreferences that is currently in use.
2. `HostileLocationSettings` is process-global with its own `LOCK`
   (`HostileLocationSettings.kt:73`). The test that failed enables it and
   disables it in a `finally`. Anything else in the process reading or writing
   it concurrently — including app background work — diverges the result.

The log adjacency that made the contacts case tractable was not captured for
this run before it aged out. **Capture it next time it fails.**

## What to do

In the order I would do it.

### 1. Make the next failure diagnosable, before fixing anything

The single highest-value change. On failure the job should attach the full
`TestRunner: started/finished` sequence, so the class that ran immediately
before is recoverable without racing GitHub's log retention. The suite already
dumps logcat; the ordering lines are in it, but nothing surfaces them.

Without this, every future flake costs the archaeology this handoff just did.

### 2. Fix the two sharp edges that are wrong regardless of the race

Cheap, independently correct, and they may be the whole thing:

- `DeviceContactVisibilityTest.insertUngroupedRawContact` should select by the
  display name it just inserted, not by account type alone.
- `DeviceContactAccountTeardownTest` and `DeviceContactVisibilityTest` should not
  be able to interleave against one live account. Either give each test a
  distinct account name, or make the visibility test assert its own probe rather
  than whatever the account currently holds.

### 3. Decide on isolation

Android Test Orchestrator with `clearPackageData = true` runs each test in its
own process and clears package data between tests. It is the standard answer to
exactly this shape of problem and would close the SharedPreferences and DataStore
half outright.

It does **not** fix CP2 or AccountManager, which are system state outside the
package — so it is a partial fix, and worth saying so before someone reaches for
it expecting a cure. It also costs wall-clock: a process per test across 56
classes is materially slower, on a job that already takes 7 minutes.

### 4. What NOT to do, unless the above fails

Add a blanket retry to the instrumented step.

It would make the symptom go away today. It would also hide a genuine
intermittent bug just as effectively, and these are security-adjacent surfaces —
the contacts provider the app writes the user's address book into, and the
Hostile Location Protection switch that decides whether keywords touch a
plaintext file at all. A test that fails one run in ten on those is telling you
something, and a retry is how you stop hearing it.

If a retry is added anyway, log every retried failure loudly enough that a rising
rate is visible. A silent retry is indistinguishable from a passing suite.

## Open questions

- Does the same pair flake locally under repetition? `--rerun-tasks` with the
  two classes forced adjacent would test the hypothesis in §"contacts" directly,
  and is the cheapest possible confirmation.
- Is `ci-emulator (34, Fdroid)` — added in D3 (2/2) — any more or less prone than
  the Play legs? It has only run a handful of times.
- Do any of the 56 classes already depend on ordering by accident and pass only
  because of the order they happen to get?

## What was not checked

- Whether background WorkManager jobs actually run during the suite. It is
  plausible and would broaden the shared-state surface, but nothing was measured.
- Whether the keyguard watchdog interacts with these tests at all. It should not
  — they never show UI — but that was reasoned, not observed.
- Any leg other than the two that failed.
