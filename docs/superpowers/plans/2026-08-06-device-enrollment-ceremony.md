# Device Enrollment Ceremony Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give a paired Android device a Security-page ceremony that publishes an enrollment key, shows a short code the user types in their browser, opens the sealed envelope, re-seals it under a lock-screen-bound Keystore key, and reports the result — plus the CI this repository has never had.

**Architecture:** A pure `EnrollmentCeremony` state machine with no Android imports drives the whole flow through five injected ports (identity, transport, keys, vault sealer, clock) and two injected guard lambdas. A `DeviceEnrollmentViewModel` owns the ceremony and exposes `StateFlow<EnrollmentUiState>` so rotation cannot republish a key. `DeviceEnrollmentActivity` renders state and owns the one Activity-bound piece, `BiometricPrompt`. The Security page renders a row from a second pure function.

**Tech Stack:** Kotlin, Android views (no Compose), AndroidX Lifecycle ViewModel + StateFlow, AndroidX Biometric, OkHttp `Call.Factory`, kotlinx.serialization, WorkManager, JUnit 4 + `kotlin-test-junit`, `androidx.test` for instrumented tests, GitHub Actions.

**Source spec:** `docs/superpowers/specs/2026-08-06-device-enrollment-ceremony-design.md`. Spec 1 (the crypto core this calls) is `docs/superpowers/specs/2026-08-05-device-enrollment-2c-crypto-core-design.md`.

## Global Constraints

Every task's requirements implicitly include this section.

- **Every string describes capability, never behaviour.** Success says "This device now holds a key for your encrypted mail." Nothing may say the user can now read encrypted mail on the phone — they cannot until the deferred on-device decryption work lands.
- **Failure states are sentinels, never server text.** `Failed(reason)` carries an enum; every displayed string is a local resource. No server-supplied message is ever rendered on these screens.
- **"Could not check" is not "no."** A failed identity check must never render as "your account doesn't use encrypted mail".
- **Every network client that carries the device credential is constructed with `pinnedPairingCallFactory(context)`.** `EnrollmentClients.callFactory` has no default so this cannot be forgotten (see `d410827`). `PgpBootstrapClient.callFactory` *does* default, to the **unpinned** `pairingHttpClient()` — pass the pinned factory explicitly.
- **`deleteKeyPair()` fires on every ceremony exit that ends the attempt**, including success. The agreement key's life is one ceremony, not one install. Two exits keep it, and only these two: `WaitingTimedOut`, and the `ShowingCode` a cancelled biometric returns to — both are resumable by "Check again" against the same keypair, and rotating there would invalidate a code the user may already have typed.
- **A failed GCM open is never a retry.** The AAD binds device and identity; a failure means the envelope was sealed for another device or under an identity the account no longer advertises.
- **A failed report still means enrolled.** The local seal is real; only the server's marker is stale, and `EnrollmentStateWorker` already exists to correct it.
- **The plaintext never enters `EnrollmentSession`,** and is zeroed in place on every path out of the seal step.
- **No new Gradle dependencies.** `gradle/verification-metadata.xml` has `verify-metadata=true` and 600+ pinned components; adding a dependency means regenerating checksums, and CI must never regenerate that file. Every test below is written against what is already on the classpath (`runBlocking`, hand-rolled fakes — this repo has no mocking framework and no `kotlinx-coroutines-test`).
- **Baseline, verified 2026-08-06 on `main` at `ef83939`:** `./gradlew testDebugUnitTest lint` is green — 558 unit tests pass from a clean `--rerun-tasks`, lint reports 0 errors (367 warnings, which do not fail the build). 105 instrumented tests pass per the prior session's hardware run.
- **Code display grouping is 4-3-4-3** (`5R9K-6FW-A18A-8YP`), on both the phone and the browser. The underlying value `5R9K6FWA18A8YP` never changes — grouping is stripped before any comparison and never enters the hash.
- **Commit after every task.** Conventional Commits, and end each message with `Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>`.

## Deviations from the spec, and why

Read these before starting. Each is a deliberate, reasoned departure — not an oversight.

1. **Five ports, not four.** The spec names `IdentitySource`, `EnrollmentTransport`, `VaultSealer` and `Clock`. The spec's own required test — "`deleteKeyPair()` on **every** exit, parameterised across the exit table" — cannot be written without a fake for the keystore, which is none of those four. Task 3 therefore adds `EnrollmentKeys`, a fifth port wrapping `EnrollmentKeyStore`.
2. **The two preconditions are lambdas, not a port.** Hostile Location Protection and "is there a secure lock screen" are injected as `() -> Boolean` constructor parameters, following the existing `elapsedRealtimeMs: () -> Long = SystemClock::elapsedRealtime` precedent in `AppLockManager`. They are neither identity, network, vault nor time, and a sixth interface for two booleans buys nothing.
3. **`IdentitySource` wraps `PgpBootstrapClient` only, not `hasPgpIdentity` as well.** One `GET /api/pgp/bootstrap` answers all three questions the port is defined by — is there an identity, is it client-protected, and what is its fingerprint. Calling `hasPgpIdentity` as well would add a second request that can only ever agree or disagree with the first, and a disagreement has no defined resolution. `hasPgpIdentity` is left untouched for its existing callers.
4. **The Security-page row is decided by a pure function, and local facts are checked before network facts.** The spec's row table is ordered with `Enrolled` and `KEY_INVALIDATED` last. Task 9 checks both *before* the identity branch, because they are local facts: with the network down, the spec's ordering would render an invalidated device as "couldn't check", hiding the one row whose whole job is to say the device can no longer open its mail — and would hide "Remove from this device", which is a local security action that must stay reachable offline.
5. **The row table gains a ninth state, `CouldNotCheck`.** The spec's table has eight rows and no entry for a failed identity check, while the spec's own decision 10 requires that "could not check" never render as "no". Task 9 adds it.
6. **"Remove from this device" reports through `EnrollmentStateWorker`, not a direct `reportState(false)`.** The worker re-probes live state on every run, retries when offline, and is already tested; a direct call adds a second reporting path that can silently fail. This is the same shape `tearDownEnrollmentForHostileLocation` already uses.
8. **A cancelled biometric ends the polling window instead of re-prompting.** The spec's exit table says a cancel goes "back to `ShowingCode`". Taken literally inside the poll loop, that re-fetches the same envelope three seconds later and puts the prompt straight back on screen, repeatedly, for the rest of the five minutes — the envelope stays on the relay for seven days, so nothing stops it. Task 5 therefore returns to `ShowingCode` *and stops the window*; `checkAgain()` resumes it, driven by the same button the timeout uses. The ViewModel exposes an `idle` flag so the Activity knows to offer that button in both cases. (Repeated cancels do not risk biometric lockout — that counts failed matches, not dismissals — so the cost here is purely one of usability, which is why it is worth a one-line departure and not more.)

7. **The instrumented "renders each state" test is a string-resolution test, not an `ActivityScenario` launch.** This repository has no `ActivityScenario` test today, and driving `SecuritySettingsActivity` through eight states needs injection points the screen does not have. Task 12 asserts instead that every row state resolves to a distinct, non-blank string against a real `Context` — which is the part that can silently rot — and Task 9 covers the decision itself exhaustively on the JVM. The screen's rendering remains a manual check, stated rather than claimed.

## File Structure

**Created**

| File | Responsibility |
|---|---|
| `.github/workflows/ci.yml` | Unit + instrumented gates |
| `app/src/main/java/com/urlxl/mail/pgp/EnrollmentUiState.kt` | The sealed UI state and its two reason enums. No logic. |
| `app/src/main/java/com/urlxl/mail/pgp/EnrollmentPorts.kt` | The five port interfaces and their result types |
| `app/src/main/java/com/urlxl/mail/pgp/EnrollmentCeremony.kt` | The state machine. No Android imports. |
| `app/src/main/java/com/urlxl/mail/pgp/EnrollmentCodeFormat.kt` | 4-3-4-3 display grouping. Pure. |
| `app/src/main/java/com/urlxl/mail/pgp/EnrollmentPortsAndroid.kt` | The real implementation of each port |
| `app/src/main/java/com/urlxl/mail/pgp/EnrollmentRow.kt` | The Security-page row decision. Pure. |
| `app/src/main/java/com/urlxl/mail/pgp/DeviceEnrollmentViewModel.kt` | Owns the ceremony, exposes `StateFlow`, tears down in `onCleared` |
| `app/src/main/java/com/urlxl/mail/pgp/DeviceEnrollmentActivity.kt` | Renders state, hosts `BiometricPrompt` |
| `app/src/main/res/layout/activity_device_enrollment.xml` | The ceremony screen |
| `app/src/test/java/com/urlxl/mail/pgp/FakeEnrollmentPorts.kt` | JVM fakes for all five ports |
| `app/src/test/java/com/urlxl/mail/pgp/EnrollmentCeremonyGateTest.kt` | Preconditions and identity gating |
| `app/src/test/java/com/urlxl/mail/pgp/EnrollmentCeremonyCodeTest.kt` | Publish, code derivation, polling, resume |
| `app/src/test/java/com/urlxl/mail/pgp/EnrollmentCeremonyExitTest.kt` | Open, seal, report, and the exit table |
| `app/src/test/java/com/urlxl/mail/pgp/EnrollmentCodeFormatTest.kt` | Display grouping |
| `app/src/test/java/com/urlxl/mail/pgp/EnrollmentRowTest.kt` | The row decision |
| `app/src/androidTest/java/com/urlxl/mail/pgp/EnrollmentEnvelopeRoundTripTest.kt` | Real Keystore round trip |
| `app/src/androidTest/java/com/urlxl/mail/pgp/EnrollmentRowStringsTest.kt` | Every row state has distinct real copy |

**Modified**

| File | Change |
|---|---|
| `app/src/main/java/com/urlxl/mail/pgp/WebmailDeepLink.kt` | Add `webmailHomeUrl` |
| `app/src/main/java/com/urlxl/mail/push/NativeRegistration.kt` | Send the device secret on re-registration |
| `app/src/main/java/com/urlxl/mail/security/SecuritySettingsActivity.kt` | The enrollment entry and removal action |
| `app/src/main/res/layout/activity_push_pairing.xml` | The static pointer |
| `app/src/main/res/values/strings.xml` | All new copy |
| `app/src/main/AndroidManifest.xml` | Register `DeviceEnrollmentActivity` |
| `kypost-server` `frontend/src/lib/deviceEnrollment.ts` + its test | 4-3-4-3 grouping |
| `docs/superpowers/specs/2026-08-05-device-enrollment-2c-crypto-core-design.md` | Displayed form of the normative vector |

---

### Task 1: CI for the repository

Independent of every other task. It touches no application code and is verifiable against suites that already exist and pass, so it lands first and every task after it merges behind a green gate.

**Files:**
- Create: `.github/workflows/ci.yml`

**Interfaces:**
- Consumes: nothing.
- Produces: two required checks, `ci-unit` and `ci-instrumented`. No Kotlin symbols.

- [ ] **Step 1: Confirm the baseline is green before adding a gate to it**

A gate added over a red suite is indistinguishable from a gate that does not work.

Run: `./gradlew testDebugUnitTest lint --rerun-tasks`
Expected: `BUILD SUCCESSFUL`. If lint reports an *error* (not a warning), stop and fix it — do not add a `lintOptions` suppression to make this step pass.

- [ ] **Step 2: Confirm the two Android traps are still live**

Run:
```bash
git check-ignore -v app/google-services.json
grep -n "verify-metadata" gradle/verification-metadata.xml
```
Expected: the first prints a `.gitignore` line (so a fresh checkout has no `google-services.json`, and the `com.google.gms.google-services` plugin fails the build outright without one); the second prints `<verify-metadata>true</verify-metadata>`.

- [ ] **Step 3: Write the workflow**

Create `.github/workflows/ci.yml`:

```yaml
name: ci

# kypost-server/.github/workflows/ci.yml establishes every convention below; this file
# follows it. Push is restricted to main rather than "**": with a pull_request trigger as
# well, every push to a PR branch would otherwise run the whole suite twice for the same
# commit.
on:
  push:
    branches: [main]
  pull_request:

permissions:
  contents: read

# Supersede an in-flight run when the same ref is pushed again. main is excluded from
# cancellation: a green tick against a specific main commit is the record of whether that
# commit built, and cancelling it destroys that record.
concurrency:
  group: ${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: ${{ github.ref != 'refs/heads/main' }}

# Every action below is pinned to a commit SHA rather than a tag. A tag is a mutable
# pointer: whoever controls it controls a job running in this repository. The sibling
# server repo already holds this standard and states why.

jobs:
  unit:
    name: ci-unit
    runs-on: ubuntu-latest
    timeout-minutes: 25
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1

      # gradle/wrapper/gradle-wrapper.jar is committed to this repository, so CI executes a
      # binary out of the tree it is testing. This step is the control that stops a swapped
      # jar running here: it checks the jar against the checksums Gradle publishes for every
      # release. It must come before any ./gradlew invocation.
      - uses: gradle/actions/wrapper-validation@9c971963bec38e04b3d30dcc455b5382be2fdbfb # v6.3.0

      # Temurin 25 rather than the JDK 26 this was developed on: 25 is what Gradle 9.6
      # officially supports, and "works on my machine's 26" is not the same claim. If AGP
      # 9.3.1 ever refuses this JDK, raise the number here — do not lower the Gradle version.
      - uses: actions/setup-java@b6effb05e454b25005698d916606bdc6ffcbf961 # v5.7.0
        with:
          distribution: temurin
          java-version: '25'
          cache: gradle

      - name: placeholder google-services.json
        run: |
          # app/google-services.json is gitignored, so a fresh checkout has none and the
          # com.google.gms.google-services plugin fails the build before a single test runs.
          # Nothing in CI talks to Firebase — the plugin only turns this file into string
          # resources — so a placeholder carrying the right package name is the whole
          # requirement. Written only when absent, so anyone running these steps locally
          # with a real file keeps theirs.
          if [ ! -f app/google-services.json ]; then
            cat > app/google-services.json <<'JSON'
          {
            "project_info": {
              "project_number": "000000000000",
              "project_id": "kypost-ci-placeholder",
              "storage_bucket": "kypost-ci-placeholder.appspot.com"
            },
            "client": [
              {
                "client_info": {
                  "mobilesdk_app_id": "1:000000000000:android:0000000000000000",
                  "android_client_info": { "package_name": "com.urlxl.mail" }
                },
                "oauth_client": [],
                "api_key": [ { "current_key": "AIzaSyAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" } ],
                "services": { "appinvite_service": { "other_platform_oauth_client": [] } }
              }
            ],
            "configuration_version": "1"
          }
          JSON
          fi

      # NEVER add --write-verification-metadata to any Gradle invocation in this file.
      # gradle/verification-metadata.xml has verify-metadata=true and 600+ pinned
      # components, and the entire point is that CI FAILS on an unrecorded artifact. A job
      # that regenerates it silently defeats the supply-chain control this repo already paid
      # for: an injected dependency would be recorded as legitimate by the very run that
      # should have caught it.
      - name: unit tests and lint
        run: ./gradlew testDebugUnitTest lint

      # The other half of the rule above, expressed as a check rather than a comment: if
      # anything in this job regenerated the metadata, the file is dirty and the job fails.
      - name: dependency verification metadata is unchanged
        run: git diff --exit-code -- gradle/verification-metadata.xml

      - name: unit test report
        if: failure()
        run: |
          find app/build/reports/tests -name '*.html' -print || true
          find app/build/test-results -name '*.xml' -exec grep -l '<failure' {} + | while read -r f; do
            echo "=== $f ==="
            cat "$f"
          done

  instrumented:
    name: ci-instrumented
    runs-on: ubuntu-latest
    # Slower and flakier than unit-only, and still worth it: the wipe, teardown, Keystore
    # and enrollment-state guarantees are asserted ONLY here. A CI that ran unit tests alone
    # would give this repository false confidence about precisely its most security-relevant
    # behaviour.
    timeout-minutes: 45
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
      - uses: gradle/actions/wrapper-validation@9c971963bec38e04b3d30dcc455b5382be2fdbfb # v6.3.0
      - uses: actions/setup-java@b6effb05e454b25005698d916606bdc6ffcbf961 # v5.7.0
        with:
          distribution: temurin
          java-version: '25'
          cache: gradle

      - name: placeholder google-services.json
        run: |
          if [ ! -f app/google-services.json ]; then
            cat > app/google-services.json <<'JSON'
          {
            "project_info": {
              "project_number": "000000000000",
              "project_id": "kypost-ci-placeholder",
              "storage_bucket": "kypost-ci-placeholder.appspot.com"
            },
            "client": [
              {
                "client_info": {
                  "mobilesdk_app_id": "1:000000000000:android:0000000000000000",
                  "android_client_info": { "package_name": "com.urlxl.mail" }
                },
                "oauth_client": [],
                "api_key": [ { "current_key": "AIzaSyAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" } ],
                "services": { "appinvite_service": { "other_platform_oauth_client": [] } }
              }
            ],
            "configuration_version": "1"
          }
          JSON
          fi

      # Hardware acceleration for the emulator. Without it the AVD falls back to software
      # and a 45-minute timeout is not enough.
      - name: enable KVM
        run: |
          echo 'KERNEL=="kvm", GROUP="kvm", MODE="0666", OPTIONS+="static_node=kvm"' \
            | sudo tee /etc/udev/rules.d/99-kvm4all.rules
          sudo udevadm control --reload-rules
          sudo udevadm trigger --name-match=kvm

      # target: google_apis, NOT google_apis_playstore. Play Store images are user builds,
      # where `adb shell locksettings` is not permitted — and without it the lock-screen step
      # below cannot run at all.
      - uses: reactivecircus/android-emulator-runner@a421e43855164a8197daf9d8d40fe71c6996bb0d # v2.38.0
        with:
          api-level: 34
          target: google_apis
          arch: x86_64
          force-avd-creation: false
          emulator-options: -no-window -gpu swiftshader_indirect -noaudio -no-boot-anim -camera-back none
          disable-animations: true
          script: |
            # EnrollmentVault.ensureKey() returns false on a device with no secure lock
            # screen, BY DESIGN — the envelope's protection IS the lock screen. On a bare
            # emulator that makes EnrollmentVaultTest, EnrollmentStateTest and the enrollment
            # round-trip test fail as though the code were broken. Set one first.
            adb shell locksettings set-pin 1234

            # Prove it took, rather than assuming. A silent failure here reads downstream as
            # a Keystore bug and costs an afternoon.
            adb shell locksettings verify --old 1234 | tee /tmp/lockcheck.txt
            grep -qi "verified successfully" /tmp/lockcheck.txt || {
              echo "The emulator has no secure lock screen; the vault suites cannot pass." >&2
              exit 1
            }

            # Dismiss the keyguard the PIN just armed, so the test run is not typing into it.
            adb shell input keyevent 82
            adb shell input text 1234
            adb shell input keyevent 66

            ./gradlew connectedDebugAndroidTest

      - name: dependency verification metadata is unchanged
        run: git diff --exit-code -- gradle/verification-metadata.xml

      - name: instrumented test report
        if: failure()
        run: |
          find app/build/reports/androidTests -name '*.html' -print || true
          find app/build/outputs/androidTest-results -name '*.xml' -exec grep -l '<failure' {} + | while read -r f; do
            echo "=== $f ==="
            cat "$f"
          done
```

- [ ] **Step 4: Check the workflow parses before pushing it**

Run: `python3 -c "import yaml,sys; yaml.safe_load(open('.github/workflows/ci.yml')); print('parsed')"`
Expected: `parsed`. A YAML error here is a red X on every PR until someone notices.

- [ ] **Step 5: Prove the placeholder actually builds**

The placeholder is the single most likely thing in this task to be wrong, and its failure mode is "every CI run red from the first commit". Test it against a real build with the real file moved aside:

```bash
cp app/google-services.json /tmp/gs-real-backup.json
# Paste the exact JSON from the workflow's heredoc into app/google-services.json, then:
./gradlew :app:processDebugGoogleServices :app:testDebugUnitTest
cp /tmp/gs-real-backup.json app/google-services.json
diff app/google-services.json /tmp/gs-real-backup.json && echo "real file restored"
```
Expected: `BUILD SUCCESSFUL`, then `real file restored`.

The file is gitignored, so `git status` will not tell you whether it was put back — the `diff` is the
check. **This was verified working on 2026-08-06** against AGP 9.3.1 with exactly the JSON above; a
failure here means the placeholder was transcribed wrongly, not that it was rejected.

- [ ] **Step 6: Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "ci: run the unit and instrumented suites on every push

558 unit and 105 instrumented tests ran only when someone remembered. The
instrumented job is the expensive one and the necessary one: the wipe, teardown,
Keystore and enrollment-state guarantees are asserted nowhere else.

Three Android-specific controls: the committed wrapper jar is validated before
gradlew runs, verification-metadata.xml is never regenerated and is checked for
dirt afterwards, and the emulator is given a lock screen because
EnrollmentVault.ensureKey() returns false without one by design.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

- [ ] **Step 7: Watch the first run and fix it before starting Task 2**

Push the branch and open the PR. Run: `gh run watch` (or `gh run list --limit 3`).
Expected: both `ci-unit` and `ci-instrumented` green.

The two failures to expect, and what they mean:
- **`google-services.json is missing`** — the placeholder heredoc's indentation is wrong. In a YAML `run: |` block every line is dedented equally, so the heredoc terminator must sit at the same indentation as the JSON body.
- **`Dependency verification failed`** — CI resolved an artifact the local machine never did. Do **not** answer this with `--write-verification-metadata` in CI. Reproduce locally with the same task, regenerate locally, review the added entries by hand, and commit them.

---

### Task 2: The code's display grouping, on both clients

Decision 8 of the spec. Landed early and on its own because it is a two-line change in each of two repositories, and leaving the browser on 7-7 while the phone shows 4-3-4-3 is a disagreement between two screens showing the same code.

**Files:**
- Create: `app/src/main/java/com/urlxl/mail/pgp/EnrollmentCodeFormat.kt`
- Create: `app/src/test/java/com/urlxl/mail/pgp/EnrollmentCodeFormatTest.kt`
- Modify (other repo): `/home/yoshi/git/kypost-server/frontend/src/lib/deviceEnrollment.ts:202-205`
- Modify (other repo): `/home/yoshi/git/kypost-server/frontend/src/lib/deviceEnrollment.test.ts:148-160`

**Interfaces:**
- Consumes: `deviceEnrollmentCode(rawPublicKey, deviceId, bucket): String` from `DeviceEnrollmentCode.kt` (existing, `internal`).
- Produces: `internal fun formatEnrollmentCode(code: String): String` — Task 8 renders with it.

- [ ] **Step 1: Write the failing test**

Create `app/src/test/java/com/urlxl/mail/pgp/EnrollmentCodeFormatTest.kt`:

```kotlin
package com.urlxl.mail.pgp

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * The code is transcribed by a human across two devices, which is the failure the grouping exists
 * to prevent. Four groups of at most four is the pattern people already read off bank cards; two
 * groups of seven are long runs that are easy to lose your place in, and an omitted character in a
 * long run is silently wrong rather than visibly a wrong-length group.
 *
 * The browser's `formatEnrollmentCode` must group identically — see
 * `kypost-server/frontend/src/lib/deviceEnrollment.ts`. Grouping never reaches the hash:
 * `normalizeEnrollmentCode` strips `/[\s-]/g` before comparing.
 */
class EnrollmentCodeFormatTest {

    @Test
    fun groupsTheNormativeVectorAsFourThreeFourThree() {
        assertEquals("5R9K-6FW-A18A-8YP", formatEnrollmentCode("5R9K6FWA18A8YP"))
    }

    /**
     * The guard the browser's own suite already carries, for the same reason: a hardcoded slice
     * silently TRUNCATED the code when its width grew from 10 to 14 — and because the short code is
     * a prefix of the long one, the truncated form looked entirely plausible while dropping the four
     * characters carrying the extra 20 bits.
     */
    @Test
    fun neverDropsCharacters() {
        val rawKey = ByteArray(65).also {
            it[0] = 0x04
            for (i in 1..32) it[i] = 0x01
            for (i in 33..64) it[i] = 0x02
        }
        val code = deviceEnrollmentCode(rawKey, "test-device", 14_000_000L)

        assertEquals(code, formatEnrollmentCode(code).replace("-", ""))
    }

    /** A width this function was not designed around must still be shown in full, not clipped. */
    @Test
    fun aLongerCodeKeepsItsTail() {
        assertEquals("ABCD-EFG-HJKM-NPQ-RSTV", formatEnrollmentCode("ABCDEFGHJKMNPQRSTV"))
    }
}
```

- [ ] **Step 2: Run it to make sure it fails**

Run: `./gradlew testDebugUnitTest --tests '*EnrollmentCodeFormatTest*'`
Expected: FAIL — `Unresolved reference: formatEnrollmentCode`.

- [ ] **Step 3: Write the implementation**

Create `app/src/main/java/com/urlxl/mail/pgp/EnrollmentCodeFormat.kt`:

```kotlin
package com.urlxl.mail.pgp

/**
 * Group sizes for the displayed code: `5R9K-6FW-A18A-8YP`, not `5R9K6FW-A18A8YP`.
 *
 * Derived from nothing — these are a display choice, not a function of [deviceEnrollmentCode]'s
 * width — but the tail rule below means a width change cannot silently truncate.
 */
private val CODE_GROUPS = intArrayOf(4, 3, 4, 3)

/**
 * The code as the user reads it aloud.
 *
 * **Safe on the wire:** the browser's `normalizeEnrollmentCode` strips all whitespace and hyphens
 * (`/[\s-]/g`) and applies Crockford's decode rules before comparing, so grouping never reaches the
 * hash. The browser's `formatEnrollmentCode` groups identically; the two must move together.
 *
 * Anything left over after the last group is appended rather than dropped. A hardcoded slice is
 * exactly how the browser's version silently truncated the code when its width grew from 10 to 14,
 * and because the short code is a prefix of the long one the result looked entirely plausible.
 */
internal fun formatEnrollmentCode(code: String): String {
    val parts = mutableListOf<String>()
    var index = 0
    for (size in CODE_GROUPS) {
        if (index >= code.length) break
        parts += code.substring(index, minOf(index + size, code.length))
        index += size
    }
    if (index < code.length) parts += code.substring(index)
    return parts.joinToString("-")
}
```

- [ ] **Step 4: Run the tests and make sure they pass**

Run: `./gradlew testDebugUnitTest --tests '*EnrollmentCodeFormatTest*'`
Expected: PASS, 3 tests.

- [ ] **Step 5: Change the browser half**

In `/home/yoshi/git/kypost-server/frontend/src/lib/deviceEnrollment.ts`, replace the body of `formatEnrollmentCode` (currently `const half = CODE_LENGTH / 2; return \`${code.slice(0, half)}-${code.slice(half)}\`;`) with:

```ts
/**
 * Group sizes for the displayed code: `5R9K-6FW-A18A-8YP`, not `5R9K6FW-A18A8YP`.
 *
 * At 14 characters, two groups of seven are long runs that are easy to lose your place in. Four
 * groups of at most four is the pattern people already read off bank cards, and short runs make an
 * omitted character visible as a wrong-length group rather than a silently mistyped one. The code
 * is transcribed across two devices, so that is the failure this prevents.
 *
 * The Android client groups identically — see `EnrollmentCodeFormat.kt` in kypost-android. The two
 * must move together: a display disagreement between the two screens showing the same code reads to
 * the user as the codes not matching, which is this feature's one alarm.
 */
const CODE_GROUPS = [4, 3, 4, 3];

export function formatEnrollmentCode(code: string): string {
  const parts: string[] = [];
  let index = 0;
  for (const size of CODE_GROUPS) {
    if (index >= code.length) break;
    parts.push(code.slice(index, index + size));
    index += size;
  }
  // Anything past the last group is appended rather than dropped. A hardcoded slice is how this
  // function silently truncated the code when CODE_LENGTH grew from 10 to 14.
  if (index < code.length) parts.push(code.slice(index));
  return parts.join("-");
}
```

- [ ] **Step 6: Update the browser's test**

In `/home/yoshi/git/kypost-server/frontend/src/lib/deviceEnrollment.test.ts`, the `formatEnrollmentCode` describe block currently pins `ABCDEFG-HJKMNPQ` and strips with `.replace("-", "")`. Replace the whole block with:

```ts
describe("formatEnrollmentCode", () => {
  it("groups as XXXX-XXX-XXXX-XXX", () => {
    expect(formatEnrollmentCode("ABCDEFGHJKMNPQ")).toBe("ABCD-EFG-HJKM-NPQ");
  });

  // The grouping must not drop characters. `.replace("-", "")` would have removed only the
  // FIRST hyphen — fine when there was one, wrong now there are three — so this strips every
  // separator the same way normalizeEnrollmentCode does.
  it("never drops characters", async () => {
    const code = await deriveEnrollmentCode(VECTOR_KEY_B64, VECTOR_DEVICE_ID, VECTOR_BUCKET);
    expect(formatEnrollmentCode(code).split("-").join("")).toBe(code);
  });

  // The phone and the browser must show the same grouping of the same value.
  it("matches the Android client on the normative vector", () => {
    expect(formatEnrollmentCode("5R9K6FWA18A8YP")).toBe("5R9K-6FW-A18A-8YP");
  });
});
```

- [ ] **Step 7: Run the browser's suite**

Run: `cd /home/yoshi/git/kypost-server/frontend && npm test -- --run deviceEnrollment`
Expected: PASS. If `npm test` needs a full install first, run `npm ci` in `frontend/`.

- [ ] **Step 8: Update the spec's displayed vector**

The underlying value `5R9K6FWA18A8YP` is unchanged; only its displayed form moves. In `docs/superpowers/specs/2026-08-05-device-enrollment-2c-crypto-core-design.md` and `docs/superpowers/plans/2026-08-05-device-enrollment-2c-handoff.md`, replace every occurrence of `5R9K6FW-A18A8YP` with `5R9K-6FW-A18A-8YP`.

Run: `grep -rn "5R9K6FW-A18A8YP" docs/`
Expected: no output.

- [ ] **Step 9: Commit, in both repositories**

```bash
git add app/src/main/java/com/urlxl/mail/pgp/EnrollmentCodeFormat.kt \
        app/src/test/java/com/urlxl/mail/pgp/EnrollmentCodeFormatTest.kt \
        docs/superpowers/specs/2026-08-05-device-enrollment-2c-crypto-core-design.md \
        docs/superpowers/plans/2026-08-05-device-enrollment-2c-handoff.md
git commit -m "feat(pgp): group the enrollment code 4-3-4-3

Two groups of seven are long runs that are easy to lose your place in. The code is
transcribed by hand across two devices, so an omitted character should show up as a
wrong-length group rather than a silently mistyped one.

Grouping never reaches the hash — normalizeEnrollmentCode strips separators before
comparing — so this is display-only and the normative vector is unchanged.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

```bash
cd /home/yoshi/git/kypost-server
git add frontend/src/lib/deviceEnrollment.ts frontend/src/lib/deviceEnrollment.test.ts
git commit -m "fix(enrollment): group the displayed code 4-3-4-3, matching Android

The helper has no production call site yet — only tests import it — so this is
cosmetic today. It is changed rather than deleted because a display helper sitting
ready to be wired up is a future disagreement between the two screens showing the
same code, and that disagreement surfaces to the user as this feature's one alarm.

The 'never drops characters' test stripped with .replace('-', ''), which removed only
the first separator. There are three now.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 3: The ports, the UI state, and the ceremony's gate

The first slice of the state machine: everything that happens *before* a keypair is minted. Decision 9 of the spec — enrollment is blocked, not attempted, under Hostile Location Protection and without a secure lock screen — plus the identity check.

**Files:**
- Create: `app/src/main/java/com/urlxl/mail/pgp/EnrollmentUiState.kt`
- Create: `app/src/main/java/com/urlxl/mail/pgp/EnrollmentPorts.kt`
- Create: `app/src/main/java/com/urlxl/mail/pgp/EnrollmentCeremony.kt`
- Create: `app/src/test/java/com/urlxl/mail/pgp/FakeEnrollmentPorts.kt`
- Create: `app/src/test/java/com/urlxl/mail/pgp/EnrollmentCeremonyGateTest.kt`

**Interfaces:**
- Consumes: `EnrollmentCallResult` (existing, `internal`, in `EnrollmentClients.kt`).
- Produces, and every later task depends on these exact names:
  - `internal enum class UnavailableReason { NOT_PAIRED, HOSTILE_LOCATION, NO_SECURE_LOCK_SCREEN, NO_IDENTITY, SERVER_HELD_KEY, COULD_NOT_CHECK }`
  - `internal enum class FailureReason { PUBLISH_REJECTED, UNAUTHORIZED, RATE_LIMITED, ENVELOPE_MALFORMED, COULD_NOT_OPEN, NO_SECURE_LOCK_SCREEN, SEAL_FAILED, NO_DEVICE_KEY }`
  - `internal sealed class EnrollmentUiState` with `CheckingIdentity`, `Unavailable(reason)`, `PublishingKey`, `ShowingCode(code, expiresAtEpochMs)`, `WaitingTimedOut(code, expiresAtEpochMs)`, `Opening`, `AwaitingAuth`, `Enrolled`, `Failed(reason)`
  - `internal sealed class IdentityCheck` with `ClientProtected(fingerprint)`, `ServerHeld`, `NoIdentity`, `CouldNotCheck`
  - `internal interface IdentitySource { suspend fun check(): IdentityCheck }`
  - `internal interface EnrollmentTransport` — `suspend fun deviceId(): String?`, `suspend fun publishKey(encodedPublicKey: String): EnrollmentCallResult`, `suspend fun fetchEnvelope(): EnrollmentCallResult`, `suspend fun reportEnrolled(enrolled: Boolean): EnrollmentCallResult`, `fun enqueueDurableReport()`
  - `internal interface EnrollmentKeys` — `fun newKeyPair(): Boolean`, `fun rawPublicKey(): ByteArray?`, `fun encodedPublicKey(): String?`, `fun sharedSecret(epk: ByteArray): ByteArray?`, `fun deleteKeyPair(): Boolean`
  - `internal sealed class SealOutcome { object Sealed; object Cancelled; object NoSecureLockScreen; data class Failed(val message: String) }`
  - `internal interface VaultSealer { suspend fun seal(plaintext: ByteArray): SealOutcome }`
  - `internal interface EnrollmentClock { fun epochSeconds(): Long; fun elapsedRealtimeMs(): Long; suspend fun sleep(millis: Long) }`
  - `internal class EnrollmentCeremony(identity, transport, keys, sealer, clock, hostileLocationEnabled, hasSecureLockScreen, onState)` with `suspend fun run()`, `suspend fun checkAgain()`, `fun teardown()`

- [ ] **Step 1: Write the state and reason types**

Create `app/src/main/java/com/urlxl/mail/pgp/EnrollmentUiState.kt`:

```kotlin
package com.urlxl.mail.pgp

/**
 * Why enrollment cannot be started at all. Distinct from [FailureReason]: nothing has been minted
 * or published yet, so there is nothing to clean up and nothing went wrong — the device is simply
 * not in a position to hold a key.
 */
internal enum class UnavailableReason {
    NOT_PAIRED,
    HOSTILE_LOCATION,
    NO_SECURE_LOCK_SCREEN,
    NO_IDENTITY,
    SERVER_HELD_KEY,

    /**
     * The identity check could not be answered — not paired for the purposes of an authenticated
     * call, a network failure, a server error.
     *
     * **"Could not check" is not "no."** The copy for this must never read as "your account doesn't
     * use encrypted mail": a user told that will go and create a second identity.
     */
    COULD_NOT_CHECK,
}

/**
 * Why a started ceremony ended badly. A closed set, deliberately: the browser half enforces the same
 * rule so that an adversarial server's error string cannot select the alarming copy, and Android
 * matches. No server text is ever rendered from these.
 */
internal enum class FailureReason {
    /** The server refused the enrollment key for a reason that is not 401 or 429. */
    PUBLISH_REJECTED,

    /** 401 on any call. This device's credential is not accepted; re-pairing is the fix. */
    UNAUTHORIZED,

    RATE_LIMITED,

    /** The envelope did not parse, or its fields were the wrong size. Never a retry. */
    ENVELOPE_MALFORMED,

    /**
     * GCM authentication failed.
     *
     * The only point at which the phone can detect the attack the ceremony exists to prevent, and
     * the only failure that gets its own copy. That copy **describes rather than accuses**: an
     * identity rotation mid-ceremony is indistinguishable by construction from a hostile
     * substitution, because both produce exactly this. Never a retry — the AAD binds device and
     * identity, so a failure means the envelope was sealed for someone else or under an identity the
     * account no longer advertises.
     */
    COULD_NOT_OPEN,

    /** Discovered at the seal rather than the gate — the lock screen was removed mid-ceremony. */
    NO_SECURE_LOCK_SCREEN,

    SEAL_FAILED,

    /**
     * The Keystore would not mint or return the agreement keypair.
     *
     * Not in the spec's exit table, and not foldable into [PUBLISH_REJECTED]: nothing was published,
     * so telling the user their server refused the key would be false. `EnrollmentKeyStore` already
     * falls back from StrongBox to the TEE, so reaching this means neither worked.
     */
    NO_DEVICE_KEY,
}

/**
 * Every state the ceremony screen can be in.
 *
 * `Reporting` is deliberately absent. A failed report still means enrolled, so surfacing it as a
 * state would offer the user a distinction they must not act on.
 */
internal sealed class EnrollmentUiState {
    object CheckingIdentity : EnrollmentUiState()

    data class Unavailable(val reason: UnavailableReason) : EnrollmentUiState()

    object PublishingKey : EnrollmentUiState()

    /** [expiresAtEpochMs] is the end of the current 120-second bucket, for the countdown. */
    data class ShowingCode(val code: String, val expiresAtEpochMs: Long) : EnrollmentUiState()

    /**
     * The five-minute polling window closed with no envelope.
     *
     * Carries the code because "Check again" **resumes rather than restarts**: it reopens a fresh
     * window against the same keypair, so the code on screen stays valid and the user does not have
     * to re-read it. This is the one exit that keeps the keypair.
     */
    data class WaitingTimedOut(val code: String, val expiresAtEpochMs: Long) : EnrollmentUiState()

    object Opening : EnrollmentUiState()

    object AwaitingAuth : EnrollmentUiState()

    object Enrolled : EnrollmentUiState()

    data class Failed(val reason: FailureReason) : EnrollmentUiState()
}
```

- [ ] **Step 2: Write the ports**

Create `app/src/main/java/com/urlxl/mail/pgp/EnrollmentPorts.kt`:

```kotlin
package com.urlxl.mail.pgp

/**
 * What the account's PGP identity is, as far as this device can tell.
 *
 * [CouldNotCheck] is a distinct case from [NoIdentity] on purpose — see [UnavailableReason].
 */
internal sealed class IdentityCheck {
    /** The only case enrollment may proceed from. [fingerprint] is what the envelope's AAD binds;
     *  it is hashed from the key bytes by [ownFingerprintFromBootstrap], never read off a server
     *  field sitting beside them. */
    data class ClientProtected(val fingerprint: String) : IdentityCheck()

    object ServerHeld : IdentityCheck()
    object NoIdentity : IdentityCheck()
    object CouldNotCheck : IdentityCheck()
}

internal interface IdentitySource {
    suspend fun check(): IdentityCheck
}

/**
 * The three device-authenticated enrollment calls plus the durable fallback, with the pairing
 * resolved inside rather than threaded through the state machine.
 *
 * The real implementation **must** be built on `pinnedPairingCallFactory`. Every call here carries
 * the device bearer credential.
 */
internal interface EnrollmentTransport {
    /** This device's paired id — hashed into the code and bound into the envelope's AAD. Null when
     *  there is no usable pairing, which the ceremony reports as [UnavailableReason.NOT_PAIRED]. */
    suspend fun deviceId(): String?

    suspend fun publishKey(encodedPublicKey: String): EnrollmentCallResult

    suspend fun fetchEnvelope(): EnrollmentCallResult

    suspend fun reportEnrolled(enrolled: Boolean): EnrollmentCallResult

    /** Hands the report to [EnrollmentStateWorker], which re-probes live state and retries. Called
     *  when the direct report failed and the device is nonetheless enrolled. */
    fun enqueueDurableReport()
}

/**
 * The device's enrollment agreement keypair.
 *
 * A port rather than a direct call into [EnrollmentKeyStore] because "`deleteKeyPair()` on every
 * exit" is the property this design most needs a test for, and a Keystore object cannot be observed
 * from a JVM test.
 */
internal interface EnrollmentKeys {
    /** Mints a fresh keypair for one ceremony, destroying any previous one. */
    fun newKeyPair(): Boolean

    /** The uncompressed SEC1 point, `0x04 ‖ X ‖ Y`. **The code derives from this** — never from
     *  anything the server sent back, and never from a cached copy of what was published. */
    fun rawPublicKey(): ByteArray?

    /** The base64 of the same point, as published. */
    fun encodedPublicKey(): String?

    fun sharedSecret(epk: ByteArray): ByteArray?

    fun deleteKeyPair(): Boolean
}

internal sealed class SealOutcome {
    /** Sealed **and stored**. The sealer owns the ciphertext end to end so that no key material
     *  passes back through the state machine. */
    object Sealed : SealOutcome()

    /** The user dismissed the prompt, or the Activity hosting it was destroyed. Not a failure: the
     *  ceremony returns to the code and keeps polling, so the user can try again. */
    object Cancelled : SealOutcome()

    object NoSecureLockScreen : SealOutcome()

    data class Failed(val message: String) : SealOutcome()
}

/**
 * The re-seal, requested through an interface because the orchestrator cannot call `BiometricPrompt`
 * — it is Activity-bound. This is the seam that keeps the state machine testable: "biometric
 * cancelled" is a JVM test with a fake rather than an instrumented one.
 */
internal interface VaultSealer {
    suspend fun seal(plaintext: ByteArray): SealOutcome
}

/**
 * Time, and waiting.
 *
 * Two clocks because the two uses need different guarantees. [epochSeconds] is wall clock: the
 * 120-second bucket must agree with the browser's, so it has to be the same timebase. It is
 * therefore subject to the user changing the date, which costs a code mismatch and nothing worse.
 * [elapsedRealtimeMs] is monotonic, for the poll deadline, following the `elapsedRealtime` precedent
 * in `AppLockManager` and `AppLockStore` — a wall-clock deadline can be skipped past or never
 * reached at all.
 */
internal interface EnrollmentClock {
    fun epochSeconds(): Long
    fun elapsedRealtimeMs(): Long

    /** Injected rather than calling `delay` directly so a JVM test runs the five-minute polling
     *  window in microseconds without a test dispatcher — this module has no
     *  `kotlinx-coroutines-test` on the classpath. */
    suspend fun sleep(millis: Long)
}
```

- [ ] **Step 3: Write the failing gate test**

Create `app/src/test/java/com/urlxl/mail/pgp/EnrollmentCeremonyGateTest.kt`:

```kotlin
package com.urlxl.mail.pgp

import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Everything that must happen — or must NOT happen — before a keypair exists.
 *
 * The shared claim under all of these: a blocked ceremony leaves nothing behind. `newKeyPair()`
 * destroys any previous key and mints a fresh one, so calling it speculatively and giving up is not
 * free; and publishing a key the user then cannot use leaves the account's device row advertising an
 * enrollment key for a device that has none.
 */
class EnrollmentCeremonyGateTest {

    /**
     * Hostile Location Protection's contract is that no envelope exists on this device. Enrolling
     * under it would create exactly the artefact its teardown destroys.
     */
    @Test
    fun hostileLocationProtectionBlocksBeforeAnyKeyIsMinted() = runBlocking {
        val ports = FakePorts(hostileLocation = true)
        val ceremony = ports.ceremony()

        ceremony.run()

        assertEquals(
            EnrollmentUiState.Unavailable(UnavailableReason.HOSTILE_LOCATION),
            ports.states.last(),
        )
        assertEquals("no keypair may be minted", 0, ports.keys.newKeyPairCalls)
        assertEquals("nothing may be published", 0, ports.transport.publishedKeys.size)
    }

    /**
     * `EnrollmentVault.ensureKey()` returns false without a secure lock screen, by design — the
     * envelope's protection *is* the lock screen. Saying so at the entry beats a biometric prompt
     * that cannot be satisfied after the user has already read a code aloud.
     */
    @Test
    fun noSecureLockScreenBlocksBeforeAnyKeyIsMinted() = runBlocking {
        val ports = FakePorts(secureLockScreen = false)

        ports.ceremony().run()

        assertEquals(
            EnrollmentUiState.Unavailable(UnavailableReason.NO_SECURE_LOCK_SCREEN),
            ports.states.last(),
        )
        assertEquals(0, ports.keys.newKeyPairCalls)
    }

    /**
     * Test 8 from the original 2b handoff — enrollment before an identity exists.
     *
     * There is nothing for the browser to seal, so a ceremony started here would show the user a
     * code and poll for five minutes against an envelope that can never arrive.
     */
    @Test
    fun anAccountWithNoIdentityIsUnavailableAndMintsNothing() = runBlocking {
        val ports = FakePorts(identityResult = IdentityCheck.NoIdentity)

        ports.ceremony().run()

        assertEquals(
            EnrollmentUiState.Unavailable(UnavailableReason.NO_IDENTITY),
            ports.states.last(),
        )
        assertEquals(0, ports.keys.newKeyPairCalls)
    }

    /** A server-held key needs no device copy; the browser is where that account's key lives. */
    @Test
    fun aServerHeldKeyIsUnavailable() = runBlocking {
        val ports = FakePorts(identityResult = IdentityCheck.ServerHeld)

        ports.ceremony().run()

        assertEquals(
            EnrollmentUiState.Unavailable(UnavailableReason.SERVER_HELD_KEY),
            ports.states.last(),
        )
        assertEquals(0, ports.keys.newKeyPairCalls)
    }

    /**
     * The distinction decision 10 exists to protect. A failed check must not collapse into
     * [UnavailableReason.NO_IDENTITY]: those two render as different sentences to the user, and one
     * of them tells a user with a perfectly good identity to go and make another.
     */
    @Test
    fun aFailedCheckIsCouldNotCheckAndNotNoIdentity() = runBlocking {
        val ports = FakePorts(identityResult = IdentityCheck.CouldNotCheck)

        ports.ceremony().run()

        assertEquals(
            EnrollmentUiState.Unavailable(UnavailableReason.COULD_NOT_CHECK),
            ports.states.last(),
        )
    }

    @Test
    fun anUnpairedDeviceIsUnavailableAndMintsNothing() = runBlocking {
        val ports = FakePorts(deviceIdValue = null)

        ports.ceremony().run()

        assertEquals(
            EnrollmentUiState.Unavailable(UnavailableReason.NOT_PAIRED),
            ports.states.last(),
        )
        assertEquals(0, ports.keys.newKeyPairCalls)
    }

    /** The first thing the user sees is the check, not a blank screen. */
    @Test
    fun theFirstStateIsCheckingIdentity() = runBlocking {
        val ports = FakePorts(identityResult = IdentityCheck.NoIdentity)

        ports.ceremony().run()

        assertEquals(EnrollmentUiState.CheckingIdentity, ports.states.first())
    }

    /**
     * Ordering matters, not just outcomes. Hostile Location Protection is a local declaration that
     * this network is hostile, so answering it must not require a request to a server on that
     * network first.
     */
    @Test
    fun hostileLocationIsCheckedBeforeTheIdentityRequest() = runBlocking {
        val ports = FakePorts(hostileLocation = true, identityResult = IdentityCheck.ClientProtected("AA"))

        ports.ceremony().run()

        assertTrue("no identity request may be made", ports.identity.checkCalls == 0)
    }
}
```

- [ ] **Step 4: Write the fakes**

Create `app/src/test/java/com/urlxl/mail/pgp/FakeEnrollmentPorts.kt`:

```kotlin
package com.urlxl.mail.pgp

/**
 * JVM fakes for all five enrollment ports, plus a [FakePorts] bundle that wires a ceremony from
 * them. This repo has no mocking framework — see `com.urlxl.mail.testing.FakeCalls` for the same
 * approach one layer down.
 *
 * `internal`, not `private`: Kotlin compiles a top-level `private` class to a package-level JVM
 * name, so a second file in this package declaring the same name fails to compile as a duplicate
 * class. That already cost this package four near-identical copies of one fake.
 */
internal class FakeIdentitySource(private val result: IdentityCheck) : IdentitySource {
    var checkCalls = 0
        private set

    override suspend fun check(): IdentityCheck {
        checkCalls++
        return result
    }
}

/**
 * [rawPublicKey] and [encodedPublicKey] deliberately **disagree**.
 *
 * The one security property the device half owns is that the code derives from the key in this
 * device's own keystore, never from anything the server sent back or from a cached copy of what was
 * published. A fake whose two accessors returned the same point could not tell a correct
 * implementation from one that derived the code from the value it published — both would be green.
 * Making them differ is what turns that into a test that fails when the derivation moves.
 */
internal class FakeEnrollmentKeys(
    private val keyByte: Byte = 0x11,
    private val publishedByte: Byte = 0x22,
    private val minting: Boolean = true,
) : EnrollmentKeys {
    var newKeyPairCalls = 0
        private set
    var deleteCalls = 0
        private set
    var sharedSecretResult: ByteArray? = ByteArray(32) { 0x33 }
    private var exists = false

    /** The point the code must be derived from. */
    val keystorePoint: ByteArray = ByteArray(65).also { it[0] = 0x04; for (i in 1..64) it[i] = keyByte }

    /** A *different* point, standing in for "whatever was published". Nothing correct derives the
     *  code from this. */
    private val publishedPoint: ByteArray =
        ByteArray(65).also { it[0] = 0x04; for (i in 1..64) it[i] = publishedByte }

    override fun newKeyPair(): Boolean {
        newKeyPairCalls++
        exists = minting
        return minting
    }

    override fun rawPublicKey(): ByteArray? = keystorePoint.takeIf { exists }

    override fun encodedPublicKey(): String? =
        publishedPoint.takeIf { exists }?.let { java.util.Base64.getEncoder().encodeToString(it) }

    override fun sharedSecret(epk: ByteArray): ByteArray? = sharedSecretResult

    override fun deleteKeyPair(): Boolean {
        deleteCalls++
        exists = false
        return true
    }
}

/**
 * [fetchResults] is consumed one entry per poll; when it runs out, [fetchWhenExhausted] is returned
 * forever. That is how a test says "404 twice, then the envelope" or "404 until the window closes".
 */
internal class FakeEnrollmentTransport(
    private val deviceId: String? = "dev-1",
    var publishResult: EnrollmentCallResult = EnrollmentCallResult.Ok,
    private val fetchResults: MutableList<EnrollmentCallResult> = mutableListOf(),
    private val fetchWhenExhausted: EnrollmentCallResult = EnrollmentCallResult.NotFound,
    var reportResult: EnrollmentCallResult = EnrollmentCallResult.Ok,
) : EnrollmentTransport {
    val publishedKeys = mutableListOf<String>()
    val reported = mutableListOf<Boolean>()
    var fetchCalls = 0
        private set
    var durableReports = 0
        private set

    override suspend fun deviceId(): String? = deviceId

    override suspend fun publishKey(encodedPublicKey: String): EnrollmentCallResult {
        publishedKeys += encodedPublicKey
        return publishResult
    }

    override suspend fun fetchEnvelope(): EnrollmentCallResult {
        fetchCalls++
        return if (fetchResults.isEmpty()) fetchWhenExhausted else fetchResults.removeAt(0)
    }

    override suspend fun reportEnrolled(enrolled: Boolean): EnrollmentCallResult {
        reported += enrolled
        return reportResult
    }

    override fun enqueueDurableReport() {
        durableReports++
    }
}

internal class FakeVaultSealer(
    var outcome: SealOutcome = SealOutcome.Sealed,
) : VaultSealer {
    /** A copy of what was handed over, taken before the ceremony zeroes the caller's array, so a
     *  test can prove the original was wiped without the fake's own copy being wiped too. */
    val received = mutableListOf<ByteArray>()

    /** The caller's array itself, kept by reference so a test can assert it was zeroed in place. */
    val handedArrays = mutableListOf<ByteArray>()

    override suspend fun seal(plaintext: ByteArray): SealOutcome {
        received += plaintext.copyOf()
        handedArrays += plaintext
        return outcome
    }
}

/**
 * A clock the test drives. [sleep] does not sleep — it advances [elapsedRealtimeMs] and
 * [epochSeconds] by exactly the amount asked for, so a five-minute polling window costs a hundred
 * iterations of arithmetic rather than five minutes of wall clock.
 */
internal class FakeEnrollmentClock(
    // 1_680_000_000 / 120 is exactly 14_000_000, so the clock starts on a bucket boundary and a
    // test can count boundary crossings without arithmetic in its head.
    startEpochSeconds: Long = 1_680_000_000L,
    startElapsedMs: Long = 10_000L,
) : EnrollmentClock {
    var epochMs: Long = startEpochSeconds * 1_000
    var elapsedMs: Long = startElapsedMs
    val sleeps = mutableListOf<Long>()

    override fun epochSeconds(): Long = epochMs / 1_000

    override fun elapsedRealtimeMs(): Long = elapsedMs

    override suspend fun sleep(millis: Long) {
        sleeps += millis
        elapsedMs += millis
        epochMs += millis
    }
}

/**
 * Every port, a recorded transcript of the states the ceremony emitted, and a factory.
 *
 * One constructor with named defaults, not an overload set. Two constructors whose parameters both
 * default would be ambiguous at any call site that names only a parameter they share.
 */
internal class FakePorts(
    identityResult: IdentityCheck = IdentityCheck.ClientProtected("164D5B834E7FE927"),
    deviceIdValue: String? = "dev-1",
    private val hostileLocation: Boolean = false,
    private val secureLockScreen: Boolean = true,
    publishResult: EnrollmentCallResult = EnrollmentCallResult.Ok,
    fetchResults: MutableList<EnrollmentCallResult> = mutableListOf(),
    fetchWhenExhausted: EnrollmentCallResult = EnrollmentCallResult.NotFound,
    reportResult: EnrollmentCallResult = EnrollmentCallResult.Ok,
) {
    val identity = FakeIdentitySource(identityResult)
    val keys = FakeEnrollmentKeys()
    val transport = FakeEnrollmentTransport(
        deviceId = deviceIdValue,
        publishResult = publishResult,
        fetchResults = fetchResults,
        fetchWhenExhausted = fetchWhenExhausted,
        reportResult = reportResult,
    )
    val sealer = FakeVaultSealer()
    val clock = FakeEnrollmentClock()

    /** Every state the ceremony emitted, in order. */
    val states = mutableListOf<EnrollmentUiState>()

    fun ceremony(): EnrollmentCeremony = EnrollmentCeremony(
        identity = identity,
        transport = transport,
        keys = keys,
        sealer = sealer,
        clock = clock,
        hostileLocationEnabled = { hostileLocation },
        hasSecureLockScreen = { secureLockScreen },
        onState = { states += it },
    )
}
```

- [ ] **Step 5: Run the tests to verify they fail**

Run: `./gradlew testDebugUnitTest --tests '*EnrollmentCeremonyGateTest*'`
Expected: FAIL — `Unresolved reference: EnrollmentCeremony`.

- [ ] **Step 6: Write the ceremony's gate**

Create `app/src/main/java/com/urlxl/mail/pgp/EnrollmentCeremony.kt`. This is the whole file for now; Tasks 4 and 5 fill in `publishAndPoll` and `openAndSeal`.

```kotlin
package com.urlxl.mail.pgp

/**
 * The device-enrollment state machine.
 *
 * **No Android imports, and none may be added.** The ceremony has more branches than any existing
 * call site in this app — identity missing, publish rejected, poll timeout, envelope 404, GCM open
 * failure, biometric cancelled, no lock screen, re-seal failure, report failure, user abandons — and
 * every one of them is something the user must be told about. Audit run-6's one unfixable finding
 * was that logic living in an Activity is logic no unit test can reach; splitting this out is what
 * makes each branch above a JVM test.
 *
 * [hostileLocationEnabled] and [hasSecureLockScreen] are lambdas rather than a port, following the
 * `elapsedRealtimeMs: () -> Long = SystemClock::elapsedRealtime` precedent in `AppLockManager`.
 *
 * [onState] rather than an owned `StateFlow`: the ViewModel owns the flow (it is what survives
 * rotation), and a callback lets a JVM test record the full transcript rather than sampling a
 * conflating flow.
 */
internal class EnrollmentCeremony(
    private val identity: IdentitySource,
    private val transport: EnrollmentTransport,
    private val keys: EnrollmentKeys,
    private val sealer: VaultSealer,
    private val clock: EnrollmentClock,
    private val hostileLocationEnabled: () -> Boolean,
    private val hasSecureLockScreen: () -> Boolean,
    private val onState: (EnrollmentUiState) -> Unit,
) {

    private var deviceId: String? = null
    private var fingerprint: String? = null

    /** Set once a keypair exists, so [teardown] knows whether there is anything to destroy and
     *  cannot report a deletion it never performed. */
    private var keyPairLive = false

    private fun emit(state: EnrollmentUiState) = onState(state)

    /**
     * Runs the ceremony from the gate to a terminal state.
     *
     * Every path out of this function is one row of the spec's exit table.
     */
    suspend fun run() {
        emit(EnrollmentUiState.CheckingIdentity)

        // Local declarations first, and in this order. Hostile Location Protection means the user
        // has just said this network is hostile, so answering it must not require a request to a
        // server on that network.
        if (hostileLocationEnabled()) {
            emit(EnrollmentUiState.Unavailable(UnavailableReason.HOSTILE_LOCATION))
            return
        }
        if (!hasSecureLockScreen()) {
            emit(EnrollmentUiState.Unavailable(UnavailableReason.NO_SECURE_LOCK_SCREEN))
            return
        }

        val id = transport.deviceId()
        if (id.isNullOrBlank()) {
            emit(EnrollmentUiState.Unavailable(UnavailableReason.NOT_PAIRED))
            return
        }
        deviceId = id

        when (val check = identity.check()) {
            is IdentityCheck.ClientProtected -> fingerprint = check.fingerprint
            IdentityCheck.ServerHeld -> {
                emit(EnrollmentUiState.Unavailable(UnavailableReason.SERVER_HELD_KEY))
                return
            }
            IdentityCheck.NoIdentity -> {
                emit(EnrollmentUiState.Unavailable(UnavailableReason.NO_IDENTITY))
                return
            }
            IdentityCheck.CouldNotCheck -> {
                emit(EnrollmentUiState.Unavailable(UnavailableReason.COULD_NOT_CHECK))
                return
            }
        }

        // Task 4 replaces this line with publishAndPoll().
    }

    /**
     * Destroys the agreement key, whatever state the ceremony was in.
     *
     * Called from the ViewModel's `onCleared` — the user leaving the screen, the app locking
     * mid-ceremony and the Activity being destroyed all land here. Idempotent: leaving a screen that
     * never minted anything must not report a deletion.
     */
    fun teardown() {
        if (!keyPairLive) return
        keys.deleteKeyPair()
        keyPairLive = false
    }
}
```

- [ ] **Step 7: Run the tests to verify they pass**

Run: `./gradlew testDebugUnitTest --tests '*EnrollmentCeremonyGateTest*'`
Expected: PASS, 8 tests.

- [ ] **Step 8: Commit**

```bash
git add app/src/main/java/com/urlxl/mail/pgp/EnrollmentUiState.kt \
        app/src/main/java/com/urlxl/mail/pgp/EnrollmentPorts.kt \
        app/src/main/java/com/urlxl/mail/pgp/EnrollmentCeremony.kt \
        app/src/test/java/com/urlxl/mail/pgp/FakeEnrollmentPorts.kt \
        app/src/test/java/com/urlxl/mail/pgp/EnrollmentCeremonyGateTest.kt
git commit -m "feat(pgp): gate the enrollment ceremony before any key is minted

Hostile Location Protection and a missing secure lock screen block at the entry, not
at a biometric prompt the user reaches after reading a code aloud. Both are checked
before the identity request: HLP is the user declaring this network hostile, so
answering it must not require talking to a server on it.

'Could not check' stays distinct from 'no identity' — one of those tells a user with
a working identity to go and make another.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 4: Publish, show the code, and poll

The middle of the state machine: mint, publish, derive the code from the keystore, poll for five minutes, and resume on "Check again".

**Files:**
- Modify: `app/src/main/java/com/urlxl/mail/pgp/EnrollmentCeremony.kt`
- Create: `app/src/test/java/com/urlxl/mail/pgp/EnrollmentCeremonyCodeTest.kt`

**Interfaces:**
- Consumes: everything Task 3 produced, plus `deviceEnrollmentCode(rawPublicKey: ByteArray, deviceId: String, bucket: Long): String` (existing, `internal`).
- Produces: `EnrollmentCeremony.checkAgain()` reaches a live implementation. Task 8 calls it from the "Check again" button. `private const val BUCKET_SECONDS = 120L`, `POLL_INTERVAL_MS = 3_000L`, `POLL_WINDOW_MS = 5 * 60 * 1_000L` inside `EnrollmentCeremony.kt`.

- [ ] **Step 1: Write the failing tests**

Create `app/src/test/java/com/urlxl/mail/pgp/EnrollmentCeremonyCodeTest.kt`:

```kotlin
package com.urlxl.mail.pgp

import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Base64

/**
 * The published key, the displayed code, and the polling window.
 *
 * Every assertion here distinguishes a correct implementation from a plausible wrong one. Audit
 * run-6 found the previous plan's Task 7 asserting `WorkInfo.progress`, which is empty for every
 * worker ever enqueued — it would have passed against a credential leak.
 */
class EnrollmentCeremonyCodeTest {

    private fun bucketOf(ports: FakePorts): Long = ports.clock.epochSeconds() / 120L

    /**
     * **The one security property the device half owns.**
     *
     * The browser derives its code from the key the *server* handed it and refuses to seal unless
     * the two match. If this device ever derived from a server-supplied value — or from a cached
     * copy of what it published — the comparison would compare the server against itself and the
     * whole control would be decoration.
     *
     * [FakeEnrollmentKeys] returns a different point from `rawPublicKey()` than the one
     * `encodedPublicKey()` base64s, so "derived from the keystore" and "derived from what was
     * published" are different strings. That is what makes this test able to fail.
     */
    @Test
    fun theCodeDerivesFromTheKeystoreKeyAndNotFromWhatWasPublished() = runBlocking {
        val ports = FakePorts()
        val bucket = bucketOf(ports)

        ports.ceremony().run()

        val shown = ports.states.filterIsInstance<EnrollmentUiState.ShowingCode>().first()
        val fromKeystore = deviceEnrollmentCode(ports.keys.keystorePoint, "dev-1", bucket)
        assertEquals(fromKeystore, shown.code)

        val published = Base64.getDecoder().decode(ports.transport.publishedKeys.single())
        val fromPublished = deviceEnrollmentCode(published, "dev-1", bucket)
        assertNotEquals(
            "the code must not be derivable from the published value",
            fromPublished,
            shown.code,
        )
    }

    /**
     * Any write to the account's PGP identity clears the stored key server-side, so a device that
     * published only at pairing fails silently after a rotation — the user sees a code, types it,
     * and nothing ever arrives.
     */
    @Test
    fun theKeyIsPublishedOnEveryCeremonyNotOnce() = runBlocking {
        val ports = FakePorts()

        ports.ceremony().run()
        ports.ceremony().run()

        assertEquals(2, ports.transport.publishedKeys.size)
        assertEquals("each ceremony mints a fresh keypair", 2, ports.keys.newKeyPairCalls)
    }

    /**
     * Three buckets are crossed in a five-minute window (0s, 120s, 240s), so exactly three codes are
     * shown. Fewer means the code went stale on screen while the browser had moved on; more means it
     * is being recomputed off the boundary, and the user is re-reading a code for no reason.
     */
    @Test
    fun theCodeRecomputesOnTheBucketBoundaryAndNotBefore() = runBlocking {
        val ports = FakePorts()

        ports.ceremony().run()

        val shown = ports.states.filterIsInstance<EnrollmentUiState.ShowingCode>()
        assertEquals(3, shown.size)
        assertEquals("each bucket gives a different code", 3, shown.map { it.code }.toSet().size)
    }

    /** The countdown has to point at the end of the current bucket, not at a fixed offset. */
    @Test
    fun theExpiryIsTheEndOfTheCurrentBucket() = runBlocking {
        val ports = FakePorts()
        val bucket = bucketOf(ports)

        ports.ceremony().run()

        val shown = ports.states.filterIsInstance<EnrollmentUiState.ShowingCode>().first()
        assertEquals((bucket + 1) * 120L * 1_000L, shown.expiresAtEpochMs)
    }

    /**
     * The window is bounded, and the bound is not cosmetic: the screen holds a published enrollment
     * key and a code the user is reading aloud, and spec 1 requires `deleteKeyPair()` on the exits of
     * a ceremony — so there has to *be* a defined exit rather than a loop that runs until the process
     * dies.
     *
     * 300 seconds at 3-second intervals is exactly 100 attempts.
     */
    @Test
    fun pollingStopsAtTheDeadline() = runBlocking {
        val ports = FakePorts()

        ports.ceremony().run()

        assertEquals(100, ports.transport.fetchCalls)
        assertTrue(ports.states.last() is EnrollmentUiState.WaitingTimedOut)
        assertTrue("every wait is the 3-second interval", ports.clock.sleeps.all { it == 3_000L })
    }

    /**
     * **"Check again" resumes; it does not restart.**
     *
     * A restart would rotate the key, which would invalidate the code the user may have already
     * typed into the browser. Leaving the screen and re-entering is the restart, and that path does
     * rotate.
     */
    @Test
    fun checkAgainOpensAFreshWindowAgainstTheSameKeypair() = runBlocking {
        val ports = FakePorts()
        val ceremony = ports.ceremony()

        ceremony.run()
        val statesBeforeResume = ports.states.size

        ceremony.checkAgain()

        assertEquals("a second full window ran", 200, ports.transport.fetchCalls)
        assertEquals("the key must not be re-minted", 1, ports.keys.newKeyPairCalls)
        assertEquals("the key must not be republished", 1, ports.transport.publishedKeys.size)

        // The code itself still rotates with the 120-second bucket — that is not a restart, and
        // the browser accepts the current bucket. What must not change is the key BEHIND it, so
        // the assertion is that the resumed code is still derivable from the same keystore point.
        val resumed = ports.states.drop(statesBeforeResume)
            .filterIsInstance<EnrollmentUiState.ShowingCode>()
            .first()
        val resumedBucket = resumed.expiresAtEpochMs / 1_000L / 120L - 1L
        assertEquals(
            "the resumed code must come from the same keypair the user already read",
            deviceEnrollmentCode(ports.keys.keystorePoint, "dev-1", resumedBucket),
            resumed.code,
        )
    }

    /** 404 is "never sealed" and "expired" collapsed into one result by design. Both mean keep
     *  waiting, not fail. */
    @Test
    fun aNotFoundKeepsWaiting() = runBlocking {
        val ports = FakePorts(
            fetchResults = mutableListOf(
                EnrollmentCallResult.NotFound,
                EnrollmentCallResult.NotFound,
                EnrollmentCallResult.Envelope("{}"),
            ),
        )

        ports.ceremony().run()

        assertEquals(3, ports.transport.fetchCalls)
        assertTrue(ports.states.any { it is EnrollmentUiState.Opening })
    }

    /** A transient network failure or a 429 mid-window is not a reason to tear down a ceremony the
     *  user is halfway through typing. */
    @Test
    fun aTransientFailureOrRateLimitKeepsWaiting() = runBlocking {
        val ports = FakePorts(
            fetchResults = mutableListOf(
                EnrollmentCallResult.Failed("connection reset"),
                EnrollmentCallResult.RateLimited(5L),
                EnrollmentCallResult.Envelope("{}"),
            ),
        )

        ports.ceremony().run()

        assertEquals(3, ports.transport.fetchCalls)
        // Up to the point the envelope arrives. What happens to a `{}` envelope afterwards is
        // Task 5's business, and this test must not start asserting it.
        assertTrue(
            ports.states.takeWhile { it !is EnrollmentUiState.Opening }
                .none { it is EnrollmentUiState.Failed },
        )
    }

    /** A credential the server refuses will not start working, and the ceremony holds a published
     *  key that must not be left behind. */
    @Test
    fun a401WhilePollingFailsAndDestroysTheKeypair() = runBlocking {
        val ports = FakePorts(
            fetchResults = mutableListOf(EnrollmentCallResult.Unauthorized),
        )

        ports.ceremony().run()

        assertEquals(
            EnrollmentUiState.Failed(FailureReason.UNAUTHORIZED),
            ports.states.last(),
        )
        assertEquals(1, ports.keys.deleteCalls)
    }

    @Test
    fun aRejectedPublishFailsAndDestroysTheKeypair() = runBlocking {
        val ports = FakePorts(publishResult = EnrollmentCallResult.Failed("boom"))

        ports.ceremony().run()

        assertEquals(
            EnrollmentUiState.Failed(FailureReason.PUBLISH_REJECTED),
            ports.states.last(),
        )
        assertEquals(1, ports.keys.deleteCalls)
        assertEquals("nothing may be polled for", 0, ports.transport.fetchCalls)
    }

    @Test
    fun a401OnPublishIsItsOwnReason() = runBlocking {
        val ports = FakePorts(publishResult = EnrollmentCallResult.Unauthorized)

        ports.ceremony().run()

        assertEquals(EnrollmentUiState.Failed(FailureReason.UNAUTHORIZED), ports.states.last())
    }

    @Test
    fun a429OnPublishIsItsOwnReason() = runBlocking {
        val ports = FakePorts(publishResult = EnrollmentCallResult.RateLimited(30L))

        ports.ceremony().run()

        assertEquals(EnrollmentUiState.Failed(FailureReason.RATE_LIMITED), ports.states.last())
    }
}
```

- [ ] **Step 2: Run them to verify they fail**

Run: `./gradlew testDebugUnitTest --tests '*EnrollmentCeremonyCodeTest*'`
Expected: FAIL — `Unresolved reference: checkAgain`, and the ceremony never leaves `CheckingIdentity`.

- [ ] **Step 3: Add the constants and the publish-and-poll body**

In `app/src/main/java/com/urlxl/mail/pgp/EnrollmentCeremony.kt`, add above the class:

```kotlin
/** The code's validity window, and the browser's. `deviceEnrollmentCode`'s bucket is
 *  `unixSeconds / 120`; changing this alone strands every honest enrollment. */
private const val BUCKET_SECONDS = 120L

/** How often the phone asks whether the browser has sealed yet. There is no browser-to-device
 *  channel — the publish step is device-to-server POST only — so polling is the only discovery
 *  mechanism this protocol has. */
private const val POLL_INTERVAL_MS = 3_000L

/**
 * How long one polling window lasts.
 *
 * **A background completion is impossible, not merely undesirable:** the re-seal uses a key with
 * `setUserAuthenticationRequired(true)` and per-use auth, so it needs a live `BiometricPrompt`. The
 * ceremony's tail requires the user present and the app foregrounded, which means an unbounded loop
 * would be a screen holding a published key and a spoken-aloud code until the process dies. Five
 * minutes also means the code has rotated at least twice, so the screen has had to refresh it anyway.
 */
private const val POLL_WINDOW_MS = 5 * 60 * 1_000L
```

Replace the `// Task 4 replaces this line with publishAndPoll().` comment in `run()` with `publishAndPoll()`, and add these members to the class:

```kotlin
    /** The code currently on screen, so [checkAgain] can resume without re-deriving from a bucket
     *  that has since moved — and so [EnrollmentUiState.WaitingTimedOut] can carry it. */
    private var shownCode: String = ""
    private var shownExpiresAtEpochMs: Long = 0L
    private var shownBucket: Long = Long.MIN_VALUE

    private suspend fun publishAndPoll() {
        emit(EnrollmentUiState.PublishingKey)

        // Mints a FRESH keypair, destroying any previous one. A key that outlives a ceremony is a
        // standing unauthenticated path to every envelope the relay has retained.
        //
        // Marked live BEFORE the check, not after. `newKeyPair()` deletes the previous key and then
        // generates — attempting StrongBox first and falling back to the TEE — so a `false` can
        // still leave something behind. Treating a failed mint as "nothing was created" is how a
        // half-generated key survives a ceremony.
        keyPairLive = true
        if (!keys.newKeyPair()) {
            failAndDestroy(FailureReason.NO_DEVICE_KEY)
            return
        }

        val encoded = keys.encodedPublicKey()
        if (encoded == null) {
            failAndDestroy(FailureReason.NO_DEVICE_KEY)
            return
        }

        when (transport.publishKey(encoded)) {
            is EnrollmentCallResult.Ok -> Unit
            is EnrollmentCallResult.Unauthorized -> return failAndDestroy(FailureReason.UNAUTHORIZED)
            is EnrollmentCallResult.RateLimited -> return failAndDestroy(FailureReason.RATE_LIMITED)
            // NotFound (the device row is gone), Failed, and an Envelope this route cannot send.
            // None is retryable, and all leave a minted key that must not survive.
            is EnrollmentCallResult.NotFound,
            is EnrollmentCallResult.Failed,
            is EnrollmentCallResult.Envelope,
            -> return failAndDestroy(FailureReason.PUBLISH_REJECTED)
        }

        poll()
    }

    /**
     * Reopens a five-minute window against the **same** keypair.
     *
     * The key is not republished and `newKeyPair()` is not called again: a restart would rotate the
     * key, invalidating the code the user may already have typed into the browser. Leaving the
     * screen and re-entering is the restart, and that path does rotate.
     */
    suspend fun checkAgain() {
        if (!keyPairLive) return
        poll()
    }

    private suspend fun poll() {
        val deadline = clock.elapsedRealtimeMs() + POLL_WINDOW_MS

        while (clock.elapsedRealtimeMs() < deadline) {
            val bucket = clock.epochSeconds() / BUCKET_SECONDS
            if (bucket != shownBucket) {
                // Re-read from the keystore on every recomputation rather than caching the point.
                // The code must describe the key material actually in hand.
                val raw = keys.rawPublicKey()
                if (raw == null) {
                    failAndDestroy(FailureReason.NO_DEVICE_KEY)
                    return
                }
                shownBucket = bucket
                shownCode = deviceEnrollmentCode(raw, requireNotNull(deviceId), bucket)
                shownExpiresAtEpochMs = (bucket + 1) * BUCKET_SECONDS * 1_000L
                emit(EnrollmentUiState.ShowingCode(shownCode, shownExpiresAtEpochMs))
            }

            when (val result = transport.fetchEnvelope()) {
                is EnrollmentCallResult.Envelope -> {
                    openAndSeal(result.envelope)
                    return
                }
                // 401 is the one polling answer that cannot improve: the credential this device
                // holds is not accepted, and no amount of waiting changes that.
                is EnrollmentCallResult.Unauthorized -> return failAndDestroy(FailureReason.UNAUTHORIZED)
                // 404 covers "never sealed" and "expired", indistinguishable by design and both
                // meaning keep waiting. A 429 or a dropped connection mid-window is not a reason to
                // tear down a ceremony the user is halfway through typing. `Ok` cannot occur on this
                // route.
                is EnrollmentCallResult.NotFound,
                is EnrollmentCallResult.RateLimited,
                is EnrollmentCallResult.Failed,
                is EnrollmentCallResult.Ok,
                -> Unit
            }

            clock.sleep(POLL_INTERVAL_MS)
        }

        // The one exit that KEEPS the keypair — "Check again" resumes against it.
        emit(EnrollmentUiState.WaitingTimedOut(shownCode, shownExpiresAtEpochMs))
    }

    private fun failAndDestroy(reason: FailureReason) {
        teardown()
        emit(EnrollmentUiState.Failed(reason))
    }

    /** Task 5 replaces this stub. */
    private suspend fun openAndSeal(envelopeJson: String) {
        emit(EnrollmentUiState.Opening)
    }
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `./gradlew testDebugUnitTest --tests '*EnrollmentCeremonyCodeTest*' --tests '*EnrollmentCeremonyGateTest*'`
Expected: PASS, 20 tests.

- [ ] **Step 5: Commit**

```bash
git add app/src/main/java/com/urlxl/mail/pgp/EnrollmentCeremony.kt \
        app/src/test/java/com/urlxl/mail/pgp/EnrollmentCeremonyCodeTest.kt
git commit -m "feat(pgp): publish the enrollment key and poll for the sealing

The code derives from this device's own keystore point, never from anything the
server sent back — the fake's two accessors deliberately disagree so that a
derivation moved onto the published value fails the suite instead of passing it.

The key is published on every ceremony because any write to the account's PGP
identity clears it server-side; a device that published only at pairing fails
silently after a rotation.

Polling is bounded at five minutes because the tail of this ceremony needs a live
BiometricPrompt, so a background completion is impossible rather than undesirable.
'Check again' reopens a window against the same keypair — a restart would rotate the
key and invalidate a code the user may already have typed.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 5: Open, seal, report — and the exit table

The tail of the state machine, and the test that makes the cleanup rule structural rather than remembered.

**Files:**
- Modify: `app/src/main/java/com/urlxl/mail/pgp/EnrollmentCeremony.kt`
- Create: `app/src/test/java/com/urlxl/mail/pgp/EnrollmentCeremonyExitTest.kt`

**Interfaces:**
- Consumes: `parseDeviceEnvelope(json): DeviceEnvelopeFields?`, `deviceEnvelopeAad(deviceId, pgpFingerprint): ByteArray`, `openDeviceEnvelope(sharedSecret, ownRawPublicKey, fields, aad): ByteArray?` (all existing, `internal`, in `DeviceEnvelope.kt`).
- Produces: `EnrollmentCeremony.isIdle: Boolean` — true whenever no window is running, which Task 7 mirrors into the ViewModel and Task 8 uses to decide whether to offer "Check again".

- [ ] **Step 1: Write the failing tests**

Create `app/src/test/java/com/urlxl/mail/pgp/EnrollmentCeremonyExitTest.kt`:

```kotlin
package com.urlxl.mail.pgp

import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.util.Base64

/**
 * The tail of the ceremony, and the exit table.
 *
 * A real envelope is built here rather than mocked, because the seam being tested is exactly the one
 * between the state machine and the pure crypto in `DeviceEnvelope.kt`: a ceremony that assembled the
 * AAD or the HKDF salt wrongly would still "work" against a stubbed opener.
 */
class EnrollmentCeremonyExitTest {

    private val fingerprint = "164D5B834E7FE927"

    /**
     * Seals a real envelope the fake ports can open, using the same primitives the browser does.
     *
     * The shared secret is whatever [FakeEnrollmentKeys.sharedSecretResult] returns — the ECDH is
     * the one step a JVM test cannot perform, and it is already covered on hardware by
     * `EnrollmentKeyStoreTest`.
     */
    private fun sealEnvelope(
        keys: FakeEnrollmentKeys,
        deviceId: String = "dev-1",
        aadFingerprint: String = fingerprint,
    ): String {
        val sharedSecret = requireNotNull(keys.sharedSecretResult)
        val ephemeral = ByteArray(65).also { it[0] = 0x04; for (i in 1..64) it[i] = 0x44 }
        val key = hkdfSha256(
            ikm = sharedSecret,
            salt = keys.keystorePoint,
            info = "kypost-device-envelope/v2".toByteArray(Charsets.UTF_8),
            length = 32,
        )
        val iv = ByteArray(12) { 0x55 }
        val cipher = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding").apply {
            init(
                javax.crypto.Cipher.ENCRYPT_MODE,
                javax.crypto.spec.SecretKeySpec(key, "AES"),
                javax.crypto.spec.GCMParameterSpec(128, iv),
            )
            updateAAD(deviceEnvelopeAad(deviceId, aadFingerprint))
        }
        val ct = cipher.doFinal(PLAINTEXT.toByteArray(Charsets.UTF_8))
        val b64 = Base64.getEncoder()
        return """
            {"v":"2","alg":"ECDH-P256+HKDF-SHA256+A256GCM",
             "epk":"${b64.encodeToString(ephemeral)}",
             "iv":"${b64.encodeToString(iv)}",
             "ct":"${b64.encodeToString(ct)}"}
        """.trimIndent().replace("\n", "")
    }

    private fun portsWithEnvelope(
        sealFor: String = "dev-1",
        aadFingerprint: String = fingerprint,
    ): FakePorts {
        val probe = FakeEnrollmentKeys()
        val envelope = sealEnvelope(probe, sealFor, aadFingerprint)
        return FakePorts(fetchResults = mutableListOf(EnrollmentCallResult.Envelope(envelope)))
    }

    @Test
    fun aSealedEnvelopeReachesEnrolled() = runBlocking {
        val ports = portsWithEnvelope()

        ports.ceremony().run()

        assertEquals(EnrollmentUiState.Enrolled, ports.states.last())
        assertEquals(listOf(true), ports.transport.reported)
        assertEquals("the agreement key is spent on success too", 1, ports.keys.deleteCalls)
        assertEquals("no durable fallback was needed", 0, ports.transport.durableReports)
    }

    /** The sealer receives what the browser sealed, byte for byte. Anything else means the AAD, the
     *  HKDF salt or the parse is wrong, and the user would see the substituted-key alarm. */
    @Test
    fun theSealerReceivesTheOpenedPlaintext() = runBlocking {
        val ports = portsWithEnvelope()

        ports.ceremony().run()

        assertArrayEquals(PLAINTEXT.toByteArray(Charsets.UTF_8), ports.sealer.received.single())
    }

    /**
     * The plaintext is the account's PGP private key. Its lifetime is the real exposure, and it does
     * NOT go into `EnrollmentSession` — that holder has no consumer until the deferred decryption
     * work lands, and populating it for zero readers is exposure bought for nothing.
     */
    @Test
    fun thePlaintextIsZeroedInPlaceAfterSealing() = runBlocking {
        val ports = portsWithEnvelope()

        ports.ceremony().run()

        val handed = ports.sealer.handedArrays.single()
        assertTrue("every byte must be zero", handed.all { it == 0.toByte() })
    }

    /**
     * **A failed report still means enrolled.** The local seal is real; only the server's marker is
     * stale, and the durable worker already exists to correct it. Reporting this as a failure would
     * make the user re-run a ceremony whose expensive half already succeeded.
     */
    @Test
    fun aFailedReportStillMeansEnrolledAndEnqueuesTheWorker() = runBlocking {
        val probe = FakeEnrollmentKeys()
        val ports = FakePorts(
            fetchResults = mutableListOf(EnrollmentCallResult.Envelope(sealEnvelope(probe))),
            reportResult = EnrollmentCallResult.Failed("offline"),
        )

        ports.ceremony().run()

        assertEquals(EnrollmentUiState.Enrolled, ports.states.last())
        assertEquals(1, ports.transport.durableReports)
        assertEquals(1, ports.keys.deleteCalls)
    }

    /**
     * **A failed GCM open is never a retry.** The AAD binds device and identity, so a failure means
     * the envelope was sealed for another device or under an identity the account no longer
     * advertises. Here the envelope was sealed for a different device id.
     */
    @Test
    fun anEnvelopeSealedForAnotherDeviceIsCouldNotOpen() = runBlocking {
        val ports = portsWithEnvelope(sealFor = "some-other-device")

        ports.ceremony().run()

        assertEquals(
            EnrollmentUiState.Failed(FailureReason.COULD_NOT_OPEN),
            ports.states.last(),
        )
        assertEquals(1, ports.keys.deleteCalls)
        assertEquals("no second attempt", 1, ports.transport.fetchCalls)
    }

    /** The other half of the AAD binding: an envelope minted under a fingerprint this account no
     *  longer advertises. Same verdict, same copy — the phone cannot tell the two apart, and the
     *  copy must not claim it can. */
    @Test
    fun anEnvelopeSealedUnderAnotherIdentityIsCouldNotOpen() = runBlocking {
        val ports = portsWithEnvelope(aadFingerprint = "AAAABBBBCCCCDDDD")

        ports.ceremony().run()

        assertEquals(
            EnrollmentUiState.Failed(FailureReason.COULD_NOT_OPEN),
            ports.states.last(),
        )
    }

    @Test
    fun aMalformedEnvelopeIsItsOwnReasonAndDestroysTheKeypair() = runBlocking {
        val ports = FakePorts(
            fetchResults = mutableListOf(EnrollmentCallResult.Envelope("""{"v":"1"}""")),
        )

        ports.ceremony().run()

        assertEquals(
            EnrollmentUiState.Failed(FailureReason.ENVELOPE_MALFORMED),
            ports.states.last(),
        )
        assertEquals(1, ports.keys.deleteCalls)
    }

    /** The lock screen can be removed between the gate and the seal. `EnrollmentVault.ensureKey()`
     *  reports it, and the ceremony must not present it as a mysterious failure. */
    @Test
    fun losingTheLockScreenBeforeTheSealIsItsOwnReason() = runBlocking {
        val ports = portsWithEnvelope()
        ports.sealer.outcome = SealOutcome.NoSecureLockScreen

        ports.ceremony().run()

        assertEquals(
            EnrollmentUiState.Failed(FailureReason.NO_SECURE_LOCK_SCREEN),
            ports.states.last(),
        )
        assertEquals(1, ports.keys.deleteCalls)
    }

    @Test
    fun aSealFailureIsItsOwnReasonAndDestroysTheKeypair() = runBlocking {
        val ports = portsWithEnvelope()
        ports.sealer.outcome = SealOutcome.Failed("keystore said no")

        ports.ceremony().run()

        assertEquals(EnrollmentUiState.Failed(FailureReason.SEAL_FAILED), ports.states.last())
        assertEquals(1, ports.keys.deleteCalls)
    }

    /**
     * A cancel is not a failure. The envelope is still on the relay, so the user gets the code back
     * and a way to try again — and the plaintext does not survive the round trip.
     *
     * The window ends rather than re-prompting three seconds later; see deviation 8 in this plan.
     */
    @Test
    fun aCancelledBiometricReturnsToTheCodeWithThePlaintextZeroed() = runBlocking {
        val ports = portsWithEnvelope()
        ports.sealer.outcome = SealOutcome.Cancelled

        val ceremony = ports.ceremony()
        ceremony.run()

        assertTrue(ports.states.last() is EnrollmentUiState.ShowingCode)
        assertTrue(ports.sealer.handedArrays.single().all { it == 0.toByte() })
        assertEquals("a cancel destroys nothing", 0, ports.keys.deleteCalls)
        assertTrue("the user must be able to try again", ceremony.isIdle)
    }

    /** Leaving the screen is the restart path, and it must take the key with it. */
    @Test
    fun teardownDestroysALiveKeypairAndIsIdempotent() = runBlocking {
        val ports = FakePorts()
        val ceremony = ports.ceremony()
        ceremony.run()

        ceremony.teardown()
        ceremony.teardown()

        assertEquals(1, ports.keys.deleteCalls)
    }

    /** A ceremony blocked at the gate never minted anything, so teardown must not claim a deletion
     *  it did not perform — `EnrollmentTeardown` feeds that boolean to a `SecurityWipe.step`. */
    @Test
    fun teardownAfterABlockedGateDestroysNothing() = runBlocking {
        val ports = FakePorts(identityResult = IdentityCheck.NoIdentity)
        val ceremony = ports.ceremony()
        ceremony.run()

        ceremony.teardown()

        assertEquals(0, ports.keys.deleteCalls)
    }

    /**
     * **The exit table, made structural.**
     *
     * The `when` below is exhaustive over [EnrollmentUiState] with no `else`, so adding a state
     * without deciding its cleanup is a **compile error**, not a silently untested path. That is the
     * point: an exit added later without cleanup is exactly the defect this ceremony cannot afford.
     */
    private enum class Cleanup {
        DESTROYS_THE_KEYPAIR,
        KEEPS_THE_KEYPAIR,
        NOTHING_WAS_MINTED,

        /** Reaching one of these as a ceremony's last state is itself the bug. */
        NOT_A_TERMINAL_STATE,
    }

    private fun expectedCleanup(state: EnrollmentUiState): Cleanup = when (state) {
        // Transient. A ceremony that stops here has stalled somewhere it must not.
        EnrollmentUiState.CheckingIdentity,
        EnrollmentUiState.PublishingKey,
        EnrollmentUiState.Opening,
        EnrollmentUiState.AwaitingAuth,
        -> Cleanup.NOT_A_TERMINAL_STATE

        // Blocked at the gate: no keypair was ever minted.
        is EnrollmentUiState.Unavailable -> Cleanup.NOTHING_WAS_MINTED

        // The one exit that keeps it — "Check again" resumes against the same key.
        is EnrollmentUiState.WaitingTimedOut -> Cleanup.KEEPS_THE_KEYPAIR

        // A cancelled seal lands back here with the window closed; the key is still needed.
        is EnrollmentUiState.ShowingCode -> Cleanup.KEEPS_THE_KEYPAIR

        // Success spends the key exactly as failure does. A key that outlives every ceremony is a
        // standing unauthenticated path to every envelope the relay has retained.
        EnrollmentUiState.Enrolled -> Cleanup.DESTROYS_THE_KEYPAIR
        is EnrollmentUiState.Failed -> Cleanup.DESTROYS_THE_KEYPAIR
    }

    @Test
    fun everyTerminalExitMatchesItsRowInTheExitTable() = runBlocking {
        val probe = FakeEnrollmentKeys()
        val cases: List<Pair<String, FakePorts>> = listOf(
            "hostile location" to FakePorts(hostileLocation = true),
            "no lock screen" to FakePorts(secureLockScreen = false),
            "not paired" to FakePorts(deviceIdValue = null),
            "no identity" to FakePorts(identityResult = IdentityCheck.NoIdentity),
            "server-held" to FakePorts(identityResult = IdentityCheck.ServerHeld),
            "could not check" to FakePorts(identityResult = IdentityCheck.CouldNotCheck),
            "publish rejected" to FakePorts(publishResult = EnrollmentCallResult.Failed("no")),
            "publish 401" to FakePorts(publishResult = EnrollmentCallResult.Unauthorized),
            "publish 429" to FakePorts(publishResult = EnrollmentCallResult.RateLimited(1L)),
            "poll timeout" to FakePorts(),
            "poll 401" to FakePorts(fetchResults = mutableListOf(EnrollmentCallResult.Unauthorized)),
            "malformed envelope" to FakePorts(
                fetchResults = mutableListOf(EnrollmentCallResult.Envelope("nonsense")),
            ),
            "could not open" to FakePorts(
                fetchResults = mutableListOf(
                    EnrollmentCallResult.Envelope(sealEnvelope(probe, deviceId = "elsewhere")),
                ),
            ),
            "success" to FakePorts(
                fetchResults = mutableListOf(EnrollmentCallResult.Envelope(sealEnvelope(probe))),
            ),
            "report failed" to FakePorts(
                fetchResults = mutableListOf(EnrollmentCallResult.Envelope(sealEnvelope(probe))),
                reportResult = EnrollmentCallResult.Unauthorized,
            ),
        )

        for ((name, ports) in cases) {
            ports.ceremony().run()
            val terminal = ports.states.last()
            val deletions = ports.keys.deleteCalls
            when (expectedCleanup(terminal)) {
                Cleanup.DESTROYS_THE_KEYPAIR ->
                    assertEquals("$name: $terminal must destroy the keypair", 1, deletions)
                Cleanup.KEEPS_THE_KEYPAIR ->
                    assertEquals("$name: $terminal must keep the keypair", 0, deletions)
                Cleanup.NOTHING_WAS_MINTED ->
                    assertEquals("$name: blocked at the gate, so there is nothing to destroy", 0, deletions)
                Cleanup.NOT_A_TERMINAL_STATE ->
                    fail("$name: the ceremony stopped in a transient state: $terminal")
            }
        }
    }

    private companion object {
        const val PLAINTEXT = "-----BEGIN PGP PRIVATE KEY BLOCK-----\nnot a real key\n-----END-----"
    }
}
```

- [ ] **Step 2: Run them to verify they fail**

Run: `./gradlew testDebugUnitTest --tests '*EnrollmentCeremonyExitTest*'`
Expected: FAIL — `Unresolved reference: isIdle`, and every envelope case stops at `Opening`.

- [ ] **Step 3: Implement the tail**

In `app/src/main/java/com/urlxl/mail/pgp/EnrollmentCeremony.kt`, add the idle flag and replace the `openAndSeal` stub.

Add to the class body:

```kotlin
    /**
     * True whenever no polling window is running — the ceremony is finished, blocked, timed out, or
     * waiting for the user after a cancelled prompt.
     *
     * The Activity offers "Check again" on this, rather than on the state alone: `ShowingCode` means
     * two different things depending on whether a window is still open behind it.
     */
    var isIdle: Boolean = true
        private set
```

Set it around every window: at the top of `run()` and `checkAgain()` write `isIdle = false`, and in a `finally` on each write `isIdle = true`. In `run()`:

```kotlin
    suspend fun run() {
        isIdle = false
        try {
            runInner()
        } finally {
            isIdle = true
        }
    }
```
Rename the existing body to `private suspend fun runInner()`, and give `checkAgain()` the same wrapper around its `poll()` call.

Replace the `openAndSeal` stub with:

```kotlin
    private suspend fun openAndSeal(envelopeJson: String) {
        emit(EnrollmentUiState.Opening)

        val fields = parseDeviceEnvelope(envelopeJson)
        if (fields == null) {
            failAndDestroy(FailureReason.ENVELOPE_MALFORMED)
            return
        }

        // The AAD is built from this device's id and the fingerprint the identity check returned —
        // never from anything in the envelope. deviceEnvelopeAad normalises and validates the
        // fingerprint itself; a throw here is a programming error, not a user condition, but it is
        // caught rather than crashed because the alternative is a crash on a security screen.
        val aad = runCatching {
            deviceEnvelopeAad(requireNotNull(deviceId), requireNotNull(fingerprint))
        }.getOrNull()
        if (aad == null) {
            failAndDestroy(FailureReason.ENVELOPE_MALFORMED)
            return
        }

        val ownPoint = keys.rawPublicKey()
        if (ownPoint == null) {
            failAndDestroy(FailureReason.NO_DEVICE_KEY)
            return
        }

        val sharedSecret = keys.sharedSecret(fields.epk)
        if (sharedSecret == null) {
            // The ECDH itself failed — a malformed peer point that got past the parse, or a key the
            // Keystore will no longer agree with. Indistinguishable from a hostile envelope from
            // here, and treated the same: no retry.
            failAndDestroy(FailureReason.COULD_NOT_OPEN)
            return
        }

        val plaintext = try {
            // ownPoint is the HKDF salt — this device's own point, not the ephemeral one in the
            // envelope.
            openDeviceEnvelope(sharedSecret, ownPoint, fields, aad)
        } finally {
            sharedSecret.fill(0)
        }
        if (plaintext == null) {
            failAndDestroy(FailureReason.COULD_NOT_OPEN)
            return
        }

        try {
            sealAndReport(plaintext)
        } finally {
            // The armored private key, zeroed in place on every path out — including the throw the
            // sealer is not supposed to produce. It never enters EnrollmentSession: that holder has
            // no reader until the deferred decryption work lands.
            plaintext.fill(0)
        }
    }

    private suspend fun sealAndReport(plaintext: ByteArray) {
        emit(EnrollmentUiState.AwaitingAuth)

        // Re-checked here as well as at the gate: the user can remove the lock screen between the
        // two, and EnrollmentVault.ensureKey() would then fail behind a prompt that never appears.
        if (!hasSecureLockScreen()) {
            failAndDestroy(FailureReason.NO_SECURE_LOCK_SCREEN)
            return
        }

        when (sealer.seal(plaintext)) {
            is SealOutcome.Sealed -> report()
            is SealOutcome.NoSecureLockScreen -> failAndDestroy(FailureReason.NO_SECURE_LOCK_SCREEN)
            is SealOutcome.Failed -> failAndDestroy(FailureReason.SEAL_FAILED)
            is SealOutcome.Cancelled ->
                // Back to the code with the window closed. The envelope stays on the relay for
                // seven days, so "Check again" picks it straight back up; re-prompting from inside
                // the poll loop would put the dialog back three seconds after the user dismissed
                // it, over and over, for the rest of the window.
                emit(EnrollmentUiState.ShowingCode(shownCode, shownExpiresAtEpochMs))
        }
    }

    /**
     * Tells the server this device is enrolled, and stops depending on the answer.
     *
     * A failed report is **not** a failed enrollment: the local seal is real, only the marker is
     * stale, and `EnrollmentStateWorker` re-probes live state and retries. The agreement key is spent
     * either way — its life is one ceremony.
     */
    private suspend fun report() {
        if (transport.reportEnrolled(true) !is EnrollmentCallResult.Ok) {
            transport.enqueueDurableReport()
        }
        teardown()
        emit(EnrollmentUiState.Enrolled)
    }
```

- [ ] **Step 4: Run the whole ceremony suite**

Run: `./gradlew testDebugUnitTest --tests '*EnrollmentCeremony*'`
Expected: PASS.

If `everyTerminalExitMatchesItsRowInTheExitTable` fails with "is not a terminal state", a case in the table ended somewhere unexpected — print `ports.states` for that case rather than loosening the assertion.

- [ ] **Step 5: Run the full unit suite to catch anything the new files broke**

Run: `./gradlew testDebugUnitTest`
Expected: `BUILD SUCCESSFUL`, and the total is 558 plus the new tests.

- [ ] **Step 6: Commit**

```bash
git add app/src/main/java/com/urlxl/mail/pgp/EnrollmentCeremony.kt \
        app/src/test/java/com/urlxl/mail/pgp/EnrollmentCeremonyExitTest.kt
git commit -m "feat(pgp): open the envelope, re-seal it, and report

The exit-table test maps every EnrollmentUiState to an expected cleanup through an
exhaustive when with no else, so adding a state without deciding whether it destroys
the agreement key is a compile error rather than an untested path.

A failed GCM open is never a retry and gets its own copy: the AAD binds device and
identity, so a failure means the envelope was sealed for someone else or under an
identity the account no longer advertises. It describes rather than accuses, because
an identity rotation mid-ceremony is indistinguishable from a substitution.

A failed report still means enrolled. The plaintext is zeroed in place on every path
and never enters EnrollmentSession, which has no reader yet.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 6: The real port implementations

The Android side of the five ports. No new behaviour — every decision is already made and tested; this is the wiring that lets the tested state machine touch a real device.

**Files:**
- Create: `app/src/main/java/com/urlxl/mail/pgp/EnrollmentPortsAndroid.kt`

**Interfaces:**
- Consumes: `EnrollmentKeyStore` (object), `EnrollmentClients(callFactory)`, `EnrollmentStateWorker.enqueue(context)`, `PgpBootstrapClient(json, callFactory)`, `ownFingerprintFromBootstrap(result)`, `pinnedPairingCallFactory(context)`, `PushRuntime.graph(context).repository.pairingForAuthenticatedCall()`.
- Produces: `AndroidEnrollmentKeys` (object), `AndroidIdentitySource(context)`, `AndroidEnrollmentTransport(context)`, `SystemEnrollmentClock` (object), and `internal fun hasSecureLockScreen(context: Context): Boolean`. Tasks 7 and 10 use all five.

- [ ] **Step 1: Write the implementations**

Create `app/src/main/java/com/urlxl/mail/pgp/EnrollmentPortsAndroid.kt`:

```kotlin
package com.urlxl.mail.pgp

import android.content.Context
import android.os.SystemClock
import com.urlxl.mail.push.PushRuntime
import com.urlxl.mail.push.pinnedPairingCallFactory
import kotlinx.coroutines.delay

/** [EnrollmentKeyStore] behind the port, so the ceremony's cleanup rule is testable on the JVM. */
internal object AndroidEnrollmentKeys : EnrollmentKeys {
    override fun newKeyPair(): Boolean = EnrollmentKeyStore.newKeyPair()
    override fun rawPublicKey(): ByteArray? = EnrollmentKeyStore.rawPublicKey()
    override fun encodedPublicKey(): String? = EnrollmentKeyStore.encodedPublicKey()
    override fun sharedSecret(epk: ByteArray): ByteArray? = EnrollmentKeyStore.sharedSecret(epk)
    override fun deleteKeyPair(): Boolean = EnrollmentKeyStore.deleteKeyPair()
}

/**
 * The identity check, from **one** `GET /api/pgp/bootstrap`.
 *
 * Bootstrap answers all three questions this port is defined by — is there an identity, is it
 * client-protected, and what is its fingerprint — so `hasPgpIdentity` is not called as well. A second
 * request could only ever agree or disagree with the first, and a disagreement has no resolution.
 *
 * The fingerprint is **hashed from the key bytes** by [ownFingerprintFromBootstrap], never read off
 * the response's own `fingerprint` field: that field is a claim sitting beside `publicKey` with no
 * cryptographic tie to it, and this value is about to be bound into an envelope's AAD.
 */
internal class AndroidIdentitySource(context: Context) : IdentitySource {
    private val appContext = context.applicationContext

    override suspend fun check(): IdentityCheck {
        val pairing = PushRuntime.graph(appContext).repository.pairingForAuthenticatedCall()
        val deviceId = pairing?.deviceId
        val deviceSecret = pairing?.deviceSecret
        if (pairing == null || deviceId.isNullOrBlank() || deviceSecret.isNullOrBlank()) {
            // Not "no identity". The credential may simply be gated and the app currently locked.
            return IdentityCheck.CouldNotCheck
        }

        // The pinned factory, not PgpBootstrapClient's unpinned default. This request carries the
        // device bearer credential, like every other credentialed call in this app.
        val client = PgpBootstrapClient(callFactory = pinnedPairingCallFactory(appContext))
        return when (val result = client.fetch(pairing.serverUrl, deviceId, deviceSecret)) {
            is PgpBootstrapResult.Failed -> IdentityCheck.CouldNotCheck
            is PgpBootstrapResult.Success -> when {
                !result.hasIdentity -> IdentityCheck.NoIdentity
                result.protection == PROTECTION_CLIENT ->
                    ownFingerprintFromBootstrap(result)
                        ?.let { IdentityCheck.ClientProtected(it) }
                    // An identity whose key will not parse is not an identity this device can bind
                    // an AAD to. Reporting it as "could not check" rather than "no identity" keeps
                    // the user's own key from being described as absent.
                        ?: IdentityCheck.CouldNotCheck
                result.protection == PROTECTION_SERVER -> IdentityCheck.ServerHeld
                // Degrade, never guess — the same rule pgpComposeStateOf follows. Guessing "client"
                // here starts a ceremony that can only end at a failed GCM open, which is this
                // feature's one alarm.
                else -> IdentityCheck.CouldNotCheck
            }
        }
    }
}

/**
 * The three enrollment calls, with the pairing resolved per call rather than captured.
 *
 * Read at call time and never cached: the credential gate can drop the cached key when the app locks
 * mid-ceremony, and a captured secret would keep working from a state the user has left.
 */
internal class AndroidEnrollmentTransport(context: Context) : EnrollmentTransport {
    private val appContext = context.applicationContext

    // callFactory has no default on EnrollmentClients precisely so this cannot be forgotten; see
    // d410827. The bare default was unpinned, on the one request carrying the device credential.
    private val clients = EnrollmentClients(callFactory = pinnedPairingCallFactory(appContext))

    private fun pairing() = PushRuntime.graph(appContext).repository.pairingForAuthenticatedCall()
        ?.takeIf { !it.deviceId.isNullOrBlank() && !it.deviceSecret.isNullOrBlank() }

    override suspend fun deviceId(): String? = pairing()?.deviceId

    override suspend fun publishKey(encodedPublicKey: String): EnrollmentCallResult {
        val p = pairing() ?: return EnrollmentCallResult.Unauthorized
        return clients.publishKey(p.serverUrl, p.deviceId!!, p.deviceSecret!!, encodedPublicKey)
    }

    override suspend fun fetchEnvelope(): EnrollmentCallResult {
        val p = pairing() ?: return EnrollmentCallResult.Unauthorized
        return clients.fetchEnvelope(p.serverUrl, p.deviceId!!, p.deviceSecret!!)
    }

    override suspend fun reportEnrolled(enrolled: Boolean): EnrollmentCallResult {
        val p = pairing() ?: return EnrollmentCallResult.Unauthorized
        return clients.reportState(p.serverUrl, p.deviceId!!, p.deviceSecret!!, enrolled)
    }

    override fun enqueueDurableReport() = EnrollmentStateWorker.enqueue(appContext)
}

/**
 * Whether this device has a PIN, pattern or password.
 *
 * `KeyguardManager.isDeviceSecure` and **not** `EnrollmentVault.ensureKey()`, even though the vault
 * is the authority. `ensureKey()` mutates: on a key that no longer matches the spec it regenerates,
 * and generation clears the stored blob in the same breath. Using it as a read-only probe would mean
 * opening the ceremony screen could destroy an existing enrollment. The vault still has the final
 * word at the seal, where a mutation is expected.
 */
internal fun hasSecureLockScreen(context: Context): Boolean =
    context.getSystemService(android.app.KeyguardManager::class.java)?.isDeviceSecure == true

/**
 * Wall clock for the bucket, monotonic for the deadline.
 *
 * `elapsedRealtime` for the deadline follows `AppLockManager` and `AppLockStore`, whose own comments
 * explain the choice: a wall-clock deadline can be stepped over or never reached when the user or
 * the network changes the date.
 */
internal object SystemEnrollmentClock : EnrollmentClock {
    override fun epochSeconds(): Long = System.currentTimeMillis() / 1_000
    override fun elapsedRealtimeMs(): Long = SystemClock.elapsedRealtime()
    override suspend fun sleep(millis: Long) = delay(millis)
}
```

- [ ] **Step 2: Expose the two protection constants**

`PROTECTION_CLIENT` and `PROTECTION_SERVER` are `private` in `PgpComposeState.kt`. Widen them to `internal` in place, keeping the existing comment:

```kotlin
/** The two `protection` values this app understands. Anything else degrades to "not server". */
internal const val PROTECTION_SERVER = "server"
internal const val PROTECTION_CLIENT = "client"
```

Do **not** duplicate the literals in `EnrollmentPortsAndroid.kt`. Two spellings of `"client"` in one module is how the compose screen and the Security page end up disagreeing about the same account.

- [ ] **Step 3: Compile and run the whole suite**

Run: `./gradlew testDebugUnitTest lint`
Expected: `BUILD SUCCESSFUL`. Nothing calls these implementations yet, so no behaviour changes — this step is a compile check plus a guard that lint has not gained an error.

- [ ] **Step 4: Verify the pinning claim rather than trusting the comment**

Run: `grep -n "pairingHttpClient()\|pinnedPairingCallFactory\|ensureKey" app/src/main/java/com/urlxl/mail/pgp/EnrollmentPortsAndroid.kt`
Expected: two `pinnedPairingCallFactory` hits, **no** `pairingHttpClient()` hit, and **no** `ensureKey` hit. `PgpBootstrapClient` defaults to the unpinned client, so an omitted argument here is silent; and `ensureKey()` used as a probe would clear the stored blob of an already-enrolled device.

- [ ] **Step 5: Commit**

```bash
git add app/src/main/java/com/urlxl/mail/pgp/EnrollmentPortsAndroid.kt \
        app/src/main/java/com/urlxl/mail/pgp/PgpComposeState.kt
git commit -m "feat(pgp): implement the enrollment ports against the real device

One bootstrap call answers all three questions IdentitySource is defined by, so
hasPgpIdentity is not called as well — a second request could only agree or disagree
with the first, and a disagreement has no resolution.

Both clients are built on pinnedPairingCallFactory. PgpBootstrapClient defaults to
the UNPINNED pairingHttpClient(), so omitting the argument would have put the one
request carrying this device's credential outside the TOFU pin.

An unrecognised protection value degrades to 'could not check' rather than being
guessed as client: guessing starts a ceremony that can only end at a failed GCM open,
which is this feature's one alarm.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 7: The ViewModel

What makes rotation survivable. **No Activity in this app declares `configChanges`**, so rotation destroys every screen — and a ceremony whose state lived in an Activity would republish a key and force the user to re-read a new code every time the phone turned.

**Files:**
- Create: `app/src/main/java/com/urlxl/mail/pgp/DeviceEnrollmentViewModel.kt`

**Interfaces:**
- Consumes: everything Tasks 3–6 produced, plus `SecurityRuntime.graph(context).hostileLocationSettings.isEnabled()`.
- Produces: `internal class DeviceEnrollmentViewModel(application: Application) : AndroidViewModel` with `val state: StateFlow<EnrollmentUiState>`, `val idle: StateFlow<Boolean>`, `fun installSealer(sealer: VaultSealer?)`, `fun checkAgain()`. Task 8 uses all four.

- [ ] **Step 1: Write the ViewModel**

Create `app/src/main/java/com/urlxl/mail/pgp/DeviceEnrollmentViewModel.kt`:

```kotlin
package com.urlxl.mail.pgp

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.urlxl.mail.security.SecurityRuntime
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

/**
 * Owns one ceremony for the lifetime of the screen, across rotations.
 *
 * No Activity in this app declares `configChanges`, so rotation destroys every screen. A ceremony
 * living in an Activity would, on rotation, mint and publish a *new* keypair and put a new code on
 * screen — invalidating the one the user had already started typing into their browser. The
 * ViewModel is what makes that survivable: it is created once and `run()` is started once.
 */
internal class DeviceEnrollmentViewModel(application: Application) : AndroidViewModel(application) {

    private val _state = MutableStateFlow<EnrollmentUiState>(EnrollmentUiState.CheckingIdentity)
    val state: StateFlow<EnrollmentUiState> = _state.asStateFlow()

    /** True when no polling window is running. The Activity offers "Check again" on this, because
     *  `ShowingCode` means two different things depending on whether a window is open behind it. */
    private val _idle = MutableStateFlow(false)
    val idle: StateFlow<Boolean> = _idle.asStateFlow()

    /**
     * The live Activity, or null between one being destroyed and the next installing itself.
     *
     * `@Volatile` because it is written from the main thread and read from whatever dispatcher the
     * ceremony is suspended on.
     */
    @Volatile
    private var activitySealer: VaultSealer? = null

    private val ceremony = EnrollmentCeremony(
        identity = AndroidIdentitySource(application),
        transport = AndroidEnrollmentTransport(application),
        keys = AndroidEnrollmentKeys,
        // A proxy, not the Activity itself: the ViewModel outlives the Activity, and a captured
        // reference would keep a destroyed one alive and prompt on a dead window. A rotation while
        // the prompt is up destroys it, BiometricPrompt reports the cancellation, and the ceremony
        // treats it exactly as a user cancel — code back on screen, nothing destroyed.
        sealer = object : VaultSealer {
            override suspend fun seal(plaintext: ByteArray): SealOutcome =
                activitySealer?.seal(plaintext) ?: SealOutcome.Cancelled
        },
        clock = SystemEnrollmentClock,
        hostileLocationEnabled = {
            SecurityRuntime.graph(application).hostileLocationSettings.isEnabled()
        },
        hasSecureLockScreen = { hasSecureLockScreen(application) },
        onState = { _state.value = it },
    )

    init {
        viewModelScope.launch {
            try {
                ceremony.run()
            } finally {
                _idle.value = ceremony.isIdle
            }
        }
    }

    fun installSealer(sealer: VaultSealer?) {
        activitySealer = sealer
    }

    /** Reopens a polling window against the same keypair. Ignored while one is already running, so
     *  a double tap cannot start two. */
    fun checkAgain() {
        if (!_idle.value) return
        _idle.value = false
        viewModelScope.launch {
            try {
                ceremony.checkAgain()
            } finally {
                _idle.value = ceremony.isIdle
            }
        }
    }

    /**
     * The "user leaves" row of the exit table.
     *
     * `viewModelScope` is already cancelled by the time this runs, so any suspended poll or prompt
     * is gone; this destroys the agreement key it left behind. It is idempotent and destroys nothing
     * if the ceremony never minted anything, because `EnrollmentKeyStore.deleteKeyPair()`'s boolean
     * feeds a `SecurityWipe.step` elsewhere and a deletion that never happened must not be reported.
     */
    override fun onCleared() {
        ceremony.teardown()
        super.onCleared()
    }
}
```

- [ ] **Step 2: Compile**

Run: `./gradlew testDebugUnitTest`
Expected: `BUILD SUCCESSFUL`. There is no unit test for this class — it is wiring, and every decision inside it belongs to `EnrollmentCeremony`, which is covered. Its one behaviour worth checking on hardware (rotation not republishing) is in Task 12's manual checklist.

- [ ] **Step 3: Commit**

```bash
git add app/src/main/java/com/urlxl/mail/pgp/DeviceEnrollmentViewModel.kt
git commit -m "feat(pgp): hold the enrollment ceremony in a ViewModel

No Activity in this app declares configChanges, so rotation destroys every screen. A
ceremony living in one would mint and publish a new keypair on every rotation and put
a new code on screen, invalidating the one the user was already typing.

The sealer is reached through a proxy rather than captured: the ViewModel outlives the
Activity, and a rotation with the prompt up resolves as a cancel — code back on
screen, nothing destroyed.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 8: The ceremony screen

The Activity, its layout, all of the ceremony's copy, and the one Activity-bound piece — `BiometricPrompt`.

**Files:**
- Create: `app/src/main/res/layout/activity_device_enrollment.xml`
- Create: `app/src/main/java/com/urlxl/mail/pgp/DeviceEnrollmentActivity.kt`
- Modify: `app/src/main/res/values/strings.xml`
- Modify: `app/src/main/AndroidManifest.xml`

**Interfaces:**
- Consumes: `DeviceEnrollmentViewModel`, `formatEnrollmentCode(code)`, `EnrollmentVault(context)` (`ensureKey`, `sealCipher`, `store`), and the theme helpers `applyThemeToActivity`, `applyTopInsetWithHeader`, `applyPrimaryButtonTheme`, `applyGhostButtonTheme`.
- Produces: `class DeviceEnrollmentActivity : LockedActivity()`, launchable with a bare `Intent(context, DeviceEnrollmentActivity::class.java)`. Task 10 launches it.

- [ ] **Step 1: Add the strings**

Append to `app/src/main/res/values/strings.xml`, before `</resources>`:

```xml
    <!-- Device enrollment.

         EVERY STRING HERE DESCRIBES CAPABILITY, NEVER BEHAVIOUR. A user who completes this
         ceremony gets a device that HOLDS a key it does not yet USE: reading mail with the
         enrolled key is deferred (see the 2026-07-29 on-device-decryption spec, gated on a
         measurement nobody has taken). Saying "you can now read encrypted mail on this device"
         would be false until that lands. -->
    <string name="enrollment_title">Set up encrypted mail</string>
    <string name="enrollment_checking">Checking your account…</string>
    <string name="enrollment_publishing">Preparing this device…</string>
    <string name="enrollment_code_intro">In your browser, open KyPost and go to Settings → Encryption, choose “Set up a device”, and type this code:</string>
    <string name="enrollment_code_expiry">This code changes in %1$d seconds. The new one works just as well.</string>
    <string name="enrollment_code_expiry_now">This code is about to change.</string>
    <string name="enrollment_waiting">Waiting for your browser…</string>
    <string name="enrollment_timed_out">Nothing has arrived in the last five minutes. The code above is still the right one — type it in your browser, then check again.</string>
    <string name="enrollment_check_again">Check again</string>
    <string name="enrollment_opening">Opening the key that was sent to this device…</string>
    <string name="enrollment_awaiting_auth">Confirm it\'s you to finish setting up this device.</string>
    <string name="enrollment_auth_title">Confirm it\'s you</string>
    <string name="enrollment_auth_subtitle">This protects the key that\'s about to be stored on this device.</string>
    <string name="enrollment_enrolled">This device now holds a key for your encrypted mail.</string>
    <!-- The honest second half of success. Capability, not behaviour. -->
    <string name="enrollment_enrolled_detail">You\'ll still read your encrypted mail in your browser for now.</string>
    <string name="enrollment_done">Done</string>
    <string name="enrollment_cancel">Cancel</string>

    <!-- Unavailable: nothing was started, so nothing went wrong. -->
    <string name="enrollment_unavailable_hostile_location">Not available while Hostile Location Protection is on.</string>
    <string name="enrollment_unavailable_no_lock_screen">Set a screen lock on this device first. Your screen lock is what protects the key.</string>
    <string name="enrollment_unavailable_not_paired">Pair this device with your server first.</string>
    <string name="enrollment_unavailable_no_identity">Your account doesn\'t use encrypted mail yet. You can set that up in your browser.</string>
    <string name="enrollment_unavailable_server_held">Your account\'s encryption key is held by the server, so this device doesn\'t need its own copy.</string>
    <!-- "Couldn't check" is not "no". This must never read as "your account doesn't use
         encrypted mail" — a user told that will go and create a second identity. -->
    <string name="enrollment_unavailable_could_not_check">Couldn\'t check your account. Try again when you\'re back online.</string>

    <!-- Failures. A closed set of local strings: no server-supplied text is ever shown here, so
         an adversarial server cannot pick which of these the user reads. -->
    <string name="enrollment_failed_generic">Something went wrong setting up this device. Nothing was saved. You can try again.</string>
    <string name="enrollment_failed_unauthorized">Your server didn\'t accept this device. Re-pair it from the pairing screen, then try again.</string>
    <string name="enrollment_failed_rate_limited">Your server is asking this device to slow down. Try again in a few minutes.</string>
    <string name="enrollment_failed_no_lock_screen">Your screen lock was removed while this was running. Set one again, then try again.</string>
    <string name="enrollment_failed_no_device_key">This device couldn\'t create the key it needs. Nothing was saved.</string>
    <!-- The ONE failure with its own copy: the only point where this device can detect the
         substitution the ceremony exists to prevent. It DESCRIBES rather than ACCUSES, because a
         key rotation mid-ceremony is indistinguishable by construction from a hostile one — both
         produce exactly this — and an alarm that cries wolf is one users learn to dismiss. -->
    <string name="enrollment_failed_could_not_open">This device could not open the key that was sent to it. That happens if your account\'s encryption key changed while you were setting this up — or if the key didn\'t come from your account. Nothing was saved on this device. Start again to try once more.</string>
```

- [ ] **Step 2: Write the layout**

Create `app/src/main/res/layout/activity_device_enrollment.xml`:

```xml
<?xml version="1.0" encoding="utf-8"?>
<ScrollView xmlns:android="http://schemas.android.com/apk/res/android"
    android:id="@+id/deviceEnrollmentRoot"
    android:layout_width="match_parent"
    android:layout_height="match_parent">

    <LinearLayout
        android:layout_width="match_parent"
        android:layout_height="wrap_content"
        android:orientation="vertical"
        android:padding="20dp">

        <TextView
            android:id="@+id/enrollmentHeadline"
            android:layout_width="match_parent"
            android:layout_height="wrap_content"
            android:textSize="18sp"
            android:textStyle="bold"
            android:layout_marginBottom="12dp" />

        <TextView
            android:id="@+id/enrollmentDetail"
            android:layout_width="match_parent"
            android:layout_height="wrap_content"
            android:textSize="14sp"
            android:layout_marginBottom="20dp" />

        <!-- Monospace and letter-spaced: this is read aloud, character by character, into a
             different device. The font is the same one the pairing screen uses for the device id. -->
        <TextView
            android:id="@+id/enrollmentCode"
            android:layout_width="match_parent"
            android:layout_height="wrap_content"
            android:gravity="center"
            android:textSize="28sp"
            android:textStyle="bold"
            android:fontFamily="@font/ibm_plex_mono"
            android:letterSpacing="0.08"
            android:textIsSelectable="true"
            android:visibility="gone"
            android:layout_marginBottom="8dp" />

        <TextView
            android:id="@+id/enrollmentExpiry"
            android:layout_width="match_parent"
            android:layout_height="wrap_content"
            android:gravity="center"
            android:textSize="13sp"
            android:visibility="gone"
            android:layout_marginBottom="20dp" />

        <Button
            android:id="@+id/btnEnrollmentCheckAgain"
            android:layout_width="match_parent"
            android:layout_height="wrap_content"
            android:text="@string/enrollment_check_again"
            android:visibility="gone"
            android:layout_marginBottom="12dp" />

        <Button
            android:id="@+id/btnEnrollmentClose"
            android:layout_width="match_parent"
            android:layout_height="wrap_content"
            android:text="@string/enrollment_cancel" />
    </LinearLayout>
</ScrollView>
```

- [ ] **Step 3: Write the Activity**

Create `app/src/main/java/com/urlxl/mail/pgp/DeviceEnrollmentActivity.kt`:

```kotlin
package com.urlxl.mail.pgp

import android.os.Bundle
import android.view.View
import android.view.WindowManager
import android.widget.Button
import android.widget.TextView
import androidx.activity.viewModels
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import com.urlxl.mail.R
import com.urlxl.mail.applyGhostButtonTheme
import com.urlxl.mail.applyPrimaryButtonTheme
import com.urlxl.mail.applyThemeToActivity
import com.urlxl.mail.applyTopInsetWithHeader
import com.urlxl.mail.security.LockedActivity
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.launch
import kotlinx.coroutines.suspendCancellableCoroutine
import java.util.concurrent.Executors
import kotlin.coroutines.resume

/**
 * The enrollment ceremony's screen: renders [EnrollmentUiState] and owns the one piece the pure
 * orchestrator cannot — `BiometricPrompt`, which is Activity-bound.
 *
 * A dedicated Activity rather than a section of `SecuritySettingsActivity` (706 lines, and where the
 * `NonCancellable` continuation bug lived) or `PgpKeyActivity` (466). Neither should grow a
 * multi-minute stateful ceremony.
 */
class DeviceEnrollmentActivity : LockedActivity() {

    private val viewModel: DeviceEnrollmentViewModel by viewModels()

    private lateinit var headline: TextView
    private lateinit var detail: TextView
    private lateinit var codeText: TextView
    private lateinit var expiryText: TextView
    private lateinit var checkAgainButton: Button
    private lateinit var closeButton: Button

    private var countdown: Job? = null

    /**
     * Where the AES-GCM `doFinal` and the `commit()`-backed store run.
     *
     * Not the main thread — `EnrollmentVault.store` is a Keystore round trip plus a synchronous
     * write into `EncryptedSharedPreferences`, which is exactly the work `SecuritySettingsActivity`'s
     * own KDoc records having wrongly run on the UI thread. Not `lifecycleScope` either: that is
     * cancelled when this Activity is destroyed, and a seal cancelled halfway leaves a continuation
     * nothing ever resumes, hanging the ceremony. A plain executor is independent of both.
     */
    private val sealExecutor = Executors.newSingleThreadExecutor()

    /**
     * The `VaultSealer` handed to the ViewModel.
     *
     * An anonymous object rather than making this Activity implement the interface: `VaultSealer` is
     * `internal`, and a public class may not widen an internal supertype.
     */
    private val vaultSealer = object : VaultSealer {
        override suspend fun seal(plaintext: ByteArray): SealOutcome =
            suspendCancellableCoroutine { continuation ->
                val vault = EnrollmentVault(applicationContext)

                // The authority on "is there a secure lock screen", and the point where a key is
                // legitimately generated. Returns false by design without one.
                if (!vault.ensureKey()) {
                    continuation.resume(SealOutcome.NoSecureLockScreen)
                    return@suspendCancellableCoroutine
                }
                val cipher = vault.sealCipher()
                if (cipher == null) {
                    continuation.resume(SealOutcome.Failed("The vault cipher could not be created"))
                    return@suspendCancellableCoroutine
                }

                val prompt = BiometricPrompt(
                    this@DeviceEnrollmentActivity,
                    ContextCompat.getMainExecutor(this@DeviceEnrollmentActivity),
                    object : BiometricPrompt.AuthenticationCallback() {
                        override fun onAuthenticationSucceeded(
                            result: BiometricPrompt.AuthenticationResult,
                        ) {
                            val authenticated = result.cryptoObject?.cipher
                            if (authenticated == null) {
                                if (continuation.isActive) {
                                    continuation.resume(
                                        SealOutcome.Failed("No authenticated cipher was returned"),
                                    )
                                }
                                return
                            }
                            sealExecutor.execute {
                                val outcome = runCatching {
                                    val ciphertext = authenticated.doFinal(plaintext)
                                    vault.store(authenticated.iv, ciphertext)
                                    SealOutcome.Sealed
                                }.getOrElse { SealOutcome.Failed(it.message ?: "The seal failed") }
                                if (continuation.isActive) continuation.resume(outcome)
                            }
                        }

                        /** Includes the user dismissing the prompt AND this Activity being
                         *  destroyed under it — a rotation lands here. The ceremony treats both the
                         *  same: back to the code, nothing destroyed. */
                        override fun onAuthenticationError(
                            errorCode: Int,
                            errString: CharSequence,
                        ) {
                            if (continuation.isActive) continuation.resume(SealOutcome.Cancelled)
                        }

                        // onAuthenticationFailed is a non-matching finger. The prompt stays up and
                        // the user tries again; there is nothing to resume.
                    },
                )

                // DEVICE_CREDENTIAL is allowed because the vault key itself allows it — see
                // EnrollmentVault's KDoc on why biometric-only would invalidate the key on every
                // fingerprint change. With DEVICE_CREDENTIAL in the set, setNegativeButtonText must
                // NOT be called: BiometricPrompt throws if both are given.
                val info = BiometricPrompt.PromptInfo.Builder()
                    .setTitle(getString(R.string.enrollment_auth_title))
                    .setSubtitle(getString(R.string.enrollment_auth_subtitle))
                    .setAllowedAuthenticators(
                        BiometricManager.Authenticators.BIOMETRIC_STRONG or
                            BiometricManager.Authenticators.DEVICE_CREDENTIAL,
                    )
                    .build()

                prompt.authenticate(info, BiometricPrompt.CryptoObject(cipher))
                continuation.invokeOnCancellation { runCatching { prompt.cancelAuthentication() } }
            }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // The app lock redirects and finishes in super.onCreate; nothing below may run.
        if (redirectedToUnlock) return
        setContentView(R.layout.activity_device_enrollment)
        setTitle(R.string.enrollment_title)
        applyThemeToActivity(this)
        applyTopInsetWithHeader(this, findViewById(R.id.deviceEnrollmentRoot))

        headline = findViewById(R.id.enrollmentHeadline)
        detail = findViewById(R.id.enrollmentDetail)
        codeText = findViewById(R.id.enrollmentCode)
        expiryText = findViewById(R.id.enrollmentExpiry)
        checkAgainButton = findViewById(R.id.btnEnrollmentCheckAgain)
        closeButton = findViewById(R.id.btnEnrollmentClose)

        checkAgainButton.setOnClickListener { viewModel.checkAgain() }
        closeButton.setOnClickListener { finish() }

        // Installed here rather than in onStart: the ceremony may reach the seal at any moment, and
        // a null sealer resolves as a cancel.
        viewModel.installSealer(vaultSealer)

        lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.STARTED) {
                combine(viewModel.state, viewModel.idle) { state, idle -> state to idle }
                    .collect { (state, idle) -> render(state, idle) }
            }
        }
    }

    override fun onResume() {
        super.onResume()
        if (redirectedToUnlock) return
        applyThemeToActivity(this)
        applyPrimaryButtonTheme(this, checkAgainButton)
        applyGhostButtonTheme(this, closeButton)
    }

    override fun onDestroy() {
        // Only clear the slot if this Activity is still the one in it. On a rotation the new
        // Activity's onCreate runs BEFORE the old one's onDestroy, so an unconditional null here
        // would uninstall the incoming sealer and turn the next prompt into a cancel.
        viewModel.installSealer(null)
        sealExecutor.shutdown()
        super.onDestroy()
    }

    private fun render(state: EnrollmentUiState, idle: Boolean) {
        countdown?.cancel()
        countdown = null

        val showingCode = state is EnrollmentUiState.ShowingCode ||
            state is EnrollmentUiState.WaitingTimedOut

        // FLAG_KEEP_SCREEN_ON while the code is up. Without it the screen times out while the user
        // is typing into their browser, which backgrounds the app, which starts the lock grace —
        // and the user comes back to an unlock prompt with the ceremony destroyed.
        if (showingCode) {
            window.addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
        } else {
            window.clearFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
        }

        val code = when (state) {
            is EnrollmentUiState.ShowingCode -> state.code to state.expiresAtEpochMs
            is EnrollmentUiState.WaitingTimedOut -> state.code to state.expiresAtEpochMs
            else -> null
        }
        codeText.visibility = if (code == null) View.GONE else View.VISIBLE
        expiryText.visibility = if (code == null) View.GONE else View.VISIBLE
        if (code != null) {
            codeText.text = formatEnrollmentCode(code.first)
            startCountdown(code.second)
        }

        headline.setText(headlineFor(state))
        detail.setText(detailFor(state))

        checkAgainButton.visibility = if (idle && showingCode) View.VISIBLE else View.GONE
        closeButton.setText(
            if (state is EnrollmentUiState.Enrolled) R.string.enrollment_done
            else R.string.enrollment_cancel,
        )
    }

    /** Recomputes from the wall clock every second rather than counting down from a captured value,
     *  so a screen that was backgrounded shows the truth when it comes back. */
    private fun startCountdown(expiresAtEpochMs: Long) {
        countdown = lifecycleScope.launch {
            while (true) {
                val remaining = (expiresAtEpochMs - System.currentTimeMillis()) / 1_000L
                expiryText.text = if (remaining > 0) {
                    getString(R.string.enrollment_code_expiry, remaining.toInt())
                } else {
                    getString(R.string.enrollment_code_expiry_now)
                }
                delay(1_000L)
            }
        }
    }

    private fun headlineFor(state: EnrollmentUiState): Int = when (state) {
        EnrollmentUiState.CheckingIdentity -> R.string.enrollment_checking
        EnrollmentUiState.PublishingKey -> R.string.enrollment_publishing
        is EnrollmentUiState.ShowingCode -> R.string.enrollment_waiting
        is EnrollmentUiState.WaitingTimedOut -> R.string.enrollment_waiting
        EnrollmentUiState.Opening -> R.string.enrollment_opening
        EnrollmentUiState.AwaitingAuth -> R.string.enrollment_awaiting_auth
        EnrollmentUiState.Enrolled -> R.string.enrollment_enrolled
        is EnrollmentUiState.Unavailable -> unavailableCopy(state.reason)
        is EnrollmentUiState.Failed -> failureCopy(state.reason)
    }

    private fun detailFor(state: EnrollmentUiState): Int = when (state) {
        is EnrollmentUiState.ShowingCode -> R.string.enrollment_code_intro
        is EnrollmentUiState.WaitingTimedOut -> R.string.enrollment_timed_out
        EnrollmentUiState.Enrolled -> R.string.enrollment_enrolled_detail
        else -> R.string.empty_string
    }

    private fun unavailableCopy(reason: UnavailableReason): Int = when (reason) {
        UnavailableReason.NOT_PAIRED -> R.string.enrollment_unavailable_not_paired
        UnavailableReason.HOSTILE_LOCATION -> R.string.enrollment_unavailable_hostile_location
        UnavailableReason.NO_SECURE_LOCK_SCREEN -> R.string.enrollment_unavailable_no_lock_screen
        UnavailableReason.NO_IDENTITY -> R.string.enrollment_unavailable_no_identity
        UnavailableReason.SERVER_HELD_KEY -> R.string.enrollment_unavailable_server_held
        UnavailableReason.COULD_NOT_CHECK -> R.string.enrollment_unavailable_could_not_check
    }

    private fun failureCopy(reason: FailureReason): Int = when (reason) {
        // The only failure with its own copy — see the string's comment.
        FailureReason.COULD_NOT_OPEN -> R.string.enrollment_failed_could_not_open
        FailureReason.UNAUTHORIZED -> R.string.enrollment_failed_unauthorized
        FailureReason.RATE_LIMITED -> R.string.enrollment_failed_rate_limited
        FailureReason.NO_SECURE_LOCK_SCREEN -> R.string.enrollment_failed_no_lock_screen
        FailureReason.NO_DEVICE_KEY -> R.string.enrollment_failed_no_device_key
        FailureReason.PUBLISH_REJECTED -> R.string.enrollment_failed_generic
        FailureReason.ENVELOPE_MALFORMED -> R.string.enrollment_failed_generic
        FailureReason.SEAL_FAILED -> R.string.enrollment_failed_generic
    }
}
```

- [ ] **Step 4: Add the empty-string resource if it does not exist**

Run: `grep -n 'name="empty_string"' app/src/main/res/values/strings.xml`

If there is no match, add to `strings.xml`:
```xml
    <!-- Deliberately empty: a detail line with nothing to say. Used rather than "" inline so the
         setText(Int) overload stays consistent with every other branch. -->
    <string name="empty_string" translatable="false"></string>
```

- [ ] **Step 5: Register the Activity**

In `app/src/main/AndroidManifest.xml`, immediately after the `.pgp.PgpKeyActivity` entry, add:

```xml
        <activity
            android:name=".pgp.DeviceEnrollmentActivity"
            android:exported="false" />
```

No `configChanges`, deliberately — nothing else in this app declares it, and the ViewModel is what makes rotation survivable. No `excludeFromRecents`: `LockedActivity` already sets `FLAG_SECURE` on every window, so the Recents card is blank.

- [ ] **Step 6: Build and check lint**

Run: `./gradlew assembleDebug lint`
Expected: `BUILD SUCCESSFUL` with 0 lint errors. A missing string or a mistyped resource id fails here.

- [ ] **Step 7: Confirm the copy rule mechanically**

Run: `grep -n "enrollment_" app/src/main/res/values/strings.xml | grep -iE "can (now )?read|able to read|decrypt"`
Expected: **no output**. Every string describes capability; none claims the user can now read encrypted mail on the phone.

- [ ] **Step 8: Commit**

```bash
git add app/src/main/java/com/urlxl/mail/pgp/DeviceEnrollmentActivity.kt \
        app/src/main/res/layout/activity_device_enrollment.xml \
        app/src/main/res/values/strings.xml \
        app/src/main/AndroidManifest.xml
git commit -m "feat(pgp): add the device enrollment screen

Renders the ceremony's states and owns the one Activity-bound piece, BiometricPrompt.
DEVICE_CREDENTIAL is in the allowed authenticators because the vault key allows it,
which means setNegativeButtonText must not be set — BiometricPrompt throws on both.

FLAG_KEEP_SCREEN_ON while the code is up: without it the screen times out while the
user is typing into their browser, which backgrounds the app, starts the lock grace,
and returns them to an unlock prompt with the ceremony destroyed.

The seal runs on its own executor, not lifecycleScope: a seal cancelled halfway would
leave a continuation nothing ever resumes.

Every string describes capability, never behaviour. Success says this device now
HOLDS a key — reading mail with it is still deferred.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 9: The Security-page row, as a pure function

The decision behind the entry, split from the screen so all nine states are JVM tests rather than an instrumented walk through a 706-line Activity.

**Files:**
- Create: `app/src/main/java/com/urlxl/mail/pgp/EnrollmentRow.kt`
- Create: `app/src/test/java/com/urlxl/mail/pgp/EnrollmentRowTest.kt`

**Interfaces:**
- Consumes: `IdentityCheck` (Task 3), `EnrollmentStatus` (existing, in `EnrollmentState.kt`).
- Produces: `internal sealed class EnrollmentRow` with objects `Hidden`, `HostileLocation`, `NoSecureLockScreen`, `KeyInvalidated`, `Enrolled`, `ServerHeldKey`, `NoIdentity`, `CouldNotCheck`, `NotEnrolled`; and `internal fun enrollmentRowFor(paired, hostileLocation, hasSecureLockScreen, status, identity): EnrollmentRow`. Task 10 renders it.

- [ ] **Step 1: Write the failing test**

Create `app/src/test/java/com/urlxl/mail/pgp/EnrollmentRowTest.kt`:

```kotlin
package com.urlxl.mail.pgp

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * Which row the Security page shows.
 *
 * A pure function so all nine outcomes are asserted here rather than through a 706-line Activity.
 * The ordering is as load-bearing as the mapping: two of these rows are LOCAL facts that must
 * survive the network being down, and the spec's table has them last.
 */
class EnrollmentRowTest {

    private fun row(
        paired: Boolean = true,
        hostileLocation: Boolean = false,
        hasSecureLockScreen: Boolean = true,
        status: EnrollmentStatus = EnrollmentStatus.NO_BLOB,
        identity: IdentityCheck = IdentityCheck.ClientProtected("164D5B834E7FE927"),
    ) = enrollmentRowFor(paired, hostileLocation, hasSecureLockScreen, status, identity)

    @Test
    fun anUnpairedDeviceShowsNothing() {
        assertEquals(EnrollmentRow.Hidden, row(paired = false))
    }

    @Test
    fun hostileLocationProtectionHidesTheOffer() {
        assertEquals(EnrollmentRow.HostileLocation, row(hostileLocation = true))
    }

    @Test
    fun noSecureLockScreenExplainsItself() {
        assertEquals(EnrollmentRow.NoSecureLockScreen, row(hasSecureLockScreen = false))
    }

    @Test
    fun aClientKeyThatIsNotYetEnrolledOffersTheCeremony() {
        assertEquals(EnrollmentRow.NotEnrolled, row())
    }

    @Test
    fun anEnrolledDeviceOffersRemoval() {
        assertEquals(EnrollmentRow.Enrolled, row(status = EnrollmentStatus.ENROLLED))
    }

    /**
     * A real state spec 1 produces — a biometric enrollment change or a Keystore invalidation kills
     * the vault key. It must be *said*, not silently read as un-enrolled: the server may still be
     * telling the user this device can read their mail, and they may decommission the device that
     * actually holds a working copy.
     */
    @Test
    fun anInvalidatedKeyIsSaidRatherThanReadingAsUnEnrolled() {
        assertEquals(EnrollmentRow.KeyInvalidated, row(status = EnrollmentStatus.KEY_INVALIDATED))
    }

    /** The retirement nudge: it names where the key lives rather than saying "unavailable", and
     *  hands the user the action that fixes it. */
    @Test
    fun aServerHeldKeyNamesWhereTheKeyLives() {
        assertEquals(EnrollmentRow.ServerHeldKey, row(identity = IdentityCheck.ServerHeld))
    }

    @Test
    fun anAccountWithNoIdentityIsToldSo() {
        assertEquals(EnrollmentRow.NoIdentity, row(identity = IdentityCheck.NoIdentity))
    }

    /** Decision 10, on the screen this time. */
    @Test
    fun aFailedCheckIsItsOwnRowAndNotNoIdentity() {
        assertEquals(EnrollmentRow.CouldNotCheck, row(identity = IdentityCheck.CouldNotCheck))
    }

    /**
     * **The ordering that matters most.** Both of these are local facts, and both are hidden by the
     * spec's table ordering the moment the identity request fails — which is exactly when a user is
     * most likely to be looking at this screen.
     */
    @Test
    fun localFactsSurviveTheNetworkBeingDown() {
        assertEquals(
            "an invalidated key must be reported even when the account cannot be reached",
            EnrollmentRow.KeyInvalidated,
            row(status = EnrollmentStatus.KEY_INVALIDATED, identity = IdentityCheck.CouldNotCheck),
        )
        assertEquals(
            "removal is a local action and must stay reachable offline",
            EnrollmentRow.Enrolled,
            row(status = EnrollmentStatus.ENROLLED, identity = IdentityCheck.CouldNotCheck),
        )
    }

    /**
     * Hostile Location Protection outranks everything except pairing. Its contract is that no
     * envelope exists on this device, so an `ENROLLED` probe under it is a contradiction the row
     * must not repeat back to the user as "this device holds a key".
     */
    @Test
    fun hostileLocationOutranksALocalEnrollment() {
        assertEquals(
            EnrollmentRow.HostileLocation,
            row(hostileLocation = true, status = EnrollmentStatus.ENROLLED),
        )
    }

    /** Without a lock screen the vault key cannot exist, so there is nothing to remove and nothing
     *  to offer — say why, and say it before anything that depends on the network. */
    @Test
    fun theLockScreenCheckOutranksTheIdentityCheck() {
        assertEquals(
            EnrollmentRow.NoSecureLockScreen,
            row(hasSecureLockScreen = false, identity = IdentityCheck.CouldNotCheck),
        )
    }
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `./gradlew testDebugUnitTest --tests '*EnrollmentRowTest*'`
Expected: FAIL — `Unresolved reference: enrollmentRowFor`.

- [ ] **Step 3: Write the implementation**

Create `app/src/main/java/com/urlxl/mail/pgp/EnrollmentRow.kt`:

```kotlin
package com.urlxl.mail.pgp

/**
 * What the Security page's encrypted-mail row says, and what it offers.
 *
 * A type rather than a string so the decision is testable and the copy lives with the screen.
 */
internal sealed class EnrollmentRow {
    /** Not paired: there is no account to hold a key for. */
    object Hidden : EnrollmentRow()

    object HostileLocation : EnrollmentRow()
    object NoSecureLockScreen : EnrollmentRow()

    /** The vault key is gone — a biometric enrollment change, a Keystore invalidation. Offers the
     *  ceremony again. */
    object KeyInvalidated : EnrollmentRow()

    /** This device holds a key. Offers removal. */
    object Enrolled : EnrollmentRow()

    /** The account's key is held by the server. Offers webmail — this is the retirement nudge. */
    object ServerHeldKey : EnrollmentRow()

    /** The account has no PGP identity yet. Offers webmail, where one can be made. */
    object NoIdentity : EnrollmentRow()

    /** The account could not be reached. Offers nothing, and says so without implying "no". */
    object CouldNotCheck : EnrollmentRow()

    /** A client-protected key this device does not hold yet. Offers the ceremony. */
    object NotEnrolled : EnrollmentRow()
}

/**
 * Decides the row.
 *
 * **Local facts before network facts.** The spec's row table lists `Enrolled` and `KEY_INVALIDATED`
 * last, after the identity branch. Ordered that way, a device with no connectivity renders as
 * "couldn't check your account" — which hides the one row whose entire job is to tell the user this
 * device can no longer open their mail, and hides "Remove from this device", a local security action
 * that must not require a working network. Both are facts about this device's own Keystore, so they
 * are answered from the Keystore first.
 *
 * Hostile Location Protection and the lock screen come before both, because under either of them the
 * `ENROLLED` probe is either a contradiction or impossible.
 */
internal fun enrollmentRowFor(
    paired: Boolean,
    hostileLocation: Boolean,
    hasSecureLockScreen: Boolean,
    status: EnrollmentStatus,
    identity: IdentityCheck,
): EnrollmentRow = when {
    !paired -> EnrollmentRow.Hidden
    hostileLocation -> EnrollmentRow.HostileLocation
    !hasSecureLockScreen -> EnrollmentRow.NoSecureLockScreen

    // Local, and both unsafe to withhold.
    status == EnrollmentStatus.KEY_INVALIDATED -> EnrollmentRow.KeyInvalidated
    status == EnrollmentStatus.ENROLLED -> EnrollmentRow.Enrolled

    else -> when (identity) {
        is IdentityCheck.ServerHeld -> EnrollmentRow.ServerHeldKey
        is IdentityCheck.NoIdentity -> EnrollmentRow.NoIdentity
        is IdentityCheck.CouldNotCheck -> EnrollmentRow.CouldNotCheck
        is IdentityCheck.ClientProtected -> EnrollmentRow.NotEnrolled
    }
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `./gradlew testDebugUnitTest --tests '*EnrollmentRowTest*'`
Expected: PASS, 12 tests.

- [ ] **Step 5: Commit**

```bash
git add app/src/main/java/com/urlxl/mail/pgp/EnrollmentRow.kt \
        app/src/test/java/com/urlxl/mail/pgp/EnrollmentRowTest.kt
git commit -m "feat(pgp): decide the Security page's encrypted-mail row purely

Local facts are answered before network facts. Ordered the other way, a device with
no connectivity renders as 'couldn't check your account' — hiding the row that says
this device can no longer open its mail, and hiding 'Remove from this device', which
is a local security action that must not need a working network.

'Could not check' is its own row rather than collapsing into 'no identity'.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 10: The Security-page entry

The row on screen, the launch into the ceremony, and "Remove from this device" — without which the only ways to undo an enrollment are Hostile Location Protection or a full wipe, both nuclear.

**Files:**
- Modify: `app/src/main/java/com/urlxl/mail/pgp/WebmailDeepLink.kt`
- Modify: `app/src/test/java/com/urlxl/mail/pgp/WebmailDeepLinkTest.kt`
- Modify: `app/src/main/java/com/urlxl/mail/pgp/EnrollmentTeardown.kt`
- Modify: `app/src/main/java/com/urlxl/mail/security/SecuritySettingsActivity.kt`
- Modify: `app/src/main/res/values/strings.xml`

**Interfaces:**
- Consumes: `enrollmentRowFor(...)`, `EnrollmentRow`, `AndroidIdentitySource`, `hasSecureLockScreen(context)`, `probeEnrollment(vault)`, `openWebmail(activity, serverUrl, url)`, `DeviceEnrollmentActivity`.
- Produces: `fun webmailHomeUrl(serverUrl: String): String?`, `EnrollmentTeardown.destroyAndReport(context): List<String>`.

- [ ] **Step 1: Write the failing test for the webmail home URL**

Append to `app/src/test/java/com/urlxl/mail/pgp/WebmailDeepLinkTest.kt`, inside the existing test class:

```kotlin
    /** The Security page's "open webmail" actions target the account, not one message. */
    @Test
    fun webmailHomeUrlIsTheServerRoot() {
        assertEquals("https://relay.example.com/", webmailHomeUrl("https://relay.example.com"))
        assertEquals("https://relay.example.com/", webmailHomeUrl("https://relay.example.com/"))
    }

    /** A path on the stored server URL must not survive into the handoff target. */
    @Test
    fun webmailHomeUrlDropsAnyPath() {
        assertEquals("https://relay.example.com/", webmailHomeUrl("https://relay.example.com/read?message=7"))
    }

    /** Same failure mode as every other builder here: no button rather than a dead one. */
    @Test
    fun webmailHomeUrlRefusesAnUnusableServerUrl() {
        assertNull(webmailHomeUrl("not a url"))
    }
```

Add `import org.junit.Assert.assertNull` if the file does not already have it.

- [ ] **Step 2: Run it to verify it fails**

Run: `./gradlew testDebugUnitTest --tests '*WebmailDeepLinkTest*'`
Expected: FAIL — `Unresolved reference: webmailHomeUrl`.

- [ ] **Step 3: Add the builder**

Append to `app/src/main/java/com/urlxl/mail/pgp/WebmailDeepLink.kt`:

```kotlin
/**
 * The account's webmail home.
 *
 * Used by the Security page's "open webmail" actions, where the destination is "your account in the
 * browser" rather than one message — creating a PGP identity and choosing client custody are both
 * web-session-only actions on the backend.
 *
 * The path is replaced rather than appended: the stored `serverUrl` is the pairing's origin, but a
 * value carrying a path would otherwise produce `…/read/` and land nowhere. `isFirstPartyWebmailUrl`
 * still gates the launch on the origin.
 */
fun webmailHomeUrl(serverUrl: String): String? =
    serverUrl.toHttpUrlOrNull()?.newBuilder()?.encodedPath("/")?.build()?.toString()
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `./gradlew testDebugUnitTest --tests '*WebmailDeepLinkTest*'`
Expected: PASS.

- [ ] **Step 5: Add the removal helper**

Append to `app/src/main/java/com/urlxl/mail/pgp/EnrollmentTeardown.kt`, inside the `EnrollmentTeardown` object:

```kotlin
    /**
     * [destroy] plus the correction to the server, for the user-initiated "Remove from this device".
     *
     * The report goes through [EnrollmentStateWorker] rather than a direct `reportState(false)`
     * because the worker re-probes live state on every run and retries when offline — so if the
     * teardown half-failed, the server is told this device is still enrolled rather than being told
     * a comforting lie. A direct call would be a second reporting path that can fail silently.
     *
     * `SecuritySettingsActivity.tearDownEnrollmentForHostileLocation` performs the same two steps
     * for the protection toggle. It is deliberately left alone rather than routed through here: it
     * is driven by an instrumented test that exists to keep the toggle and the teardown in step, and
     * a refactor of that path buys nothing this function needs.
     */
    fun destroyAndReport(context: Context): List<String> {
        val leftBehind = destroy(context)
        EnrollmentStateWorker.enqueue(context)
        return leftBehind
    }
```

- [ ] **Step 6: Add the Security-page strings**

Append to `app/src/main/res/values/strings.xml`:

```xml
    <!-- The Security page's encrypted-mail entry. Capability, never behaviour — see the enrollment
         strings above. -->
    <string name="security_encryption_section">Encrypted mail</string>
    <string name="security_encryption_hostile_location">Not available while Hostile Location Protection is on.</string>
    <string name="security_encryption_no_lock_screen">Set a screen lock to use encrypted mail on this device.</string>
    <string name="security_encryption_server_held">Your account\'s encryption key is held by the server.</string>
    <string name="security_encryption_no_identity">Your account doesn\'t use encrypted mail yet.</string>
    <string name="security_encryption_not_enrolled">Set up encrypted mail on this device.</string>
    <string name="security_encryption_enrolled">This device holds a key for your encrypted mail.</string>
    <string name="security_encryption_invalidated">This device can no longer open your encrypted mail.</string>
    <string name="security_encryption_could_not_check">Couldn\'t check whether your account uses encrypted mail. Open this screen again when you\'re back online.</string>
    <string name="security_encryption_open_webmail">Open webmail</string>
    <string name="security_encryption_set_up">Set up</string>
    <string name="security_encryption_set_up_again">Set up again</string>
    <string name="security_encryption_remove">Remove from this device</string>
    <string name="security_encryption_remove_title">Remove encrypted mail from this device?</string>
    <string name="security_encryption_remove_body">This device will stop holding a key for your encrypted mail. Your mail and your account\'s key are not affected, and you can set this device up again at any time.</string>
    <string name="security_encryption_remove_confirm">Remove</string>
    <string name="security_encryption_removed">Removed from this device</string>
    <string name="security_encryption_webmail_failed">Couldn\'t open webmail on this device</string>
```

- [ ] **Step 7: Add the entry to the Security page**

In `app/src/main/java/com/urlxl/mail/security/SecuritySettingsActivity.kt`:

Add these fields beside the existing `lateinit var` declarations:

```kotlin
    private lateinit var encryptionSectionLabel: TextView
    private lateinit var encryptionRowText: TextView
    private lateinit var encryptionActionButton: Button
```

At the end of `buildViews(snapshot)`, immediately before `scrollView.addView(container)`, add:

```kotlin
        // Encrypted mail. Built hidden and filled in asynchronously: deciding the row needs a
        // Keystore probe and (usually) one authenticated request, neither of which may run on the
        // main thread or block the rest of this screen from appearing.
        encryptionSectionLabel = TextView(this).apply {
            text = getString(R.string.security_encryption_section)
            visibility = View.GONE
        }
        container.addViewSpaced(encryptionSectionLabel, topDp = 8, bottomDp = 8)
        encryptionRowText = TextView(this).apply {
            textSize = 13f
            visibility = View.GONE
        }
        container.addViewSpaced(encryptionRowText, bottomDp = 8)
        encryptionActionButton = Button(this).apply { visibility = View.GONE }
        container.addViewSpaced(encryptionActionButton, bottomDp = 16)
```

Add to `onResume` (creating one if the class has none — it currently does not), so the row is correct after returning from the ceremony or the removal:

```kotlin
    override fun onResume() {
        super.onResume()
        if (redirectedToUnlock) return
        // ::isInitialized guards the window between onCreate's launch starting and buildViews
        // running — onResume can fire first, and these are lateinit.
        if (::encryptionRowText.isInitialized) refreshEncryptionRow()
    }
```

And add these methods:

```kotlin
    /**
     * Recomputes the encrypted-mail row.
     *
     * The identity request is skipped whenever a local fact already decides the row. That is not
     * only an optimisation: under Hostile Location Protection the user has just declared this
     * network hostile, and this screen must not answer that by making a request over it.
     */
    private fun refreshEncryptionRow() {
        lifecycleScope.launch {
            val activity = this@SecuritySettingsActivity
            val local = withContext(SecurityWork) {
                val pairing = PushRuntime.graph(activity).repository.pairingForAuthenticatedCall()
                Triple(
                    pairing != null && !pairing.deviceId.isNullOrBlank(),
                    SecurityRuntime.graph(activity).hostileLocationSettings.isEnabled(),
                    com.urlxl.mail.pgp.hasSecureLockScreen(activity),
                )
            }
            val (paired, hostileLocation, lockScreen) = local
            val status = withContext(SecurityWork) {
                com.urlxl.mail.pgp.probeEnrollment(com.urlxl.mail.pgp.EnrollmentVault(activity))
            }
            val identity = if (paired && !hostileLocation && lockScreen) {
                com.urlxl.mail.pgp.AndroidIdentitySource(activity).check()
            } else {
                com.urlxl.mail.pgp.IdentityCheck.CouldNotCheck
            }
            if (isFinishing || isDestroyed) return@launch
            renderEncryptionRow(
                com.urlxl.mail.pgp.enrollmentRowFor(
                    paired = paired,
                    hostileLocation = hostileLocation,
                    hasSecureLockScreen = lockScreen,
                    status = status,
                    identity = identity,
                ),
            )
        }
    }

    private fun renderEncryptionRow(row: com.urlxl.mail.pgp.EnrollmentRow) {
        if (row is com.urlxl.mail.pgp.EnrollmentRow.Hidden) {
            encryptionSectionLabel.visibility = View.GONE
            encryptionRowText.visibility = View.GONE
            encryptionActionButton.visibility = View.GONE
            return
        }
        encryptionSectionLabel.visibility = View.VISIBLE
        applySectionEyebrowLabel(this, encryptionSectionLabel)
        encryptionRowText.visibility = View.VISIBLE
        encryptionRowText.setText(encryptionRowCopy(row))

        val action: Pair<Int, () -> Unit>? = when (row) {
            com.urlxl.mail.pgp.EnrollmentRow.ServerHeldKey,
            com.urlxl.mail.pgp.EnrollmentRow.NoIdentity,
            -> R.string.security_encryption_open_webmail to { openAccountWebmail() }

            com.urlxl.mail.pgp.EnrollmentRow.NotEnrolled ->
                R.string.security_encryption_set_up to { launchEnrollmentCeremony() }

            com.urlxl.mail.pgp.EnrollmentRow.KeyInvalidated ->
                R.string.security_encryption_set_up_again to { launchEnrollmentCeremony() }

            com.urlxl.mail.pgp.EnrollmentRow.Enrolled ->
                R.string.security_encryption_remove to { confirmRemoveEnrollment() }

            // Nothing the user can do from here fixes any of these.
            com.urlxl.mail.pgp.EnrollmentRow.HostileLocation,
            com.urlxl.mail.pgp.EnrollmentRow.NoSecureLockScreen,
            com.urlxl.mail.pgp.EnrollmentRow.CouldNotCheck,
            com.urlxl.mail.pgp.EnrollmentRow.Hidden,
            -> null
        }

        if (action == null) {
            encryptionActionButton.visibility = View.GONE
            return
        }
        encryptionActionButton.visibility = View.VISIBLE
        encryptionActionButton.setText(action.first)
        encryptionActionButton.setOnClickListener { action.second() }
        if (row is com.urlxl.mail.pgp.EnrollmentRow.Enrolled) {
            applyDangerButtonTheme(this, encryptionActionButton)
        } else {
            applyPrimaryButtonTheme(this, encryptionActionButton)
        }
    }

    private fun encryptionRowCopy(row: com.urlxl.mail.pgp.EnrollmentRow): Int = when (row) {
        com.urlxl.mail.pgp.EnrollmentRow.Hidden -> R.string.empty_string
        com.urlxl.mail.pgp.EnrollmentRow.HostileLocation -> R.string.security_encryption_hostile_location
        com.urlxl.mail.pgp.EnrollmentRow.NoSecureLockScreen -> R.string.security_encryption_no_lock_screen
        com.urlxl.mail.pgp.EnrollmentRow.KeyInvalidated -> R.string.security_encryption_invalidated
        com.urlxl.mail.pgp.EnrollmentRow.Enrolled -> R.string.security_encryption_enrolled
        com.urlxl.mail.pgp.EnrollmentRow.ServerHeldKey -> R.string.security_encryption_server_held
        com.urlxl.mail.pgp.EnrollmentRow.NoIdentity -> R.string.security_encryption_no_identity
        com.urlxl.mail.pgp.EnrollmentRow.CouldNotCheck -> R.string.security_encryption_could_not_check
        com.urlxl.mail.pgp.EnrollmentRow.NotEnrolled -> R.string.security_encryption_not_enrolled
    }

    private fun launchEnrollmentCeremony() {
        startActivity(
            android.content.Intent(this, com.urlxl.mail.pgp.DeviceEnrollmentActivity::class.java),
        )
    }

    /** Built from the pairing's own `serverUrl`, never from anything a response supplied —
     *  `openWebmail` refuses a non-first-party URL rather than degrading to a browser launch. */
    private fun openAccountWebmail() {
        lifecycleScope.launch {
            val serverUrl = withContext(SecurityWork) {
                PushRuntime.graph(this@SecuritySettingsActivity)
                    .repository.pairingForAuthenticatedCall()?.serverUrl
            }
            val url = serverUrl?.let { com.urlxl.mail.pgp.webmailHomeUrl(it) }
            val opened = url != null &&
                com.urlxl.mail.pgp.openWebmail(this@SecuritySettingsActivity, serverUrl, url)
            if (!opened) {
                Toast.makeText(
                    this@SecuritySettingsActivity,
                    R.string.security_encryption_webmail_failed,
                    Toast.LENGTH_SHORT,
                ).show()
            }
        }
    }

    /**
     * Confirmed, because it is destructive and not obviously reversible from the user's side: the
     * envelope goes, and getting it back means another two-device ceremony.
     */
    private fun confirmRemoveEnrollment() {
        AlertDialog.Builder(this)
            .setTitle(R.string.security_encryption_remove_title)
            .setMessage(R.string.security_encryption_remove_body)
            .setPositiveButton(R.string.security_encryption_remove_confirm) { _, _ ->
                lifecycleScope.launch {
                    // SecurityWork, like every other destructive step on this screen: this is a
                    // Keystore deletion plus a commit()-backed prefs clear.
                    val leftBehind = withContext(SecurityWork) {
                        com.urlxl.mail.pgp.EnrollmentTeardown.destroyAndReport(
                            this@SecuritySettingsActivity,
                        )
                    }
                    if (leftBehind.isNotEmpty()) {
                        android.util.Log.e(
                            "SecuritySettings",
                            "Enrollment removal left $leftBehind behind",
                        )
                    }
                    if (isFinishing || isDestroyed) return@launch
                    // The enqueued report probes live state, so a half-failed teardown is reported
                    // honestly rather than as a removal that did not happen.
                    Toast.makeText(
                        this@SecuritySettingsActivity,
                        R.string.security_encryption_removed,
                        Toast.LENGTH_SHORT,
                    ).show()
                    refreshEncryptionRow()
                }
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }
```

Add the imports this needs to the top of the file — verified absent as of `ef83939`:

```kotlin
import com.urlxl.mail.applyDangerButtonTheme
import com.urlxl.mail.applyPrimaryButtonTheme
import com.urlxl.mail.applySectionEyebrowLabel
```

`Toast`, `View`, `Button`, `TextView`, `AlertDialog`, `lifecycleScope`, `withContext` and `PushRuntime` are already imported.

Finally, call `refreshEncryptionRow()` at the end of `buildViews`, after `applyThemeToActivity(this)`.

- [ ] **Step 8: Build, lint and run the whole unit suite**

Run: `./gradlew assembleDebug lint testDebugUnitTest`
Expected: `BUILD SUCCESSFUL`, 0 lint errors.

- [ ] **Step 9: Check the row cannot silently lose a state**

Run: `grep -c "com.urlxl.mail.pgp.EnrollmentRow\." app/src/main/java/com/urlxl/mail/security/SecuritySettingsActivity.kt`
Expected: at least 18 — every `EnrollmentRow` variant appears in both `encryptionRowCopy` (a `when` expression over a sealed class, so exhaustive at compile time) and the action `when`. If a new row is added later, both fail to compile rather than falling through to a blank line.

- [ ] **Step 10: Commit**

```bash
git add app/src/main/java/com/urlxl/mail/pgp/WebmailDeepLink.kt \
        app/src/test/java/com/urlxl/mail/pgp/WebmailDeepLinkTest.kt \
        app/src/main/java/com/urlxl/mail/pgp/EnrollmentTeardown.kt \
        app/src/main/java/com/urlxl/mail/security/SecuritySettingsActivity.kt \
        app/src/main/res/values/strings.xml
git commit -m "feat(security): offer encrypted mail on the Security page

The row is decided by a pure function and rendered here. 'Remove from this device'
exists because without it the only ways to undo an enrollment are Hostile Location
Protection or a full wipe, both nuclear; it reports through EnrollmentStateWorker,
which probes live state, so a half-failed teardown is not reported as a clean one.

The identity request is skipped whenever a local fact already decides the row —
under Hostile Location Protection that is a requirement, not an optimisation: the
user has just declared this network hostile.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 11: The pairing pointer

One static line, and deliberately nothing else.

**Files:**
- Modify: `app/src/main/res/layout/activity_push_pairing.xml`
- Modify: `app/src/main/res/values/strings.xml`

**Interfaces:**
- Consumes: nothing. **No Kotlin change at all** — that is the point. `applyThemeToActivity` walks the view tree, so a plain `TextView` with `android:text` is themed without a `findViewById`.
- Produces: nothing.

- [ ] **Step 1: Add the string**

Append to `app/src/main/res/values/strings.xml`:

```xml
    <!-- The pairing screen's pointer at enrollment.

         Worded conditionally ("If your account uses encrypted mail") rather than as a promise,
         because this line is NOT gated on hasPgpIdentity and never will be. Gating it would add an
         authenticated request to the pairing flow to answer a question the browser has usually
         already settled at first login — and hasPgpIdentity returns Boolean?, so a network failure
         would leave the app guessing anyway. Conditional wording also means it never goes stale: a
         user who creates their identity a week after pairing still finds the entry where this said
         it would be. -->
    <string name="push_pairing_encryption_hint">If your account uses encrypted mail, you can set this device up for it in Settings → Security.</string>
```

- [ ] **Step 2: Add the line to the pairing layout**

In `app/src/main/res/layout/activity_push_pairing.xml`, inside the first `CardView`'s `LinearLayout`, immediately after the closing `</com.google.android.material.chip.ChipGroup>` tag and before that `LinearLayout`'s closing tag, add:

```xml
            <TextView
                android:layout_width="match_parent"
                android:layout_height="wrap_content"
                android:text="@string/push_pairing_encryption_hint"
                android:textSize="13sp"
                android:layout_marginTop="16dp" />
```

There is deliberately **no** `android:id`: nothing reads or updates this view, and giving it one would invite a future change to make it conditional.

- [ ] **Step 3: Build**

Run: `./gradlew assembleDebug lint`
Expected: `BUILD SUCCESSFUL`, 0 lint errors.

- [ ] **Step 4: Confirm no network call was added to the pairing flow**

Run: `git diff --stat HEAD -- app/src/main/java/`
Expected: **no output**. This task must not touch Kotlin. If it did, the hint has been gated on something — which is exactly what decision 2 rules out.

- [ ] **Step 5: Commit**

```bash
git add app/src/main/res/layout/activity_push_pairing.xml app/src/main/res/values/strings.xml
git commit -m "feat(pairing): point at encrypted mail from the pairing screen

Static text, no network call. Gating it on hasPgpIdentity would add an authenticated
request to the pairing flow to answer a question the browser has usually already
settled — and that call returns Boolean?, so a failure leaves the app guessing.

Worded conditionally so it never goes stale: a user who creates their identity a week
after pairing still finds the entry where this said it would be.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 12: Instrumented tests, and the manual checklist

What the JVM cannot reach: the real Keystore, and the copy actually resolving on a device.

**Files:**
- Create: `app/src/androidTest/java/com/urlxl/mail/pgp/EnrollmentEnvelopeRoundTripTest.kt`
- Create: `app/src/androidTest/java/com/urlxl/mail/pgp/EnrollmentRowStringsTest.kt`

**Interfaces:**
- Consumes: `EnrollmentKeyStore`, `EnrollmentVault`, `deviceEnvelopeAad`, `hkdfSha256`, `openDeviceEnvelope`, `parseDeviceEnvelope`, `EnrollmentRow`.
- Produces: nothing.

- [ ] **Step 1: Write the Keystore round trip**

Create `app/src/androidTest/java/com/urlxl/mail/pgp/EnrollmentEnvelopeRoundTripTest.kt`:

```kotlin
package com.urlxl.mail.pgp

import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.security.KeyPairGenerator
import java.security.spec.ECGenParameterSpec
import java.security.interfaces.ECPublicKey
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * The one thing no JVM test can do: a real ECDH against a non-extractable P-256 key in this device's
 * Keystore, opened with the same envelope format the browser produces.
 *
 * The JVM suite proves the state machine routes every branch correctly; this proves the branch it
 * routes to actually works. Without it, an AAD or HKDF-salt mistake would surface to a user as the
 * substituted-key alarm — this feature's one alarm — on every honest enrollment.
 *
 * **Requires a secure lock screen** for the vault half. See the `locksettings set-pin` step in
 * `.github/workflows/ci.yml`; on a bare emulator `ensureKey()` returns false by design.
 *
 * **`sealCipher()` is deliberately not exercised here.** The vault key is
 * `setUserAuthenticationRequired(true)` with per-use auth, so `Cipher.init(ENCRYPT_MODE, ...)`
 * cannot succeed outside a satisfied `BiometricPrompt` — it returns null, and a test asserting that
 * would be asserting the absence of authentication rather than the presence of encryption. The spec
 * lists `sealCipher` under instrumented coverage; it is not reachable, and that is stated rather
 * than papered over with a test that passes for the wrong reason. `openCipher` IS reachable
 * (`Cipher.init` on GCM needs no authentication) and is already covered by `EnrollmentStateTest`
 * through `probeEnrollment`.
 */
@RunWith(AndroidJUnit4::class)
class EnrollmentEnvelopeRoundTripTest {

    private val vault = EnrollmentVault(ApplicationProvider.getApplicationContext())

    @Before fun clean() { EnrollmentKeyStore.deleteKeyPair(); vault.destroy() }
    @After fun cleanup() { EnrollmentKeyStore.deleteKeyPair(); vault.destroy() }

    /** Plays the browser's part: mint an ephemeral P-256 key, agree with the device's published
     *  point, derive with the device's point as the HKDF salt, and seal under the v2 AAD. */
    private fun sealAsBrowserWould(
        devicePoint: ByteArray,
        deviceId: String,
        fingerprint: String,
        plaintext: ByteArray,
    ): String {
        val ephemeral = KeyPairGenerator.getInstance("EC").apply {
            initialize(ECGenParameterSpec("secp256r1"))
        }.generateKeyPair()

        val devicePublic = java.security.KeyFactory.getInstance("EC").generatePublic(
            java.security.spec.ECPublicKeySpec(
                java.security.spec.ECPoint(
                    java.math.BigInteger(1, devicePoint.copyOfRange(1, 33)),
                    java.math.BigInteger(1, devicePoint.copyOfRange(33, 65)),
                ),
                (ephemeral.public as ECPublicKey).params,
            ),
        )
        val shared = KeyAgreement.getInstance("ECDH").run {
            init(ephemeral.private)
            doPhase(devicePublic, true)
            generateSecret()
        }
        // Salt is the DEVICE's point, not the ephemeral one. Getting this backwards is the
        // single easiest way to build a system where nothing ever opens.
        val key = hkdfSha256(
            ikm = shared,
            salt = devicePoint,
            info = "kypost-device-envelope/v2".toByteArray(Charsets.UTF_8),
            length = 32,
        )
        val iv = ByteArray(12).also { java.security.SecureRandom().nextBytes(it) }
        val ct = Cipher.getInstance("AES/GCM/NoPadding").run {
            init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, iv))
            updateAAD(deviceEnvelopeAad(deviceId, fingerprint))
            doFinal(plaintext)
        }
        val w = (ephemeral.public as ECPublicKey).w
        val epk = sec1UncompressedPoint(w.affineX, w.affineY)
        val b64 = java.util.Base64.getEncoder()
        return """{"v":"2","alg":"ECDH-P256+HKDF-SHA256+A256GCM","epk":"${b64.encodeToString(epk)}",""" +
            """"iv":"${b64.encodeToString(iv)}","ct":"${b64.encodeToString(ct)}"}"""
    }

    @Test
    fun aBrowserSealedEnvelopeOpensAgainstTheKeystoreKey() {
        assertTrue(EnrollmentKeyStore.newKeyPair())
        val devicePoint = requireNotNull(EnrollmentKeyStore.rawPublicKey())
        assertEquals(65, devicePoint.size)

        val plaintext = "-----BEGIN PGP PRIVATE KEY BLOCK-----".toByteArray(Charsets.UTF_8)
        val envelope = sealAsBrowserWould(devicePoint, "dev-1", "164D 5B83 4E7F E927", plaintext)

        val fields = requireNotNull(parseDeviceEnvelope(envelope))
        val shared = requireNotNull(EnrollmentKeyStore.sharedSecret(fields.epk))
        val opened = openDeviceEnvelope(
            sharedSecret = shared,
            ownRawPublicKey = devicePoint,
            fields = fields,
            // Space-grouped on the way in, exactly as PgpFingerprint.compute emits it. If
            // deviceEnvelopeAad stopped normalising, this would fail here rather than in the field.
            aad = deviceEnvelopeAad("dev-1", "164D 5B83 4E7F E927"),
        )

        assertArrayEquals(plaintext, opened)
    }

    /** The AAD binding, on real hardware: an envelope minted for another device does not open,
     *  even though the ECDH itself succeeds. */
    @Test
    fun anEnvelopeSealedForAnotherDeviceDoesNotOpen() {
        assertTrue(EnrollmentKeyStore.newKeyPair())
        val devicePoint = requireNotNull(EnrollmentKeyStore.rawPublicKey())
        val envelope = sealAsBrowserWould(devicePoint, "someone-else", "164D5B834E7FE927", ByteArray(64))

        val fields = requireNotNull(parseDeviceEnvelope(envelope))
        val shared = requireNotNull(EnrollmentKeyStore.sharedSecret(fields.epk))

        assertNull(
            openDeviceEnvelope(shared, devicePoint, fields, deviceEnvelopeAad("dev-1", "164D5B834E7FE927")),
        )
    }

    /** The agreement key's life is one ceremony. A second `newKeyPair()` must not reuse the first. */
    @Test
    fun aFreshCeremonyRotatesTheAgreementKey() {
        assertTrue(EnrollmentKeyStore.newKeyPair())
        val first = requireNotNull(EnrollmentKeyStore.rawPublicKey())

        assertTrue(EnrollmentKeyStore.newKeyPair())
        val second = requireNotNull(EnrollmentKeyStore.rawPublicKey())

        assertTrue("a ceremony must not inherit the previous key", !first.contentEquals(second))
    }

    /** The vault half, end to end, minus the BiometricPrompt: seal with an authenticated cipher is
     *  not reachable here, but ensureKey/store/stored/destroy are. */
    @Test
    fun theVaultStoresAndDestroysWhatTheCeremonyWouldWrite() {
        assertTrue("no secure lock screen on this device — see the CI locksettings step", vault.ensureKey())
        vault.store(ByteArray(12) { 7 }, ByteArray(48) { 9 })

        assertNotNull(vault.stored())
        assertEquals(EnrollmentStatus.ENROLLED, probeEnrollment(vault))

        assertTrue(EnrollmentTeardown.destroy(ApplicationProvider.getApplicationContext()).isEmpty())
        assertNull(vault.stored())
    }
}
```

- [ ] **Step 2: Write the copy test**

Create `app/src/androidTest/java/com/urlxl/mail/pgp/EnrollmentRowStringsTest.kt`:

```kotlin
package com.urlxl.mail.pgp

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.urlxl.mail.R
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Every state a user can be shown has real, distinct copy.
 *
 * Not an `ActivityScenario` walk: driving `SecuritySettingsActivity` through nine states needs
 * injection points that screen does not have, and this repository has no Activity-launching test to
 * build on. What *can* rot silently is a resource that was never added, a duplicate that makes two
 * different situations read identically, or a string that drifts into promising behaviour the app
 * does not have — and all three are caught here against a real Context.
 *
 * The mapping under test is the one the screens use; if a screen stops using it, that is visible in
 * review rather than here.
 */
@RunWith(AndroidJUnit4::class)
class EnrollmentRowStringsTest {

    private val context: Context = ApplicationProvider.getApplicationContext()

    private val rowCopy: Map<EnrollmentRow, Int> = mapOf(
        EnrollmentRow.HostileLocation to R.string.security_encryption_hostile_location,
        EnrollmentRow.NoSecureLockScreen to R.string.security_encryption_no_lock_screen,
        EnrollmentRow.KeyInvalidated to R.string.security_encryption_invalidated,
        EnrollmentRow.Enrolled to R.string.security_encryption_enrolled,
        EnrollmentRow.ServerHeldKey to R.string.security_encryption_server_held,
        EnrollmentRow.NoIdentity to R.string.security_encryption_no_identity,
        EnrollmentRow.CouldNotCheck to R.string.security_encryption_could_not_check,
        EnrollmentRow.NotEnrolled to R.string.security_encryption_not_enrolled,
    )

    @Test
    fun everyRowHasCopy() {
        for ((row, id) in rowCopy) {
            val text = context.getString(id)
            assertTrue("$row has no copy", text.isNotBlank())
        }
    }

    /** Two rows that read the same are two situations the user cannot tell apart. */
    @Test
    fun noTwoRowsReadTheSame() {
        val rendered = rowCopy.values.map { context.getString(it) }
        assertEquals("every row must be distinguishable", rendered.size, rendered.toSet().size)
    }

    /**
     * **The capability rule, enforced.** A user who completes this ceremony gets a device that HOLDS
     * a key it does not yet USE. Any string here claiming the user can read encrypted mail on this
     * device is false until the deferred decryption work lands.
     */
    @Test
    fun noStringClaimsThisDeviceCanReadEncryptedMail() {
        val all = rowCopy.values.map { context.getString(it) } + listOf(
            context.getString(R.string.enrollment_enrolled),
            context.getString(R.string.enrollment_enrolled_detail),
            context.getString(R.string.enrollment_code_intro),
        )
        val banned = listOf("can read", "can now read", "able to read", "decrypt")
        for (text in all) {
            for (phrase in banned) {
                assertFalse(
                    "copy describes behaviour, not capability: \"$text\"",
                    text.lowercase().contains(phrase),
                )
            }
        }
    }

    /** The one failure with its own copy must actually differ from the generic one, and must not
     *  accuse — a key rotation mid-ceremony produces exactly the same failure as a substitution. */
    @Test
    fun theCouldNotOpenCopyIsItsOwnAndDoesNotAccuse() {
        val specific = context.getString(R.string.enrollment_failed_could_not_open)
        val generic = context.getString(R.string.enrollment_failed_generic)

        assertTrue(specific != generic)
        for (word in listOf("attack", "attacker", "tamper", "malicious", "hacked")) {
            assertFalse("the copy must describe, not accuse: $specific", specific.lowercase().contains(word))
        }
    }
}
```

- [ ] **Step 3: Run the instrumented suite**

With a device or emulator attached **and a secure lock screen set** (`adb shell locksettings set-pin 1234`):

Run: `./gradlew connectedDebugAndroidTest`
Expected: `BUILD SUCCESSFUL`, 105 existing tests plus the new ones.

If `theVaultStoresAndDestroysWhatTheCeremonyWouldWrite` fails on `ensureKey()`, the device has no secure lock screen — that is the failure the assertion message names, and it is not a code defect.

- [ ] **Step 4: Work through the manual checklist**

These are not automatable and this plan does not pretend otherwise. Record the result of each in the commit message or the PR description.

- [ ] The `BiometricPrompt` actually appears at `AwaitingAuth`, and satisfying it reaches `Enrolled`.
- [ ] Dismissing the prompt returns to the code with "Check again" offered, and does **not** re-prompt on its own.
- [ ] **Rotating the phone while the code is displayed keeps the same code** and does not republish. (This is the single property the ViewModel exists for.)
- [ ] The screen does not time out while the code is displayed.
- [ ] Backgrounding the app during the ceremony and returning within the lock grace leaves the ceremony running; beyond it, the unlock screen appears and the ceremony is gone.
- [ ] A full end-to-end enrollment against a real browser: the code the phone shows and the code the browser expects match, in the same 4-3-4-3 grouping.

- [ ] **Step 5: Commit**

```bash
git add app/src/androidTest/java/com/urlxl/mail/pgp/EnrollmentEnvelopeRoundTripTest.kt \
        app/src/androidTest/java/com/urlxl/mail/pgp/EnrollmentRowStringsTest.kt
git commit -m "test(pgp): round-trip a browser-sealed envelope through the real Keystore

The JVM suite proves the state machine routes every branch; this proves the branch it
routes to works. An AAD or HKDF-salt mistake would otherwise reach users as the
substituted-key alarm on every honest enrollment.

The copy test enforces the rule the whole feature rests on: a device that completes
this ceremony HOLDS a key it does not yet USE, so no string may claim otherwise.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 13: Re-registration must send the device secret

The spec's "carried over and not yet placed" item — test 7 from the original 2b handoff. It belongs to the registration path rather than the ceremony, and the spec says it "must land somewhere rather than evaporating".

**This is a live bug, not just a missing test.** `NativeRegistrationClient.register` builds its request with `Request.Builder().url(...).post(...).build()` and attaches **no** device-auth headers. Per the 2c handoff: *"Rebinding an existing `deviceId` at `POST /api/notifications/native/register` returns **409** unless you send `X-Kypost-Device-Secret`."* So an ordinary FCM-token refresh on an already-paired device 409s today, and the enrollment feature makes that worse: the published enrollment key is carried forward across re-registration, which is only worth anything if re-registration succeeds.

Verify before writing anything:

Run: `grep -n "pairingAuthHeaders" app/src/main/java/com/urlxl/mail/push/NativeRegistration.kt`
Expected: **no output**. If this now matches, the bug was fixed elsewhere — read that change and reduce this task to the test alone.

**Files:**
- Modify: `app/src/main/java/com/urlxl/mail/push/NativeRegistration.kt`
- Create: `app/src/test/java/com/urlxl/mail/push/NativeRegistrationClientTest.kt`

**Interfaces:**
- Consumes: `Request.Builder.pairingAuthHeaders(deviceId, deviceSecret)` (existing, in `com.urlxl.mail`), `FakeCallFactory`, `response` (existing, in `com.urlxl.mail.testing`).
- Produces: no new symbols.

- [ ] **Step 1: Write the failing test**

Create `app/src/test/java/com/urlxl/mail/push/NativeRegistrationClientTest.kt`:

```kotlin
package com.urlxl.mail.push

import com.urlxl.mail.HEADER_DEVICE_ID
import com.urlxl.mail.HEADER_DEVICE_SECRET
import com.urlxl.mail.testing.FakeCallFactory
import com.urlxl.mail.testing.response
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Test 7, carried over from the original 2b handoff and finally placed.
 *
 * Rebinding an existing `deviceId` returns **409** unless the current device secret is sent, and the
 * reason the server requires it is not cosmetic: without it a stolen session could take over an
 * existing device row, keeping its `MFAApprover` status and redirecting that user's push. The
 * FCM-token-refresh flow re-registers, so this is the ordinary path, not an edge case.
 *
 * It also matters to enrollment specifically. The server carries `enrollmentPublicKey` and
 * `encryptionEnrolled` forward across re-registration on both branches — which is worth nothing if
 * re-registration itself 409s.
 */
class NativeRegistrationClientTest {

    private val paired = PairingData(
        subscriberId = "sub-1",
        serverUrl = "https://relay.example.com",
        registrationUrl = "https://relay.example.com/api/notifications/native/register",
        pairingToken = "tok",
        deviceId = "dev-1",
        deviceSecret = "secret-1",
        pairedAtEpochMs = 0L,
    )

    private val success =
        """{"ok":true,"synced":true,"deviceId":"dev-1","deviceSecret":"secret-2"}"""

    @Test
    fun aReRegistrationCarriesTheCurrentDeviceCredential() = runBlocking {
        val factory = FakeCallFactory { req -> response(req, success, 200) }

        NativeRegistrationClient(callFactory = factory).register(paired, token = "fcm-token")

        val sent = factory.requests.single()
        assertEquals("dev-1", sent.header(HEADER_DEVICE_ID))
        assertEquals("secret-1", sent.header(HEADER_DEVICE_SECRET))
    }

    /**
     * A first pairing has no secret yet — it is what this call mints. Sending an empty or absent
     * credential must not be confused with sending a wrong one.
     */
    @Test
    fun aFirstPairingSendsNoDeviceCredential() = runBlocking {
        val factory = FakeCallFactory { req -> response(req, success, 200) }
        val unpaired = paired.copy(deviceId = null, deviceSecret = null)

        NativeRegistrationClient(callFactory = factory).register(unpaired, token = "fcm-token")

        val sent = factory.requests.single()
        assertNull(sent.header(HEADER_DEVICE_ID))
        assertNull(sent.header(HEADER_DEVICE_SECRET))
    }

    /** A half-known pairing — an id with no readable secret, which the credential gate produces
     *  while the app is locked — must not send a device id on its own. The server reads that as a
     *  rebind attempt with no credential. */
    @Test
    fun anIdWithNoSecretSendsNeitherHeader() = runBlocking {
        val factory = FakeCallFactory { req -> response(req, success, 200) }
        val gated = paired.copy(deviceSecret = null)

        NativeRegistrationClient(callFactory = factory).register(gated, token = "fcm-token")

        val sent = factory.requests.single()
        assertNull(sent.header(HEADER_DEVICE_ID))
        assertNull(sent.header(HEADER_DEVICE_SECRET))
    }

    /** 409 is a distinct, actionable outcome — "this device row belongs to a credential you did not
     *  send" — and must not read as a generic transport failure. */
    @Test
    fun aRebindRejectionIsReportedAsItsOwnError() = runBlocking {
        val factory = FakeCallFactory { req -> response(req, "", 409) }

        val result = NativeRegistrationClient(callFactory = factory)
            .register(paired, token = "fcm-token")

        assertTrue(result is NativeRegistrationResult.Error)
        assertTrue(
            "the message must name the rebind: ${(result as NativeRegistrationResult.Error).message}",
            result.message.contains("already registered", ignoreCase = true),
        )
    }
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `./gradlew testDebugUnitTest --tests '*NativeRegistrationClientTest*'`
Expected: FAIL — the first test reports `null` for both headers, and the 409 test reports the generic `Failed to register device (409)`.

If `response(...)` does not accept these arguments, check its signature in `app/src/test/java/com/urlxl/mail/testing/FakeCalls.kt` and match it.

- [ ] **Step 3: Send the credential**

In `app/src/main/java/com/urlxl/mail/push/NativeRegistration.kt`, add the import:

```kotlin
import com.urlxl.mail.pairingAuthHeaders
```

Replace the `httpRequest` construction:

```kotlin
        val httpRequest = Request.Builder()
            .url(pairing.registrationUrl)
            .post(json.encodeToString(request).toRequestBody(JSON_MEDIA_TYPE))
            // Re-registration REBINDS an existing device row, and the server refuses that with 409
            // unless the current credential is presented: without the check, a stolen session could
            // take over a device row, keep its MFAApprover status and redirect that user's push.
            // The FCM-token-refresh flow re-registers, so this is the ordinary path.
            //
            // Both halves or neither. A first pairing has no secret yet — this call is what mints
            // one — and a device id sent alone reads to the server as a rebind attempt with no
            // credential, which is exactly the request it is designed to refuse. The credential gate
            // produces that shape whenever the app is locked.
            .apply {
                val deviceId = pairing.deviceId
                val deviceSecret = pairing.deviceSecret
                if (!deviceId.isNullOrBlank() && !deviceSecret.isNullOrBlank()) {
                    pairingAuthHeaders(deviceId, deviceSecret)
                }
            }
            .build()
```

And add a 409 branch to the status mapping, above `else`:

```kotlin
            // The device row exists and belongs to a credential this call did not present. Not a
            // transport failure and not a retry: re-pairing is the only thing that resolves it.
            409 -> NativeRegistrationResult.Error(
                "This device is already registered with a different credential — re-pair it",
            )
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `./gradlew testDebugUnitTest --tests '*NativeRegistrationClientTest*'`
Expected: PASS, 4 tests.

- [ ] **Step 5: Run the whole unit suite**

Run: `./gradlew testDebugUnitTest`
Expected: `BUILD SUCCESSFUL`. This change touches the pairing path, which is the app's most audited one — if anything else asserted the absence of these headers, it fails here.

- [ ] **Step 6: Commit**

```bash
git add app/src/main/java/com/urlxl/mail/push/NativeRegistration.kt \
        app/src/test/java/com/urlxl/mail/push/NativeRegistrationClientTest.kt
git commit -m "fix(pairing): send the device credential when re-registering

Rebinding an existing deviceId returns 409 unless the current device secret is sent,
and this client sent no device-auth headers at all — so an ordinary FCM token refresh
on a paired device failed. The server requires it because a stolen session could
otherwise take over a device row, keep its MFAApprover status and redirect push.

Both headers or neither: a first pairing has no secret yet, and a device id sent alone
is exactly the credential-less rebind the server refuses.

This is test 7 from the original 2b handoff, which had been carried between three
documents without a home.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 14: Close the loop

Verification of the whole feature, and the documents that would otherwise go stale.

**Files:**
- Modify: `docs/superpowers/specs/2026-08-06-device-enrollment-ceremony-design.md`
- Modify: `docs/superpowers/plans/2026-08-06-session-handoff-ceremony-spec-and-audit-run-6.md`

**Interfaces:**
- Consumes: everything.
- Produces: nothing.

- [ ] **Step 1: Full verification, from clean**

Run:
```bash
./gradlew clean
./gradlew testDebugUnitTest lint
```
Expected: `BUILD SUCCESSFUL`, 0 lint errors, and a unit count above the 558 baseline.

Record the actual number:
```bash
grep -ho 'tests="[0-9]*"' app/build/test-results/testDebugUnitTest/*.xml \
  | grep -o '[0-9]*' | paste -sd+ | bc
```

- [ ] **Step 2: Instrumented, on hardware or an emulator with a lock screen**

Run:
```bash
adb shell locksettings set-pin 1234
./gradlew connectedDebugAndroidTest
```
Expected: `BUILD SUCCESSFUL`, above the 105 baseline.

Four of those existing suites are the ones this feature must not have broken — the spec names them
as "interactions [that] already work and must not break". Confirm each ran and passed by name:

```bash
grep -ho 'classname="[^"]*"' app/build/outputs/androidTest-results/connected/**/*.xml \
  | sort -u | grep -E "HostileLocationEnrollmentTeardownTest|UnpairEnrollmentTeardownTest|SecurityWipeTest|EnrollmentStateWorkerTest"
```
Expected: all four. Hostile Location Protection, `SecurityWipe` and unpair each tear the enrollment
down (`0da30b8`, `2bcf38e`); a green overall run that silently skipped one of these is not the
evidence it looks like.

- [ ] **Step 3: Confirm CI agrees**

Push and run: `gh run watch`
Expected: `ci-unit` and `ci-instrumented` both green. **Do not skip this in favour of the local run** — the whole point of Task 1 is that the local run and CI can disagree, and the first time they do must not be after a merge.

- [ ] **Step 4: Update the spec's "Server-side change required" section**

In `docs/superpowers/specs/2026-08-06-device-enrollment-ceremony-design.md`, mark the section as done rather than deleting it — it records why the change was made:

Replace the section heading `## Server-side change required` with:

```markdown
## Server-side change required — done

Landed alongside this feature. `formatEnrollmentCode` in
`kypost-server/frontend/src/lib/deviceEnrollment.ts` now groups 4-3-4-3, matching
`EnrollmentCodeFormat.kt` in this repository, and its test's "never drops characters" case strips
every separator rather than only the first.
```

Keep the paragraphs beneath it unchanged.

- [ ] **Step 5: Record what is still owed**

Append to `docs/superpowers/plans/2026-08-06-session-handoff-ceremony-spec-and-audit-run-6.md`:

```markdown
## Update — the ceremony plan is implemented

`docs/superpowers/plans/2026-08-06-device-enrollment-ceremony.md` executed. CI landed first and both
jobs are green.

**Still owed, and unchanged by this work:**

- **On-device decryption is still deferred.** A user who completes the ceremony gets a device that
  HOLDS a key it does not yet USE, and every string on these screens says so. The gate remains the
  measurement in `docs/superpowers/specs/2026-07-29-on-device-pgp-decryption-design.md` — whether
  context-switch friction survived the Custom Tabs change at `e42ad96`. Nobody has taken it.
  `EnrollmentSession` still has no writer, deliberately.
- **The browser-minted 128-bit challenge (spec 1's decision 8) is still not built.** It needs a
  browser-to-device channel this protocol does not have, so it is a new transport leg and its own
  piece of work. 70 bits makes it *not urgent*, not unnecessary.
- **The `BiometricPrompt` interaction itself is not automated,** and this plan did not claim
  otherwise. `VaultSealer` is an interface so everything around it is a JVM test; the prompt
  appearing and being satisfied is Task 12's manual checklist.
- **Deviations from the spec are listed at the top of the plan,** with reasons. Two are worth
  carrying forward: the spec named four injected ports where five are needed (the keystore has no
  fake otherwise, and "`deleteKeyPair()` on every exit" is the property most needing one), and its
  row table has no entry for "could not check" even though its own decision 10 requires one.
```

- [ ] **Step 6: Commit and open the PR**

```bash
git add docs/superpowers/specs/2026-08-06-device-enrollment-ceremony-design.md \
        docs/superpowers/plans/2026-08-06-session-handoff-ceremony-spec-and-audit-run-6.md
git commit -m "docs: record the ceremony as implemented, and what is still owed

The headline item stays owed: on-device decryption is deferred, so a device that
completes this ceremony holds a key it does not yet use. Every string on these
screens is written to that constraint, and a test enforces it.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

Then open the PR with `gh pr create`, and put the Task 12 manual checklist results in the body — including whether the end-to-end enrollment against a real browser was actually performed. If it was not, say so; do not leave it implied.

---

## What this plan does not do

Stated here so a reader does not have to infer it from absence.

- **Reading mail with the enrolled key.** Out of scope in the spec and out of scope here. The whole copy discipline exists because of it.
- **The browser-minted challenge** that would replace the 70-bit widening. A new transport leg.
- **Qt clients (2d).**
- **Automating the `BiometricPrompt` interaction.** Task 12 has a manual checklist instead.
- **Dependabot for the pinned action SHAs.** The server repo has one; this repo does not, and adding it is a separate change with its own review. The SHAs in Task 1 are pinned and will go stale — that is a known, deliberate cost of pinning, and updating them is a normal maintenance PR.

