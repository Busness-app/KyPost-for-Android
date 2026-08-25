# D1 — Android Product Flavors for Three Channels: Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give the Play, GitHub and F-Droid builds distinct `applicationId` values so all three install side by side and each updates from its own channel under its own signing key.

**Architecture:** One Gradle flavor dimension (`channel`) with three flavors. `play` keeps today's `applicationId` byte-for-byte so the in-flight closed test is unaffected; `github` and `fdroid` are `applicationIdSuffix` variants. `namespace` stays `org.kysecurity.mail` for all three, so Kotlin packages, `BuildConfig`, manifest class names and the exported-component allowlist are untouched. One hardcoded identifier — the contacts `accountType` — has to become applicationId-derived first, or side-by-side install breaks; that is Task 1 and is a no-op for the current build. Nothing about push transport, Firebase runtime behaviour or the `kypost://` intent filter changes here.

**Tech Stack:** Android Gradle Plugin 9.x, Gradle 9.6, Kotlin, GitHub Actions.

**Spec:** `../../../../kypost-server/docs/superpowers/handoffs/2026-08-25-android-flavors-d1.md` (written from the server repo; several of its open questions are resolved below under Established Facts).

---

## Global Constraints

- `play` flavor `applicationId` **must** remain exactly `org.kysecurity.mail`. The closed test breaks otherwise.
- `namespace` stays `org.kysecurity.mail` on every flavor. Do not make it flavor-dependent.
- `versionCode = 10`, `versionName = "0.3.3"` stay in `defaultConfig`, shared by all flavors. `release.yml` asserts the git tag equals `versionName`; do not add `versionNameSuffix`.
- Declare `play` **first** in the `productFlavors` block. AGP picks the first flavor for the default variant, and `./gradlew lint` analyses the default variant only.
- `gradle/verification-metadata.xml` has `verify-metadata=true`. **Never** pass `--write-verification-metadata` to any Gradle invocation, in CI or locally. No task in this plan adds a dependency, so this file must not change.
- `app/google-services.json` is gitignored and must never be committed (`ci.yml` enforces this).
- Every non-trivial change carries one runnable check — repo rule, `AGENTS.md`.
- Minimum diff. Reuse what exists. Mark deliberate ceilings with `ponytail:` comments naming the upgrade path — repo rule, `AGENTS.md`.

---

## Established Facts (verified in code — read before starting)

These resolve the handoff's open questions. Do not re-litigate them.

1. **`deviceId` is server-minted, not client-derived.** It arrives in the registration response (`app/src/main/java/org/kysecurity/mail/push/NativeRegistration.kt:43`) and is persisted verbatim (`push/PushSyncCoordinator.kt:90`). Nothing derives it from the package name or `BuildConfig`. Changing `applicationId` per flavor **cannot** affect enrollment codes, the `device:<deviceId>` envelope slot, or the `4-3-4-3` code the browser shows.
2. **`applicationId` and `namespace` are both `org.kysecurity.mail` today** (`app/build.gradle.kts:71,78`). Only `applicationId` becomes flavor-dependent.
3. **Both content-provider authorities already interpolate `${applicationId}`** (`AndroidManifest.xml:36,165`), so they diverge per flavor automatically. No change needed.
4. **The contacts `accountType` does NOT.** It is the hardcoded literal `org.kysecurity.mail.contacts` in two places (`res/xml/contact_authenticator.xml:3` and `contacts/device/DeviceContactAccount.kt:13`). Android keys account types globally across the device and binds the authenticator to a signing key. Three flavors declaring the same type under three different keys collide — one authenticator wins and the others' contact sync silently fails. **This is the one real blocker to side-by-side install, and Task 1 fixes it.**
5. **`google-services.json` currently declares only `org.kysecurity.mail`** (plus an unrelated `org.kysecurity.authenticator`). The `com.google.gms.google-services` plugin fails any variant whose `applicationId` is not listed, so `github` and `fdroid` will not build until the file gains clients for them. **Decision taken: register all three now.**
6. **`SourceRulesTest` scans `src/main/java` only** (`app/src/test/java/org/kysecurity/mail/SourceRulesTest.kt:179`). This plan adds only `res/` to the new flavor source sets, so coverage is unaffected. If a later task adds flavor-specific Kotlin, that test stops covering it.

### Out of scope, recorded for D2/D3/D4

- **F-Droid transport — decision taken: UnifiedPush, with WebPush encryption implemented server-side.** The client half is already complete: it registers RFC 8291 `p256dh`/`auth` keys (`push/KyPostUnifiedPushService.kt:34-38`) and **drops any message that is not encrypted** (`KyPostUnifiedPushService.kt:70-74`). The server sends bare JSON and ignores those keys (`kypost-server/backend/internal/processor/native_sender.go:319-345`), so UnifiedPush delivers nothing end-to-end today. The pull alternative was rejected: `deliveryMode` is a single server-wide meta value (`state/store.go:702-712`) and `SendNativePushToDevices` diverts **all** of an account's devices into the pull queue (`processor/push_dispatch.go:269-274`), so it cannot be a per-device property without a server change of its own.
- **`attemptPairing` hard-requires an FCM token** (`push/PushSyncCoordinator.kt:52-53`) and returns an error when it is null. A Firebase-free `fdroid` build cannot pair at all. D3 is therefore more than flavor-scoped dependencies.
- **`allowedExportedComponents` (`app/build.gradle.kts`) has a "vanished" check** that fails when a listed component is no longer exported. When D3 drops Firebase from `fdroid`, `com.google.firebase.iid.FirebaseInstanceIdReceiver` disappears from that variant's merged manifest and the check fires. It will need to become variant-aware then. In D1 all three flavors still carry Firebase, so no change is needed.

---

## File Structure

| File | Responsibility | Task |
| --- | --- | --- |
| `app/src/main/java/org/kysecurity/mail/contacts/device/DeviceContactAccount.kt` | Derive `ACCOUNT_TYPE` from `BuildConfig.APPLICATION_ID` instead of a literal | 1 |
| `app/src/main/res/xml/contact_authenticator.xml` | Reference `@string/contact_account_type` instead of a literal | 1 |
| `app/build.gradle.kts` | `resValue` for `contact_account_type`; the `channel` flavor dimension and its three flavors | 1, 2 |
| `app/src/test/java/org/kysecurity/mail/contacts/device/DeviceContactAccountTest.kt` | Pins the Kotlin-side derivation rule | 1 |
| `app/src/androidTest/java/org/kysecurity/mail/contacts/device/AccountTypeMatchesManifestTest.kt` | Pins that the resource and `BuildConfig` agree on-device | 1 |
| `app/src/github/res/values/strings.xml` | `app_name` override so the three installs are distinguishable | 2 |
| `app/src/fdroid/res/values/strings.xml` | Same, for F-Droid | 2 |
| `.github/actions/placeholder-google-services/action.yml` | Placeholder must list all three package names or CI cannot build them | 2 |
| `.github/workflows/ci.yml` | Flavor-aware Gradle task names | 3 |
| `.github/workflows/release.yml` | Per-channel artifact paths, build tasks, and google-services assertions | 4 |
| `README.md` | Document the three channels and the one-time sideload break | 5 |

---

## Human Prerequisite (do this before Task 2)

Task 2 cannot be verified locally without a `google-services.json` carrying all three package names. CI uses a placeholder, but a local `assembleGithubDebug` will fail without the real file.

In the Firebase console, in the **same project** that currently holds `org.kysecurity.mail`:

1. **Add app → Android** → package name `org.kysecurity.mail.github` → Register.
2. **Add app → Android** → package name `org.kysecurity.mail.fdroid` → Register.
3. Do **not** add SHA-1/SHA-256 fingerprints. Nothing in this app uses a Firebase feature that needs them (no Auth, no Dynamic Links); adding the upload-key fingerprint here would be noise.
4. Download the project-level `google-services.json` (it now contains all three clients) and save it to `app/google-services.json`.
5. Confirm it is not staged: `git status --porcelain app/google-services.json` must print nothing (the file is gitignored).
6. Store the same file contents in the `GOOGLE_SERVICES_JSON` secret on the **`release`** GitHub environment, replacing the current value. Task 4 adds assertions that will fail the release if you skip this.

Verify locally:

```bash
grep -c 'org.kysecurity.mail.github' app/google-services.json   # expect 1
grep -c 'org.kysecurity.mail.fdroid' app/google-services.json   # expect 1
```

---

### Task 1: Derive the contacts `accountType` from `applicationId`

Fixes the one hardcoded identifier that would collide across side-by-side installs. **This task changes no observable value:** `applicationId` is still `org.kysecurity.mail`, so the derived type is still `org.kysecurity.mail.contacts` and no existing install's device account is orphaned. It lands before the flavors so any regression is attributable.

**Files:**
- Modify: `app/build.gradle.kts` (inside `defaultConfig`, next to the existing `buildConfigField`)
- Modify: `app/src/main/java/org/kysecurity/mail/contacts/device/DeviceContactAccount.kt:13`
- Modify: `app/src/main/res/xml/contact_authenticator.xml:3`
- Test: `app/src/test/java/org/kysecurity/mail/contacts/device/DeviceContactAccountTest.kt` (create)
- Test: `app/src/androidTest/java/org/kysecurity/mail/contacts/device/AccountTypeMatchesManifestTest.kt` (create)

**Interfaces:**
- Consumes: nothing.
- Produces: `DeviceContactAccount.ACCOUNT_TYPE: String` changes from `const val` to `val` (still `String`, still the same value). It has ~20 readers across `DeviceContactRepository.kt`, `DeviceGroupLinker.kt`, `DeviceContactPurge.kt` and `DeviceContactAccount.kt` itself — verified, **every one of them consumes it as a plain runtime `String`** (selection args, `ContentValues`, URI query params, equality checks). None uses it in a `when` branch, an annotation argument, or another position that requires a compile-time constant, so dropping `const` compiles. Re-verify with `grep -rn 'ACCOUNT_TYPE' app/src --include='*.kt'` before editing; if that grep shows a new use in an annotation or `when` subject, stop and re-plan. Produces string resource `R.string.contact_account_type`.

- [ ] **Step 1: Read the two files you are about to change**

```bash
cat app/src/main/java/org/kysecurity/mail/contacts/device/DeviceContactAccount.kt
cat app/src/main/res/xml/contact_authenticator.xml
```

Confirm `ACCOUNT_TYPE` is `"org.kysecurity.mail.contacts"` and that the XML `android:accountType` is the same literal. If either differs, stop and re-plan.

- [ ] **Step 2: Write the failing unit test**

Create `app/src/test/java/org/kysecurity/mail/contacts/device/DeviceContactAccountTest.kt`:

```kotlin
package org.kysecurity.mail.contacts.device

import org.kysecurity.mail.BuildConfig
import kotlin.test.Test
import kotlin.test.assertEquals

/** The account type is global to the device and signature-bound: two installs claiming the same
 *  one collide, and only the first authenticator wins. Deriving it from the applicationId is what
 *  lets the play, github and fdroid builds coexist — this pins the derivation so a later edit
 *  cannot quietly return to a literal. */
class DeviceContactAccountTest {
    @Test
    fun accountTypeIsDerivedFromTheApplicationId() {
        assertEquals("${BuildConfig.APPLICATION_ID}.contacts", DeviceContactAccount.ACCOUNT_TYPE)
    }

    @Test
    fun theDefaultFlavorKeepsTodaysAccountType() {
        // Only true for the play flavor, which must not migrate existing installs' device account.
        if (BuildConfig.APPLICATION_ID == "org.kysecurity.mail") {
            assertEquals("org.kysecurity.mail.contacts", DeviceContactAccount.ACCOUNT_TYPE)
        }
    }
}
```

- [ ] **Step 3: Run it and confirm it passes for the wrong reason**

```bash
./gradlew :app:testDebugUnitTest --tests '*DeviceContactAccountTest*'
```

Expected: **PASS**. The literal already equals the derived value, so this test is green before the change. That is intentional — it is a *regression pin*, and its job is to stay green through Step 5 and then fail if anyone reintroduces a literal. Do not "fix" it to fail first.

- [ ] **Step 4: Add the string resource to `defaultConfig`**

In `app/build.gradle.kts`, inside `android { defaultConfig { … } }`, immediately after the existing `buildConfigField("boolean", "ALLOW_SCREENSHOTS", "false")` line, add:

```kotlin
        // res/xml cannot read ${applicationId} the way the manifest can, so the account type is
        // injected as a string resource instead. It MUST track applicationId: AccountManager keys
        // account types globally across the device and binds each to a signing key, so two flavors
        // claiming one type means only the first-installed one has a working authenticator.
        // DeviceContactAccount derives the same value from BuildConfig; DeviceContactAccountTest
        // and AccountTypeMatchesManifestTest pin the two halves together.
        resValue("string", "contact_account_type", "org.kysecurity.mail.contacts")
```

- [ ] **Step 5: Point the XML and the Kotlin at the derived value**

In `app/src/main/res/xml/contact_authenticator.xml`, replace the `android:accountType` line:

```xml
    android:accountType="@string/contact_account_type"
```

In `app/src/main/java/org/kysecurity/mail/contacts/device/DeviceContactAccount.kt`, replace line 13:

```kotlin
    val ACCOUNT_TYPE = "${org.kysecurity.mail.BuildConfig.APPLICATION_ID}.contacts"
```

(`const` must go — `BuildConfig.APPLICATION_ID` is a `String` field, not a compile-time constant expression usable in `const val`.)

- [ ] **Step 6: Write the on-device test that closes the loop**

The unit test proves the Kotlin side. Only a device test can prove the *resource* the authenticator actually registers with agrees. Create `app/src/androidTest/java/org/kysecurity/mail/contacts/device/AccountTypeMatchesManifestTest.kt`:

```kotlin
package org.kysecurity.mail.contacts.device

import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import android.content.Context
import org.junit.Test
import org.junit.runner.RunWith
import org.kysecurity.mail.BuildConfig
import org.kysecurity.mail.R
import kotlin.test.assertEquals

/** contact_authenticator.xml is what the platform registers; DeviceContactAccount is what the app
 *  asks AccountManager for. If they disagree the account silently never resolves, and nothing at
 *  compile time notices. */
@RunWith(AndroidJUnit4::class)
class AccountTypeMatchesManifestTest {
    @Test
    fun theRegisteredAccountTypeIsTheOneTheAppAsksFor() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        assertEquals(
            "${BuildConfig.APPLICATION_ID}.contacts",
            context.getString(R.string.contact_account_type),
        )
        assertEquals(context.getString(R.string.contact_account_type), DeviceContactAccount.ACCOUNT_TYPE)
    }
}
```

- [ ] **Step 7: Run the unit tests and lint**

```bash
./gradlew :app:testDebugUnitTest :app:lint
```

Expected: PASS. `DeviceContactAccountTest` green. If lint reports a new `HardcodedText` or unused-resource finding, read it — `contact_account_type` is referenced only from XML, and lint sometimes misses `res/xml` references; if it flags `UnusedResources`, that check is not in the `fatal` list so it will not abort, but confirm the reference is real by grepping.

```bash
grep -rn 'contact_account_type' app/src/main/res/
```

- [ ] **Step 8: Run the instrumented test on a device or emulator**

```bash
./gradlew :app:connectedDebugAndroidTest --tests '*AccountTypeMatchesManifestTest*'
```

Expected: PASS. If no device is attached, this step is not optional — start an emulator (`emulator -avd <name> &` then `adb wait-for-device`). The whole point of Task 1 is a property only the device can confirm.

- [ ] **Step 9: Confirm the built manifest still declares the original type**

```bash
./gradlew :app:processDebugMainManifest
grep -rn 'contact_account_type\|org.kysecurity.mail.contacts' app/build/intermediates/merged_res/debug/ 2>/dev/null | head
```

Expected: the generated `contact_account_type` value is `org.kysecurity.mail.contacts` — unchanged from before this task. Any other value means an existing install's device account would be orphaned; stop and fix.

- [ ] **Step 10: Commit**

```bash
git add app/build.gradle.kts \
        app/src/main/java/org/kysecurity/mail/contacts/device/DeviceContactAccount.kt \
        app/src/main/res/xml/contact_authenticator.xml \
        app/src/test/java/org/kysecurity/mail/contacts/device/DeviceContactAccountTest.kt \
        app/src/androidTest/java/org/kysecurity/mail/contacts/device/AccountTypeMatchesManifestTest.kt
git commit -m "contacts: derive the account type from applicationId

AccountManager keys account types globally across the device and binds each
to a signing key, so the play, github and fdroid builds cannot all declare
org.kysecurity.mail.contacts — only the first-installed authenticator would
work. Value is unchanged for the current build, so no install migrates."
```

---

### Task 2: Add the `channel` flavor dimension

**Files:**
- Modify: `app/build.gradle.kts` (add a `flavorDimensions`/`productFlavors` block inside `android { }`, after `defaultConfig` and before `signingConfigs`)
- Create: `app/src/github/res/values/strings.xml`
- Create: `app/src/fdroid/res/values/strings.xml`
- Modify: `.github/actions/placeholder-google-services/action.yml`

**Interfaces:**
- Consumes: `resValue("string", "contact_account_type", …)` from Task 1 — each flavor overrides it.
- Produces: variant names `playDebug`, `playRelease`, `githubDebug`, `githubRelease`, `fdroidDebug`, `fdroidRelease`. Tasks 3 and 4 use these names. Produces flavor names `play`, `github`, `fdroid` for output paths.

**Prerequisite:** the Human Prerequisite section above must be done, or `assembleGithubDebug` fails at `processGithubDebugGoogleServices`.

- [ ] **Step 1: Add the flavor block**

In `app/build.gradle.kts`, inside `android { }`, after the closing brace of `defaultConfig { }` and before `signingConfigs { }`:

```kotlin
    // Android identifies an app by applicationId AND signature, and the three channels sign with
    // three different keys: Play re-signs under Play App Signing, the GitHub APK carries the upload
    // key, F-Droid signs with its own. One applicationId across all three means a user who
    // installed from one cannot update from another without uninstalling, which destroys local
    // data. Distinct ids dissolve that: each is a separate app, and they install side by side.
    flavorDimensions += "channel"
    productFlavors {
        // FIRST on purpose: AGP builds the default variant from the first flavor, and `./gradlew
        // lint` analyses only the default variant. play must be the one that gets analysed.
        create("play") {
            dimension = "channel"
            // No suffix. This id is in the closed test; changing it breaks every tester's update.
            resValue("string", "contact_account_type", "org.kysecurity.mail.contacts")
        }
        create("github") {
            dimension = "channel"
            applicationIdSuffix = ".github"
            resValue("string", "contact_account_type", "org.kysecurity.mail.github.contacts")
        }
        create("fdroid") {
            dimension = "channel"
            applicationIdSuffix = ".fdroid"
            resValue("string", "contact_account_type", "org.kysecurity.mail.fdroid.contacts")
        }
    }
```

Leave the `resValue` line added in Task 1 in `defaultConfig`. It is the fallback each flavor overrides, and deleting it would make a future fourth flavor fail to compile the resource rather than fail obviously here.

No `versionNameSuffix`: `release.yml` asserts the git tag equals `versionName`, and a suffix would break that gate.

- [ ] **Step 2: Give the two new flavors distinguishable labels**

Three identically named launcher icons make the side-by-side acceptance test unverifiable by eye. `play` inherits `app_name` from `src/main`, so only the other two need a file.

Create `app/src/github/res/values/strings.xml`:

```xml
<?xml version="1.0" encoding="utf-8"?>
<resources>
    <!-- Overrides src/main. The play flavor deliberately has no override and keeps "KyPost". -->
    <string name="app_name">KyPost (GitHub)</string>
</resources>
```

Create `app/src/fdroid/res/values/strings.xml`:

```xml
<?xml version="1.0" encoding="utf-8"?>
<resources>
    <!-- Overrides src/main. The play flavor deliberately has no override and keeps "KyPost". -->
    <string name="app_name">KyPost (F-Droid)</string>
</resources>
```

- [ ] **Step 3: Teach the CI placeholder about all three package names**

Without this, every CI job that builds `github` or `fdroid` dies at `processGithubDebugGoogleServices` with "No matching client found for package name".

In `.github/actions/placeholder-google-services/action.yml`, replace the single-entry `"client"` array with three entries. The full replacement `client` array:

```yaml
          "client": [
            {
              "client_info": {
                "mobilesdk_app_id": "1:000000000000:android:0000000000000000",
                "android_client_info": { "package_name": "org.kysecurity.mail" }
              },
              "oauth_client": [],
              "api_key": [ { "current_key": "AIzaSyAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" } ],
              "services": { "appinvite_service": { "other_platform_oauth_client": [] } }
            },
            {
              "client_info": {
                "mobilesdk_app_id": "1:000000000000:android:0000000000000001",
                "android_client_info": { "package_name": "org.kysecurity.mail.github" }
              },
              "oauth_client": [],
              "api_key": [ { "current_key": "AIzaSyAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" } ],
              "services": { "appinvite_service": { "other_platform_oauth_client": [] } }
            },
            {
              "client_info": {
                "mobilesdk_app_id": "1:000000000000:android:0000000000000002",
                "android_client_info": { "package_name": "org.kysecurity.mail.fdroid" }
              },
              "oauth_client": [],
              "api_key": [ { "current_key": "AIzaSyAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" } ],
              "services": { "appinvite_service": { "other_platform_oauth_client": [] } }
            }
          ],
```

Keep the surrounding `project_info` / `configuration_version` and the `if [ ! -f app/google-services.json ]` guard exactly as they are. The `mobilesdk_app_id` values must be distinct — the plugin rejects duplicates.

Also update the action's `description` and the heredoc's leading comment if either claims a single package. Check:

```bash
grep -n 'package name\|package_name' .github/actions/placeholder-google-services/action.yml
```

- [ ] **Step 4: Build all three debug variants**

```bash
./gradlew :app:assemblePlayDebug :app:assembleGithubDebug :app:assembleFdroidDebug
```

Expected: BUILD SUCCESSFUL. Each `assemble` transitively runs `checkExportedComponents<Variant>` and `checkRuntimeMatchedClassNames<Variant>`, so a green run also means the exported-component allowlist still holds for every flavor.

If `processGithubDebugGoogleServices` fails with "No matching client found", your local `app/google-services.json` is missing the new clients — go back to the Human Prerequisite.

- [ ] **Step 5: Assert the three applicationIds are what we intended**

Do not eyeball this. Run it:

```bash
for f in play github fdroid; do
  printf '%s: ' "$f"
  jq -r '.elements[0].applicationId' "app/build/outputs/apk/$f/debug/output-metadata.json"
done
```

Expected, exactly:

```
play: org.kysecurity.mail
github: org.kysecurity.mail.github
fdroid: org.kysecurity.mail.fdroid
```

Any other value for `play` is a stop-the-line failure — it breaks the closed test.

- [ ] **Step 6: Assert the account types diverged**

Read it out of the generated resource, which is what actually ships. Step 4 already built all three, so no rebuild is needed:

```bash
grep -rh 'contact_account_type' app/build/generated/res/resValues/*/debug/values/gradleResValues.xml
```

Expected: three lines, one per flavor, with values `org.kysecurity.mail.contacts`, `org.kysecurity.mail.github.contacts`, `org.kysecurity.mail.fdroid.contacts`.

If that path does not exist on your AGP version, find it rather than guessing:

```bash
find app/build -name 'gradleResValues.xml' -exec grep -l contact_account_type {} +
```

The authoritative alternative is Step 8, which asserts the same property from inside each installed app via the Task 1 instrumented test.

- [ ] **Step 7: Run the unit tests on the play variant**

The task name changed — `testDebugUnitTest` no longer exists.

```bash
./gradlew :app:testPlayDebugUnitTest
```

Expected: PASS, including `DeviceContactAccountTest`.

- [ ] **Step 8: Install all three on one device and confirm they coexist**

```bash
adb install -r app/build/outputs/apk/play/debug/app-play-debug.apk
adb install -r app/build/outputs/apk/github/debug/app-github-debug.apk
adb install -r app/build/outputs/apk/fdroid/debug/app-fdroid-debug.apk
adb shell pm list packages | grep org.kysecurity.mail
```

Expected: three lines — `org.kysecurity.mail`, `org.kysecurity.mail.github`, `org.kysecurity.mail.fdroid`. All three launchers visible, labelled `KyPost`, `KyPost (GitHub)`, `KyPost (F-Droid)`.

Then confirm each registered its own authenticator:

```bash
adb shell dumpsys account | grep -i 'org.kysecurity.mail.*contacts'
```

Expected: three distinct account types. **One** type here means Task 1 did not take effect and side-by-side contact sync is broken — stop.

- [ ] **Step 9: Verify dependency verification metadata did not move**

```bash
git diff --exit-code -- gradle/verification-metadata.xml
```

Expected: no output, exit 0. This task adds no dependencies; a dirty file means something regenerated it and the supply-chain control is compromised.

- [ ] **Step 10: Commit**

```bash
git add app/build.gradle.kts \
        app/src/github/res/values/strings.xml \
        app/src/fdroid/res/values/strings.xml \
        .github/actions/placeholder-google-services/action.yml
git commit -m "build: three product flavors for the three distribution channels

play keeps org.kysecurity.mail so the closed test is unaffected; github and
fdroid take .github and .fdroid suffixes so each channel's signing identity
gets its own package and all three install side by side."
```

---

### Task 3: Make CI flavor-aware

Every Gradle task name in `ci.yml` that names a variant is now wrong, and the failure mode is a hard "task not found" — loud, but it blocks every PR until fixed. This task must land with Task 2 or immediately after.

**Files:**
- Modify: `.github/workflows/ci.yml:70` (the `unit` job's Gradle line)
- Modify: `.github/workflows/ci.yml:387` (the instrumented job's `connectedDebugAndroidTest`)

**Interfaces:**
- Consumes: variant names from Task 2.
- Produces: nothing consumed downstream.

- [ ] **Step 1: Find every variant-named task in the workflow**

```bash
grep -n 'Debug\|Release\|assemble\|bundle\|connected\|testDebug' .github/workflows/ci.yml
```

Work from this list, not from memory. Expected hits include line 70 and line 387; note anything else the grep turns up and handle it in the same edit.

- [ ] **Step 2: Update the unit job's task line**

`.github/workflows/ci.yml:70`, replace:

```yaml
        run: ./gradlew checkSigningSecretsAreNotInTheTree checkExportedComponentsDebug testDebugUnitTest lint
```

with:

```yaml
        run: ./gradlew checkSigningSecretsAreNotInTheTree checkExportedComponentsPlayDebug testPlayDebugUnitTest lint
```

`lint` needs no suffix: it analyses the default variant, which is `playDebug` because `play` is declared first. The other two flavors' exported-component gates run in the `ci-release` job — see Step 3.

- [ ] **Step 3: Confirm the release job now covers all three flavors, and decide whether that is acceptable**

`.github/workflows/ci.yml:153` reads:

```yaml
        run: ./gradlew checkSigningSecretsAreNotInTheTree :app:assembleRelease
```

**Leave this line unchanged.** With flavors, `assembleRelease` expands to `assemblePlayRelease`, `assembleGithubRelease` and `assembleFdroidRelease` — so it now proves all three build, all three pass their exported-component and R8-name gates, and all three resolve against the placeholder `google-services.json`. That is exactly the coverage this plan needs, for a one-word diff of zero.

The cost is real: three R8 passes per PR instead of one. Measure it on the first run:

```bash
gh run list --workflow=ci.yml --limit 5
```

If `ci-release` wall-clock roughly triples and that becomes painful, the lean alternative is to narrow to `:app:assemblePlayRelease :app:assembleGithubDebug :app:assembleFdroidDebug` — full R8 coverage on the shipped-to-Play variant, cheap build-only coverage on the others. Do **not** make that change pre-emptively; the flavors are byte-identical apart from `applicationId` today, but they will not be after D3, and dropping coverage before it is needed is how a broken fdroid release ships. If you do narrow it, add a `ponytail:` comment naming the condition under which it must widen again.

- [ ] **Step 4: Update the instrumented job**

`.github/workflows/ci.yml:387`, replace `connectedDebugAndroidTest` with `connectedPlayDebugAndroidTest`. Read the surrounding lines first — the task is embedded in a shell line with `|| echo failed > /tmp/testfail.txt`, and the rest of that construct must survive:

```bash
sed -n '380,395p' .github/workflows/ci.yml
```

- [ ] **Step 5: Validate the workflow parses**

```bash
python3 -c "import yaml,sys; yaml.safe_load(open('.github/workflows/ci.yml')); print('ok')"
```

Expected: `ok`.

- [ ] **Step 6: Prove the new task names actually exist**

A typo here is invisible until CI runs. Check them against the real task list:

```bash
./gradlew :app:tasks --all | grep -E 'checkExportedComponentsPlayDebug|testPlayDebugUnitTest|connectedPlayDebugAndroidTest'
```

Expected: all three names present. Then dry-run them:

```bash
./gradlew --dry-run checkSigningSecretsAreNotInTheTree checkExportedComponentsPlayDebug testPlayDebugUnitTest lint
```

Expected: BUILD SUCCESSFUL, with the task graph printed and no "task not found".

- [ ] **Step 7: Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "ci: flavor-aware Gradle task names

Flavors rename every variant task; checkExportedComponentsDebug and
testDebugUnitTest no longer exist. assembleRelease is left alone on
purpose -- it now expands to all three flavors, which is the coverage
we want."
```

---

### Task 4: Publish per-channel artifacts from `release.yml`

The release workflow builds and verifies fixed paths that flavors move, and asserts a `google-services.json` package name that is now one of three. Left alone, the next tag either fails or publishes an unverified artifact.

**This task changes what the GitHub Release APK is.** It goes from `org.kysecurity.mail` to `org.kysecurity.mail.github`. Existing sideload users **cannot** update in place; they must uninstall and reinstall, losing local data. That break is unavoidable — once Play App Signing takes over `org.kysecurity.mail`, a Google-signed build and an upload-key-signed build under one id can never update each other. Making it explicit and one-time is the point of this whole change. Step 8 documents it.

**Files:**
- Modify: `.github/workflows/release.yml` — the google-services check, the assemble step, the metadata check, the signer check, the artifact-naming step, and the mapping upload.

**Interfaces:**
- Consumes: flavor and variant names from Task 2.
- Produces: release assets `kypost-<tag>.apk` (now the `github` flavor) and workflow artifacts `bundle-<tag>` (the `play` bundle) and `mapping-<tag>`.

- [ ] **Step 1: Read the whole workflow before editing it**

```bash
cat .github/workflows/release.yml
```

Every path this task touches appears more than once. Do not edit from the excerpts below alone.

- [ ] **Step 2: Assert all three package names in the production google-services.json**

In the `production google-services.json` step, replace the single package-name check:

```bash
          if ! grep -q '"package_name": *"org.kysecurity.mail"' app/google-services.json; then
            echo "GOOGLE_SERVICES_JSON does not name package org.kysecurity.mail." >&2
            exit 1
          fi
```

with:

```bash
          # One client per flavor. The google-services plugin fails any variant whose
          # applicationId it cannot find, so a secret that is missing one silently means that
          # channel's release never builds -- discovered at tag time, which is the worst moment.
          for pkg in org.kysecurity.mail org.kysecurity.mail.github org.kysecurity.mail.fdroid; do
            if ! grep -q "\"package_name\": *\"${pkg}\"" app/google-services.json; then
              echo "GOOGLE_SERVICES_JSON does not name package ${pkg}." >&2
              exit 1
            fi
          done
```

Note the grep for `"org.kysecurity.mail"` is quote-anchored on both sides, so it does not false-match `org.kysecurity.mail.github`. Keep it that way.

- [ ] **Step 3: Build the Play bundle and the GitHub APK, not `…Release`**

Replace the `assemble release` step's `run:` body:

```bash
          set -euo pipefail
          # play only: the bundle is the Play upload artifact, and Play is the only channel that
          # takes one. github/fdroid ship APKs.
          ./gradlew checkSigningSecretsAreNotInTheTree :app:bundlePlayRelease
          # github only, arm-only: this is the sideload APK. The Play bundle above must NOT carry
          # the flag, so Play keeps every ABI and x86_64 Chromebooks still get served.
          # fdroid is built by F-Droid's own infrastructure from source, never here.
          ./gradlew -PkypostArmOnlyApk :app:assembleGithubRelease
```

Keep the existing two-invocation comment above the step — its reasoning (`ndk.abiFilters` is global to the variant) is unchanged and still load-bearing.

- [ ] **Step 4: Fix the versionName/versionCode metadata path**

In the `tag matches the versioned manifest` step, replace:

```bash
          metadata=app/build/outputs/apk/release/output-metadata.json
```

with:

```bash
          metadata=app/build/outputs/apk/github/release/output-metadata.json
```

The assertion itself is unchanged — no flavor sets `versionNameSuffix`, so the github metadata's `versionName` is the shared one the tag must match.

- [ ] **Step 5: Fix the signer-identity check's APK path**

In the `signer identity is the expected release key` step, replace:

```bash
          apk=app/build/outputs/apk/release/app-release.apk
```

with:

```bash
          apk=app/build/outputs/apk/github/release/app-github-release.apk
```

The rest of that step — `apksigner verify`, the digest parse, the comparison against `RELEASE_KEY_SHA256` — is unchanged. This still gates the only artifact published to the Releases page.

- [ ] **Step 6: Fix the artifact-naming step**

In the `name the artifact` step, replace the two `cp` source paths:

```bash
          cp app/build/outputs/apk/github/release/app-github-release.apk "${RUNNER_TEMP}/kypost-${TAG}.apk"
```

and

```bash
          cp app/build/outputs/bundle/playRelease/app-play-release.aab "${RUNNER_TEMP}/kypost-${TAG}.aab"
```

Note the bundle directory is the **variant** name `playRelease` (one word, camelCase), while the APK directory is the **flavor** name `play`/`github` followed by the build type. AGP is inconsistent here; this is not a typo.

The destination filenames stay `kypost-<tag>.apk` / `.aab` — users' download links do not change, only what is inside.

- [ ] **Step 7: Fix the mapping-file upload path**

In the `retain the R8 mapping` step, replace:

```yaml
          path: app/build/outputs/mapping/release/mapping.txt
```

with:

```yaml
          path: |
            app/build/outputs/mapping/playRelease/mapping.txt
            app/build/outputs/mapping/githubRelease/mapping.txt
```

Two mappings now, because two R8 runs produce two different obfuscations. A crash report from the sideloaded APK is unreadable against the Play mapping. Keep `if-no-files-found: error` — with a multi-line `path`, `actions/upload-artifact` fails only if *no* pattern matched, so also confirm both files exist in the run log before trusting it.

- [ ] **Step 8: Document the sideload break where users will see it**

Add to `README.md`, in whatever section covers installation (find it first: `grep -n -i 'install\|download\|apk\|releases' README.md`):

```markdown
### Channels

KyPost for Android ships from three channels, and each is a separate app on your device:

| Channel | Package | Signed by |
| --- | --- | --- |
| Google Play | `org.kysecurity.mail` | Google, under Play App Signing |
| GitHub Releases | `org.kysecurity.mail.github` | our upload key |
| F-Droid | `org.kysecurity.mail.fdroid` | F-Droid |

Android identifies an app by its package **and** its signature, so a build from one
channel can never update a build from another. Distinct packages make that explicit
rather than presenting it as a corrupt update: you can run more than one at a time,
and each keeps its own mail, contacts and keys.

**Upgrading a sideloaded install from before v0.4.0:** the GitHub APK's package changed
from `org.kysecurity.mail` to `org.kysecurity.mail.github`. Android will not install it
over the old one. Uninstall the old app first — **this erases its local data, so re-pair
with your server afterwards.** This is a one-time break; GitHub-channel updates after
this one install normally.
```

Adjust the version in the last paragraph to whatever tag actually carries this change.

- [ ] **Step 9: Validate the workflow parses and every path is spelled right**

```bash
python3 -c "import yaml,sys; yaml.safe_load(open('.github/workflows/release.yml')); print('ok')"
grep -n 'outputs/apk\|outputs/bundle\|outputs/mapping' .github/workflows/release.yml
```

Expected: `ok`, then six path lines matching exactly what Steps 4–7 specify. Compare each against reality — do not trust the plan over the build:

```bash
./gradlew :app:bundlePlayRelease :app:assembleGithubRelease 2>&1 | tail -5
ls app/build/outputs/apk/github/release/
ls app/build/outputs/bundle/playRelease/
ls app/build/outputs/mapping/playRelease/ app/build/outputs/mapping/githubRelease/
```

This needs local signing material (`KYPOST_KEYSTORE` etc.); without it the release variants refuse to package and you will see the `No signing material` message from `app/build.gradle.kts`. That is expected on a machine without the key — in that case verify the paths against a debug build's shape instead (`app/build/outputs/apk/github/debug/`) and confirm the release directory names on the first tagged run, before publishing.

- [ ] **Step 10: Commit**

```bash
git add .github/workflows/release.yml README.md
git commit -m "release: per-channel artifacts

The Play bundle comes from bundlePlayRelease and the sideload APK from
assembleGithubRelease, so the published APK now carries
org.kysecurity.mail.github. Both R8 mappings are retained -- a crash from
the sideloaded build is unreadable against the Play mapping. README states
the one-time reinstall this costs existing sideload users."
```

---

### Task 5: Verify the acceptance criteria end to end

Nothing here changes code. It is the evidence that D1 is done, and it is not optional — the handoff's acceptance list contains two properties (pairing against a live 0.3.0 server, enrollment codes matching the browser) that no automated test in this repo covers.

**Files:**
- Modify: `AGENTS.md` (record the flavor contract so future work does not have to rediscover it)

**Interfaces:**
- Consumes: everything from Tasks 1–4.
- Produces: nothing.

- [ ] **Step 1: Three flavors build**

```bash
./gradlew :app:assemblePlayDebug :app:assembleGithubDebug :app:assembleFdroidDebug
```

Expected: BUILD SUCCESSFUL. Record the output.

- [ ] **Step 2: `play` produces exactly the applicationId in the closed test**

```bash
jq -r '.elements[0].applicationId' app/build/outputs/apk/play/debug/output-metadata.json
```

Expected, exactly: `org.kysecurity.mail`. Cross-check against what Play shows for the closed test track before signing this off.

- [ ] **Step 3: All three install simultaneously, each with its own data**

```bash
adb install -r app/build/outputs/apk/play/debug/app-play-debug.apk
adb install -r app/build/outputs/apk/github/debug/app-github-debug.apk
adb install -r app/build/outputs/apk/fdroid/debug/app-fdroid-debug.apk
adb shell pm list packages | grep org.kysecurity.mail
adb shell dumpsys account | grep -i 'org.kysecurity.mail.*contacts'
```

Expected: three packages, three account types. Then confirm the data directories are genuinely separate:

```bash
for p in org.kysecurity.mail org.kysecurity.mail.github org.kysecurity.mail.fdroid; do
  printf '%s: ' "$p"
  adb shell run-as "$p" ls -d /data/data/"$p"/databases 2>&1 | head -1
done
```

Expected: each resolves under its own package path. (`run-as` works on debug builds only, which is what you installed.)

- [ ] **Step 4: Pairing still works on `play` against a 0.3.0 server, including `pin=`**

Manual, and it needs a real server. On the `play` install:

1. Pair by scanning the QR from the server's security page. Confirm it completes and the pairing screen shows a synced state.
2. Repeat with a pairing link that carries a `pin=` parameter. Confirm the SPKI pin is honoured — the registration must succeed, and a subsequent request against a host presenting a different leaf must fail.
3. Confirm push arrives: send yourself mail and check the notification lands.

Record which server version you tested against. If it is not 0.3.0, say so rather than rounding up.

- [ ] **Step 5: Enrollment codes still match the browser**

`deviceId` is server-minted and `play`'s `applicationId` is unchanged, so there is no mechanism by which this could regress — but the handoff asks for it and the failure mode presents to users as an attack warning, so confirm rather than reason.

```bash
./gradlew :app:testPlayDebugUnitTest --tests '*EnrollmentCodeFormatTest*' --tests '*DeviceEnrollmentCodeTest*'
```

Expected: PASS.

Then on the device: run the device-enrollment ceremony on the `play` install and compare the code it shows against the browser's, character for character. Expected: 14 characters, `4-3-4-3` grouping, identical.

- [ ] **Step 6: Full local check, matching what CI will run**

```bash
./gradlew checkSigningSecretsAreNotInTheTree checkExportedComponentsPlayDebug testPlayDebugUnitTest lint
git diff --exit-code -- gradle/verification-metadata.xml
git status --porcelain app/google-services.json
```

Expected: BUILD SUCCESSFUL; no diff on the verification metadata; no output for `google-services.json` (gitignored and unstaged).

- [ ] **Step 7: Record the flavor contract in `AGENTS.md`**

Add to the root `AGENTS.md`, after the project description at the top:

```markdown
# Distribution channels

Three product flavors on the `channel` dimension, in `app/build.gradle.kts`:

| Flavor | `applicationId` | Ships as |
| --- | --- | --- |
| `play` | `org.kysecurity.mail` | Play bundle, `bundlePlayRelease` |
| `github` | `org.kysecurity.mail.github` | sideload APK, `assembleGithubRelease` |
| `fdroid` | `org.kysecurity.mail.fdroid` | built by F-Droid from source |

`play` must keep `org.kysecurity.mail`; it is the id in the Play listing, and Play App
Signing is scoped to it. `play` is declared first so it is the default variant, which is
the one bare `./gradlew lint` analyses.

`namespace` stays `org.kysecurity.mail` on every flavor — Kotlin packages, `BuildConfig`
and manifest class names are flavor-independent, and `allowedExportedComponents` in
`app/build.gradle.kts` lists them by their fixed names.

Anything that identifies this app to the *device* must derive from `applicationId`, or
the three installs collide. Today that is the two provider authorities (already
`${applicationId}`-interpolated in the manifest) and the contacts `accountType` (the
`contact_account_type` resValue, mirrored by `DeviceContactAccount.ACCOUNT_TYPE`).
Adding another such identifier means adding it to that list.

Variant-named Gradle tasks: use `…PlayDebug`, not `…Debug`.
```

- [ ] **Step 8: Commit and open the PR**

```bash
git add AGENTS.md
git commit -m "docs: record the flavor contract

What must derive from applicationId and why, so the next identifier that
needs it is not discovered on a device that refuses the second install."
git push -u origin HEAD
```

Open the PR with the acceptance evidence from Steps 1–6 in the body — the actual command output, not a summary of it. Note explicitly which server version Step 4 ran against, and flag anything you could not verify rather than omitting it.

---

## Self-Review

**Spec coverage.** Handoff acceptance criteria, mapped: "three flavors build" → Task 2 Step 4, Task 5 Step 1. "`play` produces exactly the current applicationId" → Task 2 Step 5, Task 5 Step 2. "all three install simultaneously with their own data" → Task 1 (the accountType blocker), Task 2 Step 8, Task 5 Step 3. "pairing still works on `play` against 0.3.0 including `pin=`" → Task 5 Step 4. "enrollment codes still match the browser" → Task 5 Step 5. The handoff's suggested order item 1 ("establish how `deviceId` is generated") is answered in Established Facts rather than as a task, because it turned out to need no work.

**Deliberately not covered.** Handoff Decisions 1–3 are D2/D3/D4 concerns. Decision 1 has been taken (UnifiedPush + server-side WebPush encryption) and is recorded under "Out of scope"; Decisions 2 and 4 are untouched here, and this plan changes nothing about the `kypost://` intent filter, so D4's problem is neither helped nor worsened. Decision 3 (losing push-MFA on F-Droid) becomes moot if the WebPush encryption work lands, since the confidentiality objection in `MFATransportEligible` is what excludes UnifiedPush today.

**Known gap this plan creates.** After Task 2, `github` and `fdroid` are `play` with a different package — they still bundle Firebase and still register over FCM. That is intended: D1 is the flavors, nothing else. `fdroid` is not shippable to F-Droid until D3, and Task 5 does not claim otherwise.
