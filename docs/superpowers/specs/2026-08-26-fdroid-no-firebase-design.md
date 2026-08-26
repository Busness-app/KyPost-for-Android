# D3 — the fdroid flavor ships no Google code

Design, 2026-08-26. Item **D3** of the public-launch plan. D1 (three flavors)
and D2 (Firebase registration) are merged; this is the flavor's actual content.

Every file and line reference below was read before being written down.

---

## Goal

`assembleFdroidRelease` produces an APK containing **no class under
`com/google/android/gms/` or `com/google/firebase/`**, and that build still
pairs, receives notifications, and answers MFA challenges.

F-Droid's inclusion policy refuses proprietary dependencies. A flavor that
merely disables FCM at runtime still carries them and is still refused.

## Decisions already taken

| Question | Answer | Why |
| --- | --- | --- |
| fdroid transport | **UnifiedPush**, primary | `deliveryMode` is per-USER, not per-device (`state/store.go:39-42`), so choosing `pull` would move every device that user owns. Recorded in `PLATFORM_BASELINE.md` §4. |
| UnifiedPush confidentiality | **Solved before this work** | Server PR #149 encrypts payloads under RFC 8291. Without it, making UnifiedPush a whole channel's default would have put every F-Droid user's mail subjects on a public broker in cleartext. |
| QR scanner | **FOSS on fdroid only** | ML Kit's `GmsBarcodeScanning` needs no `CAMERA` permission because it runs in the Play Services process. A CameraX scanner needs one. Scoping the replacement to fdroid keeps that permission — and D6's Data Safety declaration — off the Play and GitHub builds. |
| `google-services` plugin | **Stays applied** | Build-time only; its output is a few string resources. fdroid is now registered in Firebase (D2), so it will not fail the variant. The APK class check below is what proves the artifact is clean — the build file is not the evidence. |

## What actually differs per flavor

Only four things, all in `push/`:

| | play / github | fdroid |
| --- | --- | --- |
| Token at pairing | `FirebaseMessaging.getInstance().token` (`PushSyncCoordinator.kt:23`) | the UnifiedPush endpoint |
| UnifiedPush failure fallback | revert to FCM (`KyPostUnifiedPushService.kt:42-60`) | **none exists** — must surface the error |
| Token teardown on wipe | `deleteToken()` + `FirebaseInstallations.delete()` (`PushRepository.kt:305-308`) | `UnifiedPush.unregister()` |
| Pairing UI | Firebase ⇄ UnifiedPush chips (`PushPairingActivity.kt:215-224`) | UnifiedPush only |

### The seam

One interface in `main`, two implementations:

```
app/src/main/java/.../push/PushTokenSource.kt   // interface + the flavor-neutral callers
app/src/gms/java/.../push/GmsPushTokenSource.kt // play + github, via srcDir
app/src/fdroid/java/.../push/UnifiedPushTokenSource.kt
```

`play` and `github` share `src/gms/java` through
`sourceSets.getByName("play").java.srcDir("src/gms/java")` and the same for
`github`. Dependencies follow the same shape:

```kotlin
val gmsImplementation by configurations.creating
configurations.named("playImplementation") { extendsFrom(gmsImplementation) }
configurations.named("githubImplementation") { extendsFrom(gmsImplementation) }
```

Moving to `gmsImplementation`: `firebase-bom`, `firebase-messaging`,
`play-services-code-scanner`, `kotlinx-coroutines-play-services`. The last one is
Apache-2 itself but pulls `com.google.android.gms:play-services-tasks`; it is
still needed by play/github for `Task.await()` on the Firebase token
(5 call sites: `PushRepository.kt:18`, `PgpKeyActivity.kt:30`,
`PushPairingActivity.kt:36`, `SecurityWipe.kt:13`, `PushSyncCoordinator.kt:8`).

### Pairing on fdroid requires a distributor first

`PushSyncCoordinator.pairAndRegister` aborts when the token is null
(`PushSyncCoordinator.kt:54-55`). On fdroid that becomes "no distributor app, no
pairing". The pairing screen must say so **before** the scanner opens, not after
a failed attempt — this is the first thing a new F-Droid user touches.

`UnifiedPushRegistrar.beginRegistration` already reports
`ResolvedDistributor.NoneAvailable` with a usable message
(`UnifiedPushRegistrar.kt:18-21`); the fdroid pairing flow calls it up front
instead of treating it as a transport switch.

### The three FCM fallbacks that have nothing to fall back to

`KyPostUnifiedPushService` reverts to FCM on `onRegistrationFailed` and
`onUnregistered`, and `PushPairingActivity` offers a "Use Firebase" chip. On
fdroid all three must instead surface the failure and leave the user on
UnifiedPush, because there is no second transport. Silently "reverting" to a
transport that does not exist is how a device ends up paired and permanently
silent.

## The QR scanner

Replace `GmsBarcodeScanning` on fdroid only. Two call sites:
`PushPairingActivity.kt:277` and `PgpKeyActivity.kt:166`, both
`GmsBarcodeScanning.getClient(this).startScan().await().rawValue`.

- Interface `QrScanner` in `main`, GMS implementation in `src/gms`, CameraX +
  `zxing-core` implementation in `src/fdroid`.
- `zxing-core` is already a dependency (`libs.versions.toml:79`), used today for
  QR *generation* on the My QR Code screen. Decoding needs
  `MultiFormatReader` + `PlanarYUVLuminanceSource` + `HybridBinarizer`.
- CameraX artifacts are **not** in the version catalog and must be added:
  `camera-core`, `camera-camera2`, `camera-lifecycle`, `camera-view`.
- `<uses-permission android:name="android.permission.CAMERA" />` goes in
  **`app/src/fdroid/AndroidManifest.xml`**, so the manifest merger scopes it to
  that variant. `app/src/main/AndroidManifest.xml:5-10` declares no camera
  permission today and must keep declaring none.
- Runtime permission request, with a denial path that still lets the user paste
  a pairing URI rather than dead-ending.

## Build gates that break, and how

These are not speculative. Each was read.

### 1. `allowedExportedComponents` is bidirectional

`app/build.gradle.kts:310-323` allowlists exported components, and the gate at
`:388-395` **also fails on stale entries** — `allowed - exported` must be empty.
The list contains `com.google.firebase.iid.FirebaseInstanceIdReceiver`. On the
fdroid variant that receiver is not in the merged manifest, so
`checkExportedComponentsFdroidRelease` fails with "allowedExportedComponents
lists components the merged manifest no longer exports".

Fix: make the allowlist variant-aware — the Firebase receiver is expected on
play/github and forbidden on fdroid. Do **not** weaken the stale-entry check;
it is the half that stops the gate from quietly covering nothing.

### 2. `KyPostFirebaseMessagingService` must leave the fdroid manifest

Declared at `app/src/main/AndroidManifest.xml:127`. It has to move to
`src/gms/AndroidManifest.xml` (or be removed via the merger), or the fdroid APK
declares a service whose class does not exist.

### 3. The R8 check only looks at `playRelease`

`.github/workflows/ci.yml:168-181` reads
`app/build/outputs/mapping/playRelease/mapping.txt` and carries a `ponytail:`
note saying exactly this: *"Widen this to also check githubRelease/fdroidRelease
once the fdroid flavor drops the Firebase dependency… at that point its R8 input
differs from play's and this check stops covering it."* D3 is that point. Honour
the marker.

### 4. Dependency verification

`gradle/verification-metadata.xml` pins 644 components and CI fails on any diff
(`ci.yml:183`). Adding CameraX means regenerating it, and that regeneration is
part of the change, not an afterthought.

## The verification that makes the claim true

A CI step that unzips the fdroid release APK and fails if any class under
`com/google/android/gms/` or `com/google/firebase/` is present.

This is the acceptance criterion. "No Firebase dependency" asserted from the
build file is not evidence — the build file is what a mistake would live in. The
artifact is the only thing that settles it, and it is cheap to check.

## Testing

- `PushTokenSource` / `QrScanner`: the flavor-neutral callers tested against
  fakes, so the branch logic is covered without an emulator.
- The fdroid no-fallback behaviour: assert that a UnifiedPush registration
  failure surfaces an error rather than attempting an FCM resync.
- `AccountTypeMatchesManifestTest` and `DeviceContactAccountTest` already pin
  applicationId-derived values per flavor; confirm they still run for fdroid.
- The APK class check above, in CI.
- Instrumented: all three flavors install side by side (D1's criterion) and
  fdroid pairs against a live distributor.

## Out of scope

- **D4**, the `kypost://` chooser. Separate item; the chosen fix is a distinct
  `android:label` per flavor.
- Lifting anything else about `pull`. It stays exactly as it is — server-driven,
  account-wide, available on every flavor.
- VAPID subscription binding. Same open question as the Linux client has; needs
  a server change to expose the key on device auth.
- The Linux client's missing MFA path, tracked in that repo's handoff.
