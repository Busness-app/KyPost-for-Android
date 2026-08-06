# Device Enrollment — the Android ceremony (Spec 2 of 2)

**Companion to** `2026-08-05-device-enrollment-2c-crypto-core-design.md`, which is spec 1. That spec
built the keystore keys, the envelope open, both teardown paths and enrollment-state reporting, and
deliberately stopped short of a screen. This spec is the screen and the orchestration that drives it.

## Why this exists

The programme goal is **retiring server-held PGP keys**, with every account setting up a client-held
key at first login. Enrollment is what makes a paired phone able to hold one. So this is not an
advanced opt-in bolted onto the side of the app — it is the expected path for a paired device, and
the UI should read that way.

Spec 1 landed with **no production callers**: `EnrollmentClients.publishKey`, `fetchEnvelope`,
`DeviceEnvelope`, `DeviceEnrollmentCode`, `EnrollmentKeyStore.newKeyPair` and
`EnrollmentVault.store` are written, tested and unreferenced. This spec is what calls them.

## Scope

**In:** the Security-page entry and its states, the ceremony screen, the orchestration state machine,
a "remove from this device" action, a pointer at pairing, and CI for the repository.

**Out:** reading mail with the enrolled key. See "Where this stops", below.

## Where this stops, and why the copy matters

`docs/superpowers/specs/2026-07-29-on-device-pgp-decryption-design.md` is **deferred**, gated on
measuring whether context-switch friction survived the Custom Tabs change that shipped at `e42ad96`.
That measurement has not been taken. So nothing in the app reads mail with a device-held key, and
this spec does not add it.

The consequence has to be stated plainly, because it constrains every string on these screens: a
user who completes the ceremony gets a device that **holds** a key it does not yet **use**. The
browser renders `encryptionEnrolled` as "this device can read your encrypted mail" — true about
capability, false about behaviour.

**Therefore: every string in this spec describes capability, never behaviour.** Success says "This
device now holds a key for your encrypted mail." Nothing says the user can now read encrypted mail
on the phone, because they cannot until the deferred work lands.

## Decisions

### 1. The ceremony lives on the Security page only

No pairing-time ceremony. The ceremony is two-device — the phone shows a code, the user types it in
a browser — so starting it during pairing asks the user to walk to a computer mid-setup or abandon a
half-started flow. Pairing is also the app's most audited path: runs 1 and 2 found the QR-trust,
deep-link and credential-leak findings there. It does not need a multi-minute stateful ceremony
added to it.

### 2. Pairing shows a static pointer, with no network call

Pairing gains one line of text: encrypted mail can be set up in Settings → Security. It does **not**
call `hasPgpIdentity` to decide whether to show it.

Gating the hint would add an authenticated request to the pairing flow to answer a question the
browser has usually already settled at first login — and `hasPgpIdentity` returns `Boolean?`, so a
network failure leaves the app guessing anyway. The Security page can afford to check properly, give
a real reason, and be re-opened when the answer changes. The hint is therefore worded conditionally
("if your account uses encrypted mail") rather than as a promise, and it never goes stale: a user
who creates their identity a week after pairing still finds the entry where the hint said it was.

### 3. The phone polls for the sealing, bounded

There is no browser-to-device channel — the publish step is device-to-server POST only — so the
phone discovers the sealing by polling `GET /api/pgp/device/envelope`.

**A background completion is impossible, not merely undesirable.** The re-seal uses
`EnrollmentVault.sealCipher()`, whose key is `setUserAuthenticationRequired(true)` with per-use auth,
so it needs a live `BiometricPrompt`. The ceremony's tail requires the user present and the app
foregrounded.

Polling runs every 3 seconds for 5 minutes, then stops and offers "Check again". The bound is not
cosmetic: the screen holds a published enrollment key and a code the user is reading aloud, and spec
1 requires `deleteKeyPair()` on both exits of a ceremony — so there has to *be* a defined exit rather
than a loop that runs until the process dies. Five minutes also means the code has rotated at least
twice, so the screen has had to refresh it anyway.

**"Check again" resumes; it does not restart.** It reopens a fresh 5-minute polling window against
the *same* keypair, so the code on screen stays valid and the user does not have to re-read it. The
key is not republished and `newKeyPair()` is not called again — a restart would rotate the key, which
would invalidate the code the user may have already typed into the browser. Leaving the screen and
re-entering is the restart, and that path does rotate.

### 4. A dedicated Activity, a ViewModel, and a pure orchestrator

`SecuritySettingsActivity` is already 706 lines and is where the `NonCancellable` continuation bug
lived. `PgpKeyActivity` is 466. Neither should grow a multi-minute stateful ceremony.

**No Activity in this app declares `configChanges`**, so rotation destroys every screen. A ceremony
whose state lives in an Activity would, on rotation, republish a key and force the user to re-read a
new code. The ViewModel is what makes rotation survivable.

The orchestrator is split out from the ViewModel because **the ceremony has more branches than any
existing call site in this app**: identity missing, publish rejected, poll timeout, envelope 404,
GCM open failure, biometric cancelled, no lock screen, re-seal failure, report failure, user
abandons. Every one is something the user must be told about. Audit run-6's one unfixable finding was
that the HLP teardown tests drive a shared function but not the activity's call to it — logic in an
Activity is logic no unit test can reach. Splitting the orchestrator makes every branch above a JVM
test.

### 5. The re-seal is requested through an interface

The orchestrator cannot call `BiometricPrompt` — it is Activity-bound. It calls
`VaultSealer.seal(plaintext)`, which the Activity implements. This is the seam that keeps the state
machine testable: "biometric cancelled" becomes a JVM test with a fake, not an instrumented one.

### 6. The plaintext never enters `EnrollmentSession`

Spec 1 built `EnrollmentSession` to hold the opened key for an unlock session. It has no consumer
until the deferred decryption work lands, so the ceremony seals the `ByteArray` and zeroes it in
place. Populating a process-scoped holder with the account's private key for zero readers is exposure
bought for nothing.

(`EnrollmentSession` remains registered with `ProcessState` — that fix landed in `0ecee8e` and stays,
so the holder is covered the day it gets a writer.)

### 7. The agreement key dies on success as well as failure

Spec 1's `EnrollmentKeyStore` KDoc requires the key's life to be one ceremony, not one install: a key
that outlives every ceremony is a standing unauthenticated path to every envelope the relay has
retained. Once the envelope is re-sealed under the vault key, the agreement key is spent.
`deleteKeyPair()` therefore fires on **every** exit including success — see the exit table below.

### 8. The code is displayed in four groups

`5R9K-6FW-A18A-8YP`, not `5R9K6FW-A18A8YP`.

At 14 characters, two groups of seven are long runs that are easy to lose your place in. Four groups
of at most four is the pattern people already read off bank cards and licence keys, and short runs
make an omitted character visible as a wrong-length group rather than a silently mistyped one. The
code is transcribed across two devices, so that is the failure the grouping prevents.

**Safe on the wire, verified:** the browser's `normalizeEnrollmentCode` strips all whitespace and
hyphens (`/[\s-]/g`) and applies Crockford's decode rules before comparing, so grouping never reaches
the hash. See "Server-side change required".

### 9. Enrollment is blocked, not attempted, under two preconditions

**Hostile Location Protection on.** HLP's contract is that no envelope exists on the device;
enrolling under it creates exactly the artefact its teardown destroys. Blocked at the entry.

**No secure lock screen.** `EnrollmentVault.ensureKey()` returns false by design, because the
envelope's protection *is* the lock screen. Saying so at the entry beats a biometric prompt that
cannot be satisfied after the user has already read a code aloud.

### 10. Failure states are sentinels, never server text

The browser half enforces this already — its failure state holds a closed set so an adversarial
server's error string cannot select the alarming copy. Android matches: `Failed(reason)` carries an
enum and every string is local.

A related rule: **"could not check" is not "no."** `hasPgpIdentity` returns `Boolean?` precisely so
callers do not conflate them.

## Components

| Unit | Responsibility | Depends on |
|---|---|---|
| `EnrollmentCeremony` | The state machine. No Android imports. | The four interfaces below |
| `EnrollmentUiState` | Sealed: `CheckingIdentity`, `Unavailable(reason)`, `ShowingCode(code, expiresAt)`, `WaitingTimedOut`, `Opening`, `AwaitingAuth`, `Enrolled`, `Failed(reason)` | — |
| `DeviceEnrollmentViewModel` | Owns the ceremony, exposes `StateFlow<EnrollmentUiState>`, tears down in `onCleared` | `EnrollmentCeremony` |
| `DeviceEnrollmentActivity` | Renders state, hosts `BiometricPrompt`, implements `VaultSealer` | ViewModel |
| Security-page entry | Shows current state, launches the ceremony, offers removal | `probeEnrollment`, `IdentitySource` |
| Pairing pointer | One static line. No network call. | — |

The four injected interfaces, each with a real implementation and a JVM fake:

- **`IdentitySource`** — is there a client-protected PGP identity, and what is its fingerprint? Wraps
  `hasPgpIdentity` and `PgpBootstrapClient`.
- **`EnrollmentTransport`** — publish, fetch, report. Wraps `EnrollmentClients`. **Must be
  constructed with `pinnedPairingCallFactory`** — `EnrollmentClients.callFactory` has no default
  precisely so this cannot be forgotten (see `d410827`).
- **`VaultSealer`** — `suspend fun seal(plaintext: ByteArray): SealOutcome`. The only piece that must
  be on-device.
- **`Clock`** — bucket derivation and the poll deadline. Follows the `elapsedRealtimeMs` injection
  precedent in `AppLockManager`.

## Data flow

1. **CheckingIdentity** — identity present and client-protected? Fetch the fingerprint the AAD binds.
2. **PublishingKey** — `newKeyPair()`, then `publishKey`. **Every ceremony, not once**: any write to
   the account's PGP identity clears the stored key server-side, so a device that published only at
   pairing fails silently after a rotation.
3. **ShowingCode** — derive from `rawPublicKey` + `deviceId` + bucket; recompute on the 120-second
   boundary. Poll every 3s; 404 means keep waiting.
4. **Opening** — parse, ECDH in the secure element, HKDF-SHA256, AES-256-GCM open with the v2 AAD.
5. **AwaitingAuth** — `ensureKey()`, then `VaultSealer.seal()`, then `store(iv, ct)`.
6. **Reporting** — `reportState(true)`.
7. **Enrolled.**

### Exits

| Exit | State | Cleanup |
|---|---|---|
| No identity / server-held | `Unavailable` | none — no keypair yet |
| Publish rejected (401/429/other) | `Failed` | `deleteKeyPair()` |
| Poll hits 5 minutes | `WaitingTimedOut` | keypair **kept** — "Check again" resumes |
| User leaves / `onCleared` | — | `deleteKeyPair()` |
| Envelope malformed | `Failed` | `deleteKeyPair()` |
| **GCM open fails** | `Failed(couldNotOpen)` | `deleteKeyPair()` |
| No secure lock screen | `Failed` | `deleteKeyPair()` |
| Biometric cancelled | back to `ShowingCode` | plaintext zeroed |
| Report fails | **`Enrolled`** | `deleteKeyPair()`, enqueue `EnrollmentStateWorker` |
| Success | `Enrolled` | `deleteKeyPair()` |

Two rows carry the design's weight. **A failed report still means enrolled** — the local seal is
real, only the server's marker is stale, and the durable worker already exists to correct it. **A
failed GCM open is never a retry** — the AAD binds device and identity, so a failure means the
envelope was sealed for another device or under an identity the account no longer advertises.

## The Security-page entry

| State | Row reads | Action |
|---|---|---|
| Not paired | hidden | — |
| HLP on | "Not available while Hostile Location Protection is on." | — |
| No secure lock screen | "Set a screen lock to use encrypted mail on this device." | — |
| Server-held key | "Your account's encryption key is held by the server." | Open webmail (`WebmailDeepLink`) |
| No PGP identity | "Your account doesn't use encrypted mail yet." | Open webmail |
| Client key, not enrolled | "Set up encrypted mail on this device" | Launch ceremony |
| Enrolled | "This device holds a key for your encrypted mail" | "Remove from this device" |
| `KEY_INVALIDATED` | "This device can no longer open your encrypted mail." | Set up again |

The **server-held** row is the retirement nudge: it names where the key lives rather than saying
"unavailable", and hands the user the action that fixes it. **`KEY_INVALIDATED`** is a real state
spec 1 produces — a biometric enrollment change or Keystore invalidation kills the vault key — so it
must be said rather than silently reading as un-enrolled.

**"Remove from this device"** is `EnrollmentTeardown.destroy` plus `reportState(false)`. Without it
the only ways to undo an enrollment are Hostile Location Protection or a full wipe, both nuclear.

## The ceremony screen

Identity check, then the code in four groups with a countdown and instructions naming where to type
it, then "still waiting" at the bound, then the biometric prompt, then success.

`FLAG_KEEP_SCREEN_ON` is set while the code is displayed. Without it the screen times out while the
user is typing into the browser, which backgrounds the app, which starts the 30-second lock grace —
and the user returns to an unlock prompt with the ceremony destroyed.

## Error handling

Beyond the exit table, three rules:

- **The GCM-open failure gets its own copy.** Every other failure is "something went wrong, try
  again." This one is the only point where the phone can detect the attack the ceremony exists to
  prevent, so it says so and offers to start over.
- **It describes rather than accuses.** An identity rotation mid-ceremony is indistinguishable by
  construction from a hostile substitution — both produce a failed open. The copy says "this device
  could not open the key that was sent to it", not that an attack occurred.
- **Interactions already work and must not break:** app lock mid-ceremony destroys the Activity and
  `onCleared` cleans up; HLP, `SecurityWipe` and unpair each already tear the enrollment down
  (`0da30b8`, `2bcf38e`).

## Testing

**JVM, on `EnrollmentCeremony`, with fakes for the four interfaces:**

- The code derives from the **keystore key, never the publish response** — the one security property
  the device half owns. Mutation-proven: derive from the response, watch it go red.
- The key is published on every ceremony start, not once.
- The code recomputes on the bucket boundary and not before.
- Polling stops at the deadline; "Check again" opens a fresh window.
- `deleteKeyPair()` on **every** exit, parameterised across the exit table, so an exit added later
  without cleanup fails the suite.
- A failed GCM open produces `couldNotOpen`, never a retry.
- A failed report yields `Enrolled` and enqueues the worker.
- Biometric cancel returns to `ShowingCode` with the plaintext zeroed.
- Identity absent → `Unavailable`, no keypair created. *(This is test 8 from the original 2b
  handoff — enrollment-before-identity.)*
- HLP on, and no secure lock screen, both block before publishing.

**Instrumented:** `ensureKey` / `sealCipher` / `openCipher` round-tripping through the real Keystore;
the Security-page entry rendering each state.

**Carried over and not yet placed:** test 7 from the original handoff — re-registration sending the
device secret. It belongs to the registration path rather than this ceremony, and must land somewhere
rather than evaporating.

**Not automatable:** the `BiometricPrompt` interaction itself. `VaultSealer` is an interface so
everything around it is testable, but the prompt appearing and being satisfied is a manual check.
This spec does not claim otherwise.

**Discipline:** every test above asserts a value that differs between the correct and incorrect
implementations. Audit run-6 found the previous plan's Task 7 test asserting `WorkInfo.progress`,
which is empty for every worker ever enqueued — it would have passed against a credential leak.

## CI

**This repository has no CI at all.** `kypost-server` has four workflows; `kypost-android` has none,
so 558 unit tests and 105 instrumented tests run only when someone remembers. That is the gap this
spec closes alongside the feature, because the ceremony's guarantees are exactly the kind that decay
silently without an automated gate.

Add `.github/workflows/ci.yml`, following the conventions `kypost-server/.github/workflows/ci.yml`
already establishes:

- Triggers `push: [main]` and `pull_request` — not `push: "**"`, which would run every PR commit
  twice.
- `concurrency` group per ref, `cancel-in-progress` everywhere except `main`, so a green tick against
  a `main` commit stays a record of that commit.
- `permissions: contents: read`.
- **Every action pinned to a commit SHA, not a tag.** A tag is a mutable pointer; the server repo
  already holds this standard and states why.
- Per-job `timeout-minutes`.

Jobs:

| Job | Runs | Notes |
|---|---|---|
| `unit` | `./gradlew testDebugUnitTest lint` | Fast gate on every PR |
| `instrumented` | `./gradlew connectedDebugAndroidTest` on an emulator | The security properties live here |

Three Android-specific requirements the workflow must honour:

1. **Validate the Gradle wrapper.** `gradle/wrapper/gradle-wrapper.jar` is committed; a wrapper-
   validation step is the control that stops a swapped jar executing in CI.
2. **Never pass `--write-verification-metadata`.** `gradle/verification-metadata.xml` has
   `verify-metadata=true` and 600+ pinned components. CI must *fail* on an unrecorded artifact, which
   is the entire point of the file; a job that regenerates it silently defeats the supply-chain
   control this repo already paid for.
3. **The emulator needs a secure lock screen.** `EnrollmentVault.ensureKey()` returns false without
   one, so `EnrollmentVaultTest`, `EnrollmentStateTest` and this spec's instrumented tests fail
   confusingly on a bare emulator. The workflow must set one (e.g. `adb shell locksettings set-pin`)
   before running `connectedDebugAndroidTest`. The 2c plan already warns humans about this; CI needs
   the same warning expressed as a step.

Instrumented CI is slower and flakier than unit-only, and it is still worth it here: the wipe,
teardown, Keystore and enrollment-state guarantees are asserted *only* in instrumented tests. A CI
that ran unit tests alone would give this repository false confidence about precisely its most
security-relevant behaviour.

**CI is independent of the rest of this spec and should land first.** It touches no application code,
it is verifiable against the suites that already exist and pass (558 unit, 105 instrumented), and
every task after it benefits from an automated gate that is already green. The implementation plan
should sequence it as task 1 rather than folding it into the feature.

## Server-side change required — still outstanding

Not landed. `formatEnrollmentCode` in `kypost-server/frontend/src/lib/deviceEnrollment.ts` still
groups the code 7-7 (`CODE_LENGTH / 2`), while `EnrollmentCodeFormat.kt` in this repository now
groups 4-3-4-3. Deferred because `kypost-server` had uncommitted work in flight on another branch
when Task 14 closed out this plan. The two clients now disagree about how the same value is
displayed; the paragraphs below, written when this section was opened, still describe exactly what
is owed.

`kypost-server`, `frontend/src/lib/deviceEnrollment.ts`: `formatEnrollmentCode` groups the code 7-7
(`XXXXXXX-XXXXXXX`). Decision 8 moves the phone to 4-3-4-3. Change the browser helper to match and
update `frontend/src/lib/deviceEnrollment.test.ts:149`, which pins `ABCDEFG-HJKMNPQ`.

**This is cosmetic-only today and cannot break the ceremony:** the helper has no production call site
— only tests import it — and `normalizeEnrollmentCode` strips separators before comparing. The
alternative is to delete the helper as unused. It is recorded because a display helper sitting ready
to be wired up is a future disagreement between the two screens showing the same code.

Also update the normative vector's *displayed* form in
`2026-08-05-device-enrollment-2c-crypto-core-design.md` and the session handoff, which record
`5R9K6FW-A18A8YP`. The underlying value `5R9K6FWA18A8YP` is unchanged — grouping never enters the
hash.

## Out of scope

- **Reading mail with the enrolled key.** Deferred; see "Where this stops".
- **Decision 8 of spec 1** — the browser-minted 128-bit challenge that would replace the 70-bit
  widening. It needs a browser-to-device channel this protocol does not have, so it is a new
  transport leg and its own piece of work. 70 bits makes it *not urgent*, not unnecessary.
- **Qt clients (2d).** Whether they can hold a non-extractable key is their problem, and Android must
  not be designed around a shared abstraction with a client that may never exist.
