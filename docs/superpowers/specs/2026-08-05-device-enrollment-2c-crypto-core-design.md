# Device Enrollment 2c — Crypto Core (Spec 1 of 2)

**Written:** 2026-08-05. **Repos:** `kypost-android` (primary) and `kypost-server` (one added
route). **Branch:** `feat/device-enrollment-2c`.

**Handoff:** `docs/superpowers/plans/2026-08-05-device-enrollment-2c-handoff.md`.
**Normative wire format:** `kypost-server/docs/superpowers/specs/2026-08-04-device-enrollment-design.md`.
**Parent decision:** `docs/superpowers/specs/2026-07-29-on-device-pgp-decryption-design.md`,
section "Accepted, gated: a device-sealed envelope".

## Scope

2c is split in two. This spec is **the crypto core**: the keystore keys, opening and re-sealing
the envelope, both teardown paths, and enrollment-state reporting. Everything here is provable
with unit and instrumented tests and no screen.

**Spec 2 (not this document)** covers the user-facing half: the pairing-time enrollment prompt,
the code-display UI with its 120-second refresh, and the Security-page entry for a device that
declined or was paired before this shipped.

The split falls on a real seam. Eight of the handoff's nine "tests that matter" live in this
spec; only the pairing-prompt path belongs to spec 2. It also means the HLP and wipe teardowns
get designed alongside the key they destroy, rather than bolted on after a screen exists.

Already landed on this branch: `e0f23a8` implements the enrollment code derivation and pins the
normative vector, mutation-proven three ways. **The vector changed on 2026-08-05** when the code
widened from 50 to 70 bits (decision 8): it is now `5R9K6FWA18A8YP`, displayed `5R9K6FW-A18A8YP`.

## What this design is for, and what it cannot do

The security does not live on this device. 2b — the browser — is where the substituted-key attack
is caught: it derives a code from the key **the server handed it**, compares it against what the
user reads off this device, and refuses to seal on mismatch. This device's obligations are
narrower and stricter:

- Derive the code from the key in our own keystore, never from anything the server returned.
- Never let the private half leave the secure element.
- Report enrollment state that matches reality rather than history.

What this cannot fix, and must not claim in any copy:

- **A live hostile server defeats the code.** It ships the browser's JavaScript and can serve a
  bundle that skips the comparison. This defends against a server that retains too much, a stolen
  backup, or a compromised database.
- **After the local re-seal, the server cannot revoke this device.** Deleting the slot removes the
  transport copy only. Real revocation is identity rotation.
- **Attacks by someone holding an unlocked device are conceded.** That is the parent spec's trade;
  `setUserAuthenticationRequired` is what narrows it.

## Decisions

Eight decisions are recorded. Seven were settled before this spec was written; decision 8 was
forced by security audit run-5 and corrects an argument the original draft got wrong. Each is recorded with its reasoning,
because the reasoning is what a future reader needs when an edge case argues the other way.

### 1. Two specs, split at the UI boundary

See Scope.

### 2. The re-seal key authenticates against the OS device credential

`setUserAuthenticationRequired(true)`, satisfied through `BiometricPrompt` with device-credential
fallback.

This **amends a documented precedent**. `security/CredentialCipher.kt:111` deliberately avoids
`setUserAuthenticationRequired` on the pepper key, for two stated reasons: the app-lock PIN is
this app's own secret rather than a device credential the Keystore can gate on, and that key is
needed by background token rotations.

The second reason is the load-bearing one, and it does not apply here. The enrollment envelope is
only ever opened to show the user their own mail — always foreground, always with the user
present. The precedent stands where it is; this key is a different case and the comment on it
should say so explicitly.

Consequence: a device with no secure lock screen cannot enroll. That is honest rather than
unfortunate — the envelope's protection *is* the lock screen, and a device without one cannot
hold a device-sealed envelope that means anything.

### 3. The opened private key lives until the app locks

Open once per unlock session; hold the armored PGP private key in memory; clear it on the same
trigger that locks the app — backgrounding plus `AppLockSettings.graceMillis()`.

The plaintext lifetime is the real exposure, not the prompt frequency. Tying it to the window the
user already configured at "Lock after: …" means one concept to understand rather than two.

Because the key is only exercised once per session, this also lets the Keystore key take the
strongest setting — per-use auth — at no UX cost. A time-windowed key would be weaker (any device
unlock inside the window authorizes it, including one an attacker performed) and buy nothing.

Rejected: holding until process death, which decouples plaintext lifetime from the lock the user
chose — "Lock after: immediately" would still leave the private key resident.

### 4. `encryptionEnrolled` is probed, not remembered

At each report point, `Cipher.init(DECRYPT_MODE, vaultKey, spec)` against the re-seal key. It
needs no user authentication and distinguishes the cases that matter:

| Outcome | Reported |
|---|---|
| `init` succeeds and the sealed blob is present | `true` — key alive, merely locked |
| `KeyPermanentlyInvalidatedException` | `false` |
| Missing alias / `KeyStoreException` (app reinstall) | `false` |
| Sealed blob absent | `false` |

This reports a property of the keystore rather than of our own bookkeeping — the distinction the
handoff draws when it calls the marker "device-reported ground truth, not a record of what the
browser did". A cached boolean fails the handoff's own example: an app reinstall or a
biometric-enrollment change destroys the key without any code of ours running, so a cached `true`
would survive and the Security page would tell the user a device can read their mail when it can
read nothing.

**Assumption — verified on TEE, still open on StrongBox (updated 2026-08-05).** `Cipher.init`
against a per-use auth-bound key succeeds with no user authentication and no prompt, and reports a
healthy-but-locked key as `ENROLLED`. Confirmed by `healthyLockedKeyReportsEnrolledWithoutAPrompt`
in `EnrollmentStateTest` (commit `bda8826`), running headless with no auth UI invoked.

**That run was TEE-backed** — the emulator logged `StrongBox unavailable, falling back to TEE`, so
the StrongBox path this section originally warned about is still unverified. It needs one run on
hardware with a dedicated secure element before this is considered settled. If `init` demands auth
there, the fallback is unchanged: probe where possible and treat a cached `true` as unverified
rather than authoritative — never the reverse.

### 5. Enrollment state rides a dedicated device-authed endpoint

**New route, and the reason it must exist:** `encryptionEnrolled` as built has exactly one carrier,
`POST /api/notifications/native/register`, and that carrier fails two requirements.

- `NativeRegistrationClient.register` refuses to run without a push token
  (`push/NativeRegistration.kt:136`, `if (token.isBlank()) return Error("FCM token is empty")`).
  A pull-mode device with FCM disabled has no token, so the only channel carrying enrollment state
  cannot be invoked at all, and the marker freezes at whatever it was when the device last had one.
- On UnifiedPush, that call is driven by the distributor's registration cycle. **UnifiedPush is not
  trusted for this function**: a third party must not decide when a security-relevant marker is
  restated, and the `p256dh`/`auth` material rides the same request.

So the marker gets its own transport-independent channel. The requirement is architectural — this
marker must not depend on any push transport — and is stated that way rather than patched
per-transport.

Rejected: adding the field to the pull request (leaves UnifiedPush push-mode devices reporting via
the distributor-driven call, which is the excluded case), and forcing periodic re-registration
(requires inventing a synthetic device token, lying to the server about the transport to smuggle an
unrelated field).

### 6. The teardown report is durable work, enqueued before the flag flips

WorkManager one-shot with backoff, enqueued **before** `setEnabled(true)`. See "HLP teardown"
below for the ordering argument.

### 7. The re-seal key survives a biometric enrollment change

`setUserAuthenticationParameters(0, BIOMETRIC_STRONG or DEVICE_CREDENTIAL)`. Including
`DEVICE_CREDENTIAL` means Android does not invalidate the key when a fingerprint is added or
removed.

The security delta against `BIOMETRIC_STRONG` alone is smaller than it appears: enrolling a new
biometric requires the device credential, so an attacker who can trigger invalidation-worthy
tampering already holds what the stricter key would accept. The stricter setting would charge every
ordinary user a full browser re-enrollment ceremony for adding a fingerprint after a new phone or a
cracked screen protector.

The second-order cost decided it. `encryptionEnrolled` exists to tell the user something true and
alarming — "this device can no longer read your mail". A marker that goes false because someone
re-registered a thumb is a marker users learn to dismiss.

**Not a user-facing switch.** `setUserAuthenticationParameters` is fixed at key generation, so
changing it means destroying the key and re-running the whole ceremony — the control would be a
question asked mid-ceremony, with a code on screen, or a setting whose only effect is "re-enroll
now". The strict posture also already has a home that is strictly stronger: under Hostile Location
Protection there is no envelope at all, and Lever C (rewrap under a separate PGP passphrase) is the
client-custody path for that user. Implement as a single named constant with the trade-off in a
comment pointing at HLP. If a real user ever asks, it is a one-line change plus a re-enrollment
prompt — cheap later, expensive to carry now for nobody.

### 8. The code is 70 bits, and the missing commitment is recorded as owed

**Added 2026-08-05 after security audit run-5.** The original 50-bit code was **offline-forgeable**.

The preimage contains nothing the verifier contributes, so every input is fixed, public or
attacker-chosen and the search is a *work factor*, not a per-attempt probability. An adversary who
can write the relay's device table — explicitly this design's stated threat model, "a compromised
database" — grinds a key, or the `deviceId`, whose code collides with the honest device's at a
**chosen future bucket**, then waits for that bucket to arrive. Roughly 2^50 SHA-256 compressions:
about 14 GPU-hours and five to seven dollars per 120-second window.

**The security argument in the original draft was the bug.** It read "2^47 in 120 seconds, short of
2^50 with margin", which assumes an *online* bound. Refusing future buckets — which the browser does,
deliberately — does not prevent precomputing *into* one. Two further errors in the same paragraph:
the claim that "the attacker must generate real keypairs, so the figure is conservative" is false,
because `deviceId` is served from the same attacker-writable row and grinding it needs zero
elliptic-curve work; and the key was long-lived (see decision 2's fix), so the precompute window was
unbounded.

**Immediate fix, implemented: 70 bits** — 14 Crockford characters, displayed `XXXXXXX-XXXXXXX`. The
same search becomes ~2^70, roughly a million GPU-years per window. This is a **wire-format break**:
the browser and every other client must widen to 14 characters or no honest enrollment will match,
and because the 10-character code is a prefix of the 14-character one, a mismatched client fails
silently as "the codes never match" — which the browser reports to the user as an active attack.

**The right fix, owed: a commitment.** Matrix's SAS is *shorter* than even the original code — 36 to
39 bits — and is sound, because `m.key.verification.accept` carries a required SHA-256 commitment to
the peer's ephemeral key, so an attacker gets exactly one online guess. The Matrix spec says so in as
many words: "an attacker essentially only has one attempt... hence we can verify fewer bits." Adding
that here means the browser mints a fresh 128-bit challenge at ceremony start, delivers it to the
device, and it enters the preimage.

**Why it is not implemented yet:** there is no browser-to-device channel. The publish step is
device-to-server POST only, so the challenge needs a new transport leg across two repositories. Until
it exists, length is what carries the property. Do not treat 70 bits as making the commitment
unnecessary — it makes it *not urgent*, which is different.

## Server addition (kypost-server)

`POST /api/pgp/device/enrollment-state`

- **Auth:** device credential headers only — `X-Kypost-Device-Id` / `X-Kypost-Device-Secret`.
  Not a session.
- **Body:** `{"encryptionEnrolled": true|false}`. **Required**, unlike register's tri-state
  pointer: this endpoint's only purpose is to state an opinion, so an absent field is a `400`
  rather than "no opinion".
- **Success:** `200` → `{"ok":true}`.
- **Failure:** `401` on bad credentials; `429` with `Retry-After` when the device-auth lockout
  trips — both from the shared `writeDeviceAuthFailure`. Refused while the account owes a password
  change, consistent with `deviceAuthFromRequest`.
- **Effect:** sets the same stored marker `register`'s `encryptionEnrolled` sets.

The existing field on `register` is unchanged. Other platforms and older clients keep using it;
Android stops depending on it. Publishing to an unknown device is an error, not a silent no-op —
expect `500` if the device row was removed while the credential still exists.

This addition belongs to 2a's surface. PR #80 is open and unmerged, so it can either grow or the
route can land separately; this spec is written to be implementable either way.

## Android components

Eight units under `pgp/`, each independently testable.

| Unit | Responsibility | Depends on |
|---|---|---|
| `DeviceEnrollmentCode.kt` | **Done** (`e0f23a8`). Code derivation from the raw key. | — |
| `EnrollmentKeyStore.kt` | The P-256 `PURPOSE_AGREE_KEY` pair; raw SEC1 point; ECDH. | Keystore |
| `DeviceEnvelope.kt` | Envelope parse/validate, HKDF-SHA256, AES-256-GCM open with AAD. Pure — no Android dependencies, unit-tests on the JVM. | — |
| `EnrollmentVault.kt` | The local re-seal: owns the AES-GCM Keystore key and the sealed blob. | Keystore |
| `EnrollmentState.kt` | The `Cipher.init` probe → enrolled / not-enrolled-with-reason. | `EnrollmentVault` |
| `EnrollmentStateClient.kt` | The new endpoint. Modelled on `push/MfaResponseClient.kt`. | `PairingAuthHeaders` |
| `EnrollmentStateWorker.kt` | WorkManager one-shot; reads the credential at run time. | `SecurePairingStore` |
| `EnrollmentTeardown.kt` | Destroys both keys and the blob. One function, two callers. | — |

Anchor correction carried from the handoff: `PairingAuthHeaders.kt` is at
`app/src/main/java/com/urlxl/mail/PairingAuthHeaders.kt`, not under `push/`.

The related on-device decryption spec plans `pgp/PgpVault.kt`, `PgpEnvelope.kt`, `PgpDecryptor.kt`.
If both proceed they share the vault and must be sequenced, not written in parallel.

### Key specifications

```
alias  kypost_device_enrollment_agree      EC P-256, PURPOSE_AGREE_KEY
       setIsStrongBoxBacked(true), fallback on StrongBoxUnavailableException
       NO user authentication required
       ROTATED PER CEREMONY — newKeyPair() deletes then generates; deleteKeyPair() on both exits

alias  kypost_device_envelope_seal          AES-256-GCM, PURPOSE_ENCRYPT | PURPOSE_DECRYPT
       setUserAuthenticationRequired(true)
       setUserAuthenticationParameters(0, BIOMETRIC_STRONG or DEVICE_CREDENTIAL)
       setIsStrongBoxBacked(true), fallback on StrongBoxUnavailableException
       setRandomizedEncryptionRequired(true)
```

**Two keys, deliberately.** The `AGREE_KEY` pair carries no user-auth requirement: it only ever
opens the server's 7-day transport copy, during a foreground ceremony, and gating it would add a
prompt that protects nothing durable.

**That justification only holds if the key really does live for one ceremony**, which the first
implementation got wrong: `ensureKeyPair` returned early when the alias existed, making the key
permanent. A permanent unauthenticated key is a standing path to every envelope the relay has
retained — openable with no prompt at all by an attacker holding the database *and* code execution
under this app's UID — which defeats the vault key's per-use authentication by a parallel route. It
also handed an attacker unbounded lead time to precompute against a stable public key. Corrected
2026-08-05 after audit run-5: `newKeyPair()` deletes then generates, and the ceremony must call
`deleteKeyPair()` on both its success and failure exits. The re-seal key carries the full requirement, because it is
what stands between an extracted device image and the user's mail. Conflating them would force the
weaker requirement onto the durable key.

Timeout `0` is per-use auth, satisfied through a `BiometricPrompt.CryptoObject`.

**StrongBox falls back rather than failing.** Not every supported device has a dedicated secure
element, and refusing enrollment there would exclude a large share of the install base for a
marginal gain over TEE. Log the fallback; do not surface it.

**No secure lock screen means no enrollment.** Key generation throws; refuse with an explanation
rather than degrading silently.

### Storage

The sealed blob lives in its own `EncryptedSharedPreferences` file, `device_envelope_secure` — not
in `SecurePairingStore`. Teardown is then `deleteSharedPreferences` plus two `deleteEntry(alias)`
calls: separately assertable, and with no risk of collaterally clearing pairing state that HLP
explicitly preserves.

## Data flow

### Enrollment ceremony

1. **Verify the account has a PGP identity.** Enrollment must FOLLOW identity creation. Reversed,
   the envelope is silently discarded and the server cannot detect it, because both calls are
   individually valid and it can read neither envelope. This is a client obligation.
2. Generate the `AGREE_KEY` pair if absent.
3. `POST /api/pgp/device/enrollment-key` with the base64 SEC1 point — **every time enrollment
   starts**, not once at pairing. Any write or delete of the account's PGP identity clears the
   stored key server-side, so a device that published only at pairing fails after a rotation with
   nothing on screen to explain why.
4. Display `deviceEnrollmentCode(rawPublicKey, deviceId, bucket)`, refreshing on the 120-second
   boundary. Derived from the keystore key; **never** from the publish response. (UI is spec 2;
   the derivation and bucket handling are here.)
5. Browser verifies, seals, `PUT`s.
6. `GET /api/pgp/device/envelope` → ECDH inside the secure element → HKDF-SHA256 → AES-256-GCM open
   with AAD `kypost-device-envelope/v1|<deviceId>|<pgpFingerprint>`, fingerprint uppercase hex, no
   spaces.
7. Re-seal the plaintext under the vault key, then report `true` via `EnrollmentStateClient`. From
   here the server's copy is dead weight — fetch it, re-seal locally, and stop depending on it.
   Nothing deletes it for you; expiry is lazy and needs no caller, because a device-authenticated
   delete would hand a device the power to destroy a sealing.

`deviceId` is hashed as-is and never normalised: the server bounds it to `A-Z a-z 0-9 . _ : -`,
every character of which is byte-identical under UTF-8, NFC and NFD.

### Reading

First access per unlock session runs `BiometricPrompt` with the vault `Cipher`, opens the blob, and
holds the armored key in memory. Cleared on backgrounding plus `AppLockSettings.graceMillis()`.

### Reporting

`EnrollmentState.probe()` at each report point; result posted via `EnrollmentStateClient`.
Transport-independent, so pull-mode and UnifiedPush devices report identically.

**Report points**, in full — the marker is worthless if its freshness is left to interpretation:

- Immediately after enrollment completes (`true`).
- On HLP teardown (`false`), as durable work — see below.
- On app foreground, at most once per unlock session. This is the path that catches the two
  destructive events no code of ours observes: an app reinstall and a biometric enrollment change.
- On each periodic `PullScheduler` run for pull-mode devices, coalesced so a device polling
  frequently does not report on every poll.

A report whose probe result equals the last successfully-delivered value may be skipped, but the
**last-delivered value must be persisted separately from the probe** — it records what the server
was told, not what is true, and the two diverging is the entire reason this marker exists.

### HLP teardown

Hook: `security/SecuritySettingsActivity.kt:242`, `applyHostileLocationProtection`, which already
runs on the `SecurityWork` dispatcher behind a confirm dialog.

```
EnrollmentTeardown.destroy()             blob + both keystore aliases
enqueue EnrollmentStateWorker(false)     durable, retried with backoff
settings.setEnabled(enable)
AppRestart.relaunch()
```

**Every prefix of that order is safe under process death**, which is why it is this order:

- Die after `destroy()` — flag still off, envelope already gone. The device is honestly
  un-enrolled and the next report says so.
- Die after the enqueue — same, and the report is now durable.
- Die after `setEnabled` — protection is on and the report is already queued.

There is no interruption point that leaves the server believing the device can read mail when it
cannot. This extends the reasoning already recorded on `HostileLocationSettings.setEnabled`, which
is written after the database is deleted and uses `commit()` rather than `apply()` for the same
class of reason.

The worker **reads the device credential at run time from `SecurePairingStore`**, never captured
into the work's input data — WorkManager writes input to its own database in plaintext.

### SecurityWipe teardown

`SecurityWipe.wipeAndResetApp` calls `EnrollmentTeardown.destroy()` as a named `step(...)`, so a
failure lands in the incomplete-wipe list rather than being silently skipped.

No worker is needed on this path: the wipe deregisters and clears the pairing, so the device row
goes away server-side and there is no stale marker to correct. This path matters because it is
reached by an attacker guessing at the PIN — a keystore key that survived it would outlive a wipe
nobody chose.

## Error handling

| Condition | Behaviour |
|---|---|
| AAD verification fails | **Hostile or stale. No retry, no fallback.** Destroy local state, report `false`, require re-enrollment. |
| Envelope `404` | Expired or never sealed — indistinguishable by design. Re-run the ceremony. |
| `KeyPermanentlyInvalidatedException` | Report `false`, offer re-enrollment. Expected, not an error. |
| Identity rotated | Every sealing void by design. Report `false`. Surface as expected, not as a failure. |
| `409` on re-registration | Missing `X-Kypost-Device-Secret`. A bug in the caller, not user error. |
| Password change owed | "Sign in on the web to finish your password change" — not a pairing error. |
| `429` + `Retry-After` | Honour it, exactly as `MfaResponseClient` does. |
| No secure lock screen | Refuse enrollment and explain why. |
| Clock skew | Do not widen the window to compensate. The browser names this failure; ours must not contradict it. |
| Code mismatch | Nothing to do here. Do not offer a retry implying the user mistyped when the browser has just told them the server may be hostile. |

## Testing

JVM unit tests for `DeviceEnvelope` and the code derivation; instrumented tests for anything
touching Keystore.

**Treat "there is a test for it" as unproven until the implementation has been broken and the test
watched going red.** Two of 2b's security tests originally passed against implementations with the
property removed — one against the design's own headline attack — and were caught only by mutation.
See `1c74842` and `00feae6` in kypost-server.

1. **The vector reproduces** — `5R9K6FWA18`. **Done** (`e0f23a8`); red under three mutations:
   dropped length prefix, LSB-first bits, little-endian length and bucket.
2. The code derives from the keystore key, not from anything the server returned.
3. The private half is non-extractable; requesting raw private material throws.
4. AAD mismatch refuses — wrong `deviceId` and wrong fingerprint, asserted separately.
5. The vault key genuinely requires user authentication.
6. `encryptionEnrolled` follows reality **down** as well as up — after the key is destroyed
   (reinstall, biometric change), it reports `false`.
7. Re-registration sends the device secret and survives a token refresh without a `409`.
8. Enrollment before identity creation is rejected or retried, never silently lost.
9. HLP teardown destroys both keys and the blob, survives process death mid-teardown, and the
   queued report still lands afterward.
10. The `Cipher.init` probe distinguishes invalidated from merely-locked. **Settles decision 4's
    unverified assumption** — run it before the reporting path is trusted.
11. Teardown does not disturb pairing state: after HLP teardown, push and sync still work.

## Build note

**Resolved 2026-08-05.** `gradle/verification-metadata.xml` was missing ten BOM and parent-POM
metadata artifacts, which failed the build at configuration time and made the KSP configuration-cache
error look like a separate defect — it was a consequence, not a cause. Each artifact was downloaded
from Maven Central, checked against Central's own published `.sha1`, cross-checked against the bytes
Gradle had resolved, and only then recorded. No workaround flags are needed now.

Separately, ten instrumented tests fail on the Android 17 emulator with `PepperUnavailableException`
from `CredentialCipher`'s HMAC pepper key. Confirmed pre-existing at `cdd7dbd`, before any 2c work.
Unrelated to this spec, but it means the credential gate is broken on that platform and wants its own
investigation.

## Out of scope

- The pairing prompt, code-display UI, and Security-page entry — spec 2.
- Whether the Qt clients can hold a non-extractable key (2d). If they cannot they stay on the
  passphrase tier, and that must not block 2c. Do not design Android around a shared abstraction
  with a client that may never exist.
- Lever C (rewrap under a separate PGP passphrase). It is the HLP-on user's alternative and is not
  superseded by this design, but it is separate work.
