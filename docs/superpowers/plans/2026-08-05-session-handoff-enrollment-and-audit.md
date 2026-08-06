# Session Handoff — device enrollment 2c, security audit run-5, and the wire v2 break

> **SUPERSEDED 2026-08-06** by `2026-08-06-session-handoff-ceremony-spec-and-audit-run-6.md`.
>
> **The cliff below is resolved. Do not act on it.** Both halves of the wire break shipped:
> `kypost-server` PR #83 and `kypost-android` PR #14 are both on `main`, so the 70-bit code and the
> v2 envelope agree. This document is kept for the run-5 history and the traps section; its "must
> ship together" warning and its branch table are stale.
>
> Note also that a stale local clone makes the warning below look live — Android `main` was 25
> commits behind and server `main` 79 behind when this was re-read. `git fetch` first.

**Written:** 2026-08-05. **Spans two repos.** Read this before picking any of it up; the two halves
must ship together and one of them is currently a correctness cliff.

| Repo | Branch | State |
|---|---|---|
| `kypost-android` | `feat/device-enrollment-2c` | 13 commits ahead of `main` |
| `kypost-server` | `feat/device-enrollment-wire-v2` | 2 commits ahead of `main` |

---

## The one thing that will break if you get it wrong

**The 70-bit code and the v2 envelope must ship together.** Android already has both. The server
branch has the browser half. If either side ships alone, **every honest enrollment fails**, and it
fails as *"the codes do not match"* — which the browser presents to the user as an active attack.

The 10-character code is a **prefix** of the 14-character one, so a client left at the old width
produces a plausible-looking value that simply never matches. There is no loud failure to alert you.

Normative vector, asserted on both sides:

```
deviceId "test-device", bucket 14000000,
rawKey 0x04 ‖ 0x01×32 ‖ 0x02×32   ->   5R9K6FWA18A8YP   (displayed 5R9K6FW-A18A8YP)
```

## What happened, in order

1. **2c crypto core, tasks 1–4 of 9** — the enrollment code, envelope open, agreement keypair,
   re-seal vault, enrollment probe. Each TDD'd, reviewed, and mutation-proven.
2. **A dependency-verification gap** blocked the build. Ten BOM/parent artifacts were verified
   against Maven Central's published `.sha1`, cross-checked against the bytes Gradle resolved, and
   recorded. The KSP configuration-cache error turned out to be a *consequence* of that failure, not
   a separate bug — no workaround flags are needed anywhere now.
3. **Security audit run-5** (`~/security-audit-skill/kypost-android/run-5/`) — 18 findings, skipping
   the ~100 from runs 1–4. All 18 are now fixed.
4. **The browser half of the two wire breaks**, plus the `enrollment-state` route, on the server
   branch.

## The audit's headline finding, and what is still owed

The enrollment code was **50 bits with no commitment step**, making it forgeable **offline** rather
than by live guessing. An adversary who can write the relay's device table — explicitly in the
design's threat model — grinds a colliding key, or `deviceId`, for a chosen *future* bucket and
waits. Roughly 2^50 SHA-256 compressions: about 14 GPU-hours and a few dollars per 120-second window.

**The spec's own security argument was the bug.** "2^47 in 120 seconds, short of 2^50 with margin"
assumes an *online* bound; refusing future buckets does not stop precomputing *into* one.

Widening to 70 bits is the stopgap that shipped. **The principled fix is still owed** and is recorded
as **decision 8** in `docs/superpowers/specs/2026-08-05-device-enrollment-2c-crypto-core-design.md`:
the browser mints a fresh 128-bit challenge at ceremony start, delivers it to the device, and it
enters the preimage. That caps the attacker at 2^-50 per ceremony and is exactly why Matrix's
*shorter* 36–39-bit SAS is sound. It needs a browser-to-device channel this protocol does not have —
the publish step is device-to-server POST only — so it is a new transport leg, not a constant change.

Do not read 70 bits as making the commitment unnecessary. It makes it **not urgent**.

## Where to resume

**Android — the 2c crypto-core plan is finished.** Tasks 5–9 landed on 2026-08-05: the three
device-authed clients, teardown, the durable WorkManager report, the HLP/wipe wiring, and the
session-scoped plaintext holder. Every task was mutation-proven.

Task 8's note from Task 3's review is **settled**: `HostileLocationEnrollmentTeardownTest` asserts
the pairing survives alongside both keys being gone.

**What is left is the ceremony itself, which is spec 2's UI work.** Nothing in the crypto core has a
caller yet — `EnrollmentClients.publishKey`/`fetchEnvelope` and `EnrollmentSession.put` are written,
tested, and unreferenced by design. The plan defers the orchestrator deliberately: every one of its
failure modes is something the user must be told about. Carry over from the plan's closing note —
tests 7 and 8 from the original handoff (re-registration sending the device secret, and
enrollment-before-identity) belong there and must not be lost.

**Server — nothing blocking.** The `enrollment-state` route is done and mutation-proven.

## Traps this session actually fell into

Each of these cost real time. They are not hypotheticals.

- **A mutation check that verifies nothing.** The device-auth block is byte-identical in all three
  device-authed handlers in `pgp_device_enrollment.go`. A replace-*first*-occurrence mutation edited
  the wrong function, and the target test stayed green — which reads exactly like "this test is not
  load-bearing". It is. Anchor mutations on something unique to the function under test.
- **A green suite proving nothing.** `parseDeviceEnvelope` used `org.json`, which resolves to the
  stubbed `android.jar` in unit tests; with `isReturnDefaultValues = true` every stub returns a
  default, so the function returned null for *every* input and three tests asserting null passed
  against an implementation that validated nothing. Replacing the whole body with `= null` left the
  suite green. It now uses kotlinx.serialization. **That flag is still project-wide** — a future test
  over `TextUtils.htmlEncode` would pass with the escaping neutered.
- **A "red" that was a dead emulator.** `connectedDebugAndroidTest` fails with `No connected
  devices!`, which looks like a failing assertion in grep output. Always confirm the failure is an
  assertion before treating it as evidence.
- **Two implementations of the same prose disagreeing.** The spec said the AAD fingerprint is
  "uppercase hex, no spaces" and only the browser did it; Android's only fingerprint producer emits
  space-grouped hex. Both sides now assert the **exact AAD bytes** — `buildEnvelopeAad` is exported
  in the browser purely so its test can. Prefer a pinned byte assertion on both sides over prose.
- **Fixing one path and missing its sibling.** Most of run-5's non-crypto findings are run-4 fixes
  that closed the reported path only: downloaded attachments were wiped by `SecurityWipe` but not by
  Hostile Location Protection, whose own copy promises it erases them.
- **An assertion on the wrong field.** The plan's own Task 7 test asserted `WorkInfo.progress` was
  empty to prove no credential was in the worker's *input* data. `progress` is empty for every
  worker ever enqueued, and `WorkInfo` has no `inputData` accessor in WorkManager 2.10.1 — so the
  test would have passed against a worker shipping the device secret to WorkManager's plaintext
  database. The request is now built through a separate `buildRequest()` the test reads directly.
  A written plan is not a reviewed test.

## Verification state

- Android: **unit 558/558, instrumented 103/103**, no workaround flags. Emulator `Pixel_10`, Android
  17, TEE-backed. The ten pre-existing `PepperUnavailableException` failures the 2c plan warned
  about are gone — `33dae86` establishes the pepper before reading it — so a failure on this
  emulator is now genuinely yours.
- **One dependency was added:** `androidx.work:work-testing`, `androidTest` only. Two artifacts
  needed recording in `gradle/verification-metadata.xml`, both checked against Google Maven's
  published SHA-1. Without it a WorkManager test enqueues against the real scheduler, which runs the
  worker and fires a live credentialed call from a test.
- Server: **frontend 509/509**, `tsc` clean; **backend** `go build`/`go vet`/`gofmt` clean, full
  suite green.
- **`Cipher.init` against a per-use auth-bound key is verified on TEE only.** The emulator logs
  `StrongBox unavailable, falling back to TEE`. The StrongBox path needs one run on hardware with a
  dedicated secure element before decision 4 is settled.
- **Six fixes carry no regression test of their own** — run-5 findings 4, 5, 6, 7, 15 and 16. The
  audit demonstrated each dynamically before the fix, so the behaviour was proven, but nothing now
  guards it. Finding 6 is the one worth covering first: it is the *default* configuration, and the
  failure mode is the wipe telling the user their data may still be present when it is gone.
- **One known gap in the 2c work.** The HLP teardown tests drive
  `tearDownEnrollmentForHostileLocation`, not the activity's call to it, so deleting that one line
  in `applyHostileLocationProtection` would not turn them red. Instrumenting the toggle needs the UI
  work in spec 2. The `SecurityWipe` side has no such gap — `WipeResurrectionTest` runs the real
  `wipeAndResetApp`.

## Security audit run-5 → run-6

**Run-6** (`~/security-audit-skill/kypost-android/run-6/`) audited the tasks 5–9 delta. Five findings
— 2 MEDIUM, 3 LOW, no HIGH — **all fixed** in `d410827`, `8bf9b44`, `0ecee8e`, `2bcf38e`. Two of the
five were defects in the code written the session before, which is the point of running the audit
against your own fresh work:

- The state report was the **only** device-authenticated request outside the TOFU TLS pin, and it
  fired on the Hostile Location Protection toggle. `EnrollmentClients.callFactory` lost its default
  rather than gaining a better one: a default is what let the omission happen silently.
- `pairingSnapshot(null)` **cannot** unwrap a gated device secret, so the worker's retry branch was
  taken forever with the credential gate on — and the comment saying an unlock would fix it was
  false. The report is now re-driven from the PIN unlock, the only event that makes the secret usable.
- `AppRestart.relaunch` sat outside the `NonCancellable` block in three places, so a Back press
  during the HLP toggle committed the flag and skipped the process reset. Pre-existing since
  `8f37efc`, and now guarded by `runSecurityChangeThenReset` plus a test that cancels mid-change.
- `EnrollmentSession` had not joined the `ProcessScopedState` registry, and `resetAll()` reports only
  registered holders — so the wipe announced Complete over it.
- Unpair and re-pair did not tear the enrollment down; only the wipe and HLP did.

**Three things run-6 rejected, so nobody re-derives them:** `EnrollmentVault.destroy()`'s dead
failure detector is real but harmless (a clean return proves the key alias is gone, so residue is
dead ciphertext); the WorkManager database surviving the wipe discloses nothing that
`hostile_location_settings.xml` does not state more plainly on purpose; and `deviceEnvelopeAad`
accepting U+FB00 is not a bypass, since the AAD is built from the uppercased string.

**Still owed from run-5, and confirmed still open:** run-5 finding 3's second half. `36e7e62` fixed
the "structurally cannot fail" part of the downloaded-attachment step but not the retry part — the
`sharedPrefs` step still deletes `com.urlxl.mail.downloaded_attachments` eleven steps later, so a
resumed wipe finds an empty ledger, passes, and reports **Complete** after having promised a retry.
Reproduced on the emulator. The fix run-5 asked for is still the right one: add the ledger to
`PREFS_NAMES_RETAINED` and delete it explicitly only after the step has succeeded.

## Closed this session, for the record

- PR #80 merged, which also landed the undici bump — **Dependabot alerts on `kypost-server` are now
  zero** (were 2 high, 8 moderate).
- Run-4's supply-chain findings verified genuinely closed: JitPack has a `content{}` filter, its
  artifact is SHA-256 pinned, 601 components pinned with zero exemptions, and the release signing
  guard now keys on exact task names rather than a `startParameter` substring.
