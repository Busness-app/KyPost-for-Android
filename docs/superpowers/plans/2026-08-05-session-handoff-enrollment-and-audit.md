# Session Handoff — device enrollment 2c, security audit run-5, and the wire v2 break

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

**Android — 2c plan tasks 5–9**, in `docs/superpowers/plans/2026-08-05-device-enrollment-2c-crypto-core.md`:
the three device-authed clients, teardown, the durable WorkManager report, the HLP/wipe wiring, and
the session-scoped plaintext holder. Tasks 1–4 are done and reviewed.

Task 8 carries a note from Task 3's review: **re-check that `EnrollmentVault.destroy()` leaves
pairing state untouched** once it is actually wired in. Hostile Location Protection destroys the
envelope but deliberately keeps the device paired.

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

## Verification state

- Android: **unit 535/535, instrumented 95/95**, no workaround flags. Emulator `Pixel_10`, Android
  17, TEE-backed.
- Server: **frontend 509/509**, `tsc` clean; **backend** `go build`/`go vet`/`gofmt` clean, full
  suite green.
- **`Cipher.init` against a per-use auth-bound key is verified on TEE only.** The emulator logs
  `StrongBox unavailable, falling back to TEE`. The StrongBox path needs one run on hardware with a
  dedicated secure element before decision 4 is settled.
- **Six fixes carry no regression test of their own** — run-5 findings 4, 5, 6, 7, 15 and 16. The
  audit demonstrated each dynamically before the fix, so the behaviour was proven, but nothing now
  guards it. Finding 6 is the one worth covering first: it is the *default* configuration, and the
  failure mode is the wipe telling the user their data may still be present when it is gone.

## Closed this session, for the record

- PR #80 merged, which also landed the undici bump — **Dependabot alerts on `kypost-server` are now
  zero** (were 2 high, 8 moderate).
- Run-4's supply-chain findings verified genuinely closed: JitPack has a `content{}` filter, its
  artifact is SHA-256 pinned, 601 components pinned with zero exemptions, and the release signing
  guard now keys on exact task names rather than a `startParameter` substring.
