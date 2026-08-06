# Session Handoff — 2c crypto core shipped, audit run-6, and the ceremony spec

**Written:** 2026-08-06. Supersedes `2026-08-05-session-handoff-enrollment-and-audit.md`, whose
headline warning is now **obsolete** — read the next section before anything else.

| Repo | State |
|---|---|
| `kypost-android` | `main` at `ef83939`. PRs #15 and #16 merged. Spec branch `docs/device-enrollment-ceremony-spec` open. |
| `kypost-server` | `main` at `a383542`. The device-enrollment browser half merged in PR #83. |

---

## The previous handoff's headline warning is resolved — do not act on it

The 2026-08-05 handoff leads with *"the 70-bit code and the v2 envelope must ship together… if either
side ships alone, every honest enrollment fails."* **That was true when written and is not true now.**

Both halves are on `main` in both repos:

- `kypost-server` PR #83 merged the v2 envelope and 70-bit code.
- `kypost-android` PR #14 merged the matching half; `origin/main` has `ENVELOPE_VERSION = "2"` and
  `CODE_LENGTH = 14`.

**How this was nearly got wrong**, because the failure is easy to repeat: local clones were stale —
Android `main` was 25 commits behind `origin/main`, server `main` was 79 behind. Reading local `main`
made the constraint look live, and it was asserted three times in this session before a `git fetch`
disproved it. **Fetch before reasoning about cross-repo state.** A handoff describing a cliff is
exactly the document that stops being true without anyone editing it.

## What happened, in order

1. **2c plan tasks 5–9** — the three device-authed clients, teardown, the durable WorkManager report,
   the HLP/wipe wiring, and the session-scoped plaintext holder. Each TDD'd and mutation-proven.
2. **Security audit run-6** (`~/security-audit-skill/kypost-android/run-6/`) — six hunters, six
   adversarial validators, then one fresh verifier per surviving finding. **5 findings: 2 MEDIUM, 3
   LOW, no HIGH.** All five fixed.
3. **PR #15** merged both of the above.
4. **Run-5 finding 3's second half** — confirmed still open, fixed, merged as **PR #16**.
5. **Spec 2 brainstormed and written** —
   `docs/superpowers/specs/2026-08-06-device-enrollment-ceremony-design.md`. Not yet planned.

## Audit run-6, and the two findings that were mine

Two of the five were defects in code written in the session immediately before the audit, which is
the argument for auditing your own fresh work rather than only inherited code.

| Fix | Sev | What |
|---|---|---|
| `d410827` | MEDIUM | The state report was the **only** device-authenticated request outside the TOFU TLS pin — and its only trigger is the HLP toggle, i.e. when the user has declared the network hostile. `EnrollmentClients.callFactory` **lost its default** rather than gaining a better one: a default is what let the omission happen silently, so omitting it now fails to compile. |
| `8bf9b44` | MEDIUM | `AppRestart.relaunch` sat outside the `NonCancellable` block in three places, so a Back press during the HLP toggle committed the flag and skipped the process reset. Pre-existing since `8f37efc`. Now `runSecurityChangeThenReset`, with a test that cancels mid-change. |
| `d410827` | LOW | `pairingSnapshot(null)` **cannot** unwrap a gated device secret, so with the credential gate on the retry branch was taken forever — and the comment claiming an unlock would fix it was false. Re-driven from the PIN unlock now, and bounded at 8 attempts. |
| `0ecee8e` | LOW | `EnrollmentSession` had not joined the `ProcessScopedState` registry, and `resetAll()` reports only registered holders — so the wipe announced Complete over the opened private key. |
| `2bcf38e` | LOW | Unpair and re-pair did not tear the enrollment down; only the wipe and HLP did. The account boundary is the one an exported `kypost://native-pair` link can drive. |

**Three findings investigated and rejected** — recorded in `run-6/findings.json` so nobody re-derives
them:

- **`EnrollmentVault.destroy()`'s dead failure detector.** Real, and harmless: a clean return proves
  the AES alias is gone, so any residue is dead ciphertext. Downgraded to a hardening note.
- **WorkManager's DB surviving the wipe.** Mechanically true, impact nil — the wipe *deliberately*
  re-writes `hostile_location_settings.xml` with `enabled=true` after the sweep, publishing the same
  fact more plainly in a more accessible file, and WorkManager prunes finished rows after 24h.
- **`deviceEnvelopeAad` accepting U+FB00.** Verified exhaustively over U+0080–U+10FFFF as the only
  such codepoint, and still not a bypass: the AAD is built from the *uppercased* string, so it is
  byte-identical to an input of `FF`.

## Where to resume

**Write the implementation plan for spec 2.** The brainstorm is complete and the spec is committed
and self-reviewed; the next step is `superpowers:writing-plans`.

The spec's own sequencing note: **CI is task 1.** It touches no application code, is verifiable
against suites that already pass, and every task after it benefits from a gate that is already green.

## Owed, in rough priority order

1. **CI does not exist in this repository.** `kypost-server` has four workflows; this repo has none,
   so 558 unit and 105 instrumented tests run only when someone remembers. Specified in the ceremony
   design under "CI", including three Android-specific traps: validate the committed wrapper jar,
   never pass `--write-verification-metadata` (it would defeat the 600-component pinning this repo
   already paid for), and give the CI emulator a lock screen or `EnrollmentVault` tests fail
   confusingly.
2. **Patch the browser's `formatEnrollmentCode` to 4-3-4-3.** `kypost-server`,
   `frontend/src/lib/deviceEnrollment.ts`, plus its test at `deviceEnrollment.test.ts:149`. Cosmetic
   only today — the helper has no production call site and `normalizeEnrollmentCode` strips
   separators before comparing — but a display helper ready to be wired up is a future disagreement
   between two screens showing the same code. Also update the *displayed* normative vector in the 2c
   design doc and the previous handoff: `5R9K6FW-A18A8YP` → `5R9K-6FW-A18A-8YP`. The underlying value
   `5R9K6FWA18A8YP` is unchanged; grouping never enters the hash.
3. **Test 7 from the original 2b handoff needs a home** — re-registration sending the device secret.
   It belongs to the registration path rather than the ceremony, so the ceremony spec records it as
   unplaced rather than quietly absorbing it.
4. **Decision 8 of spec 1** — the browser-minted 128-bit challenge. Needs a browser-to-device channel
   this protocol does not have, so it is a new transport leg. 70 bits makes it *not urgent*, not
   unnecessary.
5. **StrongBox is still unverified.** `Cipher.init` against a per-use auth-bound key is proven on TEE
   only; the emulator logs `StrongBox unavailable, falling back to TEE`. Needs one run on hardware
   with a dedicated secure element before spec 1's decision 4 is settled.
6. **Six run-5 fixes carry no regression test** — findings 4, 5, 6, 7, 15, 16. Finding 6 first: it is
   the default configuration and the failure mode is the wipe telling the user their data may still
   be present when it is gone.
7. **Run-6's hardening notes** — six of them, in `run-6/REPORT.md`. The two worth doing: `deleteAll`'s
   sibling `stillResolves` re-queries through the same visibility filter that produced the ambiguous
   answer, and two `SecurityWipe` steps still discard the boolean that is their only failure signal.

## Traps this session fell into

- **A stale clone made a resolved constraint look live.** See the top of this document. Cost: three
  wrong statements to the user about what could be merged.
- **A finding reproduced on real hardware can still have nil impact.** The WorkManager-DB finding was
  proven on the emulator and rejected anyway, because the wipe already publishes the same fact more
  plainly by design. **Reproduction proves the mechanism, not the consequence** — the two need
  separate arguments.
- **A fix commit that names the hole it left.** Run-5 finding 3's remediation had two halves;
  `36e7e62` applied one, and its own commit message *and* the surviving KDoc both described the
  unfixed half as intended behaviour. When code and its explanation agree with each other but not
  with what the user is told, the comment is the thing hiding the bug.
- **Fixing data retention broke test isolation.** Retaining the attachment ledger across a wipe — the
  correct fix — meant one test's undeletable entry poisoned the next test's sweep. The failure looked
  like a bug in the fix and was a missing `@Before`.
- **The verifier caught two errors in my own audit output.** A claimed side effect that the code
  path returns before reaching, and a proposed fix using a variable that does not exist in that
  scope. Phase 6's fresh-agent gate earned its cost.
- **The obvious fix was wrong twice.** For the credential-gate finding, switching to
  `pairingForAuthenticatedCall()` alone would have converted a certain failure into a race, because
  `AppRestart.relaunch` rebuilds `AppLockManager` locked. Adversarial validation caught it before it
  shipped.

## Verification state

- Android `main`: **unit 558/558, instrumented 105/105**, zero failures. Emulator `Pixel_10`, Android
  17, TEE-backed. No workaround flags.
- The ten pre-existing `PepperUnavailableException` failures earlier handoffs warned about are gone
  (`33dae86`), so a failure on this emulator is now genuinely yours.
- Dependencies: `androidx.work:work-testing` was added in PR #15, `androidTest` only, two artifacts
  recorded in `verification-metadata.xml` and independently re-verified during run-6 against Google
  Maven's published SHA-1.
- Run-6 also ran all 278 release-classpath artifacts through OSV: five hits, every one traced to an
  unreachable code path or a version Gradle upgrades away.

## Reference

- Spec 1 (crypto core): `docs/superpowers/specs/2026-08-05-device-enrollment-2c-crypto-core-design.md`
- Spec 2 (ceremony + CI): `docs/superpowers/specs/2026-08-06-device-enrollment-ceremony-design.md`
- Audit run-6: `~/security-audit-skill/kypost-android/run-6/` — `REPORT.md`, `FINDINGS-DETAIL.md`,
  `findings.json`, `architecture.md`
- Prior audit runs 1–5: same directory, `run-1` … `run-5`. **109 confirmed findings across them** —
  read `findings.json` before reporting anything as new.

## Update — the ceremony plan is implemented

`docs/superpowers/plans/2026-08-06-device-enrollment-ceremony.md` executed. CI landed first and both
jobs are green locally: unit `627/627` (0 failures, 0 errors), lint `0 errors / 366 warnings`,
instrumented `113/113`, confirmed on `emulator-5554` (Pixel_10, API 37) with a secure lock screen and
the keyguard dismissed. **Neither job has ever run on GitHub Actions** — the branch has not been
pushed and no PR exists, so `ci-unit` and `ci-instrumented` are unproven in their real environment.
That gap does not close until someone pushes and watches the run.

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
- **The server half of the code-grouping change was never made.** `kypost-server`'s
  `frontend/src/lib/deviceEnrollment.ts` still groups the enrollment code 7-7 (`CODE_LENGTH / 2`),
  while this client now groups it 4-3-4-3. Cosmetic today — the helper has no production call site,
  only its own test imports it, and `normalizeEnrollmentCode` strips separators before comparing —
  but the two clients now disagree about how the same value is displayed. Deferred because
  `kypost-server` had uncommitted work in flight on another branch when this task executed. See the
  spec's "Server-side change required — still outstanding" section for the exact edits owed
  (`formatEnrollmentCode`, its test at `deviceEnrollment.test.ts:149`, and the normative vector's
  displayed form in the 2c design doc and this handoff).
- **All six manual checks from Task 12 are unperformed.** No live backend, account, browser session,
  or enrolled biometric was available. In particular, the end-to-end enrollment against a real
  browser has never been done — the phone-and-browser code agreement is verified only by a shared
  normative vector and unit tests, never by a real ceremony. Whoever picks this up needs a running
  `kypost-server` backend, a test account with a client-protected PGP identity, a browser session
  against it, and a device with an enrolled biometric.
- **A latent bug in `EnrollmentVault`:** it caches its `EncryptedSharedPreferences` in a `by lazy`
  per instance (`EnrollmentVault.kt:40`), while `EnrollmentTeardown.destroy` (`EnrollmentTeardown.kt`)
  runs against whatever instance is handed to it — a *different* instance than the one a caller might
  be holding. An instance held across a teardown performed through another instance reports stale
  state — reading a destroyed enrollment as still present, which is the unsafe direction. Not
  reachable today: all four production call sites construct a fresh `EnrollmentVault` at the point of
  use (`EnrollmentStateWorker.kt:89`, `DeviceEnrollmentActivity.kt:128`, `EnrollmentTeardown.kt:26`,
  `SecuritySettingsActivity.kt:324`), so no long-lived instance is ever held across a teardown in
  production. Found by Task 12's instrumented test. Fixing it means either dropping the `by lazy`
  cache or giving `EnrollmentVault` a way to invalidate it on `destroy()`.
