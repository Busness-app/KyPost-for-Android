# Session Handoff — after the enrollment ceremony landed

**Written:** 2026-08-06, at the end of the session that merged PRs #21–#24 and opened #25.
**Repo:** `kypost-android`. **Read the "Traps" section before picking anything up** — three of them
cost real time in this session and two of them are still live.

## State right now

`main` is at `5966b44`. Verified on main: **637 unit tests**, **113 instrumented tests**, **lint 0
errors**. CI runs both on every push and pull request and is green.

| PR | What | State |
|---|---|---|
| #21 | Record the browser-side 4-3-4-3 grouping as landed | merged |
| #22 | Correct why the emulator script's brace group failed | merged |
| #23 | A dismissed prompt asks for a fingerprint, not the code | merged |
| #24 | Cover the `shownBucket` reset and every `NO_DEVICE_KEY` site | merged |
| #25 | Let Studio sync by trusting sources jars and Gradle's src.zip | **open, unverified** |

## The one thing in flight: PR #25

**Android Studio cannot open this project** without it. Sync fails on dependency verification.

`verification-metadata.xml` pins binaries only, and Studio resolves source artifacts on sync
(`-Didea.gradle.download.sources=true`) so it can offer navigation into dependencies. None of those
verify. The CLI never requests them, which is why CI and `./gradlew` were green throughout while the
IDE was unusable — that asymmetry is the diagnosis, not a coincidence.

Two rounds so far, each found by reading `~/.cache/Google/AndroidStudio2026.1.3/log/idea.log`:

1. `110 artifacts failed verification`, every one a `-sources.jar` → trusted `-sources.jar` and
   `-javadoc.jar` by pattern.
2. `One artifact failed verification: gradle-9.6.0-src.zip` → trusted `.*-src[.]zip` **scoped to the
   `gradle:gradle` component**, so the rule does not extend to any third party publishing that suffix.

**Neither round is verified by me.** A sources-jar resolution cannot be driven from the CLI in this
environment, so the only real test is opening the project in Studio. Round 1 was reported as fixed and
was not — round 2 came out of that. Do not assume round 2 finished the job.

If it fails again: **read the log, do not guess.** Both causes named themselves precisely, including
the exact configuration (`:app:detachedConfiguration2`) and artifact. A third category would look the
same. Search for `Gradle sync failed` and read the lines above it.

The security trade is written into the file rather than left implicit: source archives are never on a
compile or runtime classpath, are not executed by the build, and are not packaged into the APK, so
every artifact that actually runs is still pinned by sha256 and `verify-metadata` stays `true`. The
residual risk is a tampered sources jar showing a developer misleading source beside a correct binary
— deceive-the-reader, not code execution. **The strict alternative** is to drop the whole
`<trusted-artifacts>` block and turn off "Download sources" in Studio's Gradle settings instead. That
choice belongs to whoever owns this repo's supply-chain posture; it should stay a decision, not drift.

## What is next, in order

### 1. Run the ceremony end to end against a real browser and relay

**Never done.** This is the highest-value item by a distance and nothing else on this list comes close.

The two clients agree only through a shared normative vector and unit tests. That is exactly the kind
of agreement that can be mutually wrong, and it already has been: the 4-3-4-3 grouping mismatch
between phone and browser survived both suites, and so did the dismissed-prompt bug fixed in #23. An
end-to-end run would have caught both on the first attempt.

Needs a running relay and a browser, so it cannot be done from a headless session.

Watch specifically for:
- The code the phone displays matching the browser's, character for character, **including hyphens**.
- Dismissing the fingerprint prompt: the screen must now read "Almost done" and offer "Check again",
  **not** show the code again. That is #23's change and it has never been seen by a human.
- Letting a 120-second bucket roll while the prompt is up, then resuming.

### 2. Two comments that are false, one of them newly so

Both verified still wrong against the code as of this handoff.

**`EnrollmentUiState.WaitingTimedOut`'s KDoc** makes two false claims:

- *"the code on screen stays valid and the user does not have to re-read it"* — untrue since `poll()`
  learned to re-derive on resume. `strings.xml`'s `enrollment_timed_out` was specifically reworded to
  retract exactly this, with a comment saying why.
- *"This is the one exit that keeps the keypair"* — **made false by #23 in this session.**
  `ReadyToFinish` also keeps it, and the exit table in `EnrollmentCeremonyExitTest` now says so.

It sits on the type, so it is the first thing a future implementer reads.

**`SecuritySettingsActivity`, the comment justifying `withContext(SecurityWork)`** around
`AndroidIdentitySource.check()` — it explains that `check()` does its pairing read *before* its own
`withContext(Dispatchers.IO)`, so wrapping only the network fetch would miss it. `check()` now wraps
its whole body (`EnrollmentPortsAndroid.kt:41`), so the comment describes code that no longer exists.
**The outer wrap is still correct**, just not for the stated reason. Do not delete the wrap.

### 3. Decide the `EnrollmentVault` staleness

Known and deliberately not patched. `prefs` is `by lazy` per instance, and `EnrollmentTeardown`
destroys through a *different* instance, so a long-lived `EnrollmentVault` can answer from a stale
handle. The test was adjusted to model real usage rather than patching production, and the finding was
ledgered. It needs a ruling: either make the vault re-read, or document that instances are
request-scoped and enforce it.

### 4. The 128-bit browser-minted challenge (decision 8)

The principled fix for the enrollment code's forgeability, recorded in
`2026-08-05-device-enrollment-2c-crypto-core-design.md`. The 70-bit widening that shipped is a
stopgap: it makes the commitment **not urgent**, not unnecessary. It needs a browser-to-device channel
this protocol does not have — the publish step is device-to-server POST only — so it is a new
transport leg and its own piece of work, not a constant change.

### 5. Housekeeping

`.superpowers/sdd/` holds two workspaces totalling ~1.4 MB
(`2026-08-05-device-enrollment-2c-crypto-core`, `2026-08-06-device-enrollment-ceremony`). Every
finding from both is now in git, so they are deletable. Only `progress.md` is tracked.

## Traps this session actually fell into

Each cost real time. None is hypothetical.

- **A green CLI build proves nothing about Studio.** The IDE resolves artifacts the CLI never asks
  for. 637 passing tests and green CI coexisted with a project that would not open.

- **A verification that verified nothing.** To check the emulator script's shell syntax I collapsed it
  with `tr '\n' ' '` and ran `sh -n`. It passed trivially — the script starts with `#`, so collapsing
  made the entire thing one comment. The accident was useful: it *disproved* the theory it was meant
  to confirm, because a collapsed script would have failed as command-not-found rather than a brace
  error. The real cause was that the emulator-runner action runs **each line as its own `sh -c`**, so
  no shell state survives between lines. That is now documented in `ci.yml`.

- **`--` inside an XML comment is illegal.** The first `verification-metadata.xml` edit embedded
  `--write-verification-metadata` in a comment and Gradle rejected the whole file with "Dependency
  verification cannot be performed". Useful in one way: it proves any build genuinely parses that file,
  so a syntax error cannot slip through.

- **Duplicating work already in flight.** I wrote a full doc update that PR #21 was already open with,
  because I did not run `gh pr list` first. The existing one was better. **Check open PRs and
  `git worktree list` before starting** — there was a worktree in `/tmp` I had not noticed.

- **A test that cannot fail is worse than no test.** Two branches in this codebase had production call
  sites and tests that passed either way. The follow-up file's own prescription for one of them was
  wrong: it said to advance the clock past a bucket boundary before `checkAgain()`, which makes the
  bucket genuinely differ so the assertion holds with *or without* the fix. Both are now closed and
  each was proven by deliberate break.

- **Mutate one site at a time.** `NO_DEVICE_KEY` had four call sites. Each was mutated individually and
  each killed exactly one test. A single group mutation would have proved nothing — this repo has
  already shipped a mutation that edited the wrong one of three identical blocks and left the target
  test green.

## Still true and still dangerous

`isReturnDefaultValues = true` is **project-wide**. It is what let `parseDeviceEnvelope` return null
for every input while three tests asserting null passed against an implementation that validated
nothing. A future test over anything resolving to the stubbed `android.jar` — `TextUtils.htmlEncode`
is the obvious candidate — would pass with the behaviour neutered. Any new test touching an Android
framework class should be proven by deliberate break before it is trusted.
