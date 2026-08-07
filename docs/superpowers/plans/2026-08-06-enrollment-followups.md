# Device enrollment: follow-ups

Findings from the final whole-branch review of `feat/device-enrollment-ceremony` (merged as #17)
that arrived **after** the session handoff was written, so nothing else in git records them. None
blocks the merged work; all three are small.

The larger owed items — the end-to-end ceremony (**run and passed 2026-08-06**), the six
unperformed manual checks, the browser-side code grouping, the latent `EnrollmentVault` staleness — are in
`2026-08-06-session-handoff-ceremony-spec-and-audit-run-6.md` and
`2026-08-06-handoff-server-code-grouping.md`. This file is only the remainder.

## 1. Two comments the final fix wave made false

The wave that fixed the stale-code bug corrected the copy in two places and missed a third and
fourth. Both are comment-only.

**`app/src/main/java/com/urlxl/mail/pgp/EnrollmentUiState.kt`** — `WaitingTimedOut`'s KDoc still
says the code on screen "stays valid and the user does not have to re-read it." That was true before
`poll()` learned to re-derive on resume; it is now false, and `strings.xml`'s
`enrollment_timed_out` was reworded specifically to retract the same claim. This is the one a future
implementer reads first, because it sits on the type.

**`app/src/main/java/com/urlxl/mail/security/SecuritySettingsActivity.kt`** — the comment justifying
`withContext(SecurityWork)` around `AndroidIdentitySource.check()` explains that `check()` does its
pairing read *before* its own `withContext(Dispatchers.IO)`, so wrapping only the network fetch would
miss it. The same commit made `check()` wrap its whole body, so that comment now describes code that
no longer exists. The outer wrap is still correct — just no longer for the stated reason.

## 2. ~~The stale-code fix has no regression test~~ DONE

`EnrollmentCeremony.poll()` now resets `shownBucket` on entry so every polling window opens on a
freshly derived code. That closed three reachable states which displayed a dead code under copy
asserting it was live — including `WaitingTimedOut`, whose detail line tells the user the code is
still right while nothing refreshes it.

**Both existing tests pass identically with and without the reset.** `theCodeRecomputesOnTheBucket
BoundaryAndNotBefore` sees the same three emissions either way, because the first window already
starts at `Long.MIN_VALUE`; `checkAgainOpensAFreshWindowAgainstTheSameKeypair` derives its expected
bucket from the emission it receives, so it cannot notice a missing one.

So the fix is the change on this branch most likely to be silently reverted by someone tidying up.

Closed by `aResumedWindowShowsACodeBeforeItPolls`.

**The sketch recorded here was wrong, and worth keeping as a warning.** It proposed advancing the
fake clock past a bucket boundary before `checkAgain()`. That defeats the test: once the boundary is
crossed the bucket genuinely differs from `shownBucket`, so the emission happens *with or without*
the reset. The test has to resume in the **same bucket the window closed in** — which is the case
the reset exists for — and make the envelope arrive on the resumed window's first fetch, so the next
state is `ShowingCode` with the reset and `Opening` without it.

The visible symptom is also not quite what was written above: the screen is left on
`WaitingTimedOut` ("Nothing has arrived in the last five minutes") while a window runs silently
behind it, rather than showing a stale code.

Proven by deliberate break: with `shownBucket = Long.MIN_VALUE` removed, 35 ceremony tests ran and
**only** the new one failed — confirming this file's claim that the two existing tests cannot catch it.

Related, from an earlier review and also done: `FailureReason.NO_DEVICE_KEY` had **four** production
call sites (this file previously said two) and zero tests, unreachable because `FakePorts` hardcoded
`FakeEnrollmentKeys()` with no `minting` override. `FakePorts` now takes `minting`, and
`FakeEnrollmentKeys` takes `vanished` and `encodingFails` — the last two reach the mid-ceremony sites,
where the key is destroyed under a running window exactly as `SecurityWipe` and Hostile Location
Protection can do to a live screen.

Each site has its own test, and each was mutated individually to `SEAL_FAILED` to prove the mapping is
one-to-one. That check is not ceremony: this repo has already shipped a mutation that edited the wrong
one of three identical blocks and left the target test green.

## 3. ~~Awaiting a decision~~ DECIDED: `SealOutcome.Cancelled` no longer shows a code at all

**Ruled and fixed.** Investigating the staleness turned up a larger error underneath it: `Cancelled`
is only reachable *after* `fetchEnvelope` returned an envelope, which means the browser has already
read the code and sealed. So re-emitting `ShowingCode` did not merely risk a stale value — it
instructed the user to redo a step they had finished, while polling had stopped so retyping it
achieved nothing.

The branch now emits a new `EnrollmentUiState.ReadyToFinish`, which carries **no code**: the
outstanding action is a fingerprint, not a transcription. That dissolves the staleness question
rather than patching it — there is no bucket to expire and no countdown to freeze.

Two things fell out of it that the original framing missed:

- The Activity started its **live per-second countdown** for any `ShowingCode`. `render()` already
  carried a comment explaining that a ticking label behind a closed window "would count a dead bucket
  down past zero and then sit on 'about to change' forever" — reasoned through for `WaitingTimedOut`,
  while `Cancelled` reached the same condition through a different state and got the countdown.
- `checkAgainButton` keyed off `ShowingCode || WaitingTimedOut`, so a naive new state would have
  rendered with **no way to resume** — and the screen's only other exit destroys the published key.
  That decision is now the pure, tested `offersCheckAgain(state, idle)`.

The reasoning that follows is kept as the record of what was originally found.

`EnrollmentCeremony`'s `Cancelled` branch re-emits `ShowingCode` with the code and expiry captured
*before* the biometric prompt appeared. If the 120-second bucket rolled while the prompt was up — an
ordinary thing for a user who hesitates — the code is dead and the countdown reads "This code is
about to change" indefinitely, above a detail line instructing the user to type it.

It fails safe: the browser refuses to seal on a mismatch, and "Check again" is visible and now
re-derives. It is also pre-existing rather than introduced by the fix wave, which closed two of the
three stale-code exits and left this one.

The argument for fixing it is the same one that justified fixing the other two: a stale code turns an
entirely honest enrollment into the signal reserved for an attack, and that alarm only works if users
have never been trained to dismiss it.
