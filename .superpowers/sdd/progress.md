# Pairing Auth Headers (Android) Progress Ledger

**Plan:** docs/superpowers/plans/2026-07-19-pairing-auth-headers-android.md
**Base commit:** 3f04899 (includes the plan-doc commit itself)
**Start date:** 2026-07-19

## Tasks

- [x] Task 1: Shared `pairingAuthHeaders()` extension helper
- [x] Task 2: `RelayMailSource.kt`
- [x] Task 3: `ContactSyncClient.kt`
- [x] Task 4: `GroupsSyncClient.kt`
- [x] Task 5: `PullNotificationClient.kt`
- [x] Task 6: `PgpQrClient.kt`

## Notes

- Prior ledger content (contact-sync-intro-popup plan, already merged) removed
  here — preserved in git history (`git log -p -- .superpowers/sdd/progress.md`)
  if needed again.
- Worktree created via `EnterWorktree` (branch
  `worktree-pairing-auth-headers-android`, based on local `main`).
- `app/google-services.json` is gitignored and wasn't present in the fresh
  worktree; copied over manually from the primary checkout before running
  the baseline build (same as noted in the prior plan's ledger).
- `docs/superpowers/plans/2026-07-19-pairing-auth-headers-android.md` was
  untracked in the primary checkout (written during planning, not yet
  committed) and so wasn't present in the fresh worktree either; copied over
  and committed as this branch's first commit (`3f04899`).
- Baseline `./gradlew testDebugUnitTest` passed clean before Task 1 was
  dispatched.

## Completed

- Task 1: complete (commits 67022f4..3d71f8f, review clean, no findings).
- Task 2: complete (commits 3d71f8f..dbc784d, review clean — all 10 call sites individually verified by reviewer, no findings).
- Task 3: complete (commits 540d197..9b7fec5, review clean).
  Minor (deferred to final review): import ordering in ContactSyncClientTest.kt
  (HEADER_SUBSCRIBER_ID before HEADER_SUBSCRIBER_HASH, not alphabetical) — cosmetic.
- Task 4: complete (commits 640c0c4..fdd73e9, review clean, no findings).
- Task 5: complete (commits 9662919..e94db65, review clean — constructor
  retype (OkHttpClient -> Call.Factory) verified backward-compatible with
  PullSyncCoordinator.kt, which stays untouched).
  Minor (deferred to final review): PullResult.BadRequest's kdoc at
  PullNotificationClient.kt:21 still says "sub/hash" (still semantically
  correct, just stale terminology, outside this task's mandated scope).
- Task 6: complete (commits 7364fd8..d744408, review clean, no findings —
  fetchKey independently confirmed untouched). **All 6 coding tasks complete.**

## Final Whole-Branch Review

Ready to merge: With fixes. Reviewer (opus) independently re-audited all
17 production call sites for stray sub/hash query params (grep returned
zero matches), confirmed PullSyncCoordinator.kt untouched and still
compiles against the widened PullNotificationClient constructor, confirmed
fetchKey/MfaResponseClient/NativeRegistrationClient completely untouched,
and confirmed no credential-leak path remains anywhere in app/src/main.
One recommended fix: stale "sub/hash" terminology in
PullNotificationClient.kt (kdoc line 21 + runtime message line 76) — fixed
as a 7th commit (47f6cd7), controller-verified independently (grep zero
matches, build clean, commit touches exactly the intended file). Import-
ordering Minor in ContactSyncClientTest.kt left as-is per reviewer's
explicit ruling (cosmetic, unenforced by tooling).

# Deep-Link Scheme Rename Progress (llamalabels:// -> kypost://) - kypost-android portion

**Plan:** /home/yoshi/git/kypost-server/docs/superpowers/plans/2026-07-19-deep-link-scheme-rename.md (Task 2)

Task 2 (kypost-android): complete (commits 45e4d45..ac02c6c, review clean; controller fixed a phantom-scheme wording bug the implementer correctly flagged in app/src/main/AGENTS.md rather than guessing at; gradle test/build both pass, 10/10 parser tests; unrelated .artifacts/ uncommitted changes confirmed untouched throughout)

# Remaining Llama Naming Cleanup Progress (kypost-android)

**Plan:** docs/superpowers/plans/2026-07-19-llama-naming-cleanup.md
**Start date:** 2026-07-19

## Tasks

Task 1: complete (commits ac02c6c..fbfdb23, review clean; implementer fixed one undocumented comment miss within the already-in-scope KyPostUnifiedPushService.kt)
Task 2: complete (commits fbfdb23..3ef2fe6, review clean)
Task 3: complete (commits 3ef2fe6..00a4af3, review clean)
Task 4 (final sweep): complete - zero remaining llama references, gradle build/test clean

## ALL 4 ANDROID CLEANUP TASKS COMPLETE - dispatching final whole-branch review

## FINAL WHOLE-BRANCH REVIEW: Ready to merge/close out - no issues found

## ALL TASKS COMPLETE (kypost-android llama naming cleanup) ✅

# Security/Keyword Spacing + Push Data-Leak Warning Progress

**Plan:** docs/superpowers/plans/2026-07-22-security-keyword-spacing-push-warning.md
**Base commit:** aa4d3f2 (includes the plan-doc commit itself)
**Start date:** 2026-07-22

## Tasks

- [ ] Task 1: dp-scaling + warning-callout helpers in AppTheme.kt
- [ ] Task 2: Space out SecuritySettingsActivity + add push data-leak warning
- [ ] Task 3: Space out KeywordSettingsActivity

## Notes

- Worktree created via `EnterWorktree` (branch `worktree-security-keyword-spacing`, based on local `main`).
- `app/google-services.json` is gitignored and wasn't present in the fresh worktree; copied over manually from the primary checkout before running the baseline build.
- Baseline `./gradlew :app:testDebugUnitTest` passed clean before Task 1 was dispatched.
