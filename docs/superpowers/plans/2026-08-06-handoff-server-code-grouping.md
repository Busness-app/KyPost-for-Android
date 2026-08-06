# Handoff: the browser half of the enrollment code's 4-3-4-3 grouping

**Repository:** `kypost-server` (not this one). **Status: done** — landed as PR #89, merge commit
`097af72`, change `a52a6fd`. Nothing below is owed any more; it is kept as the record of what was
asked for and why. **Size:** two functions, one file each, plus a verification run. Perhaps twenty
minutes — which is roughly what it took.

This was the only unfinished piece of `docs/superpowers/plans/2026-08-06-device-enrollment-ceremony.md`.
The Android half landed on `feat/device-enrollment-ceremony` in commit `f555e51`; the browser half was
deferred because `kypost-server` had uncommitted work in flight on another branch at the time.

Executed as written, with the `.replace("-", "")` trap called out below confirmed real: the old test
would have passed against a broken implementation and failed against a correct one. Verification came
out at 56 passing in the enrollment file (the `formatEnrollmentCode` block at 3, every other block
unchanged), 603 across the full frontend suite, with `tsc --noEmit` and `npm run build` clean.

The two items under "What this does not cover" are still open.

## What is wrong today

The two clients display the same 14-character value differently.

| Client | Displays | Source |
|---|---|---|
| Android | `5R9K-6FW-A18A-8YP` | `app/src/main/java/com/urlxl/mail/pgp/EnrollmentCodeFormat.kt` |
| Browser | `5R9K6FW-A18A8YP` | `frontend/src/lib/deviceEnrollment.ts:202-205` |

The underlying value `5R9K6FWA18A8YP` is identical in both. Only the separators differ.

## Why it is safe today, and why it still needs doing

**It cannot break the ceremony.** `formatEnrollmentCode` has no production call site in the browser —
only tests import it — and `normalizeEnrollmentCode` (`deviceEnrollment.ts:185-189`) strips
`/[\s-]/g` before any comparison, so grouping never reaches the hash. Nothing is broken in the field.

**It still needs doing**, because a display helper sitting ready to be wired up is a future
disagreement between the two screens showing the same code. The moment someone renders with it, the
browser tells the user a differently-grouped string than the phone is showing, and this feature's one
alarm — "the key this server gave the browser is not the key on that device" — is what a confused
user transcription looks like. The alternative is to delete the helper as unused; that is a
legitimate choice, but it should be a decision, not drift.

## The change

### 1. `frontend/src/lib/deviceEnrollment.ts`

Replace `formatEnrollmentCode` (currently lines 192-205, including its KDoc) with:

```ts
/**
 * Group sizes for the displayed code: `5R9K-6FW-A18A-8YP`, not `5R9K6FW-A18A8YP`.
 *
 * At 14 characters, two groups of seven are long runs that are easy to lose your place in. Four
 * groups of at most four is the pattern people already read off bank cards, and short runs make an
 * omitted character visible as a wrong-length group rather than a silently mistyped one. The code
 * is transcribed across two devices, so that is the failure this prevents.
 *
 * The Android client groups identically -- see `EnrollmentCodeFormat.kt` in kypost-android. The two
 * must move together: a display disagreement between the two screens showing the same code reads to
 * the user as the codes not matching, which is this feature's one alarm.
 */
const CODE_GROUPS = [4, 3, 4, 3];

export function formatEnrollmentCode(code: string): string {
  const parts: string[] = [];
  let index = 0;
  for (const size of CODE_GROUPS) {
    if (index >= code.length) break;
    parts.push(code.slice(index, index + size));
    index += size;
  }
  // Anything past the last group is appended rather than dropped. A hardcoded slice is how this
  // function silently truncated the code when CODE_LENGTH grew from 10 to 14 -- and because the
  // short code is a prefix of the long one, the truncated form looked entirely plausible.
  if (index < code.length) parts.push(code.slice(index));
  return parts.join("-");
}
```

`CODE_LENGTH` is no longer referenced by this function. Check whether it is still used elsewhere in
the file before removing anything.

### 2. `frontend/src/lib/deviceEnrollment.test.ts`

Replace the `formatEnrollmentCode` describe block (lines 147-160) with:

```ts
describe("formatEnrollmentCode", () => {
  it("groups as XXXX-XXX-XXXX-XXX", () => {
    expect(formatEnrollmentCode("ABCDEFGHJKMNPQ")).toBe("ABCD-EFG-HJKM-NPQ");
  });

  // The grouping must not drop characters. `.replace("-", "")` removed only the FIRST hyphen --
  // fine when there was one, wrong now there are three -- so this strips every separator the same
  // way normalizeEnrollmentCode does.
  it("never drops characters", async () => {
    const code = await deriveEnrollmentCode(VECTOR_KEY_B64, VECTOR_DEVICE_ID, VECTOR_BUCKET);
    expect(formatEnrollmentCode(code).split("-").join("")).toBe(code);
  });

  // The phone and the browser must show the same grouping of the same value.
  it("matches the Android client on the normative vector", () => {
    expect(formatEnrollmentCode("5R9K6FWA18A8YP")).toBe("5R9K-6FW-A18A-8YP");
  });
});
```

**The `.replace("-", "")` change is the part most easily missed.** `String.prototype.replace` with a
string argument replaces one occurrence. With 7-7 grouping there was exactly one hyphen, so the test
passed; with 4-3-4-3 there are three, and the old assertion fails against a correct implementation.
Changing it is required, not cosmetic.

## Verifying

```bash
cd /home/yoshi/git/kypost-server/frontend
npm ci          # only if node_modules is absent or stale
npm test -- --run deviceEnrollment
```

Expect the `formatEnrollmentCode` block at 3 passing, and every other block in that file unchanged —
`deriveEnrollmentCode`, `normalizeEnrollmentCode`, `buildEnvelopeAad` and `verifyEnrollmentCode` must
not move. If any of those change, stop: this task touches display only.

## Where to do the work

`kypost-server` is currently on `feat/per-user-labels` at `89164e4`, working tree clean. **Do not
commit onto that branch**, and do not `git checkout` in that clone — someone is working in it. Use a
worktree so their checkout is untouched:

```bash
git -C /home/yoshi/git/kypost-server worktree add /tmp/kypost-code-grouping \
    -b fix/enrollment-code-grouping origin/main
```

## Commit message

```
fix(enrollment): group the displayed code 4-3-4-3, matching Android

The helper has no production call site yet -- only tests import it -- so this is
cosmetic today. It is changed rather than deleted because a display helper sitting
ready to be wired up is a future disagreement between the two screens showing the
same code, and that disagreement surfaces to the user as this feature's one alarm.

The 'never drops characters' test stripped with .replace('-', ''), which removed
only the first separator. There are three now.
```

## After it lands

Update `docs/superpowers/specs/2026-08-06-device-enrollment-ceremony-design.md` in `kypost-android`:
its "Server-side change required" section is currently headed **"— still outstanding"**. Change that
to record it as done, and say where.

## What this does not cover

Two other items are owed on the ceremony and are **not** part of this handoff:

- The end-to-end ceremony has never been run against a real browser and relay. The two clients agree
  only by a shared normative vector and unit tests. That is the check that would have caught this
  grouping mismatch in the first place.
- `SealOutcome.Cancelled` in the Android client re-emits a possibly-stale code; the final review
  asked for an explicit decision on it.
