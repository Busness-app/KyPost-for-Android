# Handoff: reading and writing encrypted mail on the device

**Repo:** `kypost-android`. **Status:** not started. **Size:** reading is a substantial piece of
work; writing is a *separate* one and should not be folded in. See "Two pieces, not one".

This is the largest outstanding item on the project. The enrollment ceremony built the key custody;
this is what makes it worth anything. Today a fully enrolled device still sends the user to webmail
to read an encrypted message, which is exactly the friction the whole programme exists to remove.

---

## Read this before opening the spec

`docs/superpowers/specs/2026-07-29-on-device-pgp-decryption-design.md` is the design document, and
**its "What we build" section is superseded. Do not implement it as written.**

That section specifies fetching `wrappedPrivateKey` from `/api/pgp/bootstrap`, unwrapping it in
memory with a **passphrase the user types on the phone**, and persisting nothing — refetching on
every cold start. It agonises, correctly for its date, over the cost of typing an account password
into the least-trusted device.

That is no longer the shape of this system. The same spec's later section — **"Accepted, gated: a
device-sealed envelope"**, raised 2026-08-04, rejected the same day, accepted 2026-08-05 — describes
the design that actually shipped, and the enrollment ceremony built it in full. The private key is
already on the device, sealed under a StrongBox/TEE AES-GCM key with
`setUserAuthenticationRequired(true)`, and no passphrase is ever typed on the phone.

So the expensive, contentious half of that spec is **already solved**. What remains is to use the key
that is already there.

Read the spec for: the constraint section (still the reasoning behind the whole mode), "Decrypting",
"Attachments", "The unlock prompt", "Non-goals", and the HLP gate. Skip "Nothing is persisted", "The
vault" and "Unwrapping" — those describe the path not taken.

---

## What already exists, verified

| Piece | Where | State |
|---|---|---|
| Sealed private key at rest | `EnrollmentVault` — `stored()` returns `(iv, ciphertext)`, `openCipher(iv)` gives the biometric-gated `Cipher` | done |
| Process-scoped plaintext holder | `EnrollmentSession` — `put`/`peek`/`clear`, registered with `ProcessState` | **done, zero consumers** |
| Enrollment probe | `probeEnrollment` / `EnrollmentStatus` | done |
| Teardown on HLP, wipe, unpair | `EnrollmentTeardown`, `tearDownEnrollmentForHostileLocation` | done |
| Ciphertext endpoint | `GET /api/mail/pgp-payload?mailbox=&messageId=<uid>`, `withMailAuth` | done, server side |
| OpenPGP library | `bcpg-jdk18on`, already a dependency, used today **only** by `PgpFingerprint.kt` | on classpath |
| MIME parsing | `angus.mail`, already a dependency | on classpath |
| The UI state to hook | `PgpMessageState.CLIENT_PROTECTED` → today renders "Open in webmail" | done |

**`EnrollmentSession` having no writer is deliberate, not an oversight.** Decision 6 of the ceremony
spec: populating a process-scoped holder with the account's private key for zero readers is exposure
bought for nothing. **This work is the reader.** Giving it a writer is the point at which that holder
starts earning its registration — and the point at which its clear-on-lock behaviour starts mattering.

---

## Two pieces, not one

**Reading is specified. Writing is an explicit non-goal of that spec**, with a stated reason:

> Signing needs the private key, and while the vault would technically have it, sending is a separate
> surface with its own RFC 5322 construction requirements and belongs in its own piece of work.

That judgement still holds, and it is worth more now than when it was written. Reading is: unseal,
fetch ciphertext, decrypt, parse, render. Writing adds RFC 5322/PGP-MIME **construction**, recipient
key discovery, signing, and a send path that must not silently fall back to plaintext. Those are
different failure modes — a broken read shows an error, a broken write **sends the user's message in
the clear** or signs it with the wrong key.

Do reading first, ship it, then write a design doc for sending. Do not let one plan cover both.

---

## Part 1 — Reading

### The path

1. **Unseal.** `EnrollmentVault.stored()` → `openCipher(iv)` → `BiometricPrompt` → plaintext armored
   key. This is the same seam the ceremony's `VaultSealer` uses in reverse; mirror it as a port so the
   orchestration is a JVM test rather than Activity code.
2. **Hold.** `EnrollmentSession.put(armoredKey)`. Cleared on wipe/unpair via the registry
   automatically, and it must **also** clear on app lock and `onTrimMemory` — see Traps.
3. **Fetch ciphertext.** `GET /api/mail/pgp-payload?mailbox=&messageId=<uid>`. Response:
   `{ messageId, mailbox, encryptedPayload, signaturePayload, body, signerKeys }`.
4. **Decrypt and verify** with BouncyCastle against the held key.
5. **Parse** the PGP/MIME part with `angus.mail`.
6. **Render** into the existing `EmailDetailActivity` WebView — already JavaScript-off,
   `blockNetworkLoads`, no file or content access.

### Rules that are not negotiable

- **The decrypted body never reaches Room.** A decrypted body on disk is the disclosure this entire
  mode exists to prevent, and the server takes the same position for `mailcache.json`. Note
  `EmailDetailActivity` currently assigns `fetchedBodyHtml = content?.html` for reply quoting — a
  decrypted body must not travel that path into a draft cache either.
- **The signature verdict comes from the local decrypt, never the server's `pgpVerified`.** That
  field is meaningless for an account the server cannot read. `PgpSignatureState` already exists and
  already renders; feed it from the local result.
- **`signerKeys` are address-bound on purpose.** Each carries the addresses the address book binds it
  to, and the server's own comment records why: accepting any held key and re-deriving identity from
  User IDs is forgeable, since one key can self-assert two User IDs. Accept a signature only from a
  key bound to the sender being displayed.

### Where it hooks

`EmailDetailActivity.renderPgpBar`, the `CLIENT_PROTECTED` branch. Today it shows "Open in webmail".
The webmail button must stay as the fallback for every device that is not enrolled, is under HLP, or
fails to unseal — this is an added path, not a replacement.

### A dependency worth knowing about before you start

Whether this path triggers at all depends on `pgpEncrypted` being true, and **it is currently wrong
for messages the server has not warmed**. `server_inbox.go` copies the PGP flags off its warmed cache
only, and a client-protected message always has an empty body, so an unwarmed one arrives flagged as
ordinary mail. See PR #26, which added the client-side "nothing to show" notice but explicitly did
not fix the server.

For a blank screen that was cosmetic. For this feature it means **encrypted messages that silently
never offer decryption**. Fix the server side, or at minimum measure how often it happens, before
building on top of the flag.

---

## Part 2 — Writing (needs its own design doc first)

Not specified anywhere yet. What is already on the ground:

- `ComposePgpController` — `composeState()`, `keylessRecipients(addresses)`. Recipient key
  availability is already computed and already rendered in the compose UI.
- `RecipientKeyClient` — key lookup.
- Today's send path for encrypted mail: `POST /api/mail/draft`, then hand off to
  `/read?mailbox=Drafts` in webmail.

The design questions that need answering before code:

1. **What happens when one recipient has no key?** The compose screen already knows
   (`keylessRecipients`), and the preflight's own string warns that discovery also runs at send time,
   so the answer cannot simply be "check up front".
2. **Is a signature required, optional, or implied?** Signing needs a biometric unseal per message,
   or a held session — which is the same lifetime question as reading, with a worse blast radius.
3. **How does a failed encrypt fail?** The one unacceptable outcome is a message sent in the clear
   that the user believed was encrypted. This deserves the same treatment the ceremony gave its exit
   table: enumerate every exit and what the user is told.
4. **PGP/MIME construction.** `angus.mail` can build it; getting the structure exactly right is the
   work, and it is testable on the JVM against a fixed expected byte layout — the same technique the
   AAD used after two implementations of the same prose disagreed.

---

## The gate: Hostile Location Protection

Already built for enrollment and it must hold here too.

- **HLP off (default):** device envelope available, reading and writing available.
- **HLP on:** no device envelope. Enrollment is unavailable and enabling HLP **destroys** any
  existing envelope, alongside the on-disk database it already deletes.

`HostileLocationSettings.setEnabled` is deliberately written *after* the database is deleted and uses
`commit()` rather than `apply()`, so a process death cannot leave the flag off while the user believes
protection is on. Anything this work adds that holds key material must join that same teardown and
obey the same ordering.

---

## Traps

- **`InMemoryPlaintext` is deliberately not called from `AppLockManager.lockNow()`** — its KDoc
  explains why: the draft cache must survive an ordinary lock. The key holder has the **opposite**
  requirement, so it needs its own explicit call at lock, not a change to that policy. Getting this
  backwards leaves the account's private key in memory across a lock.
- **Do not route the unseal through `security/CredentialCipher.kt`.** It derives a PIN-wrapping key
  with fixed iterations plus a Keystore pepper. Right for a device-bound secret, wrong here.
- **`isReturnDefaultValues = true` is project-wide.** It is what let `parseDeviceEnvelope` return null
  for every input while three tests asserting null passed against an implementation that validated
  nothing. Any new test touching an Android framework class must be proven by deliberate break before
  it is trusted. Decryption code that resolves to a stubbed `android.jar` would fail exactly this way.
- **A "red" that is a dead emulator.** `connectedDebugAndroidTest` fails with `No connected devices!`,
  which looks like a failing assertion in grep output. Confirm a failure is an assertion before
  treating it as evidence.
- **Prefer a pinned byte assertion on both sides over prose.** The AAD fingerprint was specified as
  "uppercase hex, no spaces" and only the browser did it. Both ends now assert the exact bytes.

---

## Verification

Reading is not done until an actual encrypted message, sent from webmail, opens on the phone with the
right signature verdict. The two clients agreeing via unit tests and a shared vector is precisely the
kind of agreement that has already been wrong twice on this feature — the 4-3-4-3 grouping mismatch
and the dismissed-prompt state both survived full suites.

**The ceremony has been run end to end and it passed** (2026-08-06, real browser and real phone), so
this work starts from a device that genuinely holds a key rather than from an assumption that it can.
That run is also what surfaced the blank-message bug in PR #26 — the one whose root cause, an
unwarmed `pgpEncrypted` flag, is the dependency named above. Treat the same method as the acceptance
test here: a real message, a real phone, read by a person.

Worth knowing when planning the manual pass: the run did **not** cover dismissing the fingerprint
prompt (the `ReadyToFinish` state added in #23 has still never been seen by a human) or letting a
120-second bucket roll with the prompt up. Both are cheap to fold into the next session at a device.
