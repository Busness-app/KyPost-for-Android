# Reading encrypted mail on the device

**Date:** 2026-08-07
**Repos:** `kypost-server` (Part 0), `kypost-android` (Part 1)
**Supersedes:** the "What we build" section of
`docs/superpowers/specs/2026-07-29-on-device-pgp-decryption-design.md`

This spec covers **reading** encrypted mail on the device. Writing is a separate piece of work with
its own design document; see "Out of scope".

The enrollment ceremony built the key custody. The private key is already on the device, sealed
under a StrongBox/TEE AES-GCM key with `setUserAuthenticationRequired(true)`, and no passphrase is
ever typed on the phone. This work uses the key that is already there.

---

## Relationship to the 2026-07-29 spec

Read that spec for the constraint section, "Decrypting", "Attachments", "The unlock prompt",
"Non-goals" and the HLP gate. **Do not implement its "What we build" section.** It specifies
fetching `wrappedPrivateKey`, unwrapping it with a passphrase typed on the phone, and persisting
nothing. The design that shipped is its later section, "Accepted, gated: a device-sealed envelope".
"Nothing is persisted", "The vault" and "Unwrapping" describe the path not taken.

---

## Out of scope, with reasons

**Writing encrypted mail.** Its own spec. Reading is unseal, fetch, decrypt, parse, render. Writing
adds RFC 5322/PGP-MIME construction, recipient key discovery, signing, and a send path that must not
silently fall back to plaintext. The failure modes differ: a broken read shows an error, a broken
write sends the user's message in the clear.

**Encrypted attachments.** An encrypted message's attachments live inside the decrypted PGP/MIME
tree. They are not reachable through `serveAttachmentDownload`, because the server cannot see them
either. Supporting them means a second attachment source, memory-only bytes, and an audit that none
of it reaches `DownloadedAttachmentLedger` or Room.

> **Reason gate.** Build encrypted attachment support when a user reports having been unable to
> reach an attachment on a message this app decrypted successfully. Until that report exists, the
> cost buys a case nobody has hit. The notice points at webmail, which can already do it.

**Reply, Reply-All and Forward on client-protected messages.** Disabled until an encrypted send path
exists. This is not a UI preference. `POST /api/mail/draft` uploads the draft **to the server**, so
quoting a decrypted body would hand the server the plaintext it was deliberately never given, at one
tap, with no warning.

---

## Part 0 — the server flag and signer provenance

Part 1 is invisible without this. Ship it first.

### 0.1 The PGP flags are dropped for client-protected messages

**The defect.** Two guards gate the PGP flags on `Body != ""`:

- `backend/internal/mailcache/store.go:458` — `Upsert`, existing-UID branch
- `backend/internal/api/server_inbox.go:504` — the delta path's cache write-back

The stated reasoning is *"PGP fields are only ever known alongside a freshly fetched body"*. That
holds for a server-protected account. For a client-protected account it is inverted: a **correct**
classification (`PGPEncrypted = true`) always arrives with an empty body, because the server
deliberately does not decrypt. The flags are filtered out on exactly the messages this feature
exists for.

**How it manifests.** `cache.Sync` creates the entry from `ListOverviews`, which carries no PGP data,
so the entry starts at `PGPEncrypted = false`. The write-back that would correct it is skipped. The
first delta response is still right, because it reads `contents` directly. Every later poll and every
`Updated` row is wrong. INBOX is partly masked, because the poller sets the flag correctly on entry
creation. Non-INBOX folders have no poller and nothing ever corrects them.

On the phone the message then lands in `PgpMessageState.NONE` and renders the "nothing to show"
notice from PR #26. The decryption path is never offered.

**The fix.** Both guards widen:

```
Body != ""  →  Body != "" || (PGPEncrypted && PGPDecryptError == "")
```

Read as: *we know this is encrypted and nothing failed.* That is a stable fact about the message,
independent of whether the body could be read. Decrypt failures stay uncached, which preserves the
real half of the existing comment — a transient failure must not become sticky.

`mailcache` learns nothing about user configuration, per its `AGENTS.md`.

**Not fixed here.** `Snapshot` requires every entry to have a non-empty body before it calls a window
warm, so a client-protected mailbox can never serve the classic path from cache. That is a
performance characteristic, not this defect. Changing it would widen the diff into cache-warming
policy.

### 0.2 Signer keys carry no provenance

**The defect.** The address book already tracks how much a key is worth trusting:

- `contacts.Contact.PGPKeySource` — `manual | qr | wkd | keyserver | autocrypt`
- `contacts.Contact.PGPKeyVerified` — *"user eyeballed the fingerprint / came via QR"*
- `contacts.Contact.PGPKeyFingerprint` — the TOFU pin, enforced by `keyMatchesPin`

The wire struct discards all of it. `boundSignerKey` is `{addresses, publicKey}`.

Two consequences, and **most keys in practice are Autocrypt-harvested**, so the first is the common
case rather than the edge:

1. **A confirmed key and a harvested key are indistinguishable.** Both would render one flat
   "signature verified". TOFU guarantees *continuity* — same key as last time — not *identity*.
   A flat green badge asserts identity on evidence that supports only continuity. This is the error
   `PgpMessageState.BODY_UNAVAILABLE` and `SIGNER_UNKNOWN` each exist to prevent.
2. **A key change is indistinguishable from a stranger.** `keyMatchesPin` correctly excludes a key
   that no longer matches its pin, so there is no false green. But the message then falls into
   "no key bound to this sender", which is also what an ordinary new correspondent produces. Under
   TOFU, "this sender's key changed" is the one alarm that matters, and it would display as the most
   routine possible message.

**The fix.** In `backend/internal/api/pgp_receive.go`:

```go
type boundSignerKey struct {
	Addresses []string `json:"addresses"`
	PublicKey string   `json:"publicKey"`
	Verified  bool     `json:"verified,omitempty"`  // fingerprint eyeballed, or QR
	Source    string   `json:"source,omitempty"`    // manual|qr|wkd|keyserver|autocrypt
	Conflict  bool     `json:"conflict,omitempty"`  // stored key no longer matches its TOFU pin
}
```

`boundSignerKeys` stops discarding `PGPKeyVerified` and `PGPKeySource`, and its `continue` on a pin
mismatch becomes an emit with `Conflict: true`. A conflicted key is **never** offered to the
signature check — it is carried only so the client can say the key changed.

Nothing secret crosses the wire. This is the user's own address book describing itself, and the
public key was already there.

Both `handlePGPPayload` and `handlePGPBootstrap` build `signerKeys` through this function, so both
gain the fields.

---

## Part 1 — on-device decryption

### The path

1. **Unseal.** `EnrollmentVault.stored()` → `openCipher(iv)` → `BiometricPrompt` → plaintext armored
   key, written straight into `EnrollmentSession`.
2. **Fetch ciphertext.** `GET /api/mail/pgp-payload?mailbox=&messageId=<uid>`.
3. **Decrypt and verify** with BouncyCastle against the held key.
4. **Bind the signature** to the displayed sender using `signerKeys`.
5. **Parse** the PGP/MIME part with `angus.mail`.
6. **Render** into the existing `EmailDetailActivity` WebView — already JavaScript-off,
   `blockNetworkLoads`, no file or content access.

### Components

Six units. The orchestrator has no Android imports, following `EnrollmentCeremony`.

#### `VaultOpener` (port)

The mirror of `VaultSealer`.

```kotlin
internal sealed class OpenOutcome {
    object Opened : OpenOutcome()        // key is in EnrollmentSession — not returned
    object Cancelled : OpenOutcome()
    object NotEnrolled : OpenOutcome()
    object NoSecureLockScreen : OpenOutcome()
    data class Failed(val message: String) : OpenOutcome()
}

internal interface VaultOpener {
    suspend fun open(): OpenOutcome
}
```

`Opened` carries no key material. `VaultSealer`'s KDoc states that the sealer owns the ciphertext end
to end "so that no key material passes back through the state machine". The opener is symmetric: it
writes into `EnrollmentSession` itself.

A port rather than a direct call, because `BiometricPrompt` is Activity-bound. This is the seam that
makes "the user dismissed the prompt" a JVM test with a fake instead of an instrumented one.

**This is `EnrollmentSession`'s first writer.** Decision 6 of the ceremony spec deliberately left it
without one: populating a process-scoped holder with the account's private key for zero readers is
exposure bought for nothing. This work is the reader.

#### `PgpPayloadClient`

`GET /api/mail/pgp-payload`, built on `pinnedPairingCallFactory` like every other credentialed call,
following `PgpBootstrapClient` and `RecipientKeyClient`.

Returns a sealed result that distinguishes `NotClientProtected` (409), `TooLarge` (413), `NoPayload`
(404) and transport failure, because each gets a different message to the user.

Response shape:
`{ messageId, mailbox, encryptedPayload, signaturePayload, body, signerKeys }`.

#### `PgpDecryptor`

Pure JVM. No Android imports.

**Use BouncyCastle's lightweight `Bc*` operators, not the `Jce*` ones.** Android ships a stripped
"BC" provider that collides with the full one. The `Bc*` path uses no JCE provider at all, so the
same code runs identically in a JVM test and on the device. `bcprov-jdk18on:1.79` is already on the
runtime classpath transitively through `bcpg-jdk18on`.

Given the `isReturnDefaultValues` trap below, this is the difference between a test that proves
something and one that resolves against a stubbed `android.jar`.

Do not use `android.util.Base64` in this file. Use `java.util.Base64` or BouncyCastle's own armor
stream.

#### `PgpMimeReader`

Decrypted bytes → body, via `angus.mail`.

**`angus.mail` is declared in `libs.versions.toml` and imported by nothing in main source today.**
It is on the classpath, but this is its first actual use in this app, so it carries integration risk.

#### `SignerBinding`

A pure function: `signerKeys` + displayed sender + BouncyCastle's verdict → `PgpSignatureState`.

Accepts a signature only from a key the address book binds to the sender being displayed. The server
comment records why: accepting any held key and re-deriving identity from User IDs is forgeable,
because one key can self-assert two User IDs.

#### `EncryptedMessageReader`

The orchestrator. Sequences the five units above and returns one of the closed set of outcomes in the
exit table.

### Threading

Decrypt and parse run off the main thread, on `MailBackgroundExecutor`, matching `markRead` and the
attachment path. Only the biometric prompt and the render are on the main thread.

### Where it hooks

`EmailDetailActivity.renderPgpBar`, the `CLIENT_PROTECTED` branch. The webmail button stays as the
fallback for every device that is not enrolled, is under HLP, or fails to unseal. This is an added
path, not a replacement.

---

## The unlock model

The key lives for the window the user already configured at "Lock after: …", per `EnrollmentSession`'s
KDoc: the plaintext lifetime is the real exposure, not how often `BiometricPrompt` appears, so it is
bound to a window the user already understands rather than to a second concept of its own.

**When the prompt appears.** Opening a `CLIENT_PROTECTED` message decrypts automatically **when the
key is already held**. When it is not, the PGP bar offers a **Decrypt** button and the prompt follows
the tap.

This keeps the biometric sheet tied to a deliberate action. A prompt that appears on its own can
ambush a user who opened a message by accident, and "the user dismissed the sheet" is then a state
with no action to explain it. It also keeps the fallback ladder legible: not enrolled, under HLP, and
unseal failed all land on the webmail button that exists today.

---

## UI states and the exit table

**Whenever "Open in webmail" is visible, the `emailWebView` is replaced by a padlock placeholder** —
a new `ic_lock_large.xml` vector in a view occupying the body area. The two appear and disappear
together: the padlock means "not readable here", the button means "readable there".

Reply, Reply-All and Forward are **disabled for every `CLIENT_PROTECTED` message**, decrypted or not,
with a notice naming webmail. Consistency matters here: a button that works only after a successful
decrypt teaches the wrong model.

| # | Situation | Body area | Buttons | Told |
|---|---|---|---|---|
| 1 | Not enrolled | padlock | webmail | Encrypted; this device holds no key |
| 2 | HLP on | padlock | webmail | Protection is on; no key on this device |
| 3 | Enrolled, key not held | padlock | **Decrypt** + webmail | Encrypted; can be opened here |
| 4 | Enrolled, key held | spinner → body | — | Decrypted on this device |
| 5 | Biometric dismissed | padlock | Decrypt + webmail | *nothing* — returns to #3 silently |
| 6 | No secure lock screen | padlock | webmail | Needs a device lock screen |
| 7 | Unseal failed (key invalidated) | padlock | webmail | This device needs enrolling again → Security settings |
| 8 | Payload fetch failed | padlock | Retry + webmail | Could not reach the server |
| 9 | 413 too large | padlock | webmail | Too large to open on this device |
| 10 | 409 not client-protected | padlock | webmail | Generic; this is a bug if seen |
| 11 | Decrypt failed | padlock | webmail | Could not decrypt this message |
| 12 | Decrypted | body | — | Decrypted here + signature verdict |

**#5 is silent on purpose.** The ceremony calls its equivalent `Cancelled` and says "Not a failure".
A toast for a sheet the user just dismissed is noise.

**#11 does not clear `EnrollmentSession`.** One message failing to decrypt says nothing about the
held key. Clearing would force a re-prompt for every later message because of one bad payload.

**#2 may be unreachable.** Under HLP the database is deleted, so a cold process reports
`BODY_UNAVAILABLE`, not `CLIENT_PROTECTED` — `PgpMessageState`'s own KDoc says so. The row exists so
the ladder is total, not because it is expected.

---

## The signature verdict

`PgpSignatureState` becomes six states. The verdict comes from the **local** decrypt, never from the
server's `pgpVerified`, which is meaningless for an account the server cannot read.

| State | Meaning | Row marker |
|---|---|---|
| `NONE` | Not signed | none |
| `VERIFIED_CONFIRMED` | Signed by a key bound to the sender, and the user confirmed that key by fingerprint or QR | none |
| `VERIFIED_SEEN_BEFORE` | Signed by a key bound to the sender that still matches its TOFU pin, but was never confirmed out of band | none |
| `SIGNER_UNKNOWN` | Signed, but no key we hold is bound to this sender | none |
| `KEY_CHANGED` | A key is bound to this sender, and it no longer matches its TOFU pin | ⚠ |
| `INVALID` | Signed, and the signature does not verify against the bound key | ⚠ |

Only the two `VERIFIED_*` states carry a positive claim, and they claim different things.
`VERIFIED_CONFIRMED` says the user checked. `VERIFIED_SEEN_BEFORE` says only that this is the same
key as last time — which is worth stating, and is not identity.

`SIGNER_UNKNOWN` gets **no row marker**: the row cannot act on it, and it is the ordinary state for
anyone not yet in the address book. This follows `DECRYPTED_BY_SERVER`, which is unmarked for the
same reason — a symbol on most rows carries no information the user can act on.

`KEY_CHANGED` and `INVALID` keep the `⚠`, and a failed signature still outranks every readability
marker.

### The server-derived verdict still exists, and must not over-claim

`PgpSignatureState` is shared. `pgpSignatureStateOf(pgpSigned, pgpVerified)` is called by
`EmailAdapter` for every inbox row and by `EmailDetailActivity` at line 93, from the two booleans the
relay sends. Those two booleans cannot express six states, and they are the only verdict available
for a **server-protected** account, which this work does not change.

The mapping keeps its existing shape and takes the weaker of the two positive claims:

| `pgpSigned` | `pgpVerified` | State |
|---|---|---|
| false | — | `NONE` |
| true | true | `VERIFIED_SEEN_BEFORE` |
| true | false | `INVALID` |

`pgpVerified = true` maps to `VERIFIED_SEEN_BEFORE`, **never** `VERIFIED_CONFIRMED`. The server's
booleans do not distinguish a fingerprint-confirmed key from an Autocrypt-harvested one, and
asserting the stronger claim on evidence that cannot support it is the whole defect Part 0.2 fixes.
Degrading to the weaker claim is the safe direction.

`VERIFIED_CONFIRMED`, `SIGNER_UNKNOWN` and `KEY_CHANGED` are reachable **only** through
`SignerBinding`, from a local decrypt. This is what "the verdict comes from the local decrypt, never
the server's `pgpVerified`" means in practice: for a client-protected message the local result
replaces the server's, and for a server-protected message the server's two booleans are all that
exist and are mapped conservatively.

An inbox row for a client-protected message has no local verdict, because nothing has been decrypted
yet. It shows the readability marker only.

---

## Rules that are not negotiable

**The decrypted body never reaches Room.** A decrypted body on disk is the disclosure this entire
mode exists to prevent, and the server takes the same position for `mailcache.json`.

**`fetchedBodyHtml` is not assigned from a decrypted body.** That field feeds reply quoting, which
feeds `ComposeDraftCache`, which feeds `POST /api/mail/draft` — the server. Since Reply and Forward
are disabled for `CLIENT_PROTECTED`, the assignment is simply skipped for that state.

**For a client-protected message the signature verdict comes from the local decrypt**, never from the
server's `pgpVerified`, which is meaningless for an account the server cannot read. The server's
booleans remain the only verdict for server-protected accounts and are mapped conservatively — see
"The server-derived verdict still exists, and must not over-claim".

**`signerKeys` are address-bound on purpose.** Accept a signature only from a key bound to the sender
being displayed.

**A conflicted key is never offered to the signature check.** It exists on the wire only so the
client can report `KEY_CHANGED`.

---

## Session lifetime and teardown

`EnrollmentSession` is already registered with `ProcessState`, so a security wipe, `AppRestart.relaunch`
and the unpair purge all clear it through `resetAll`.

`AppLockManager.lockNow()` **already** calls `EnrollmentSession.clear()` (line 98), with a test at
`AppLockManagerTest.kt:289`. No change needed.

**`onTrimMemory` does not exist anywhere in the app.** This work adds it: `KyPostApp.onTrimMemory`
clears `EnrollmentSession`. Note that `InMemoryPlaintext` is deliberately **not** called from
`lockNow()`, because the draft cache must survive an ordinary lock. The key holder has the opposite
requirement. Do not change that policy — add a separate call.

### The Hostile Location Protection gate

- **HLP off (default):** device envelope available, reading available.
- **HLP on:** no device envelope. Enrollment is unavailable and enabling HLP destroys any existing
  envelope, alongside the on-disk database it already deletes.

`HostileLocationSettings.setEnabled` is written **after** the database is deleted and uses `commit()`
rather than `apply()`, so a process death cannot leave the flag off while the user believes
protection is on. Anything this work adds that holds key material joins the same teardown and obeys
the same ordering.

---

## Testing

### JVM tests

Every unit below is Android-free by construction.

- **`PgpDecryptor`** against fixed vectors: a known keypair, a known ciphertext, a pinned expected
  plaintext.
- **`SignerBinding`** — one test per state. Two matter most: an Autocrypt-sourced key yields
  `VERIFIED_SEEN_BEFORE` and never `VERIFIED_CONFIRMED`; a conflict-marked key yields `KEY_CHANGED`
  and never `SIGNER_UNKNOWN`.
- **`EncryptedMessageReader`** — one test per exit-table row, with fakes for the ports. Biometric
  dismissal is a JVM test, exactly as the ceremony made "biometric cancelled" one.
- **`PgpMimeReader`** — decrypted MIME → body, including a plain-text-only part and a
  `multipart/alternative`.
- **`pgpSignatureStateOf`** — the existing server-derived mapping. Pin that `pgpVerified = true`
  yields `VERIFIED_SEEN_BEFORE`, so a later edit cannot quietly promote it to `VERIFIED_CONFIRMED`.
  `PgpMessageStateTest` already covers this function and is where the new cases belong.

### Go tests

- The PGP flags survive an `Upsert` → `Snapshot`/`Sync` round trip for a client-protected message.
- A decrypt-failure entry is still not cached.
- `boundSignerKeys` emits `verified` and `source`, and marks a pin mismatch with `conflict` instead
  of dropping the contact.

### Cross-client agreement

A shared test vector pinning **exact bytes**, asserted on both the Go and Kotlin sides. Not prose.
The AAD fingerprint was specified as "uppercase hex, no spaces" and only the browser did it; the
4-3-4-3 grouping mismatch survived a full suite. Both ends now assert the exact bytes, and this
follows that precedent.

### The acceptance test

An actual encrypted message, sent from webmail, opened on a real phone by a person, showing the right
body and the right signature verdict. Two clients agreeing via unit tests and a shared vector is
precisely the kind of agreement that has already been wrong twice on this feature.

The manual pass covers at minimum:

- a cold session — Decrypt button, prompt, body
- a warm session — opens with no prompt
- a dismissed prompt — returns to the Decrypt button silently
- a lock and return — the prompt comes back
- a message from a correspondent not in the address book — `SIGNER_UNKNOWN`
- a message from a confirmed contact — `VERIFIED_CONFIRMED`

Two cheap additions to fold in at the device, carried from the ceremony run: the `ReadyToFinish`
state added in #23 has still never been seen by a human, and nobody has let a 120-second bucket roll
with the prompt up.

---

## Traps

- **`isReturnDefaultValues = true` is project-wide.** It is what let `parseDeviceEnvelope` return
  null for every input while three tests asserting null passed against an implementation that
  validated nothing. **Every new test must be proven by deliberate break** — invert the assertion,
  watch it fail, restore. Decryption code that resolves against a stubbed `android.jar` would fail
  exactly this way, which is why `PgpDecryptor` uses the `Bc*` operators.
- **Do not route the unseal through `security/CredentialCipher.kt`.** It derives a PIN-wrapping key
  with fixed iterations plus a Keystore pepper. Right for a device-bound secret, wrong here.
- **A "red" that is a dead emulator.** `connectedDebugAndroidTest` fails with `No connected devices!`,
  which looks like a failing assertion in grep output. Confirm a failure is an assertion before
  treating it as evidence.
- **`angus.mail` has never been exercised in this app.** Being on the classpath is not the same as
  being known to work.

---

## Build order

1. Part 0.1 — the flag guards, with Go tests.
2. Part 0.2 — signer provenance on the wire, with Go tests.
3. `PgpDecryptor`, `PgpMimeReader`, `SignerBinding` — pure units, JVM tests, no UI.
4. `PgpPayloadClient` and `VaultOpener`.
5. `EncryptedMessageReader` — the exit table, JVM tests.
6. The UI: padlock placeholder, Decrypt button, the six signature states, disabled Reply/Forward.
7. The manual acceptance pass at a real device.

Steps 1 and 2 ship independently and are worth merging before step 3 begins.
