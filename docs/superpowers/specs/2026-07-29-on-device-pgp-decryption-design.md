# On-device PGP decryption for client-custody accounts

> **Status (2026-07-29): deferred behind a cheaper step.** The context-switch
> friction this spec targets is being addressed first with in-app Custom Tabs
> (`docs/superpowers/plans/2026-07-29-webmail-custom-tabs.md`), which removes the
> app switch and the re-login for a fraction of the cost and no new cryptography.
> Build what follows only if measured friction survives that change.
>
> **Update (2026-08-04): the gating step has shipped.** Custom Tabs merged at
> `e42ad96` and is an ancestor of the current branch, so the condition above is
> live and **unmeasured**. The open question is no longer a design one. It is
> whether client-custody users still report friction now that the handoff stays
> inside the app and keeps its session. Take that measurement before building any
> of what follows — the levers below trade real posture for convenience, and
> there is no point paying that price for friction that Custom Tabs already
> removed.
>
> Two corrections to the reasoning below, found while planning that work:
>
> - On-device decryption is **not** an offline win. Ciphertext is fetched per
>   message from `/api/mail/pgp-payload`, so it needs the network regardless.
> - It may **increase** passphrase prompts rather than reduce them. The web vault
>   holds the unwrapped key for the life of the page; an Android vault clears on
>   app lock, `onTrimMemory` and process death.

## Why this exists

A client-custody account's private key is wrapped under a secret the relay does
not hold, so the server refuses to decrypt and sends `pgpEncrypted: true` with an
empty `pgpDecryptError` and no body. `kypost-android` renders that as a 🔒 row and,
in the detail view, a button that opens `/read?mailbox=&message=` — since
`e42ad96`, in a first-party Custom Tab rather than the system browser, falling back
to an external browser only when no Custom Tab provider is available
(`EmailDetailActivity.kt:425-443` via `pgp/openWebmail`, `pgp/WebmailDeepLink.kt`).

The friction that motivates this work is **context switching**, and only that.
Server-custody accounts read encrypted mail in the app already and feel nothing.
Client-custody users leave the app for every encrypted message. The segment is
expected to be small, vocal, and security-conscious — the people least willing to
accept a posture downgrade in exchange for convenience.

The goal is to make the E2E path less clunky **without** making mail recoverable
from a stolen device.

## The constraint that shapes everything

`kypost-server/docs/E2E_PGP.md` already analysed this and rejected an on-device
key. The reasoning holds and is worth restating, because it rules out the obvious
design:

> A phone pairs by QR or deep link and never learns the account password. The
> wrapped envelope is sealed under a key derived from that password, so unwrapping
> on device means introducing password entry on the least-trusted device.

And, explicitly:

> A device key held in the Keystore/Keychain makes mail recoverable without any
> user secret, which is the property "Cold start" exists to remove.

So the design of "download the key once, store it in `EncryptedSharedPreferences`,
unlock it with a PIN or biometric" is **not** an option. Keystore-wrapped material
is recoverable by anything running as this app on an unlocked device; it converts
E2E into server-custody with a stolen-phone attack surface bolted on. Biometric
gating does not fix it — biometrics authorise access to a key that already exists,
they do not reconstitute one from a secret only the user knows.

The real cost of on-device decryption is therefore **not** key-at-rest. It is that
someone has to type the vault passphrase into a phone. That is the whole trade,
and it is the thing to design around.

## What we build

Fetch the wrapped envelope, unwrap it in memory with a passphrase the user types,
decrypt per message, and never write either the envelope or the unwrapped key to
disk.

### Nothing is persisted

`GET /api/pgp/bootstrap` already returns `wrappedPrivateKey` on every call and is
`withMailAuth`, so paired-device credentials authenticate it — no session cookie,
no new endpoint. The app refetches the envelope at each cold start instead of
storing it.

This is not merely tidy. It means:

- Hostile Location Protection needs **no new wipe step**. There is nothing on disk
  to wipe, under HLM or otherwise, so the "turning on HLM must wipe the key"
  requirement is satisfied structurally rather than by remembering to add a step to
  `SecurityWipe`. Compare `PREFS_NAMES_RETAINED`, whose comment records what
  enumeration-by-memory costs.
- `data_extraction_rules.xml` needs no new exclusion. Both `<cloud-backup>` and
  `<device-transfer>` already exclude every domain, and the key is not in a domain
  regardless.
- A stolen device yields nothing. Cold start is a full reload, exactly as the web
  vault behaves.

The cost is one extra HTTPS round trip per launch for client-custody accounts, on
a call the compose path already makes.

### The vault

`PgpVault` — a process-scoped `object` holding the unwrapped secret key ring, which
registers itself with `ProcessState` (`ProcessScopedState.kt`) from its initialiser,
so `InMemoryPlaintext.clearAll()` reaches it without anyone having to remember it
exists. It is cleared on:

- security wipe and unpair — via the registry, automatically
- **app lock** — an explicit new hook. Note that `InMemoryPlaintext` is deliberately
  *not* called from `AppLockManager.lockNow()` (its KDoc explains why: the draft
  cache must survive an ordinary lock). The vault has the opposite requirement, so
  it needs its own call at lock, not a change to that policy.
- `onTrimMemory`
- an idle timeout (see Lever A)

### Unwrapping

The envelope is self-describing — `kdf`, `iterations`, `salt`, `iv` — and clients
are required to derive from what the blob says rather than hardcoding 600,000, so
the server can move to Argon2id later without stranding devices.

`javax.crypto` covers it: `SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")`
then `Cipher.getInstance("AES/GCM/NoPadding")`. No new dependency.

Do **not** route this through `security/CredentialCipher.kt`. That type derives a
PIN-wrapping key with fixed 150,000 iterations plus a Keystore pepper, which is the
right construction for a device-bound secret and the wrong one here — the
parameters must come from the envelope, and a Keystore pepper would bind the result
to this device, which the envelope must not be.

### Decrypting

`bcpg-jdk18on` is **already a dependency** (`gradle/libs.versions.toml:61`), used
today only by `pgp/PgpFingerprint.kt`. Decryption and signature verification are
new code against a library already on the classpath.

Ciphertext comes from `GET /api/mail/pgp-payload?mailbox=&messageId=<uid>`
(`kypost-server/backend/internal/api/pgp_client_read.go`), which also returns
`signerPublicKeys` so a signature verdict does not wait on a contacts sync. It is
`withMailAuth`. The verdict must come from the local decrypt, not from the server's
`pgpVerified` field, which is meaningless for an account the server cannot read.

The decrypted part is PGP/MIME, so it needs MIME parsing — `angus.mail` is already
a dependency.

Decrypted bodies go to the existing `EmailDetailActivity` WebView, which already
runs with JavaScript off, `blockNetworkLoads`, no file or content access. They are
**not** written to the Room cache: a decrypted body on disk is the disclosure this
whole mode exists to prevent, and the server takes the same position for
`mailcache.json`.

### Attachments

The body is not the only plaintext a decrypted message produces, and the existing
policy sends the rest of it to the wrong place. `security/AttachmentAction.kt`
decides between an ephemeral view and a public-Downloads save on **one** input:

```kotlin
fun attachmentActionFor(hostileLocationProtectionEnabled: Boolean): AttachmentAction =
    if (hostileLocationProtectionEnabled) AttachmentAction.VIEW_EPHEMERAL else AttachmentAction.SAVE_TO_DOWNLOADS
```

So for any client-custody account **not** running Hostile Location Protection —
the default — tapping an attachment on a locally-decrypted message writes E2E
plaintext into shared MediaStore, outside the app sandbox, where no wipe short of
`DownloadedAttachmentLedger.deleteAll` reaches it. That is a worse disclosure than
the Room cache this design already refuses, and it happens on a single unprompted
tap: `SecurityWipe`'s `downloadedAttachments` step notes that saving is "a single
unprompted tap in the default configuration".

`attachmentActionFor` therefore takes a second input — whether the attachment came
from a message this device decrypted locally — and returns `VIEW_EPHEMERAL` when
it did, regardless of the HLM flag. It stays a pure function so the rule keeps its
JVM test, in the same style as `pgpMessageStateOf`.

This is a **block, not a warning**. The plaintext of a message the server itself
cannot read must not be one confirmation dialog away from the Downloads folder,
and `EphemeralAttachmentProvider` already exists for exactly this path — its KDoc
describes itself as "the one path whose entire purpose is that this is how you
open an attachment under Hostile Location Protection".

### The unlock prompt

At the first PGP operation after the vault is empty, not at launch — a user who
never opens encrypted mail is never asked. The `CLIENT_PROTECTED` branch in
`EmailDetailActivity` gains an "Unlock to read here" action alongside the existing
webmail button rather than replacing it; webmail stays the fallback when the user
declines, when the envelope is absent, or when a decrypt fails.

## The levers

These are the friction/posture dials, listed so they are chosen deliberately rather
than defaulted into.

**Lever A — vault lifetime.** How long the unwrapped key survives in memory. Cleared
on app lock and `onTrimMemory` at minimum; an idle timeout on top is a setting with
a real cost either way. Shorter means more typing; longer means a longer window in
which a live process holds the key.

**Lever B — biometric re-admit.** Biometrics may gate *access to a vault that is
already unwrapped in memory* within a session. They may never reconstruct one from
stored material — that is Lever B collapsing into the rejected design. This
distinction is the one most likely to be eroded by a later "for convenience" change,
so it belongs in the code comments, not just here.

**Lever C — a separate PGP passphrase.** The largest posture win available. It is a
**browser** change plus a small server flag — not server cryptography. The server
holds only a scrypt hash of the password and cannot derive the wrapping key, so it
cannot rewrap anything; `frontend/src/lib/keyVault.ts` does the wrapping and `POST
/api/pgp/identity/rewrap` merely stores the resulting blob. That endpoint is
`withAuth` (session only) and `run4_security_fixes_test.go:334` asserts a paired
device cannot call it, so rewrapping from the phone is closed off by design.

Today the envelope is wrapped under the account password, so typing it on a phone
exposes the credential that also gates web login and admin — which is the objection
E2E_PGP.md raises. Rewrapping under an independent passphrase decouples those blast
radii: a compromised phone costs the mail, not the account. The envelope is
versioned, `POST /api/pgp/identity/rewrap` already exists, and users who imported a
passphrase-protected key expect a separate passphrase anyway (E2E_PGP.md notes the
Qt clients need copy explaining that it is *not* separate). It requires a matching
change in the web vault, so it is a cross-repo decision, not an Android one.

Worth doing on its own merits regardless of Android: `E2E_PGP.md` lists "admin
password reset destroys the key" as an inherent cost of the model. It is inherent
only because the wrapping secret *is* the account password. Under a separate
passphrase, a password reset stops touching the key.

**Recommendation:** ship Levers A and B with conservative defaults; treat Lever C as
a prerequisite discussion with the server side, because shipping password entry on
the phone without it is the part of this design that genuinely weakens something.

## Accepted, gated: a device-sealed envelope

Raised 2026-08-04, rejected the same day, and **accepted on 2026-08-05 as a user-visible
choice gated behind Hostile Location Protection.** The original rejection and the reasoning
that overturned it are both kept below, because the objection was not wrong — it was
outweighed, and a later reader needs to see the trade rather than assume the concern was
never raised.

It is the design a hardware keystore invites, and it is more interesting than the
naive "store the key in `EncryptedSharedPreferences`" version this spec already
rejects.

**The shape.** The phone generates an EC P-256 keypair with `PURPOSE_AGREE_KEY`,
`setIsStrongBoxBacked(true)` where the hardware allows, private half non-extractable
from the secure element. It publishes the public half to the server under its
existing pairing credential. The browser — which already holds the unwrapped key —
does ECDH against an ephemeral keypair, seals the private key into a *device
envelope*, and uploads it. The phone re-seals that under a StrongBox AES-GCM key
carrying `setUserAuthenticationRequired`, and the server drops its copy. No
passphrase is ever typed on the phone, the account password never reaches the
device, and revocation is per-device.

`minSdk = 31` makes this buildable: `PURPOSE_AGREE_KEY` landed in API 31, so ECDH
in the Keystore is available on every supported device.

**The objection, which stands on its own terms.** It fails the same test as the design in
"The constraint that shapes everything", and the argument there is worth re-reading rather
than re-deriving: biometrics and device credentials *authorise access to a key that
already exists*; they do not reconstitute one from a secret only the user knows.
An envelope openable by the secure element is openable by anyone who can satisfy
the device's own unlock — a shoulder-surfed PIN, a compelled fingerprint, a
coerced unlock at a border. Cold start stops being a full reload.

**Why it is accepted anyway (2026-08-05).** The objection describes a real downgrade, but
it was being weighed against the wrong baseline. The alternative to a device envelope is
not "the user has client custody and types a passphrase" — it is "the user never leaves
server custody at all", because the friction is what keeps them there. Measured against a
**server-held secret**, a secure-element envelope the user controls is a large improvement,
and it is the one that makes removing server custody adoptable. Preserving cold-start
purity for the few who would accept the friction, at the cost of leaving the many on
server-held keys, is the worse trade.

So the downgrade becomes an explicit user choice rather than a designed-in default, and
the threat the objection describes gets its own switch.

**The gate: Hostile Location Protection.** The coerced-unlock and border-stop scenarios the
objection names *are* the hostile-location case, and this app already has a control for it.

- **HLP off (the default):** the device envelope is available. The user may enroll, and may
  un-enroll at any time.
- **HLP on:** no device envelope. Enrollment is unavailable, and **enabling HLP must destroy
  any envelope that already exists**, alongside the on-disk database it already deletes.

That last clause is load-bearing and easy to miss. `HostileLocationSettings.setEnabled`
is deliberately written *after* the on-disk database has been deleted, and uses `commit()`
rather than `apply()` so a process death cannot leave the flag off while the user believes
protection is on. The enrollment envelope and its keystore key must join that same teardown
and obey the same ordering. An envelope surviving the switch would leave the account's
private key openable by device unlock on a device whose owner has just declared they are
somewhere hostile — precisely the disclosure HLP exists to prevent, and worse than the one
this section originally objected to.

**Lever C remains the better answer for users who want both.** The device envelope exists
to avoid typing the *account password* on a phone. Rewrapping under a separate PGP
passphrase removes that objection without giving up cold-start. It is complementary here
rather than superseded: it is what an HLP-on user should be offered.

**The handshake needs a user-verified short authentication string, and that is not
polish.** This was a condition of revisiting; it is now a condition of shipping. The
server-side design (kypost-server, `2026-08-04-device-enrollment-design.md`) specifies one
— ten Crockford base32 characters, device displays, browser verifies, browser refuses to
seal on mismatch — which satisfies the first half of what follows. The AAD binding in the
second half is **not** yet specified anywhere and remains outstanding. In client-custody
mode the server is the
adversary. If the browser trusts the server's copy of "this device's public key",
a malicious server substitutes its own, receives the sealed envelope, and opens the
key the mode exists to withhold — silently, with every client behaving correctly.
Both ends must display a fingerprint derived from the device public key for the
user to compare before the browser seals anything, the same out-of-band check
`Client_PGP_Update.md` already asks for on QR key exchange. Bind the device id and
the PGP key fingerprint into the envelope's GCM AAD as well, so a substituted or
replayed envelope fails authentication instead of decrypting into the wrong
account's key.

## Non-goals

- **Encrypted send from the device.** Unchanged: `POST /api/mail/draft` then hand off
  to `/read?mailbox=Drafts`. Signing needs the private key, and while the vault would
  technically have it, sending is a separate surface with its own RFC 5322
  construction requirements and belongs in its own piece of work.
- **Search over encrypted bodies.** Plaintext is never indexed, by construction.
- **Key generation, import, or migration on device.** Webmail keeps those.
- **Server-custody accounts.** Entirely untouched; they have no friction to fix.

## Files

New, in `app/src/main/java/com/urlxl/mail/pgp/`:

- `PgpVault.kt` — process-scoped holder, `ProcessScopedState` implementer
- `PgpEnvelope.kt` — envelope parse + PBKDF2/AES-GCM unwrap (pure Kotlin, JVM-testable)
- `PgpDecryptor.kt` — Bouncy Castle decrypt + signature verification
- `PgpPayloadClient.kt` — `GET /api/mail/pgp-payload`, modelled on `PgpBootstrapClient`
- `PgpUnlockPrompt.kt` — the passphrase sheet

Modified:

- `pgp/PgpBootstrapClient.kt` — surface `wrappedPrivateKey` and `payloadEndpoint`;
  its `PgpBootstrapDto` currently parses two fields and ignores the rest
- `EmailDetailActivity.kt:274,290,425` — the `CLIENT_PROTECTED` branches (line
  numbers refreshed 2026-08-04; the Custom Tabs work moved them)
- `security/AppLockManager` — clear the vault on lock
- `security/AttachmentAction.kt` — the second input described under "Attachments";
  its caller in `EmailDetailActivity` has to pass whether the message was decrypted
  locally
- `res/values/strings.xml`

## Verification

- **Unit (JVM).** Envelope unwrap against a fixture generated by the web
  `keyVault.ts` — the wire format is the contract, and a Kotlin-only round trip
  would pass while disagreeing with the browser. Wrong passphrase, tampered
  ciphertext (GCM tag must fail), and an envelope declaring an unknown `kdf`.
  `pgpMessageStateOf` already has this shape of test.
- **Unit (JVM).** Decrypt a known PGP/MIME message; assert a good signature verifies,
  a bad one reports failure rather than silently rendering.
- **Instrumented.** `PgpVault` registers with `ProcessState` and is empty after
  `InMemoryPlaintext.clearAll()`; empty after app lock; empty after
  `SecurityWipe.wipeAndResetApp`. Follow
  `MfaChallengeTrackerPersistenceTest` / `SecurePairingStoreCredentialGateTest`.
- **Unit (JVM).** `attachmentActionFor` returns `VIEW_EPHEMERAL` for a
  locally-decrypted message with Hostile Location Protection **off**. That is the
  case that is wrong today, so it is the case the test exists for; assert the other
  three combinations too, since the function's whole job is that the two inputs do
  not collapse into one.
- **Instrumented.** Nothing lands on disk: after unlocking and reading an encrypted
  message, no shared-prefs file, no datastore file and no Room row contains the
  plaintext or the envelope. This is the assertion that keeps the design honest —
  the web vault has the equivalent test for `localStorage`/`sessionStorage`.
- **Instrumented.** Extend that sweep to the attachment path: view an attachment on
  a locally-decrypted message with HLM off, then assert public Downloads and
  `DownloadedAttachmentLedger` are both untouched. The body and the attachment leak
  through different code, so a body-only assertion certifies half the property.
- **Manual, against a real client-custody account.** E2E_PGP.md records that
  *nothing* in this mode has been exercised against a real IMAP server or a real
  recipient. This branch should not be the thing that assumes it works: read an
  encrypted message end to end, kill the app, confirm the prompt returns, confirm
  webmail still opens when the user declines.
- **Manual, HLM.** Enable Hostile Location Protection with a vault unlocked; confirm
  the vault is empty afterwards and the app relaunches into a coherent state.
