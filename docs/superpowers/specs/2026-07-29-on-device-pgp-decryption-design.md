# On-device PGP decryption for client-custody accounts

> **Status (2026-07-29): deferred behind a cheaper step.** The context-switch
> friction this spec targets is being addressed first with in-app Custom Tabs
> (`docs/superpowers/plans/2026-07-29-webmail-custom-tabs.md`), which removes the
> app switch and the re-login for a fraction of the cost and no new cryptography.
> Build what follows only if measured friction survives that change.
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
in the detail view, a button that hands `/read?mailbox=&message=` to the system
browser (`EmailDetailActivity.kt:276`, `pgp/WebmailDeepLink.kt`).

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
- `EmailDetailActivity.kt:260,276,390` — the `CLIENT_PROTECTED` branches
- `security/AppLockManager` — clear the vault on lock
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
- **Instrumented.** Nothing lands on disk: after unlocking and reading an encrypted
  message, no shared-prefs file, no datastore file and no Room row contains the
  plaintext or the envelope. This is the assertion that keeps the design honest —
  the web vault has the equivalent test for `localStorage`/`sessionStorage`.
- **Manual, against a real client-custody account.** E2E_PGP.md records that
  *nothing* in this mode has been exercised against a real IMAP server or a real
  recipient. This branch should not be the thing that assumes it works: read an
  encrypted message end to end, kill the app, confirm the prompt returns, confirm
  webmail still opens when the user declines.
- **Manual, HLM.** Enable Hostile Location Protection with a vault unlocked; confirm
  the vault is empty afterwards and the app relaunches into a coherent state.
