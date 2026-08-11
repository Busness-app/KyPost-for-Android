# Purpose

Owns the Android app module build, manifest, source sets, resources, and test execution.

# Ownership

- Module: `app/`
- Build contract: `app/build.gradle.kts`
- Runtime package root: `app/src/main/java/com/urlxl/mail/`

# Local Contracts

- Per-device `deviceId`/`deviceSecret` pairing (`X-Kypost-Device-Id`/`X-Kypost-Device-Secret`
  headers, `PairingAuthHeaders.kt`) is the single auth mechanism for every backend call the app
  makes: native push pull, contact sync (`/api/contacts/sync`), groups (`/api/groups`), PGP QR
  token mint (`/api/pgp/qr/token`), PGP bootstrap (`/api/pgp/bootstrap`), mail relay (`/api/inbox`, `/api/inbox/folders`,
  `/api/inbox/actions`, `/api/mail/draft`, `/api/mail/send`), MFA push-respond
  (`/api/mfa/push/respond`), and self-deregistration (`/api/notifications/native/deregister`).
  `deviceSecret` is minted server-side once per successful `POST
  /api/notifications/native/register` call and returned only in that response — the app must
  persist whatever it receives unconditionally, overwriting any prior value, since every
  successful register invalidates the previous secret. No bearer tokens, no cookies, no separate
  mobile login. (Replaces the earlier account-wide `sub`/`hash` shared-secret scheme, which the
  backend removed entirely — no dual-auth fallback.)
- Pairing proof material lives in a Keystore-backed `EncryptedSharedPreferences` file
  (`SecurePairingStore`), not plaintext DataStore — see `app/src/main/AGENTS.md` for the exact
  storage split. Push delivery state and history are plaintext DataStore; the contact-sync cursor
  lives in Room with the contact outbox so acknowledgement is atomic.
- Deep-link contract for pairing is `kypost://native-pair` with required `sub`, `srv`, and
  `pt` params (`reg` optional). `hash` is no longer part of the contract — the per-device secret
  is issued only via the registration response, never carried in the pairing QR/deep-link. The
  legacy `novu-pair` scheme is removed entirely.
- Any URL this app will send pairing credentials to must pass `pairingUrlHost()`
  (`push/PairingModels.kt`): https, non-blank host, and **no userinfo**. The pairing confirmation
  dialog renders that parsed host, never the raw `srv` string — a raw URL in a trust prompt is a
  phishing surface (`https://trusted.example@evil.tld` reads as the trusted host on a wrapped
  dialog), and `kypost://native-pair` is BROWSABLE so any web page can fire it.
- Every response body is bounded by `BodySizeLimitInterceptor` in `pairingHttpClient()`
  (`PairingAuthHeaders.kt`). Add new HTTP clients through that factory rather than bounding reads
  per call site; endpoints that read raw bytes (attachment download) still apply their own tighter
  cap on top.
- `SecurityWipe.wipeAndResetApp` destroys local plaintext **before** any network call, records a
  durable `wipe_in_progress` marker so an interrupted wipe resumes at next launch
  (`enforceTripwire` checks it first), and returns `WipeResult` — never report a wipe as complete
  without checking it.
- `LockedActivity` redirects in `onCreate` (not only `onStart`), so every subclass must
  `if (redirectedToUnlock) return` immediately after `super.onCreate(...)` **and** in every other
  lifecycle callback that touches a `lateinit` view. `onDestroy` is the exception: property
  initializers such as `ioExecutor` exist regardless and still need tearing down.
- The app lock re-engages after `AppLockSettings.graceMillis()` in the background (default 30s,
  user-configurable in Security settings), not instantly — locking on every background transition
  destroyed the compose screen whenever the file picker, QR scanner or webmail handoff was used.
  `ComposeDraftCache` is the in-memory backstop; it is deliberately never written to disk so
  Hostile Location Protection needs no special case.
- MFA approval (`push/MfaApprovalActivity`) must show the sign-in's context (IP, location, user
  agent, time) and, whenever the server supplies `matchDigits`, require a number match instead of
  a bare Approve button. A contentless approval prompt is what MFA-fatigue attacks harvest. All
  context fields are optional on the wire so an un-upgraded server still works.
- Unpairing (`PushHomeViewModel.unpairDevice()`) calls `POST
  /api/notifications/native/deregister` with the device's own credentials before clearing local
  state; the local clear (and periodic pull-worker cancellation) happens unconditionally even if
  that call fails (offline, already-removed).
- Keep app behavior aligned with project goal: paired backend-relay mail, keyword-based tab
  filtering, and two-way contact sync (`contacts/` package). A local Room database
  (`data/AppDatabase`) is the UI's read model for mail and the persistence layer for contacts.
- A push notification tap must force a full inbox resync before opening its target message. The
  Room row may have stale body HTML or `bodyMode`; showing that cached row is fine for the list, but
  opening it before the resync can render the detail screen with the wrong mode.
- Avoid hardcoded secrets in committed files.
- For user-visible behavior changes, update this file or a closer child AGENTS.md.
- Contact autocomplete (ContactAutocomplete.md): `ComposeActivity`'s TO/CC/BCC fields are
  `RecipientInputView`s backed by `ContactDao.search` (name/email substring match, debounced
  150ms, top 5 shown). The address-book icon on the TO row opens `AddressBookSheet`
  (`contacts/` package), a `BottomSheetDialogFragment` offering TO/CC/BCC actions per contact.
  Both surfaces share `RecipientCandidate`/`RecipientField`/matching logic in
  `contacts/RecipientMatching.kt` — extend that file, don't duplicate matching logic in either UI
  layer.

# Work Guidance

- Choose the smallest diff that fixes root cause.
- Reuse existing classes and Android components before adding new abstractions.
- Keep background behavior explicit; document Android lifecycle limits.
- Mark intentional ceilings with `ponytail:` comments and upgrade path.

# Verification

- Run unit tests for logic changes under `app/src/test/`.
- Run unit tests for push parser/mapper changes under `app/src/test/`.
- Run Android instrumentation tests when UI/manifest behavior changes under `app/src/androidTest/`.

# Child DOX Index

- `app/src/main/` — Production Android code and resources. See [app/src/main/AGENTS.md](src/main/AGENTS.md).
- `app/src/test/` — JVM unit tests for deterministic app logic. See [app/src/test/AGENTS.md](src/test/AGENTS.md).
- `app/src/androidTest/` — Instrumented device/emulator tests. See [app/src/androidTest/AGENTS.md](src/androidTest/AGENTS.md).
