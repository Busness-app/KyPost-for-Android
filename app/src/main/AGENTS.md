# Purpose

Owns production Android app code and resources.

# Ownership

- Code: `app/src/main/java/com/urlxl/mail/`
- Resources: `app/src/main/res/`
- Manifest: `app/src/main/AndroidManifest.xml`

# Local Contracts

- Launcher supports `kypost://native-pair` deep links and QR pairing for native (non-Novu) push onboarding. The legacy `novu-pair` host (under the old `llamalabels://` scheme) and Novu relay path are removed entirely — the backend no longer serves them.
- Pairing proof material (subscriber id/hash, server URL, registration URL, pairing token, last-known device id, paired-at timestamp) is persisted in a Keystore-backed `EncryptedSharedPreferences` file (`SecurePairingStore`), not the plaintext DataStore used for history/sync.
- FCM token sync goes through the backend's native registration endpoint (`reg` from the pairing QR, or derived as `{srv}/api/notifications/native/register`) — there is no user-editable Server URL setting; `srv` is a required QR field and is always sourced from the QR.
- A device is marked paired only after the native register call returns success (`ok:true`/`synced:true`); a QR scan alone does not pair the device. `503` from the registration endpoint means the backend is missing `PAIRING_SECRET` (a persistent misconfiguration) and is not retried.
- Incoming FCM payload parser contract keys are `messageId`, `senderName`, `emailSubject`, and `keywords`/`Keywords` (either casing is accepted — the server sends the capitalised one, everything else is camelCase).
- MFA push 2FA: an incoming FCM data payload with `type: "mfa_challenge"` and `challengeId` is parsed by `MfaChallengePayloadParser` (distinct from the mail payload parser) and shown via a separate high-importance notification channel (`PushNotificationDispatcher.showMfaChallenge`). The notification carries **no Approve/Deny actions and no challenge detail** — it is tap-to-open only. Notification actions fire from the lock screen with no authentication, which let anyone holding the powered-on device approve a sign-in and bypassed the PIN/biometric/lockout/wipe apparatus entirely; the `MfaResponseReceiver` that backed them has been deleted. The decision happens only in `MfaApprovalActivity`, which re-authenticates via `BiometricPrompt` (`BIOMETRIC_STRONG or DEVICE_CREDENTIAL`) and re-checks `MfaChallengeTracker.isPending` before either button does anything. `MfaResponder.respond` POSTs to `{serverUrl}/api/mfa/push/respond` via `MfaResponseClient` using the same device-id/secret pairing credential as native register/pull. `MfaChallengeTracker` is SharedPreferences-backed, not in-memory: FCM delivers to short-lived processes, so an in-memory record was usually gone before the user tapped. Each challenge gets its own notification id — coalescing distinct challenges onto one id meant answering either cancelled both.
- Push notifications are shown via Android notification channel and copied into in-app history preview. While `AppLockManager.locked` is true, title/text are replaced with a generic string and visibility is `VISIBILITY_SECRET`; while Hostile Location Protection is on, history is held in memory only and never written to the `push_state` DataStore.
- Every screen except `UnlockActivity` and `MfaApprovalActivity` extends `security.LockedActivity`, which redirects to the unlock screen in `onStart` (and `finish()`es, so nothing is left underneath to reveal with Back) and applies `FLAG_SECURE`. Do not extend `AppCompatActivity` directly for a new screen.
- Android 13+ notification runtime permission is requested from launcher UI.
- `MainActivity` is a router, not a home screen: it sends paired devices to `InboxActivity` and
  unpaired devices to `PushPairingActivity`, then finishes itself. It passes `EXTRA_MESSAGE_ID`
  from push notifications to `InboxActivity` to
  enable deep-linking directly to a new email. It does not manage pairing, token sync, or push
  history UI — that lives in `push/PushPairingActivity`, reached from the Inbox overflow menu.
- The device must be paired via `PushPairingActivity` to use relay mail; there is no separate
  mobile login or mail-password form. Never build UI for the server's web-only mail configuration
  endpoints; an unconfigured relay is an empty state, not a form.
- `mail/RelayMailSource` calls relay endpoints over OkHttp with device-id/device-secret headers.
  `mail/MailRepository` writes results into the Room cache (`data/AppDatabase`,
  `EmailDao.replaceFolderSnapshot`) and is what `InboxActivity`/`EmailDetailActivity`/
  `ComposeActivity` call.
- PGP state on relay inbox rows: `pgpEncrypted`, `pgpSigned`, `pgpVerified`, `pgpSignerFingerprint`,
  `pgpDecryptError`. All are `omitempty` server-side, so the Kotlin defaults (false/"") are the
  contract for a message with no OpenPGP content, not an unknown state. `pgp.PgpMessageState` is the
  single place the rule lives: `pgpEncrypted` with an EMPTY `pgpDecryptError` means the account's key
  is end-to-end protected — the server holds no key, there is no body, and whether this device can
  read it depends on its enrollment state, below; a NON-empty `pgpDecryptError` means the server
  tried and failed, which is a different state with a real error to show; `pgpEncrypted` with a body
  means the server decrypted it, which `EmailDetailActivity` surfaces rather than rendering silently,
  because the user should be able to tell the server read their mail.
  **There IS an on-device private key, and this replaced the earlier "deliberately none" contract.**
  The device enrollment ceremony seals the account's PGP private key into a StrongBox/TEE AES-GCM
  envelope with `setUserAuthenticationRequired(true)` (`pgp/EnrollmentVault`), and no passphrase is
  ever typed on the phone — which is what made the old objection ("the phone never learns the
  account password") stop applying. `pgp/EncryptedMessageReader` unseals it through
  `pgp/VaultOpener`, holds it in `pgp/EnrollmentSession` for the configured lock window, and
  decrypts client-protected messages locally. So `CLIENT_PROTECTED` no longer means "cannot be read
  here": it means "not readable here **unless** this device is enrolled and unlocked". Webmail
  remains the fallback for every device that is not.
  Hostile Location Protection destroys the envelope and is the mode in which none of this exists.
  `pgpRowMarker` marks inbox rows for the two states that yield nothing readable (🔒 client-protected,
  ⚠ decrypt failed) and deliberately leaves server-decrypted rows unmarked — those open normally, so
  a marker would sit on most rows of a server-mode mailbox carrying nothing actionable. `EmailAdapter`
  also sets a spelled-out `contentDescription` for those two, because screen readers announce emoji
  inconsistently.
  A failed signature or a CHANGED signer key (`PgpSignatureState.KEY_CHANGED`) outranks both with
  ⚠. `SIGNER_UNKNOWN` deliberately does not mark: it is the ordinary state for a correspondent not
  yet in the address book, and a glyph on most rows carries nothing actionable.
- `PgpSignatureState` has six values, not a verified/unverified pair: `NONE` (unsigned, or no opinion
  expressed), `VERIFIED_CONFIRMED` (a key bound to the sender that the user confirmed out of band —
  the only state that claims identity), `VERIFIED_SEEN_BEFORE` (a bound key still matching its TOFU
  pin, but never confirmed — most keys arrive by Autocrypt harvest, so this claims only continuity,
  "same key as last time", not who they say they are), `SIGNER_UNKNOWN` (no key bound to this sender
  at all — an ordinary correspondent not yet in the address book, a key that rotated before harvest,
  and a forged `From` are locally indistinguishable, so this is not an accusation), `KEY_CHANGED` (a
  key IS bound to this sender and no longer matches its TOFU pin — the one alarm worth raising), and
  `INVALID` (signed, but it does not verify against the bound key). **The client parses no address out
  of the `From` header at all.** `senderAddrSpec` and its helpers were deleted after a differential
  harness found 27 divergences from the server's parser across 111 adversarial headers — worst, an
  RFC 5322 comment like `Bob (Eve <eve@evil>) <bob@x>`, where the client bound `eve@evil` and the
  server binds `bob@x`, letting any contact forge a verified badge for anyone. The server now ships
  `signerKeys` already narrowed to the sender it resolved (`pgp/SignerBinding.signatureStateFor`,
  consumed by `pgp/EncryptedMessageReader`). Do not reintroduce a client-side `From` parser to "wire
  up" that narrowing yourself — a second parser deciding the same binding is exactly the defect that
  was removed. `signerKeyIdsOf` also excludes revoked and expired OpenPGP keys before a signature can
  become a trusted state, and `PgpDecryptor` caps decompressed plaintext at 32 MiB before allocation.
- **The account's own PGP identity is never in the contacts database.** `ContactEntity.pgpKey` — even
  on the self-contact (`isSelf = 1`) — is an ordinary contact field, written only when a key is
  attached to a contact by hand or by the QR scan; the account's real identity lives server-side.
  Two helpers exist because of this and are the only correct readers: `contactHasLinkedPgpKey`
  (badge: self also counts as linked when `pgp.hasPgpIdentity` says so) and
  `pgp.ownFingerprintFromBootstrap` (the fingerprint `PgpKeyActivity` shows beside the user's own
  QR, from `GET /api/pgp/bootstrap`'s `publicKey`, hashed locally by `PgpFingerprint`). Reading
  `contactDao().getSelf()?.pgpKey` for either is the bug both replaced — it is empty for
  essentially every user. Do not source that fingerprint from the QR token instead: `/api/pgp/qr/key`
  is single-use server-side, so fetching our own key with it burns the code being displayed.
  Never render the server's own `fingerprint` field for either side of the exchange; it is a claim
  beside the key with no cryptographic tie to it.
- Client-protected messages offer "Open in webmail" via `pgp.webmailMessageUrl`, which builds
  `{serverUrl}/read?mailbox=&message=` — the same route a web push click uses, so no server change
  backs it. INBOX is sent as an absent `mailbox` param, matching the links the web app builds for
  itself. It is launched as an `ACTION_VIEW` intent so an installed PWA or the user's browser handles
  it, with the session it already has; **never** an in-app WebView, which would share no session and
  would put an account-password field inside this app.
- `MailOutcome.ClientSideNeeded` is relay 409 carrying `clientSideNeeded` on `/api/mail/send` — a
  client-protected account asked the server to sign or encrypt and it refused rather than silently
  sending in the clear. `MailOutcome.RateLimited` is relay 429 with `Retry-After` (the per-device
  lockout); it is mapped in `RelayMailSource.execute`/`downloadAttachment` rather than `mapErrorCode`,
  which cannot see response headers.
- Encrypted send: `MailDraft.sign`/`encrypt`/`allowPickupFallback` reach `/api/mail/send` through
  `toSendWireDto()`, deliberately *not* the shared `toWireDto()` — `/api/mail/draft` ignores them,
  so the draft path stays flagless. `/api/mail/send` has **two** 409s, told apart by which JSON
  field is present, never by status or error prose: `clientSideNeeded` (the account's key is
  client-custody; no re-send helps, hand off to webmail) and `keylessRecipients` (nothing was
  delivered; re-sending the *same* draft with `allowPickupFallback = true` is safe and cannot
  duplicate). Only those two 409s and the 200 are JSON — every other status returns plain text, so
  no decoder runs over it. The recipient preflight is `POST /api/pgp/recipients/check`, never
  `/resolve` (which 409s for every non-client-custody account); it reads contacts only, so
  `hasKey: false` is a lower bound and must never be worded as a promise. The pickup fallback
  stores the message's plaintext on the server for seven days, which is why its confirmation copy
  is fixed in `strings.xml` and is per-message — never a remembered preference.
- Inbox tabs come from the relay's `tabs`/`label` response fields.
- Email bodies carry the relay's `bodyMode` (`html`/`plain`) through the Room cache and into
  `EmailDetailActivity`; plain bodies must be escaped into whitespace-preserving block markup for
  HTML fallback/quoting, while HTML bodies must not be detected by content when the server supplied
  a mode. The detail screen renders known plain bodies in a native wrapping `TextView`, so email
  reading never requires horizontal scrolling.
- Keyword tuning is managed in `KeywordSettingsActivity` and persists hidden/visible keyword headings.
- Theme selection is managed in `ThemesActivity` and uses the shared theme name list based on `theme.ts` palettes.
- Keyword refresh is best-effort every 90 seconds while inbox UI is foregrounded (both connection modes).
- Background keyword staleness is accepted; app catches up on next foreground refresh.
- Contact sync (`contacts/` package) mirrors `push/`'s repository+coordinator+singleton-graph shape:
  `ContactSyncClient` (OkHttp, `sub`/`hash` auth) pulls/pushes `/api/contacts/sync`, `ContactSyncRepository`
  applies the delta into Room and reconciles locally-created contacts' server-assigned uid (no
  correlation id in v1 — matched by content/order, see `ContactSyncReconciliation`), and
  `ContactCursorStore` persists a per-subscriber cursor in Room alongside the contact outbox so
  acknowledgement is atomic.
  Entry point is the Inbox overflow menu ("Contacts") — the bottom nav's 4 fixed items are untouched.
  CardDAV (the doc's alternative sync surface) has no mobile client — it is web/OS-driven.
- Room (`androidx.room`, `data/AppDatabase`) is a deliberate, user-requested exception to "do not
  add new dependencies unless they reduce overall code size/complexity" below — it's the local email
  and contacts cache. KSP (Room's annotation processor) needs
  `android.disallowKotlinSourceSets=false` in `gradle.properties` to coexist with AGP's built-in
  Kotlin compilation (this project applies no separate `org.jetbrains.kotlin.android` plugin) — a
  known KSP/AGP-9 interaction (google/ksp#2729), not a general opt-out of that migration.
- **`kypost_mail.db` is deliberately NOT encrypted at rest.** It is plain SQLite holding every
  cached message body, every contact and every stored PGP key. The app-lock apparatus (PIN, lockout
  ladder, wipe threshold, `AppLockStore`'s tripwire) defends the **UI**; the Android app sandbox is
  what defends the **data**. An attacker with offline filesystem access — root, a hostile backup, a
  forensic image — reads the database directly and none of the lock machinery is in the path. Say
  this plainly rather than implying otherwise: `AppLockStore.tripwire`'s KDoc names "an attacker
  with filesystem access" as in-scope, and it means one who tampers and then *launches the app*,
  which is a much narrower adversary.
  Hostile Location Protection (`security/HostileLocationSettings` → `data/DataGraph` builds Room
  in-memory) is the answer for users whose threat model includes that adversary, at the cost of all
  offline access. SQLCipher was NOT adopted: it is a large native dependency squarely against "do
  not add new dependencies unless they reduce overall code size/complexity" below, and it would need
  a passphrase design (the app-lock PIN is a 10^6 keyspace, so the Keystore pepper would be doing
  all the work), a migration for existing plaintext databases, and rework of the wipe. Revisit that
  decision deliberately rather than drifting into it — and if it changes, this bullet and
  `AppLockStore.tripwire`'s KDoc both move together.
- STYLE_GUIDE.md §7 gaps are closed: `EmailDetailActivity`'s WebView renders the body in the real
  IBM Plex Mono font via a base64-inlined `@font-face` (`AppTheme.ibmPlexMonoFontFaceCss`, backed
  by `assets/fonts/IBMPlexMono-Regular.ttf`) rather than a `file://` base URL, to avoid granting
  untrusted email HTML `file://` origin access. `AppTheme.applyStatusBadgeTheme` is the
  active/inactive status-badge+dot component (mirrors iOS `StatusBadgeView`/Linux `StatusBadge`);
  its only current consumer is `ContactAdapter`, keyed off `ContactEntity.pgpKey` presence — the
  address-book picker (`RecipientRowAdapter`/`RecipientCandidate`) does not project `pgpKey` and
  wasn't wired up. `AppTheme.animateChipColorTransition` (120ms, `FastOutSlowIn`) is the shared
  motion helper; only `applySuccessChipTheme`'s address-book "added" transition uses it
  (`animate = true` param, default `false`) — `applyPillChipTheme`'s checked/unchecked toggle was
  deliberately left un-animated (Chip's own state machine already transitions it; STYLE_GUIDE.md §7
  doesn't require a full pass).

# Work Guidance

- Keep network off the main thread.
- Keep lifecycle-safe polling: start in foreground lifecycle, stop on background lifecycle.
- Prefer immutable model updates for inbox list and keyword tabs.
- Do not add new dependencies unless they reduce overall code size/complexity.

# Verification

- Add or update unit tests in `app/src/test/` for tab computation and filtering logic.
- Add or update unit tests for deep-link parsing, pairing validation, native registration endpoint resolution, payload parsing, and native registration request mapping.
- `SecurePairingStore` (EncryptedSharedPreferences-backed) requires a real Android Keystore and is covered by an instrumentation test in `app/src/androidTest/` instead of a JVM unit test.
- Validate manifest registration when adding activities or permissions.
- Room DAO behavior (e.g. `EmailDao.replaceFolderSnapshot`, contact upsert/delete) is covered by
  instrumentation tests in `app/src/androidTest/` using `Room.inMemoryDatabaseBuilder` (no
  Robolectric dependency in this project — don't add one for this).
- The email `bodyMode` column is additive and requires `MIGRATION_10_11` plus a migration test when
  the schema contract changes again.
- Add or update unit tests for contact-sync reconciliation/delta-merge logic and relay response
  mapping (HTTP status → `MailOutcome`/`ContactSyncOutcome`, and the `to`/`cc`/`bcc`
  comma-string-not-array request shape) under `app/src/test/`.
- Keep the PGP banner rule and the webmail URL as pure functions (`pgp/PgpMessageState.kt`,
  `pgp/WebmailDeepLink.kt`) with JVM unit tests, rather than deriving either inside an Activity —
  the Activity only picks views. Room schema changes need a matching `MigrationTest` case in
  `app/src/androidTest/`; migrations may set SQLite column defaults without the entity declaring
  `@ColumnInfo(defaultValue=…)`, since Room only validates a default when the entity side has one.

# Child DOX Index

- No child AGENTS.md files.
