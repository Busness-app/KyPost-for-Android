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
- Incoming FCM payload parser contract keys are exact: `messageId`, `senderName`, `emailSubject`, `Keywords`.
- MFA push 2FA: an incoming FCM data payload with `type: "mfa_challenge"` and `challengeId` is parsed by `MfaChallengePayloadParser` (distinct from the mail payload parser) and shown via a separate high-importance notification channel (`PushNotificationDispatcher.showMfaChallenge`) with Approve/Deny actions. Actions are handled by `MfaResponseReceiver` (`PendingIntent.getBroadcast`, the only broadcast-receiver-driven notification actions in this app); tapping the notification body instead opens `MfaApprovalActivity`, an in-app fallback for when OEM background restrictions kill the action broadcast. Both paths call `MfaResponseReceiver.respond`, which POSTs to `{serverUrl}/api/mfa/push/respond` via `MfaResponseClient` using the same `sub`/`hash` pairing credential as native register/pull — no new device-auth scheme. The backend enforces that only a push-2FA-enabled account's own paired device can approve its challenge; the mobile side surfaces `403`/`409` responses as toasts rather than treating them as generic errors.
- Push notifications are shown via Android notification channel and copied into in-app history preview.
- Android 13+ notification runtime permission is requested from launcher UI.
- `MainActivity` is a router, not a home screen: it picks `MfaApprovalActivity` (if started from an
  MFA push), `SettingsActivity` vs `InboxActivity` based on whether the active connection mode is
  actually usable (`MailSettings.isConfigured()` for Manual IMAP, device-paired check for Relay)
  and finishes itself. It passes `EXTRA_MESSAGE_ID` from push notifications to `InboxActivity` to
  enable deep-linking directly to a new email. It does not manage pairing, token sync, or push
  history UI — that lives in `push/PushPairingActivity`, reached from the Inbox overflow menu.
- Mail config (IMAP/SMTP host, port, credentials) is persisted in plaintext `SharedPreferences` and
  entered via `SettingsActivity`, only when `MailConnectionMode.MANUAL_IMAP` is selected. Required
  fields: IMAP host, SMTP host, username, password. Ports default to 993 (IMAP) and 587 (SMTP).
  IMAP folder defaults to "INBOX".
- `MailConnectionMode` (`MailSettings.getConnectionMode()`/`setConnectionMode()`) toggles between
  `MANUAL_IMAP` (default — existing IMAP/SMTP flow, unchanged) and `RELAY` (backend-relay mode; the
  device must already be paired via `PushPairingActivity` — no separate mobile login or app-specific
  mail password). Never build UI for `/api/imap/config` fields on mobile — that endpoint is
  cookie-only/web-only; an unconfigured-relay-mode fetch is an empty state, not a form.
- `mail/MailSource` is the abstraction behind both modes: `mail/ImapMailSource` wraps the existing
  `MailGateway` unchanged; `mail/RelayMailSource` calls the six relay endpoints over OkHttp with
  `sub`/`hash` query-param auth (same pattern as `push/NativeRegistration.kt`). `mail/MailRepository`
  picks the active source, writes results into the Room cache (`data/AppDatabase`,
  `EmailDao.replaceFolderSnapshot`), and is what `InboxActivity`/`EmailDetailActivity`/
  `ComposeActivity` call — none of them instantiate `MailGateway` directly anymore.
- PGP state on relay inbox rows: `pgpEncrypted`, `pgpSigned`, `pgpVerified`, `pgpSignerFingerprint`,
  `pgpDecryptError`. All are `omitempty` server-side, so the Kotlin defaults (false/"") are the
  contract for a message with no OpenPGP content, not an unknown state. `pgp.PgpMessageState` is the
  single place the rule lives: `pgpEncrypted` with an EMPTY `pgpDecryptError` means the account's key
  is end-to-end protected — the server holds no key, there is no body, and **this app cannot decrypt
  it**; a NON-empty `pgpDecryptError` means the server tried and failed, which is a different state
  with a real error to show; `pgpEncrypted` with a body means the server decrypted it, which
  `EmailDetailActivity` surfaces rather than rendering silently, because the user should be able to
  tell the server read their mail. Deliberately no on-device private key: the phone pairs by QR and
  never learns the account password that the wrapped key envelope is sealed under (see the server
  repo's `docs/E2E_PGP.md` "Mobile plan"). Do not add one without revisiting that decision.
  `pgpRowMarker` marks inbox rows for the two states that yield nothing readable (🔒 client-protected,
  ⚠ decrypt failed) and deliberately leaves server-decrypted rows unmarked — those open normally, so
  a marker would sit on most rows of a server-mode mailbox carrying nothing actionable. `EmailAdapter`
  also sets a spelled-out `contentDescription` for those two, because screen readers announce emoji
  inconsistently.
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
- Inbox tabs: Manual IMAP mode derives them from IMAP user flags (keywords) attached to messages,
  unchanged (`KeywordTabs`). Relay mode's tabs come from the server's `tabs`/`label` response fields
  instead — the two are genuinely different concepts, not unified into one function.
- Keyword tuning is managed in `KeywordSettingsActivity` and persists hidden/visible keyword headings.
- Theme selection is managed in `ThemesActivity` and uses the shared theme name list based on `theme.ts` palettes.
- Keyword refresh is best-effort every 90 seconds while inbox UI is foregrounded (both connection modes).
- Background keyword staleness is accepted; app catches up on next foreground refresh.
- Use existing lightweight mail transport dependency for direct IMAP/SMTP (Manual IMAP mode only).
- Contact sync (`contacts/` package) mirrors `push/`'s repository+coordinator+singleton-graph shape:
  `ContactSyncClient` (OkHttp, `sub`/`hash` auth) pulls/pushes `/api/contacts/sync`, `ContactSyncRepository`
  applies the delta into Room and reconciles locally-created contacts' server-assigned uid (no
  correlation id in v1 — matched by content/order, see `ContactSyncReconciliation`), and
  `ContactCursorStore` persists a per-subscriber cursor exactly like `PushRepository`'s pull cursor.
  Entry point is the Inbox overflow menu ("Contacts") — the bottom nav's 4 fixed items are untouched.
  CardDAV (the doc's alternative sync surface) has no mobile client — it is web/OS-driven.
- Room (`androidx.room`, `data/AppDatabase`) is a deliberate, user-requested exception to "do not
  add new dependencies unless they reduce overall code size/complexity" below — it's the local email
  and contacts cache. KSP (Room's annotation processor) needs
  `android.disallowKotlinSourceSets=false` in `gradle.properties` to coexist with AGP's built-in
  Kotlin compilation (this project applies no separate `org.jetbrains.kotlin.android` plugin) — a
  known KSP/AGP-9 interaction (google/ksp#2729), not a general opt-out of that migration.
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
