# Purpose

Owns production Android app code and resources.

# Ownership

- Code: `app/src/main/java/org/kysecurity/mail/`
- Resources: `app/src/main/res/`
- Manifest: `app/src/main/AndroidManifest.xml`

# Local Contracts

- Launcher supports `kypost://native-pair` deep links and QR pairing for native (non-Novu) push onboarding. The legacy `novu-pair` host (under the old `llamalabels://` scheme) and Novu relay path are removed entirely — the backend no longer serves them.
- Pairing proof material (subscriber id/hash, server URL, registration URL, pairing token, last-known device id, paired-at timestamp) is persisted in a Keystore-backed `EncryptedSharedPreferences` file (`SecurePairingStore`), not the plaintext DataStore used for history/sync.
- TLS pinning is TOFU over the **whole certificate chain**, not the leaf. `NativeRegistrationClient` pins every certificate the pairing handshake presented (`TlsPin.spkiSha256` is a `Set`), and every later successful registration refreshes the set (`PushSyncCoordinator.refreshTlsPin`) for the same host. Both halves are load-bearing: pinning only the leaf meant a routine certificate renewal — which mints a new leaf key — matched nothing, failed every call closed, and could only be cleared by unpairing, which deletes the mailbox. A `TlsPin` with an empty set is unconstructible and `pairingHttpClient` refuses one, because `CertificatePinner` passes vacuously when no pin is configured for a host. Installs predating this hold a single leaf pin under the legacy `pair_tls_spki_pin` key; `SecurePairingStore.readTlsPin` carries it forward and the next successful call replaces it with the chain.
- Recovering a credential is NOT unpairing. `PushRepository.resetPairingCredential` drops the pairing proof and TLS pin while keeping mail, contacts and keys; `clearPairing`/`unpairDevice` stay the destructive pair, for a deliberate unpair and for `attemptPairing`'s account-replacement branch. A rotated certificate or a stranded device secret must route to the former — "Reconnect to server" on the pairing screen — never the latter.
- A PIN change is staged, not swapped in place. The verifier (`app_lock_secure`) and the wrapped device secret (`push_pairing_secure`) are different preference files, so no single `commit()` covers both. `SecuritySettingsActivity.changePin` writes the new wrapping via `SecurePairingStore.stagePendingSecret` **before** `setPin`, `resolveDeviceSecret` tries the live wrapping then the staged one, and the following `savePairing` promotes and clears the staged copy. Without staging, a process death between the two files sealed the secret under a key no surviving PIN derived, `needsCredentialRewrap()` could not see it (it answers a scheme-version question only — `deviceSecretIsStranded` is the one that detects this), and the relay's eventual 409 read to the user as "re-pair this device".
- `AppLockStore.putCredentialSaltIfAbsent` is compare-and-set under a companion-scoped lock and never overwrites. It replaced a `check()` that threw `IllegalStateException` through `AppLockManager`'s PIN paths, which catch only `PepperUnavailableException`.
- `EphemeralAttachmentProvider.openFile` peeks rather than consumes: viewers that probe before reading open the same URI twice, and consuming on the first open made the attachment unreopenable. The TTL sweep is the single owner of pending bytes — the writer does not zero on completion, because that races a second reader streaming the same array. Every mutation of the pending map shares one monitor so the size budget is computed against a map nothing is concurrently draining.
- `NativePairingDeepLinkParser` emits an already-resolved `registrationUrl`; it is never blank. A blank one is meaningless downstream (`readPairing` reads it as "no pairing at all", `register` rejects it), so resolution happens once at the parse boundary. `PushSyncCoordinator.syncAndPersist` still re-derives it for *stored* pairings — a different concern, guarding host divergence written by older builds.
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
  history UI — that lives in `push/PushPairingActivity`, reached from the Settings hub.
- The device must be paired via `PushPairingActivity` to use relay mail; there is no separate
  mobile login or mail-password form. Never build UI for the server's web-only mail configuration
  endpoints; an unconfigured relay is an empty state, not a form.
- `mail/RelayMailSource` calls relay endpoints over OkHttp with device-id/device-secret headers.
  `mail/MailRepository` writes results into the Room cache (`data/AppDatabase`,
  `EmailDao.replaceFolderSnapshot`) and is what `InboxActivity`/`EmailDetailActivity`/
  `ComposeActivity` call.
- **`MailRepository` is the one synchronization boundary: the source returns facts, the repository
  decides when they become durable.** Two rules follow from that, and both were once broken.
  1. `RelayMailSource.fetchInbox` READS the cursor (to build `since`) and returns the next one as
     `MailFetchResult.checkpoint`; it must never write it. `MailRepository.refreshFolder`
     reconciles into Room FIRST and commits the checkpoint SECOND. Room and DataStore cannot share
     a transaction, so the ordering is the guarantee: a crash in between replays the window (upserts
     and deletes are idempotent), whereas advancing first made the relay skip that mail until the
     daily since=0 self-heal — a day of silently missing messages. The delta itself lands through
     `EmailDao.applyFolderDelta`, one transaction, so it cannot half-apply.
  2. HTTP 200 from `/api/inbox/actions` is transport success, not operation success: the relay
     answers 200 with per-id `failed[]` (Mobile_Mail_Relay.md Part 2). `MailOutcome<MailActionOutcome>
     .appliedTo(id)` is the only gate on touching the local row — archive/spam/delete/move drop the
     cached row and `markRead` sets `status`, both **after** the relay confirms that id, never
     before. A rejection becomes `MailOutcome.ActionRejected`, not `UpstreamFailure`: the request
     did reach the server, and "Couldn't reach the mail server" sends the user to check a
     connection that is fine. `processed` is a count rather than a list, so `processed < 1` with an
     empty `failed[]` is also treated as rejected — an unconfirmed operation must not delete a
     locally visible row. `markRead` is deliberately not optimistic: it already runs on `MailBackgroundExecutor`
     and reports nothing, so a pre-emptive local write bought no responsiveness and left the row
     lying about a state the server never reached.
- **`emails` is keyed on (folder, messageId), not messageId.** The relay's id is an IMAP UID,
  unique only within one mailbox, so INBOX and Archive can both hold `42`; under the old
  single-column key a refresh of either folder overwrote or relocated the other's row, and a
  removal in one folder deleted the other. Every per-message DAO statement takes the folder.
  Still not UIDVALIDITY-aware — the relay does not expose it and a client cannot invent one; the
  daily full resync rewrites the window, so id reuse self-heals within a day. See `EmailEntity`.
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
  no decoder runs over it. The recipient preflight is `POST /api/pgp/recipients/check`; it reads
  contacts only, so `hasKey: false` is a lower bound and must never be worded as a promise.
  (`/resolve` still 409s for every non-client-custody account, so it remains wrong for *this* path —
  but it is no longer wrong for the app as a whole; see the client-side send bullet below.) The pickup fallback
  stores the message's plaintext on the server for seven days, which is why its confirmation copy
  is fixed in `strings.xml` and is per-message — never a remembered preference.
- **Client-side encrypted send.** A client-custody account on an **enrolled** device encrypts and
  signs on the phone and posts ciphertext to `POST /api/mail/send-pgp`; it no longer falls back to
  webmail. `pgpComposeStateOf(hasIdentity, protection, deviceEnrolled, accountAddress)` is the whole
  rule, and its `clientSide` flag is what routes `ComposeActivity.sendEmail` to
  `ClientEncryptedSender` instead of `MailRepository.send`. Webmail remains the fallback for an
  unenrolled device, and for an enrolled one whose `accountAddress` is blank (no `From` could be
  built, so the relay would 403).
  - Recipient keys come from `POST /api/pgp/recipients/resolve` (`RecipientResolveClient`) — the
    endpoint the server-custody path must never call. Here 200, 409 and 413 are JSON while 400/500
    are plain text, which differs from `/check`.
  - The address split is `splitRecipientFields`, **not** `splitAddresses`: the latter dedupes across
    To/CC/BCC and would collapse a BCC recipient into the To header.
  - To+CC share delivery 0; each BCC gets its own ciphertext, so no BCC recipient's key id appears
    in a packet another recipient can read. Delivery 0 must stay first — index 0 failing is a hard
    502 while later failures only become a `warning`.
  - `OutgoingEnvelope` has no `bcc` field by construction, and the writer emits a fixed, closed
    header set — that is what structurally guarantees the relay's forbidden headers (`Received`,
    `Authentication-Results`, `Return-Path`, `Bcc`) can never appear.
  - The real subject rides inside the ciphertext as a protected header; the outer subject is always
    `OUTER_PLACEHOLDER_SUBJECT`, matching `pgpmail.OuterPlaceholderSubject`.
  - The Sent copy is encrypted to the public half of the **vault** key (`PgpEncryptor.ownPublicKey`),
    never to bootstrap's `publicKey`: a hostile server supplying "your" key would otherwise get a
    readable copy of every message sent.
  - `tier == "key_changed"` is a broken TOFU pin and must stay a distinct, louder outcome — never
    folded into "no key on file". There is **no** pickup fallback on this path and there must not be:
    the server-side one works by storing plaintext, which is what client custody exists to prevent.
  - `accountAddress` is bootstrap's `suggestedUserIDs[0]` and nothing else — the server derives it
    from the same expression `handleMailSendPGP` feeds to `resolveMailFrom`. Do not derive it from
    the public key's User ID or the self-contact.
  - `ComposePgpController` caches the **bootstrap**, not the composed state: custody is fixed at key
    creation but enrollment can change mid-process, so it is re-probed on every `composeState()`.
  - Sign-only is impossible (the relay accepts `multipart/encrypted` only), so the two chips are
    coupled when `clientSide`.
- Inbox tabs come from the relay's `tabs`/`label` response fields.
- Email bodies carry the relay's `bodyMode` (`html`/`plain`) through the Room cache and into
  `EmailDetailActivity`; plain bodies must be escaped into whitespace-preserving block markup for
  HTML fallback/quoting, while HTML bodies must not be detected by content when the server supplied
  a mode. The detail screen renders known plain bodies in a native wrapping `TextView`, so email
  reading never requires horizontal scrolling.
- Keyword tuning is managed in `KeywordSettingsActivity` and persists hidden/visible keyword headings.
- Theme selection is managed in `ThemesActivity` and uses the shared theme name list based on `theme.ts` palettes.
- `SettingsActivity` is only a hub for existing settings surfaces: Security, Themes, Keywords,
  Pairing, PGP Key, and About. Keep settings logic in the destination screens rather than
  duplicating it in the hub.
- Primary navigation uses `bottom_nav_menu.xml` for both phone bottom navigation and the `w600dp`
  rail on Inbox, Compose, Contacts, and Settings. The item order is Inbox, Compose, Lock, Contacts,
  Settings; Lock is an action that either locks immediately or opens Security when app lock is
  disabled, not a selected destination. Keep the destination behavior in `AppNavigation.kt`. Primary
  destination switches reuse existing destination activities with `FLAG_ACTIVITY_REORDER_TO_FRONT`
  and use the 120ms card-slide animations in `res/anim/nav_card_*`; settings subpages and security
  handoff use normal platform transitions. Rail insets must clear both the status bar and top app
  bar; content top insets must clear both too, because edge-to-edge content otherwise starts under
  the custom ActionBar. Inbox remains the selected primary destination for mail folders, but its
  displayed label must mirror the active folder so Junk/Trash/Archive do not leave Inbox highlighted
  by name.
- Keyword refresh is best-effort every 90 seconds while inbox UI is foregrounded (both connection modes).
- Background keyword staleness is accepted; app catches up on next foreground refresh.
- Contact sync (`contacts/` package) mirrors `push/`'s repository+coordinator+singleton-graph shape:
  `ContactSyncClient` (OkHttp, `sub`/`hash` auth) pulls/pushes `/api/contacts/sync`, `ContactSyncRepository`
  applies the delta into Room and reconciles locally-created contacts' server-assigned uid (no
  correlation id in v1 — matched by content/order, see `ContactSyncReconciliation`), and
  `ContactCursorStore` persists a per-subscriber cursor in Room alongside the contact outbox so
  acknowledgement is atomic.
  Entry point is the Contacts nav item and the settings hub; CardDAV (the doc's alternative sync
  surface) has no mobile client — it is web/OS-driven.
- Room (`androidx.room`, `data/AppDatabase`) is a deliberate, user-requested exception to "do not
  add new dependencies unless they reduce overall code size/complexity" below — it's the local email
  and contacts cache. KSP (Room's annotation processor) needs
  `android.disallowKotlinSourceSets=false` in `gradle.properties` to coexist with AGP's built-in
  Kotlin compilation (this project applies no separate `org.jetbrains.kotlin.android` plugin) — a
  known KSP/AGP-9 interaction (google/ksp#2729), not a general opt-out of that migration.
- **Comments say what the code cannot; commits say what it used to be.** A third of this
  module's non-blank lines are comments, and most of them follow the shape "X used to be Y, which
  was wrong because Z". That is a commit message — `git log` already holds it, permanently, attached
  to the diff that made the change — and in source it goes stale silently. It did: this file spent a
  release telling every reader `kypost_mail.db` was plaintext, one commit after it was encrypted.
  Keep in-source comments for what the code genuinely cannot state: a wire-format contract
  (`Sec1Point.kt`), a packet-ordering requirement (`PgpEncryptor`), a non-obvious ordering
  constraint. **Where a comment asserts a security property, write the test instead** — every
  "this cannot happen" in the at-rest path that was checked in this review turned out to be able to
  happen.
- **`kypost_mail.db` IS encrypted at rest, with SQLCipher.** Room is built through
  `SupportOpenHelperFactory` keyed from `security/DatabaseKey.kt`: 32 random bytes, base64, held in
  a Keystore-backed `EncryptedSharedPreferences` file (`db_key_secure`) and never derived from the
  app-lock PIN — the database has to open in processes where no PIN has been entered (an FCM
  delivery, a WorkManager sync). The threat this closes is **offline** reading of the file: root, an
  unlocked bootloader, a forensic image. It is explicitly not a defence against a live, rooted,
  running device.
  - Existing plaintext databases are converted in place by `data/DatabaseMigration.kt`
    (`sqlcipher_export` into a temp file, verified under the new key, then one atomic `rename(2)`).
    The conversion must never delete the original before the rename — a process death in that
    window destroyed the mailbox, and `pending_contact_changes` exists nowhere else.
    `recoverInterrupted` salvages temp files left by builds that did.
  - `DataGraph` **checks** `encryptIfNeeded`'s return and throws `DatabaseUnavailableException`
    rather than handing a plaintext file to SQLCipher, which surfaced as `SQLITE_NOTADB` on a
    background thread on every launch with the cause nowhere near the symptom.
  - `SecurityWipe` has a `databaseKey` step: an encrypted database is only as gone as its key.
  - The app-lock apparatus (PIN, lockout ladder, wipe threshold, `AppLockStore`'s tripwire) still
    defends the **UI** and is a separate control from this one. Hostile Location Protection
    (`security/HostileLocationSettings` → `data/DataGraph` builds Room in-memory) remains the
    stronger mode for users whose threat model includes a live rooted device, at the cost of all
    offline access — under it there is no file at all.
  - SQLCipher was previously rejected here as a large native dependency. That call was reversed on
    2026-08-18 because the alternative was "your mail is in the clear on disk unless you find and
    enable an off-by-default setting", which is the wrong default for a confidential mail client.
    The AAR ships `libsqlcipher.so` and loads it nowhere, hence `sqlCipherLoaded` in
    `DatabaseMigration.kt`. **If this decision is ever revisited again, update this bullet and
    `AppLockStore.tripwire`'s KDoc in the same commit** — the previous change did not, and this
    file spent a release telling every reader the database was plaintext.
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
- Certificate-chain pinning has a JVM test (`push/TlsChainPinningTest`) asserting every captured pin is registered for the host and that an empty pin set is refused. A pinning change that only tests the state machine (pinned / never-paired / lost) does not cover the lifecycle event that actually happens — renewal — so add the rotation case too.
- Interrupted-PIN-change recovery is covered by `push/PinChangeSecretRecoveryTest` in `app/src/androidTest/` (real Keystore required): it kills the change at each step and asserts the device secret is still readable, and that a genuinely stranded secret is reported by `deviceSecretIsStranded`.
- Validate manifest registration when adding activities or permissions.
- Room DAO behavior (e.g. `EmailDao.replaceFolderSnapshot`, contact upsert/delete) is covered by
  instrumentation tests in `app/src/androidTest/` using `Room.inMemoryDatabaseBuilder` (no
  Robolectric dependency in this project — don't add one for this).
- The email `bodyMode` column is additive and requires `MIGRATION_10_11` plus a migration test when
  the schema contract changes again. `MIGRATION_11_12` re-keys `emails` on (folder, messageId);
  SQLite cannot alter a primary key, so it rebuilds the table and copies rows rather than dropping
  the cache. `EmailDaoFolderScopeTest` is the authority on that key against real SQL — the JVM fake
  in `MailRepositoryTest` mirrors it, and a fake keyed on the id alone reproduces the very bug the
  key exists to prevent.
- The mail failure contract has JVM regression tests in `MailRepositoryTest`: a failed reconcile
  must leave the cursor where it was, an action returned in `failed[]` must not mutate Room, and
  `markRead` must not mark a row read the server rejected. Adding a mail sync or action path
  without one of these is how the contract rots back.
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
