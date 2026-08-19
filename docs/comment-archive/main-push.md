# Comment archive - main/push

## app/src/main/java/org/kysecurity/mail/push/DeregisterClient.kt

### `class DeregisterClient(`
```
/**
 * Talks to `POST /api/notifications/native/deregister` — lets this device remove itself from
 * the account's paired-devices list server-side, using its own X-Kypost-Device-Id/
 * X-Kypost-Device-Secret credentials, no session cookie. Kept parallel to [MfaResponseClient] —
 * same okhttp/serialization stack and status-code-to-result mapping shape.
 */
```

## app/src/main/java/org/kysecurity/mail/push/KyPostFirebaseMessagingService.kt

### `if (SecurityWipe.blockedByAbandonedWipe(applicationContext)) {`
```
        // Guarded for a sharper reason than the receive path: this re-registers with the relay,
        // and every successful registration MINTS A NEW DEVICE SECRET. A token refresh would
        // hand a freshly valid credential to a device whose wipe failed, re-arming the very
        // access the wipe was trying to revoke.
```

### `if (SecurityWipe.blockedByAbandonedWipe(applicationContext)) {`
```
        // Before the payload is even parsed. A wipe that gave up leaves the pairing credential on
        // disk more often than not, so the relay keeps pushing and this service would keep
        // rendering sender and subject onto the lock screen of a device the app already tried to
        // erase itself from — and would keep offering MFA approvals on it. Drop everything.
```

## app/src/main/java/org/kysecurity/mail/push/KyPostUnifiedPushService.kt

### `class KyPostUnifiedPushService : PushService() {`
```
/**
 * Receives UnifiedPush protocol events from whichever distributor the user picked
 * (ntfy, etc). Mirrors KyPostFirebaseMessagingService but for the UnifiedPush transport.
 * PushService is the current API; the older MessagingReceiver broadcast-based API
 * this replaced is deprecated upstream.
 */
```

### `graph.syncCoordinator.syncProvidedToken(`
```
            // pubKeySet carries the WebPush (RFC 8291) encryption keys the connector generated
            // for this endpoint. The server needs these to encrypt payloads so the connector can
            // decrypt them on receipt — without them, onMessage() only ever sees ciphertext.
```

### `UnifiedPush.removeDistributor(applicationContext)`
```
        // Distributor rejected registration. Clear the stale distributor selection and fall
        // back to FCM so the user isn't left with no delivery at all, and surface the failure
        // through the same syncError the FCM path already renders in the pairing UI.
```

### `android.util.Log.w(TAG, "Dropping UnifiedPush message: decryption failed")`
```
            // The connector couldn't decrypt this message — almost always means the server
            // encrypted with a p256dh/auth key that doesn't match what we last registered
            // (or registered none at all). message.content is ciphertext, not JSON; don't
            // attempt to parse it.
```

## app/src/main/java/org/kysecurity/mail/push/MfaApprovalActivity.kt

### `class MfaApprovalActivity : AppCompatActivity() {`
```
/**
 * The only place an MFA challenge can be approved or denied.
 *
 * The [MfaChallengeTracker] check is enforced here too, not just in
 * [org.kysecurity.mail.MainActivity]: a challenge id that never arrived via a real push must not be
 * actionable, however this screen was reached.
 */
```

### `private var authInFlight = false`
```
    /** A prompt is on screen and has not answered yet. Without this, [onStart] fires immediately
     *  after `onCreate` has already started one — `authenticated` is still false because the prompt
     *  is asynchronous — and the user gets two stacked biometric dialogs on every cold start. */
```

### `private var matchOptions: List<String> = emptyList()`
```
    /** The tile order, shuffled once per challenge and kept across recreation. Reshuffling on a
     *  configuration change or a return from the biometric prompt would move the tiles under the
     *  user's finger mid-decision. */
```

### `private var decisionKeys: org.kysecurity.mail.security.CredentialKeys? = null`
```
    /**
     * The credential keys derived when the user verified their PIN for *this* decision, when the
     * credential gate is on. Null when the gate is off, where the stored secret needs no key.
     *
     * Held here rather than re-read from [org.kysecurity.mail.security.AppLockManager.cachedCredentialKeys]
     * at send time: this screen runs on a locked app (a notification tap does not unlock anything),
     * and that accessor returns null while locked by design — so the response died locally with
     * "Device is not registered yet" and neither approve nor deny ever reached the server. Cleared
     * in [onStop] alongside `authenticated`, so it lives exactly as long as the consent does.
     */
```

### `if (SecurityWipe.blockedByAbandonedWipe(applicationContext)) {`
```
        // This screen is deliberately outside LockedActivity — see the class KDoc — so it does not
        // get that class's terminal block on an abandoned wipe, and it has to carry its own.
        // Approving a sign-in is the highest-value action in this app, and an abandoned wipe means
        // the app tried to erase itself from this device and failed: the last thing it may do is
        // let whoever is holding it approve an account login. Hand off to MainActivity, which
        // renders the "manual recovery required" block rather than leaving a dead notification tap.
```

### `resolveJob?.cancel()`
```
        // A different challenge was tapped while this singleTop instance was already on top
        // showing the previous one. Cancel any in-flight resolve() for the old challenge so it
        // can't finish() this screen out from under the new one.
```

### `Toast.makeText(this, R.string.mfa_challenge_unavailable, Toast.LENGTH_LONG).show()`
```
            // Say why. A challenge can legitimately stop being pending — it expired, it was already
            // answered, or a flood of new ones evicted it from the tracker's bounded set — and
            // finishing in silence made a tapped notification look like a broken app.
```

### `private fun renderContext(source: MfaChallengePayload) {`
```
    /**
     * Shows where the sign-in came from.
     *
     * A user who cannot see the origin cannot tell their own login from an attacker's, which makes
     * every other control on this screen ceremony. Where the server has not sent a field, say so
     * explicitly — "Unknown" is information; a blank line reads as "nothing to worry about".
     */
```

### `private fun setUpNumberMatching(source: MfaChallengePayload) {`
```
    /**
     * Renders the number match, which is the only way to approve.
     *
     * There is no bare Approve button any more. The server always mints the value it displays in
     * the browser plus two decoys and verifies the answer itself, so a challenge that does not
     * carry a complete choice set is one this client cannot approve — offering a button that sends
     * no number would spend the server's attempt budget and return a 400 telling the user they got
     * a number wrong that they were never shown. Deny stays available unconditionally.
     */
```

### `val options = matchOptions.takeIf { it.isNotEmpty() && matchDigits in it }`
```
        // Shuffled once. A restored order is reused so a recreate cannot move the tiles — but only
        // if it still contains this challenge's answer, or every tap would be wrong and the first
        // one would burn a challenge the user answered correctly.
```

### `filterTouchesWhenObscured = true`
```
                // Built at runtime, so the window-level flag set in onCreate never reached it. An
                // overlay covering the wrong tile turns a three-way match into an attacker's
                // one-in-one. See [applyOverlayProtection].
```

### `private fun onMatchChosen(chosen: String) {`
```
    /**
     * A wrong number burns the challenge. It is not a retry, and it is not merely a deny request.
     *
     * The server keeps a small attempt budget so a legitimate mis-tap is recoverable, but this
     * client deliberately does not use it: letting the user guess again turns a three-way match
     * into a one-in-three chance for an attacker whose victim is tapping blind. So the challenge is
     * struck from the tracker and its notification cancelled *before* the deny is sent, which makes
     * the burn hold even if the deny never reaches the server. Leaving it to the request alone
     * meant that offline, a failed deny re-enabled the tiles and handed back exactly the retry this
     * refuses to allow.
     */
```

### `private fun denyOnly() {`
```
    /**
     * Deny is available; approve is not, and the screen says why.
     *
     * The one state where this app will act on an unauthenticated tap, because the action can only
     * subtract access. [matchDigits] is cleared alongside so [onMatchChosen] cannot match even if a
     * tile survives — the enabled flag is a UI affordance, not the gate.
     */
```

### `private fun requireAuthentication() {`
```
    /**
     * Gates both buttons behind an authentication that **produces the key the decision needs**,
     * falling back through weaker options only as far as the device forces.
     */
```

### `val unlock = withContext(Dispatchers.IO) {`
```
            // Keystore and disk, so never on Main. Null means this device has nothing sealed —
            // no fingerprint enrolled, no PIN unlock since the feature landed, or a key the OS
            // destroyed when a biometric was enrolled.
```

### `private fun authenticateWithSealedKeys(unlock: org.kysecurity.mail.security.BiometricUnlock) {`
```
    /**
     * The good path: the fingerprint opens the app's own credential keys.
     */
```

### `private fun authenticateWithoutSealedKeys() {`
```
    /**
     * Nothing is sealed on this device, so there is no key a biometric could produce.
     *
     * **This app's own PIN comes first whenever a lock is configured**, ahead of the device
     * credential: it is throttled by the same lockout ladder and wipe threshold as every other PIN
     * check, it is specific to this app, and when the credential gate is on it is the only thing
     * that makes the challenge answerable at all.
     *
     * The prompt has no app secret to produce, so it is bound to [AuthGateKey] instead: a Keystore
     * key the OS releases only for a live authentication. It protects no data — there is none to
     * protect on this path — but it is what makes the success callback evidence rather than a
     * boolean an instrumented process can set.
     */
```

### `authInFlight = false`
```
            // Genuinely nothing to authenticate against: no sensor, no enrolled device credential,
            // and no app-lock PIN configured either.
            //
```

### `private fun promptAppLockPin() {`
```
    /**
     * The app-lock PIN, routed through [AppLockManager] so the lockout ladder and the wipe
     * threshold apply here exactly as they do on the unlock screen — an approval prompt must not
     * become an unthrottled PIN oracle.
     *
     * Uses [AppLockManager.deriveAndCacheCredentialKeys] rather than
     * [AppLockManager.verifyPinThrottled] when the credential gate is on: both run the same
     * throttled verification, but only the former caches the key that
     * [MfaResponder] needs to unwrap `deviceSecret`. Verifying alone would authenticate the user
     * and still leave the response unsendable.
     *
     * The dialog is **held and dismissed in [onStop]**. It is `setCancelable(false)` and survives
     * backgrounding, while `onStop` clears `authInFlight` — so returning to the screen ran
     * [requireAuthentication] again and stacked a second identical prompt on the first, leaking the
     * first's window and letting two dismissals burn two attempts against the wipe threshold for
     * what the user saw as one prompt.
     */
```

### `manager.verifyPinForDecision(pin, deriveKeys = gateNeedsPin)`
```
                        // verifyPinForDecision runs the same throttled check and hands the keys
                        // back only on Success, so this screen cannot hold a credential key it did
                        // not earn. It does NOT unlock the app — see AppLockManager.DecisionToken.
```

### `val ok = resolvePinAttempt(attempt)`
```
                    // resolvePinAttempt, not `is Success`: the wipe threshold applies here too, and
                    // reporting a completed destructive wipe as "authentication required" told the
                    // user nothing about what had just happened to their data. See [PinGate].
```

### `override fun onStop() {`
```
    /**
     * Authentication is consent for one decision, and it does not survive leaving the screen.
     */
```

### `override fun onStart() {`
```
    /**
     * Re-authenticates on the way back, because [onStop] de-authenticates on the way out.
     *
     * Skipped while a resolve is in flight — that decision is already made and submitted; prompting
     * for a fingerprint on top of it would be asking consent for something already sent.
     */
```

### `private fun resolve(approve: Boolean, chosenDigits: String = "") {`
```
    /**
     * [chosenDigits] is the value the user tapped. The server is what actually checks it
     * ([MfaResponseClient]); the local comparison in [onMatchChosen] only decides which request to
     * send. Empty on a deny, which the server accepts without a number.
     */
```

### `resolveJob = null`
```
            // An undelivered *approve* leaves the challenge genuinely open, and MfaResponder
            // keeps the tracker entry and re-posts the notification for exactly this — let the
            // user retry.
```

### `if (authenticated) setButtonsEnabled(true)`
```
            // Only if this screen is still authenticated. `lifecycleScope` cancels on DESTROY, not
            // on STOP, so a slow request that fails after the user pressed Home used to re-enable
            // every tile on a stopped screen — which then stayed enabled and inert on the way back,
            // since onStop had already cleared `authenticated`. onStart re-prompts instead.
```

### `internal fun mfaHasNoAuthenticator(canAuthenticateStatus: Int): Boolean = when (canAuthenticateStatus) {`
```
/**
 * Whether a [BiometricManager.canAuthenticate] status means there is genuinely **no authenticator
 * to use**, as opposed to one that could not be checked right now.
 *
 * - `BIOMETRIC_ERROR_HW_UNAVAILABLE` is *temporary* (sensor busy or powered down).
 * - `BIOMETRIC_STATUS_UNKNOWN` is documented as indeterminate, with the explicit advice to call
 *   `authenticate()` anyway.
 * - `BIOMETRIC_ERROR_SECURITY_UPDATE_REQUIRED` means the sensor is untrusted, not that the device
 *   credential is gone.
 *
 * All three occur on devices that *do* have a screen lock, so all three must show the prompt and
 * let its error callback fail the screen closed. Only the three below are terminal.
 *
 * Top-level and Context-free so the classification is unit-testable on the JVM — the same reason
 * [MfaNumberMatch] and [mfaChallengeIsFresh] live outside their callers.
 */
```

## app/src/main/java/org/kysecurity/mail/push/MfaChallengePayload.kt

### `data class MfaChallengePayload(`
```
/**
 * An MFA challenge as pushed by the server.
 *
 * All context fields are optional so a server that has not been updated yet still works; the UI
 * degrades to naming what it does not know rather than pretending there was nothing to show.
 * [matchDigits] additionally drives number matching — see [MfaApprovalActivity].
 */
```

### `val matchDigits: String = "",`
```
    /** The digits the server is simultaneously showing in the browser that started the sign-in.
     *  Blank when the server sent nothing usable, in which case this challenge cannot be approved
     *  — see [MfaNumberMatch]. */
```

### `private const val MAX_CHALLENGE_ID_LENGTH = 128`
```
    /**
     * Bound on the challenge id itself, which is the field that matters most and was the only one
     * with no bound at all.
     *
     * Every *display* string above is length-capped and the number-match values are shape-checked,
     * but the id becomes a **key in a `SharedPreferences` XML file** ([MfaChallengeTracker]), written
     * with a synchronous `commit()` on the push-delivery thread, and `prefs.all` is materialised on
     * every subsequent delivery. A hostile relay sending megabytes here filled the disk and stalled
     * the delivery thread through an input path that was already being validated for the fields that
     * only ever reach a TextView.
     *
     * The charset is restricted for the same reason: this is a server-minted opaque id (UUID-shaped
     * in practice), never free text, and it is used as a filename-adjacent map key.
     */
```

### `const val MATCH_DIGITS_MIN_LENGTH = 1`
```
    /**
     * Accepted width of a number-match value, as a range rather than a constant.
     */
```

## app/src/main/java/org/kysecurity/mail/push/MfaChallengeTracker.kt

### `private const val KEY_LAST_ALERT_AT = "!last_alert_at"`
```
/** Not a challenge id — the alert-cooldown timestamp shares this file so the whole of MFA's
 *  anti-fatigue bookkeeping survives process death together. Filtered out of [liveEntries] by the
 *  same id validation that guards writes. */
```

### `internal const val MAX_TRACKED_CHALLENGES = 8`
```
/**
 * Hard ceiling on tracked challenges.
 */
```

### `class MfaChallengeTracker(context: Context) {`
```
/**
 * Tracks challenge IDs that arrived via a real, decrypted push delivery (recorded by
 * [PushNotificationDispatcher.showMfaChallenge], and only once a notification for the challenge has
 * actually been posted). [MfaApprovalActivity] refuses any id that is not tracked, so a challenge
 * the user was never shown cannot be surfaced by anything that can start the activity — and
 * [MfaApprovalActivity.burnChallenge] uses the same mechanism in reverse to make a mis-tapped
 * challenge unanswerable.
 *
 * Persisted rather than held in a `ConcurrentHashMap`: FCM routinely delivers to a freshly-started
 * process and Android routinely kills that process again moments later, so an in-memory record was
 * usually gone by the time the user actually tapped the notification.
 *
 * Challenge IDs are not secrets (they authenticate nothing on their own; the server still requires
 * the device credential to act on one), so plain private SharedPreferences is the right storage —
 * an attacker who can write here already owns the app's sandbox.
 *
 * **Every mutation runs under [lock], which is deliberately class-level rather than per-instance.**
 * [markDelivered] is a read-modify-write that rebuilds the whole file from a snapshot, and
 * [clear] removes a single key — so without serialisation, a `clear` landing between another
 * thread's read and its rewrite was silently undone. That is not a cosmetic race: it resurrects a
 * challenge the user has already burned by mis-tapping the number, or already answered and had
 * accepted by the server, breaking the "answered once, answerable once" property the whole screen
 * rests on. It fires exactly during a challenge flood, i.e. during the attack this resists. The
 * lock is class-level because these objects are still cheap to construct per call site and all of
 * them address the same file; per-instance locking would serialise nothing.
 */
```

### `fun markDelivered(challengeId: String, nowEpochMs: Long = System.currentTimeMillis()) {`
```
    /**
     * Records [challengeId] and rewrites the file to the live, bounded set in ONE `commit()`.
     */
```

### `if (!MfaChallengePayloadParser.isValidChallengeId(challengeId)) return`
```
        // Re-validated here, not just at the parser: this id becomes a key in an XML file written
        // with commit() on the delivery thread, and `isBlank()` was the only thing standing between
        // a hostile relay and an arbitrary-length one. Defence at the point of persistence, so a
        // future caller that builds a payload some other way cannot reintroduce it.
```

### `data class AlertDecision(val suppress: Boolean, val previousAlertAtEpochMs: Long)`
```
    /**
     * The outcome of an alert-cooldown check.
     *
     * [previousAlertAtEpochMs] exists so a caller that ends up posting nothing can put the cooldown
     * back — see [restoreAlertCooldown].
     */
```

### `fun shouldSuppressAlert(cooldownMs: Long, nowEpochMs: Long = System.currentTimeMillis()): AlertDecision =`
```
    /**
     * Whether the MFA notification's *sound* should be suppressed, advancing the cooldown when it
     * should not.
     *
     * Persisted, for the same reason the challenge records are: FCM routinely delivers to a
     * freshly-started process and kills it moments later. Holding this in a process-scoped `var`
     * meant the cooldown reset on every process churn — so under a real flood, which is the only
     * situation it exists for, every challenge alerted at IMPORTANCE_HIGH.
     *
     * The check and the advance stay in one locked section so two concurrent deliveries cannot both
     * decide to alert. A caller whose notification then fails to post calls [restoreAlertCooldown]
     * with [AlertDecision.previousAlertAtEpochMs]; rolling back afterwards is what keeps the
     * atomicity while still not spending a cooldown on an alert nobody heard.
     */
```

### `fun restoreAlertCooldown(previousAlertAtEpochMs: Long) {`
```
    /**
     * Undoes [shouldSuppressAlert]'s advance when the notification it was for never reached the
     * shade — POST_NOTIFICATIONS revoked between the check and the post, or a `SecurityException`
     * on the way out.
     */
```

## app/src/main/java/org/kysecurity/mail/push/MfaNumberMatch.kt

### `internal object MfaNumberMatch {`
```
/**
 * The number-matching choice set for one MFA challenge.
 *
 * A bare Approve button asks for a tap, and a tap is exactly what an MFA-fatigue attack harvests.
 * Number matching replaces it with a discrimination the user can only make if they are looking at
 * the screen that started the sign-in.
 *
 * **Every value comes from the server.** The client used to invent decoys from a linear congruential
 * generator seeded on the challenge id when the server sent too few, which made the wrong answers
 * derivable by anyone who knew the id. The server mints the correct value and both decoys from
 * `crypto/rand` (kypost-server `mfa.newNumberMatch`), and it verifies the answer itself
 * (`Store.ResolvePushWithMatch`) — so a challenge that does not carry all three is one this client
 * cannot offer an approval for at all. [optionsFor] returns null there, and the caller must leave
 * only Deny available rather than falling back to a button the server will refuse.
 *
 * Pure and Context-free so the selection logic is unit-testable on the JVM.
 */
```

### `fun optionsFor(`
```
    /**
     * The tiles to render, in the order to render them, or null when [correct] and [serverDecoys]
     * do not describe a complete [CHOICE_COUNT]-way choice.
     *
     * Order is randomised per call. [shuffle] is injectable only so tests can pin it; callers must
     * shuffle **once** and keep the result for the life of the challenge, or a recreate would
     * reorder the tiles under the user's finger — see [MfaApprovalActivity].
     */
```

## app/src/main/java/org/kysecurity/mail/push/MfaResponder.kt

### `object MfaResponder {`
```
/**
 * Sends the user's approve/deny decision for an MFA challenge.
 */
```

### `suspend fun respond(`
```
    /**
     * Returns true when the decision actually reached the server.
     *
     * Cancel-on-success still preserves the replay property that ordering was there for: a
     * decision that reached the server cannot be re-opened.
     */
```

### `suspend fun respond(`
```
    /**
     * [decisionKeys] are the credential keys the calling screen derived when it verified the PIN for
     * *this* decision, or null when the credential gate is off (in which case the stored secret needs
     * no key). They are passed in rather than read back through
     * [org.kysecurity.mail.security.AppLockManager.cachedCredentialKeys] because this runs while the app
     * is still locked — a notification tap does not unlock the app — and that accessor deliberately
     * returns null in exactly that state, which made every gated approve and deny unsendable.
     */
```

### `showResultToast(`
```
                // Leave the challenge answerable AND put the notification back, which this comment
                // used to claim while the code only showed a toast. `setAutoCancel(true)` removed
                // the row when the user tapped it, so without the repost their only route back is
                // the Activity they are standing on — walk away and a still-open sign-in is
                // stranded for the rest of the tracker's freshness window with no UI anywhere.
```

## app/src/main/java/org/kysecurity/mail/push/MfaResponseClient.kt

### `@SerialName("matchDigits") val matchDigits: String,`
```
    /**
     * The number the user picked off [MfaApprovalActivity]'s choice row.
     *
     * The server verifies this itself (kypost-server `Store.ResolvePushWithMatch`) and refuses an
     * approval that does not carry it — this endpoint is reachable by anyone holding device
     * credentials, so the on-device comparison in [MfaApprovalActivity.onMatchChosen] is UX, not
     * the control. Always serialized, including as `""` on a deny, which the server ignores.
     */
```

### `400 -> MfaRespondResult.Error(serverError(rawBody) ?: "That is not the number shown in the browser")`
```
            // The number was wrong, but the credentials were fine and the challenge is still live —
            // so this is a re-prompt, not a re-pair. Prefer the server's own wording: it is the
            // side that knows whether this was a mismatch or a spent attempt budget.
```

## app/src/main/java/org/kysecurity/mail/push/NativeRegistration.kt

### `@SerialName("p256dh") val p256dh: String? = null,`
```
    // WebPush encryption key material (RFC 8291), present only for transport="unifiedpush".
    // The server needs these to encrypt payloads so the UnifiedPush connector can decrypt them;
    // without them, messages arrive as undecryptable ciphertext.
```

### `@SerialName("deviceSecret") val deviceSecret: String? = null,`
```
    // The raw per-device pairing secret, minted fresh on every successful registration and
    // returned only in this response — never retrievable again afterward. The caller must
    // persist it unconditionally, overwriting any prior value (see PushSyncCoordinator).
```

### `@SerialName("transport") val transport: String? = null,`
```
    // The transport the server actually stored ("fcm" | "apns" | "unifiedpush"), echoed back
    // so the client displays an authoritative value rather than just assuming its request won.
    // Absent on older servers.
```

### `fun resolvePullEndpoint(serverUrl: String, provided: String?): String {`
```
/**
 * Resolves the pull endpoint: the server-provided value wins only if it shares the paired
 * server's scheme and host, otherwise it is derived from the paired server base URL. A
 * cross-origin value is rejected rather than trusted, since this endpoint is polled
 * automatically and carries the device's bearer credential on every request.
 * Mirrors [NativeRegistrationEndpointResolver] for the register endpoint.
 */
```

### `val tlsPin: TlsPin? = null,`
```
        // TOFU (trust-on-first-use) SPKI pin of the leaf certificate seen on this successful
        // registration call's TLS handshake, paired with the host that handshake was with, or null
        // if the connection wasn't TLS or the handshake info wasn't available. Carrying the host
        // is what stops the pin being enforced against a different host later on — see
        // PinnedCallFactoryProvider. The caller decides whether to persist it.
```

### `.apply {`
```
            // Re-registration REBINDS an existing device row, and the server refuses that with 409
            // unless the current credential is presented: without the check, a stolen session could
            // take over a device row, keep its MFAApprover status and redirect that user's push.
            // The FCM-token-refresh flow re-registers, so this is the ordinary path.
            //
            // Both halves or neither. A first pairing has no secret yet — this call is what mints
            // one — and a device id sent alone reads to the server as a rebind attempt with no
            // credential, which is exactly the request it is designed to refuse. The credential gate
            // produces that shape whenever the app is locked.
```

### `NativeRegistrationResult.Error("Registration did not return a device secret")`
```
                    // A successful registration always mints a secret. Treating a 200 without one
                    // as success made savePairing erase the stored credential while leaving the rest
                    // of the pairing intact, so the UI kept reporting "Paired" while every
                    // authenticated call 401'd with nothing to explain why.
```

## app/src/main/java/org/kysecurity/mail/push/NotificationIntentToken.kt

### `internal object NotificationIntentToken {`
```
/**
 * Proof that an Intent came from a notification this app posted.
 *
 * [org.kysecurity.mail.MainActivity] is `exported="true"` — it has to be, it holds the LAUNCHER
 * filter — and it forwarded three attacker-reachable extras straight into [InboxActivity]: a
 * message id, a sender and a subject. Any co-installed app, with no permissions at all, could
 * therefore drive the mail UI to an arbitrary message and put strings of its choosing on screen as
 * if they had arrived by mail. Splitting `PushPairingLinkActivity` out closed the same shape of
 * hole for the pairing screen; this closes it for the inbox.
 *
 * A stored random value rather than a per-notification nonce, because a `PendingIntent` outlives
 * the process that created it and has to keep validating after a cold start. It is an authenticity
 * marker, not a replay defence — the extras it protects are display-only. It cannot be read by
 * another app (the file is `MODE_PRIVATE`), and [org.kysecurity.mail.security.SecurityWipe]'s
 * shared-prefs sweep removes it, so stale PendingIntents from before a wipe stop validating.
 */
```

## app/src/main/java/org/kysecurity/mail/push/PairingModels.kt

### `data class PairingData(`
```
/**
 * Deliberately **not** `@Serializable`.
 *
 * It carries `deviceSecret` and `pairingToken` — the credentials every authenticated call to the
 * relay is made with. Nothing serializes this type (the wire DTOs in `NativeRegistration.kt` are
 * separate on purpose, and [SecurePairingStore] writes field by field into a Keystore-backed store),
 * so the annotation bought nothing and stood as a standing invitation to put the whole thing in an
 * Intent extra, a log line or a crash report. Keep the credentials un-serializable by construction.
 */
```

### `internal fun sameOrigin(candidate: String, reference: String): Boolean {`
```
/**
 * True when [candidate] and [reference] are the same https origin (scheme + host + effective port).
 *
 * Every URL this app will send pairing credentials to has to pass this. The registration endpoint
 * mints and returns the device secret, so a QR that names one server in the `srv` parameter — the
 * one the confirmation dialog shows the user — and a different one in `reg` would POST the
 * subscriber ID, pairing token and FCM token to an attacker while displaying a trusted hostname.
 * The pull endpoint already had this check; the endpoint that carries the credential did not.
 *
 * Userinfo makes both sides fail closed. Two URLs can share a host and still not be the pair the
 * user was shown — and this is also reached for pairings persisted by an older build, which is
 * exactly where a userinfo URL saved before [pairingUrlHost] existed would still be sitting.
 */
```

### `fun resolve(qrReg: String?, qrServerUrl: String?): Resolution {`
```
    /**
     * A server-supplied [qrReg] wins only if it is the same origin as [qrServerUrl]; anything else
     * falls back to the endpoint derived from the paired server. Mirrors [resolvePullEndpoint], and
     * is the second gate behind [NativePairingDeepLinkParser], which rejects a cross-origin `reg`
     * outright — this one also covers a pairing persisted by an older build.
     */
```

### `if (!isHttpsUrl(srv)) {`
```
        // The server is arbitrary (self-hosted relays, no fixed domain to allowlist), so https-only
        // is the one property we can enforce — it stops a plain-http deep link/QR from pointing the
        // device's pairing token and subscriber credentials at an unencrypted, spoofable endpoint.
```

### `if (reg != null && !sameOrigin(reg, srv)) {`
```
        // https alone is not enough: https://evil.example is a perfectly valid https URL. The
        // registration URL is where the device secret is minted, and the confirmation dialog shows
        // the user srv — so reg has to be the same server, or the dialog is lying about where the
        // credentials are going. See [sameOrigin].
```

### `internal fun pairingUrlHost(value: String): String? = pairingUrl(value)?.host`
```
/**
 * The host a pairing URL will actually connect to, or null if the URL is not one this app may
 * ever send credentials to.
 *
 * A path is still allowed — `reg` legitimately carries `/api/notifications/native/register`, and a
 * self-hosted server may live under a sub-path — because a path cannot change which host the
 * request reaches. Userinfo can, which is the whole bug.
 */
```

### `internal fun pairingUrl(value: String): HttpUrl? {`
```
/**
 * Parses a pairing URL with **the same parser that will make the request**, or null if it is not
 * one this app may ever send credentials to.
 *
 * OkHttp's [HttpUrl], not [java.net.URI]. The two disagree — on backslashes, on percent-encoding, on
 * what counts as an authority — and every one of those disagreements sits between a trust decision
 * and the request it authorises: the checks ran on `URI` while the connection was built from
 * `HttpUrl`. Validating with the parser that does not decide where the bytes go is the classic
 * shape of a parser-differential bypass, and there is no reason to keep two parsers here.
 *
 * https-only, because the server is arbitrary (self-hosted relays, no fixed domain to allowlist) so
 * that is the one property that can be enforced. Userinfo is rejected outright:
 * `https://mail.trusted-corp.com@evil.tld/` is a valid https URL whose host is `evil.tld`, and the
 * pairing dialog renders this function's `host`.
 */
```

### `internal fun pairingEndpoint(serverUrl: String, path: String): HttpUrl? {`
```
/**
 * Builds an endpoint that may receive this device's pairing credential.
 *
 * Resolves [path] against the parsed base rather than concatenating strings and re-parsing: string
 * concatenation onto a URL with a query or fragment produces a request to somewhere else entirely.
 * [pairingUrl] already rejects those, so this is belt and braces — and it is the form that stays
 * correct if that ever changes.
 */
```

## app/src/main/java/org/kysecurity/mail/push/PinnedCallFactory.kt

### `class PinnedCallFactoryProvider(`
```
/**
 * Builds (and caches) a TLS-pinned [Call.Factory] from the stored TOFU pin, rebuilding only when
 * the pin actually changes — e.g. on re-pairing after a legitimate cert rotation. Returns null
 * (meaning: the caller should fall back to an unpinned client) until a pin has been captured, i.e.
 * before the very first successful pairing completes.
 *
 * The host now comes from the pin itself ([TlsPin.host]) rather than from the pairing's
 * `serverUrl`. The pin is captured from the *registration* URL's TLS handshake, so pinning it
 * against `serverUrl`'s host was only ever correct because the two usually happen to match — and
 * a pairing QR could make them differ, which pinned the wrong host's certificate and bricked every
 * subsequent request with an unrecoverable `SSLPeerUnverifiedException`.
 */
```

### `@Volatile private var cached: Pair<TlsPin, Call.Factory>? = null`
```
    /** The pin and the client built for it, published as ONE reference so a client can never be
     *  read against a pin it was not built for. Two separate `@Volatile` fields allowed exactly
     *  that under a concurrent re-pair. */
```

### `class PinnedOrFallbackCallFactory(`
```
/**
 * Adapts a [PinnedCallFactoryProvider] into a plain [Call.Factory], for constructors that only
 * accept a fixed `Call.Factory` rather than a provider to re-check per call. Falls back to
 * [fallback] (plain, unpinned) until a pin exists, then starts pinning automatically the moment
 * one is captured, re-checked on every request rather than snapshotted once at construction time —
 * important since these clients are built once and live for the process's lifetime, well before
 * the first pairing (and thus the first TLS pin) may exist.
 *
 * **The fallback is only for [TlsPinState.NeverPaired].** This used to be `pinnedProvider() ?:
 * fallback`, which answered "we have no pin yet" and "our pin is gone" with the same unpinned
 * client — so a reset of the encrypted store (or any other loss of `KEY_TLS_PIN`) silently
 * downgraded every credential-bearing request to bare system-CA trust, permanently, with nothing
 * visible changing. [TlsPinState.Lost] now fails closed.
 */
```

### `TlsPinState.Lost -> FailedCall(`
```
            // A pin existed and no longer does. Falling back here is a silent downgrade of every
            // request carrying this device's credential, on the one event that most plausibly
            // means something went wrong with the encrypted store. Refuse instead — the user
            // re-pairs, which re-establishes a pin they can actually rely on.
```

### `private val sharedPinnedCallFactory = SingletonGraph<Call.Factory> { appContext ->`
```
/**
 * The one [PinnedOrFallbackCallFactory] shared by every client/graph that lives *outside*
 * [PushGraph] itself. [PushGraph]'s own internal clients cannot use this (it would recursively call
 * [PushRuntime.graph] while [PushGraph] is still being constructed) and instead wire a
 * [PinnedCallFactoryProvider] directly to their own repository instance — see
 * `PushGraph.pinnedOrFallbackCallFactory`.
 *
 * Safe to hold across an [org.kysecurity.mail.security.AppRestart]: the pin is resolved through
 * [PushRuntime.graph] on every request rather than captured, so a rebuilt graph — or a re-pairing
 * that replaces the pin — is picked up on the next call with nothing to invalidate here.
 */
```

## app/src/main/java/org/kysecurity/mail/push/PullNotification.kt

### `enum class DeliveryMode(val wire: String) {`
```
/**
 * Delivery mode for a subscriber, mirrored from the server. "push" is the existing
 * FCM-relay path; "pull" means FCM sends nothing and the app must poll the server
 * directly via the pull endpoint. The server value is authoritative — see the
 * `deliveryMode` field on both the register response and the pull response.
 */
```

### `enum class PushTransport(val wire: String) {`
```
/**
 * How the server reaches this device — the transport it confirmed on the last successful
 * registration.
 */
```

### `fun fromWire(value: String?): PushTransport? {`
```
        /** Null for absent or unrecognised values — older servers do not echo the field back at
         *  all, and "the server said something we do not understand" must not read as any
         *  particular transport. */
```

### `fun PullNotification.toPushPayload(nowEpochMs: Long = System.currentTimeMillis()): PushPayload {`
```
/**
 * Maps a pulled notification onto the same [PushPayload] the FCM data-message path
 * produces, so pull and push notifications render identically and share the tap
 * handler. When the pull `data` object omits `messageId`, we synthesize a stable id
 * from the strictly-increasing `seq` so de-duplication (by notification id) still holds.
 */
```

### `object PullNotificationProcessor {`
```
/**
 * Pure logic for turning a pull response into the notifications to show and the next
 * cursor. Kept side-effect free so cursor/de-duplication behavior is unit testable.
 */
```

## app/src/main/java/org/kysecurity/mail/push/PullNotificationClient.kt

### `data class Success(val response: PullNotificationsResponse) : PullResult()`
```
    /** 200 with a parsed body. */
```

### `data class Retryable(val message: String, val retryAfterSeconds: Long? = null) : PullResult()`
```
    /**
     * Transient: 5xx (incl. 503 "server pairing not configured") or a network error.
     * [retryAfterSeconds] carries the Retry-After header when present.
     */
```

### `class PullNotificationClient(`
```
/**
 * Talks to `GET <pullEndpoint>?after=`. Auth is sent as X-Kypost-Device-Id/
 * X-Kypost-Device-Secret headers, never query params. Kept parallel to
 * [NativeRegistrationClient] — same okhttp/serialization stack, no session/bearer.
 */
```

## app/src/main/java/org/kysecurity/mail/push/PullSyncCoordinator.kt

### `class PullSyncCoordinator(`
```
/**
 * Drives the "App Pull" delivery mode: fetches queued notifications directly from the
 * KyPost server (bypassing FCM / the Cloudflare relay), renders them through the
 * same [PushNotificationDispatcher] the FCM data-message path uses, and advances a
 * durable per-subscriber cursor so nothing is shown twice across polls or restarts.
 *
 * The server's `deliveryMode` (from both register and pull responses) is authoritative:
 * a single [pullOnce] both persists that mode and (dis)arms the periodic background poller.
 */
```

### `suspend fun pullOnce(): PullOutcome {`
```
    /**
     * Performs one pull cycle. Safe to call when unpaired or in push mode — it simply
     * reports [PullOutcome.NotPaired]/[PullOutcome.NotPullMode] without touching the network.
     */
```

## app/src/main/java/org/kysecurity/mail/push/PullWorker.kt

### `class PullWorker(`
```
/**
 * Battery-friendly baseline poller for "App Pull" mode.
 *
 * Tradeoff: pull mode has no FCM push to wake us, so we can't get true real-time delivery
 * for free. We use WorkManager periodic work at the platform minimum (15 min) plus an
 * immediate pull on every app foreground ([KyPostApp]) and after (re)pairing. This keeps
 * background battery cost negligible at the price of up to ~15 min latency while backgrounded.
 * If near-real-time background delivery is ever required, the alternative is a foreground
 * service with a 30–60s poll loop and a persistent notification, gated behind a user setting —
 * deliberately NOT the default here.
 */
```

### `if (SecurityWipe.blockedByAbandonedWipe(applicationContext)) {`
```
        // An abandoned wipe often leaves the pairing credential on disk, and this worker is what
        // turns that into live mail metadata: it polls the relay and renders sender and subject as
        // notifications. Cancel rather than merely skip — the work is already enqueued, and nothing
        // in a blocked app will ever legitimately want it back before a reinstall.
```

## app/src/main/java/org/kysecurity/mail/push/PushHomeViewModel.kt

### `if (state.lastTokenSyncAtEpochMs == null) {`
```
                // The pairing token is single-use: once a sync has already succeeded, resending it
                // on every app open only re-triggers the backend's "expired" rejection and scares
                // the user, even though delivery is already configured and working. Only retry here
                // to recover a pairing whose initial sync never completed.
```

### `fun applyPairing(pairing: PairingData) {`
```
    /** Applies a pairing (from a deep link or a QR scan) that PushPairingActivity has already
     *  parsed and, per its own confirmation rules, either confirmed with the user or determined
     *  didn't need confirmation. */
```

### `fun switchToUnifiedPush(activity: Activity) {`
```
    /**
     * Switches this device to UnifiedPush: triggers the distributor picker (via
     * [UnifiedPushRegistrar]) and requests registration. The endpoint itself arrives
     * asynchronously via KyPostUnifiedPushService.onNewEndpoint, which completes the
     * server registration — this call only starts that flow and reports whether it
     * was successfully kicked off.
     */
```

## app/src/main/java/org/kysecurity/mail/push/PushNotificationDispatcher.kt

### `private const val MFA_ALERT_COOLDOWN_MS = 30 * 1000L`
```
    /**
     * Repeat MFA challenges inside this window post silently instead of alerting again — the
     * client-side half of MFA-fatigue resistance (the server caps push rate; see mfaPushLimiter).
     */
```

### `private const val MFA_BURST_THRESHOLD = 3`
```
    /**
     * Live challenges past which individual notifications stop being posted.
     *
     * Silencing the *sound* is not flood control: every challenge still got its own notification id
     * and its own row in the shade, so a relay minting thousands of challenges buried the device in
     * exactly the feature built to resist that. Past this threshold the challenges collapse into
     * one summary on a fixed id, which says plainly that something is wrong.
     */
```

### `private val postedNotificationIds = object : LinkedHashMap<String, Int>(16, 0.75f, false) {`
```
    /**
     * The notification id each challenge was actually posted under.
     *
     * Bounded by the same ceiling as the tracker: entries are removed on cancel, but a challenge
     * that is never answered would otherwise linger for the life of the process.
     */
```

### `@Volatile`
```
    /**
     * The challenge the burst summary currently points at, or null when no burst row is showing.
     */
```

### `org.kysecurity.mail.ProcessState.register(this)`
```
        // Both fields above are account-scoped bookkeeping in a process that AppRestart no longer
        // kills: a stale burst pointer or a stale posted-id map outlives an unpair and then makes
        // the next session cancel the wrong notification. See [org.kysecurity.mail.ProcessScopedState].
```

### `private val LEGACY_CHANNEL_IDS = listOf("llama_labels_push", "llama_labels_mfa")`
```
    /**
     * Channel ids this app posted to before the KyPost rename.
     *
     * A [NotificationChannel] outlives the constant that created it: the system keeps one until it
     * is explicitly deleted or the app is uninstalled. So renaming `CHANNEL_ID`/`MFA_CHANNEL_ID`
     * created the new pair and left the old pair registered — a user opening this app's Android
     * notification settings to decide what it may interrupt them for is shown four channels, two of
     * them Llama-branded, and the toggles on those two govern nothing because nothing posts to them.
     */
```

### `private fun pruneLegacyChannels(manager: NotificationManager) {`
```
    /**
     * Deletes [LEGACY_CHANNEL_IDS].
     *
     * Needs no persisted "already done" flag: deleting a channel that is not there is a no-op, so
     * repeating it is only ever wasted work, never wrong. It is still guarded to once per process,
     * because both callers run on push-delivery threads and this is a binder call per id — the same
     * reason those callers already return early when their own channel exists.
     */
```

### `fun show(context: Context, payload: PushPayload) {`
```
    /**
     * Posts a new-mail notification, with lock-screen redaction delegated to the framework.
     *
     * [NotificationCompat.Builder.setPublicVersion] is the framework's mechanism for exactly this
     * decision, and it is a better one on both sides. The system swaps the two forms live off
     * *keyguard* state, so the redacted form shows while the phone is locked (which is the threat
     * the old branch was reaching for — app-lock state was only ever a proxy for it) and the real
     * sender and subject appear in the shade once it is not.
     *
     * "Require Unlock to Open" is enforced where it was always actually enforced, on the tap target:
     * [MainActivity] extends [org.kysecurity.mail.security.LockedActivity], which finishes it and shows
     * the unlock screen.
     */
```

### `if (contentSuppressedWhileLocked(context)) {`
```

        // Post the redacted form as the *whole* notification, not just its public version: with the
        // credential gate on, the user has explicitly accepted losing notification content until
        // they unlock the app, and the framework's public/private swap keys off the keyguard, which
        // says nothing about this app's own lock. Unlike the branch this replaces, the row is
        // re-posted with real content by the next delivery after unlocking, and the id is stable so
        // it updates in place rather than stacking.
```

### `private fun contentSuppressedWhileLocked(context: Context): Boolean = runCatching {`
```
    /**
     * True when the app lock is engaged, so no message metadata may be shown until the user enters
     * their PIN.
     *
     * **Gated on the app lock, not on the credential gate.** This used to require
     * `isCredentialPinGateEnabled()` — a second, separate, off-by-default setting — and relied on
     * `setPublicVersion` for everything else. But the framework swaps public for private off
     * *keyguard* state, which says nothing about this app's own lock: a user who set a PIN under
     * "Require Unlock to Open", on a phone lying unlocked on a desk, had the sender and subject of
     * every arriving message printed to the shade for anyone who swiped down. The control they
     * configured was not in the path. It is now; `setPublicVersion` still covers the keyguard case
     * on top of it.
     *
     * Reads [org.kysecurity.mail.security.AppLockManager.isLockedNow] rather than the `locked` flow, for
     * the same reason every other security decision does: a background grace window that has expired
     * without `lockNow()` having fired yet is still locked.
     *
     * Failing closed on an exception is deliberate. This runs on the delivery path in a process that
     * may have just started, and the alternative to "redact" is "print the sender and subject of a
     * message to the shade" — the wrong way to resolve a question about the user's security posture.
     */
```

### `fun showMfaChallenge(context: Context, payload: MfaChallengePayload) {`
```
    /**
     * Posts the tap-to-review prompt for an MFA challenge.
     *
     * There are deliberately no "Approve"/"Deny" notification actions. Notification actions fire
     * from the lock screen without any authentication, so they let anyone holding the powered-on
     * device approve a sign-in to the account — bypassing the PIN, biometric, lockout and wipe
     * apparatus wholesale, and bypassing the [MfaChallengeTracker] check as well, since the
     * receiver they invoked never consulted it. The decision now only happens inside
     * [MfaApprovalActivity], behind re-authentication.
     */
```

### `val notificationId = postMfaNotification(context, payload, burst, alert.suppress)`
```
        // Tracked (below) only once a notification for it is actually on screen. Marking first
        // meant that with POST_NOTIFICATIONS denied — or any SecurityException on the way out — the
        // challenge became answerable for five minutes with nothing ever shown to the user, which
        // is the pretext an approval screen must not be reachable under. The alert cooldown is
        // rolled back on the same failure and for the same reason: a delivery the user never saw
        // must not silence the next five minutes of real ones.
```

### `burstChallengeId`
```
                // The summary can only point at one challenge, and this call has just repointed it.
                // Revoke the one it used to point at, so "tracked" keeps meaning "reachable from a
                // notification the user was actually shown". Without this, a flood silently
                // accumulated answerable challenges behind a single row.
```

### `fun repostMfaChallenge(context: Context, payload: MfaChallengePayload) {`
```
    /**
     * Puts a challenge's notification back after a failed approve/deny, without touching the
     * tracker.
     *
     * `setAutoCancel(true)` removed the row the moment the user tapped it, so a send that never
     * reached the server left them with a toast, an Activity they were about to leave, and no route
     * back to a challenge that is still open — for the rest of its five-minute window.
     * [MfaResponder] claimed in a comment to do this and did not.
     *
     * Deliberately does **not** call [MfaChallengeTracker.markDelivered]: the entry is still there
     * (only a *successful* response clears it) and re-marking would slide the freshness deadline
     * forward, extending an answerable window because the network failed. Silent, too — the user is
     * looking at the screen; this is a breadcrumb, not an alert.
     */
```

### `if (!PushRuntime.graph(context).mfaChallengeTracker.isPending(payload.challengeId)) return`
```
        // Only what is still answerable. A wrong number-match burns the challenge (tracker entry
        // removed) *before* the deny is sent, precisely so the burn holds when the deny fails —
        // re-posting there would put back a row whose only effect on tap is an Activity that
        // finishes instantly.
```

### `private fun postMfaNotification(`
```
    /** Builds and posts the row, returning the id it went out under, or null if nothing was
     *  posted. Shared by [showMfaChallenge] and [repostMfaChallenge] so the two cannot drift in
     *  what they put on screen. */
```

### `fun payloadFrom(intent: Intent): MfaChallengePayload? {`
```
    /**
     * Rebuilds the payload an [mfaApprovalIntent] was assembled from.
     *
     * Kept next to its inverse so the two cannot drift: [MfaApprovalActivity] needs the whole
     * payload (not just the id) to hand back to [MfaResponder] for [repostMfaChallenge], and
     * reading the seven extras out by hand at each use site is how they drift apart.
     */
```

### `private fun mfaApprovalIntent(context: Context, payload: MfaChallengePayload): Intent =`
```
    /**
     * The intent that opens [MfaApprovalActivity] for [payload] — the only way one is built, and
     * now the only route to that screen at all.
     *
     * Every field matters. A challenge that arrives without `matchDigits` and its decoys cannot be
     * approved (see [MfaNumberMatch]), so an entry point that assembled a partial intent would not
     * degrade the screen, it would disable it.
     *
     * The context is safe in Intent extras: [MfaApprovalActivity] is not exported, so only this app
     * can supply them, and [MfaChallengeTracker] still gates on the id having really been pushed.
     */
```

### `private fun postNotification(context: Context, id: Int, notification: android.app.Notification): Boolean {`
```
    /**
     * Single exit point for posting, so the POST_NOTIFICATIONS check and the failure handling live
     * in one place.
     *
     * [notificationsAllowed] is still the gate, but the permission can be revoked between that check
     * and this call, and both call sites run on FCM/UnifiedPush delivery threads where an uncaught
     * `SecurityException` takes out the message handler rather than merely dropping one notification.
     */
```

### `fun cancelMfaChallenge(context: Context, challengeId: String) {`
```
    /**
     * Cancels the notification this challenge was posted under — [postedNotificationIds], not a
     * recomputed per-challenge id, because during a burst it was posted under the shared summary id.
     *
     * Falls back to the derived id when nothing is recorded, which covers the process having been
     * restarted between the notification being posted and the user answering it. FCM routinely does
     * exactly that, and outside a burst the derived id is correct.
     */
```

### `private val assignedIds = object : LinkedHashMap<Int, String>(16, 0.75f, false) {`
```
    /**
     * A collision-resistant id derived from [key], used for both the notification id and the
     * PendingIntent request code.
     *
     * Not `String.hashCode`: it is 32 bits designed for HashMap bucketing and is trivially
     * collidable on purpose, and a collision here means one notification replaces another while
     * `FLAG_UPDATE_CURRENT` rewrites the survivor's extras — so the tap opens the wrong message.
     * SHA-256 truncated to 31 bits stays positive (some launchers dislike negative ids).
     */
```

### `private val assignedIds = object : LinkedHashMap<Int, String>(16, 0.75f, false) {`
```
    /**
     * Ids handed out so far, so a hash collision is detected rather than silently replacing another
     * message's row in the shade.
     *
     * `stableNotificationId` truncates a hash to `Int`; two distinct messages collide often enough
     * to matter on a busy mailbox, and the symptom — a notification that vanishes when an unrelated
     * one arrives — is indistinguishable from the app being broken. Bounded, because this is
     * process-scoped bookkeeping on a delivery path.
     */
```

## app/src/main/java/org/kysecurity/mail/push/PushPairingActivity.kt

### `intent.data = null`
```
        // Consumed: a recreation must not replay it. This is the SAME guard onNewIntent carries,
        // and it was missing here — on the path an attacker actually reaches first. A browser or a
        // co-installed app delivers `kypost://native-pair` through PushPairingLinkActivity ->
        // startActivity, which lands in onCreate, never onNewIntent; getIntent() then keeps
        // returning that Intent with its data intact, so every rotation, dark-mode toggle and
        // restore-after-eviction re-raised the "replace your server with evil.tld" prompt with no
        // link tap to explain it. onNewIntent's own comment describes exactly this bug and fixed
        // only the half that could not be hit first.
```

### `setIntent(intent)`
```
        // getIntent() keeps returning the Intent that created this instance unless it is replaced,
        // so without this onCreate's unconditional consumeDeepLink re-parses the ORIGINAL deep link
        // on every recreation -- a rotation, a dark-mode toggle, a restore after eviction. An
        // attacker's cancelled "replace your pairing with evil.tld" prompt would resurface later
        // with no link tap to explain it, after the user had been trained by a legitimate one.
```

### `val requestedPermission = syncEnabler.checkAndEnable()`
```
                // If this needs to request permissions, contactPermissionLauncher's callback
                // calls scanQr() once that resolves. Calling it here too would launch the QR
                // scanner on top of the still-open system permission dialog.
```

### `private fun confirmAndApplyPairing(pairing: PairingData) {`
```
    /** Every pairing source — deep link, QR scan, or replacing an existing pairing — always
     *  confirms the destination server before applying it. A QR scan proves the user operated
     *  the camera, not that they know what server the code encodes: QR codes are trivially
     *  copyable, photographable, and re-postable, so "physical action" is not proof of trust in
     *  the destination. */
```

### `val alreadyPaired = PushRuntime.graph(this).repository.isPairedNow()`
```
        // Read from the store, not from uiState. uiState is a `stateIn(WhileSubscribed(5_000))`
        // flow, so before anything subscribes it serves its initialValue — whose `pairing` is null.
        // consumeDeepLink runs in onCreate ahead of the lifecycle collector, so on the cold,
        // web-driven path (the one an attacker uses) every replacement looked like a first pairing
        // and the user was shown "This link wants to pair this device with: …" instead of the
        // warning that their current server is about to be replaced.
```

### `val shownHost = pairingUrlHost(pairing.serverUrl)`
```
        // The parsed host, never the raw `srv` string. A raw URL in a trust prompt is a phishing
        // surface: `https://mail.trusted-corp.com@evil.tld/` reads as the trusted host on a
        // wrapped dialog while every request goes to evil.tld. pairingUrlHost() also refuses such
        // a URL outright now, so this is the second of two gates, not the only one.
```

### `AlertDialog.Builder(this)`
```
        // showSecurely, not show(): `kypost://native-pair` is a BROWSABLE deep link, so any web
        // page can raise this dialog, and it is the dialog that decides where this device's
        // `X-Kypost-Device-Secret` gets minted. A plain show() leaves its accept button coverable
        // by any app holding SYSTEM_ALERT_WINDOW — one tap on an attacker's own overlay and the
        // device is paired to their relay, with the TOFU pin locking their certificate in.
```

### `override fun getItemId(position: Int): Long = position.toLong()`
```
        // Position, not messageId.hashCode(). hasStableIds() is false so this is unused today,
        // but a hashCode collapsed to a Long is not a stable id, and overriding hasStableIds()
        // later would silently make two different messages the same row.
```

## app/src/main/java/org/kysecurity/mail/push/PushPairingLinkActivity.kt

### `class PushPairingLinkActivity : Activity() {`
```
/**
 * The only public entry point for `kypost://native-pair` deep links. This activity renders
 * nothing and holds no pairing/device state — it exists purely so the exported surface area is
 * a thin, stateless forwarder rather than [PushPairingActivity] itself, which is not exported
 * and shows device ID and cached push history. Splitting the two closes a path where any
 * co-installed app could force-render that sensitive screen via an explicit-component intent,
 * since intent-filter data matching only gates implicit intent resolution, not explicit intents
 * naming the component directly.
 */
```

## app/src/main/java/org/kysecurity/mail/push/PushPayload.kt

### `val keywordsCsv = (data["keywords"] ?: data["Keywords"]).orEmpty()`
```
        // Accept either casing. The server sends "Keywords" while every other field is camelCase,
        // and a lone capital letter silently degrading to an empty keyword list is not a failure
        // mode worth keeping load-bearing.
```

## app/src/main/java/org/kysecurity/mail/push/PushRepository.kt

### `private val securePairingStore: SecurePairingStore = SecurePairingStore(context),`
```
    // Injected rather than constructed here: this store owns a StateFlow of the current pairing,
    // and four separate instances of it used to exist across the app, each with its own copy of
    // that flow. PushGraph now owns the single instance.
```

### `private val inMemoryHistory = MutableStateFlow<List<PushPayload>>(emptyList())`
```
    /**
     * Push history while Hostile Location Protection is on.
     *
     * The whole promise of that feature is that nothing touches disk — Room goes in-memory for it.
     * Push history was still being written to `push_state`, an unencrypted protobuf, carrying
     * `senderName` and `emailSubject` for the last 30 messages. That is precisely the metadata the
     * feature exists to keep off the device, so under protection it lives here and dies with the
     * process instead.
     */
```

### `fun isPairedNow(): Boolean = securePairingStore.pairing.value != null`
```
    /** Pairing data for making an authenticated relay call right now — `deviceSecret` comes back
     *  null if "require unlock to receive push/MFA" is on and the app isn't currently unlocked via
     *  PIN; callers already treat a blank/missing deviceSecret as an auth failure, so this fails
     *  the same way a real 401 would. */
```

### `fun isPairedNow(): Boolean = securePairingStore.pairing.value != null`
```
    /**
     * Whether a pairing exists right now, read straight from the store.
     *
     * For callers that need the answer synchronously *before* anything has subscribed to [state] —
     * notably the deep-link confirmation dialog, which has to say whether accepting will replace an
     * existing pairing. Reading that from the `WhileSubscribed` UI flow returned its initialValue on
     * the cold path, so every replacement was presented to the user as a first pairing.
     */
```

### `fun pairingForAuthenticatedCall(keys: org.kysecurity.mail.security.CredentialKeys?): PairingData? =`
```
    /**
     * Pairing data for a call authorised by a PIN the caller has just verified on a foreground
     * screen, using keys from [org.kysecurity.mail.security.AppLockManager.verifyPinForDecision].
     *
     * Exists for [MfaApprovalActivity], where the app is legitimately still locked at the moment the
     * decision is submitted — see that method's KDoc for why routing it through
     * `cachedCredentialKeys()` made every gated MFA response unsendable.
     */
```

### `fun currentTlsPin(): TlsPin? = securePairingStore.currentTlsPin()`
```
    /** The TOFU TLS pin captured right after the first successful pairing, with the host it came
     *  from, or null if none has been captured yet. Read fresh on every call — never cached by the
     *  caller — since it can change on re-pairing. */
```

### `sealed class PairingCredentialState {`
```
    /**
     * What [savePairing] can do with a `deviceSecret` at a given moment.
     *
     * Captured as a value rather than re-derived inside [savePairing], because a caller that is
     * about to mint a secret has to decide *before* the network call and store *after* it, and the
     * app can lock in between — a background grace window expiring drops the cached credential key.
     * Re-reading the state on the way out would turn a checked precondition into
     * [Unavailable] with the server's rotation already committed.
     */
```

### `class Available(`
```
        /** The gate is on and this process holds the PIN-derived key to wrap with. */
```

### `fun currentCredentialState(): PairingCredentialState {`
```
    /**
     * Reads the current credential state.
     *
     * **Every caller that is about to mint a new secret must take this first and hand the same
     * value back to [savePairing].** The registration endpoint mints a fresh secret on each success
     * and invalidates the previous one, so registering while the result cannot be stored burns a
     * working credential to produce one with nowhere to go — see [PushSyncCoordinator].
     *
     * Keys off [AppLockStore.isCredentialPinGateEnabled] — the *policy* — never off whether a key
     * happens to be cached, which is wrong in both directions: it would re-wrap behind a gate that
     * has just been switched off, and it would permanently store the secret unwrapped after a
     * pairing made in a biometric-only session.
     */
```

### `suspend fun savePairing(`
```
    /**
     * Saves pairing data, wrapping `deviceSecret` behind the PIN-derived credential key when the
     * credential gate is on.
     */
```

### `private suspend fun purgeAccountScopedData() {`
```
    /**
     * Drops everything scoped to the account we are leaving. None of these tables carries a
     * subscriber column and [org.kysecurity.mail.ScopedValue] scopes only the cursors, so without this
     * the previous account's data outlived the pairing that authorised it: cached mail bodies stayed
     * readable (and folders the next account never fetches are never replaced), its contacts merged
     * underneath the next account's, device-contact sync kept publishing them to the OS provider
     * with no pairing at all, and — worst — queued contact changes were flushed to whichever server
     * was paired *next*, uploading one account's contacts to another.
     */
```

### `if (org.kysecurity.mail.contacts.device.DeviceContactPurge.deleteSyncedRows(context) < 0) {`
```
        // The rows this app published into the OS contacts provider go FIRST, while the link table
        // that indexes them still exists. Unpair used to clear the links and stop there, so the
        // previous account's whole address book stayed in ContactsContract — readable by every app
        // holding READ_CONTACTS and by the phone's own Contacts app — with the app's only route back
        // to those rows deleted in the same breath. Removing the account is what makes CP2
        // hard-delete them (ContactsProvider2.removeDataOfAccount); the explicit row delete covers
        // the window before the account removal lands.
```

### `if (org.kysecurity.mail.contacts.device.DeviceContactPurge.deleteSyncedRows(context) < 0) {`
```
        // DeviceContactPurge, not DeviceContactsRuntime.graph(...).repository: building that graph
        // constructs DataRuntime.graph(...), which during a wipe rebuilds the database this is
        // running after the deletion of.
        // Best-effort here — an unpair has no incomplete-result channel the way SecurityWipe does —
        // but not silent: both failures leave the previous account's address book in ContactsContract.
```

### `val db = org.kysecurity.mail.data.DataRuntime.peekGraph()?.database`
```
            // peek, not graph: during a security wipe the database has already been closed and
            // deleted, and building a new one here recreated `kypost_mail.db` on disk — with the
            // hostile-location flag file also already deleted, it recreated it *disk-backed*, in
            // the one mode that promises nothing touches disk. Nothing to purge means nothing to do.
```

### `db.contactSyncStateDao().clearAll()`
```
                // The contact-sync cursor lives here now, not in the contacts_state DataStore the
                // file deletion below still targets. Without this a re-pair to the same account
                // resumes from the old cursor and the address book never repopulates.
```

### `android.util.Log.e(TAG, "Failed to purge account-scoped tables", it)`
```
            // This one silently swallowed the exact failure the function's own KDoc describes:
            // a purge that does not happen leaves the previous account's cached mail readable and
            // its queued contact changes ready to flush to whatever server is paired next.
```

### `listOf("mail_sync_state", "contacts_state").forEach { name ->`
```
        // The mail and contact cursor stores are scoped by subscriber, but scoping only makes a
        // stale value unreadable — it does not remove it. Leaving them behind kept a hashed map of
        // the previous account's folder set and its per-folder read timestamps on disk after an
        // unpair, and the shared-scope-key defect made one of them readable again.
```

### `listOf("mail_sync_state", "contacts_state").forEach { name ->`
```
        // contacts_state is legacy: the cursor moved into the contact_sync_state table (cleared
        // above). It stays in this list so installs that predate the move do not keep the old file.
```

### `val enrollmentResidue = org.kysecurity.mail.pgp.EnrollmentTeardown.destroy(context)`
```
        // Every process-static holder at once, via the registry rather than by name: an unsent
        // draft cached under the previous account would otherwise be restored by the next Compose
        // inside the new account's session and sent through the new account's relay; the PGP
        // custody cache would keep hiding (or offering) the Encrypt/Sign chips for the wrong
        // account; the ephemeral attachment plaintext would simply still be there. No code path
        // here restarts the process. Enumerating them individually is what let the third one be
        // written and never added — see [org.kysecurity.mail.ProcessScopedState].
        // The sealed envelope holds THIS account's PGP private key, so it is account-scoped and
        // belongs here. The wipe and Hostile Location Protection already tore it down; the account
        // boundary was the third destructive path and the one left out — so unpairing, or a re-pair
        // driven by the exported kypost://native-pair link, carried one account's private key into
        // the next account's session behind nothing but the device lock screen. The fourth path,
        // "Remove from this device" in SecuritySettingsActivity.confirmRemoveEnrollment, tears down
        // the same vault and server record but is deliberately NOT routed through here or through
        // ProcessState.resetAll(): unenroll keeps the account paired, so it must not also discard an
        // in-progress draft or ephemeral attachment the way this account-boundary purge legitimately
        // does. It clears org.kysecurity.mail.pgp.EnrollmentSession directly instead. Naming it here so
        // the next destructive path that touches account-scoped in-memory state checks this list
        // instead of repeating the omission that made EnrollmentSession the third one in the first
        // place.
```

### `suspend fun unpairDevice(`
```
    /**
     * Best-effort server deregistration, then unconditional local clear: even if the network call
     * fails (offline, server already removed the device, credentials already invalid), the device
     * must still be usable to re-pair afterward — local state can never be stuck "paired". Also
     * cancels the periodic pull worker, which [clearPairing] alone does not do.
     *
     * [pairing] defaults to reading the credential here, which is right for a user-initiated unpair.
     * [org.kysecurity.mail.security.SecurityWipe] passes one it captured *before* it started deleting
     * files: the wipe destroys `push_pairing_secure` early on purpose (plaintext first, network
     * last), so by the time it reaches this call there is nothing left to authenticate with and the
     * deregister could only ever fail — leaving the relay pushing to a wiped device indefinitely,
     * which is the exact failure the deregister exists to prevent.
     */
```

### `private suspend fun tearDownPushTransport() {`
```
    /**
     * Severs the delivery channel itself, not just the record of who we were paired with.
     *
     * [clearPairing] drops this app's *copy* of the endpoint and purges account data, but it leaves
     * the FCM registration token unrotated and the UnifiedPush subscription live at the distributor
     * — so the relay a user just walked away from kept a working push channel into a device the UI
     * reports as detached, and could still post sender/subject under this app's identity. Unpair is
     * the app's own remedy for a relay the user no longer trusts, so it has to cut the channel.
     * [org.kysecurity.mail.security.SecurityWipe] already does all of this; only this path did not.
     *
     * Deliberately NOT shared with the wipe's versions of these steps: the wipe runs each inside its
     * own fault-isolated `step(...)` because its Complete/Incomplete verdict is what tells a user
     * whether their data is really gone. Keep the two in sync by hand.
     *
     * Every operation is best-effort. A failure here must never prevent [clearPairing] below — the
     * contract this method documents is that local state can never be stuck "paired", and a
     * network-backed token delete is exactly the step most likely to fail offline.
     *
     * NOT called from the account-replacement path in [PushSyncCoordinator]: that branch
     * re-registers immediately afterwards and reads the FCM token to do it, so rotating the token
     * there would break the pairing it is in the middle of performing.
     */
```

### `runCatching { UnifiedPushRegistrar.unregister(context) }`
```
        // Unregister before deleting the connector's own state, for the reason SecurityWipe gives:
        // reversed, the unregister has no registration records left to tell the distributor about,
        // so the device stays subscribed at the distributor and its push server.
```

### `suspend fun updateUnifiedPushRegistration(endpoint: String?, p256dh: String?, auth: String?) {`
```
    /**
     * Persist the UnifiedPush endpoint + WebPush encryption keys from the last successful
     * unifiedpush registration, so a later resync can resend the same endpoint/keys instead of
     * falling back to an FCM token — there is no synchronous way to re-fetch these from the
     * UnifiedPush connector, they only ever arrive via the onNewEndpoint callback. Pass all-null
     * to clear (e.g. when the confirmed transport is no longer unifiedpush).
     */
```

### `suspend fun pullCursor(subscriberId: String): Long = pullCursorValue.get(subscriberId) ?: 0L`
```
    /**
     * The durable pull cursor for [subscriberId], defaulting to 0. Scoped to the subscriber so
     * re-pairing as a different subscriber starts from a clean cursor rather than skipping their
     * backlog.
     */
```

## app/src/main/java/org/kysecurity/mail/push/PushRuntime.kt

### `val securePairingStore = SecurePairingStore(appContext)`
```
    /**
     * The single [SecurePairingStore] for the process. It owns a StateFlow of the current pairing,
     * and four ad-hoc instances of it used to exist across the app — each with its own copy of that
     * flow, so a write through one was invisible to collectors on another and `PushRepository`
     * could keep reporting a pairing that had already been cleared or re-wrapped.
     */
```

### `val mfaChallengeTracker = MfaChallengeTracker(appContext)`
```
    /**
     * The single [MfaChallengeTracker] for the process.
     */
```

### `private val pinnedOrFallbackCallFactory: Call.Factory = PinnedOrFallbackCallFactory(`
```
    // Every credential-bearing client below shares this one pinned-or-fallback factory rather
    // than defaulting to the plain unpinned `pairingHttpClient()` — see the 2026-07-22
    // security-hardening spec's final-review fix round, finding C2. Wired directly to this
    // graph's own [repository] (not via [PushRuntime.graph], which would recursively construct
    // this same [PushGraph] instance mid-construction) — falls back to unpinned only while no pin
    // has EVER been captured (i.e. before the first successful pairing), then pins from the next
    // request onward. A pin that existed and is now gone fails closed; see [TlsPinState].
```

### `registrationClient = NativeRegistrationClient(callFactory = pinnedOrFallbackCallFactory),`
```
        // First pairing itself stays correctly TOFU-unpinned (no pin exists yet, so this falls
        // back to plain `pairingHttpClient()`); every resync afterward automatically pins once
        // the pairing call above has captured one.
```

### `val deregisterClient = DeregisterClient(`
```
    /**
     * Deregistration gets its own factory purely for the hard call timeout.
     *
     * Both callers treat a failed deregister as non-fatal and clear local state regardless
     * ([PushRepository.unpairDevice]), and [org.kysecurity.mail.security.SecurityWipe] runs it while an
     * attacker may be holding the device — where it must not be able to hold the wipe open for
     * OkHttp's default connect-plus-read budget. The wipe wrapped it in `withTimeoutOrNull`, which
     * cannot interrupt a thread blocked in a socket read; OkHttp cancelling its own call can. The
     * request is a `{}` POST with a one-field response, so this ceiling cannot cut a real one short.
     */
```

### `const val DEREGISTER_CALL_TIMEOUT_MS = 3_000L`
```
        /** Internal, not private: [org.kysecurity.mail.security.SecurityWipe] builds its own
         *  deregister client from a pin it captured before deleting anything, and it must not
         *  invent a second ceiling for the same call. */
```

## app/src/main/java/org/kysecurity/mail/push/PushSyncCoordinator.kt

### `class PushSyncCoordinator(`
```
/**
 * Every registration this class performs mints a **new** `deviceSecret` server-side and invalidates
 * the previous one (see [NativeRegistrationResponse.deviceSecret]). That makes registering while
 * the result cannot be stored strictly destructive: the working credential is revoked and its
 * replacement is discarded. [PushRepository.currentCredentialState] is therefore a precondition on
 * every path below, not a courtesy check — with the credential PIN gate on, a background FCM token
 * rotation in a process that was never PIN-unlocked used to leave the device permanently
 * unauthenticated behind a UI still reading "Paired".
 */
```

### `val existing = repository.state.first().pairing`
```
        // A pairing for a different account is a REPLACEMENT, and the previous account's data must
        // not survive into it. purgeAccountScopedData exists for exactly this and its own KDoc names
        // the harm — "queued contact changes were flushed to whichever server was paired next,
        // uploading one account's contacts to another" — but it was only ever reachable from the
        // explicit Unpair button and from SecurityWipe. This path, which any web page can drive
        // through the exported BROWSABLE kypost://native-pair link behind one confirmation tap,
        // called neither: the pending-change queue is not scoped by subscriber, and
        // ContactSyncRepository.sync prefers push whenever it is non-empty, so the *first* contacts
        // call to the new relay uploaded the previous account's records, pgpKey included.
        //
        // Before the network call, so a registration that succeeds cannot land on stale data.
```

### `val credentialState = repository.currentCredentialState()`
```
        // Taken BEFORE the network call and reused after it: the app can lock while the call is in
        // flight, and re-reading the state on the way out would discard a secret the server has
        // already committed to.
```

### `return kotlinx.coroutines.withContext(kotlinx.coroutines.NonCancellable) {`
```
        // NonCancellable from the request onward: the server mints the replacement deviceSecret and
        // invalidates the previous one before it answers, so being cancelled after the call and
        // before savePairing leaves the device holding a revoked credential behind a UI still
        // reading "Paired", recoverable only by scanning a fresh QR code. This scope belongs to the
        // pairing screen's ViewModel, which is cancelled by onCleared the moment the user navigates
        // away — a Back press during a slow registration was enough.
```

### `result.tlsPin?.let { repository.saveTlsPin(it) }`
```
                // TOFU: capture the TLS pin only here, on the pairing call itself — never on the
                // routine resyncs below (syncAndPersist), so a MITM that appears after pairing gets
                // rejected rather than silently re-trusted on the next successful resync.
```

### `suspend fun resyncActiveTransport(): NativeRegistrationResult {`
```
    /**
     * Resyncs using whichever transport is currently confirmed active, instead of always
     * assuming FCM: if the last successful registration was unifiedpush, resends the stored
     * endpoint + WebPush keys (there's no way to re-fetch these from the connector on demand,
     * they only arrive via onNewEndpoint), otherwise falls back to [syncCurrentPairingToken].
     * Used by user/app-initiated resyncs (e.g. "resync token", app-open) — NOT by flows that
     * explicitly want to force FCM (switching away from UnifiedPush), which should keep calling
     * [syncCurrentPairingToken] directly.
     */
```

### `return if (endpoint != null) {`
```
        // unifiedPushEndpoint is only ever set (see syncAndPersist) when we last successfully
        // registered with transport="unifiedpush", and cleared on any other successful sync —
        // it's a reliable local signal independent of whether the server echoes transport back.
```

### `val resolution = NativeRegistrationEndpointResolver.resolve(`
```
        // Re-derive the registration URL on every use rather than trusting what the store hands
        // back. NativeRegistrationEndpointResolver's own KDoc claims it "also covers a pairing
        // persisted by an older build", but its only caller runs on freshly *parsed* links — this
        // path took the stored value verbatim and put it straight into Request.Builder().url(...).
        // That URL carries the device secret and, on an install with no pin yet, is what seeds the
        // TOFU pin: OkHttp's CertificatePinner enforces nothing for a hostname it has no pattern
        // for, so a stored serverUrl/registrationUrl host divergence left every credential-bearing
        // client silently unpinned. RelayMailSource.baseUrl re-validates serverUrl per request for
        // exactly this reason.
```

### `val credentialState = repository.currentCredentialState()`
```
        // The single choke point for every resync entry point (token refresh, transport switch,
        // manual "Resync token", app-open recovery), so none of them can register into a state
        // where the minted secret has nowhere to go. Reported as a sync error like any other, which
        // is what surfaces it on the pairing screen instead of failing silently in the background.
```

### `return kotlinx.coroutines.withContext(kotlinx.coroutines.NonCancellable) {`
```
        // NonCancellable for the same reason as attemptPairing: from here on the server has minted a
        // replacement secret and revoked the previous one, so dropping the response strands the
        // device with a credential that no longer works.
```

### `if (repository.currentTlsPin() == null) {`
```
                // Still TOFU — the pin is captured on the pairing call, never *replaced* here, so a
                // MITM appearing after pairing is still rejected rather than re-trusted. But an
                // install carried over from a build that predated pinning has no pin at all and no
                // way to ever acquire one, which left it silently running the unpinned fallback
                // client forever. Capture on first success when, and only when, none is stored.
```

### `if (transport == PushTransport.UNIFIED_PUSH) {`
```
                // Gate on the transport we requested, not result.transport: older servers may
                // not echo transport back (it's null in that case), which would otherwise wipe
                // the endpoint/keys we just successfully registered right after setting them.
```

## app/src/main/java/org/kysecurity/mail/push/SecurePairingStore.kt

### `data class TlsPin(val host: String, val spkiSha256: String)`
```
/** A TOFU certificate pin together with the host it was actually observed on. The host used to be
 *  inferred from the pairing's `serverUrl` at enforcement time, while the pin itself came from the
 *  *registration* URL's handshake — two different URLs, one pin, correct only by coincidence. */
```

### `sealed interface TlsPinState {`
```
/**
 * Why a request is or is not pinned.
 *
 * Exists so "we have never paired" cannot be answered the same way as "we had a pin and it is
 * gone". The first is the legitimate TOFU window and must allow an unpinned connection; the second
 * is a downgrade and must fail closed.
 */
```

### `sealed interface SecretWrite {`
```
/**
 * What [SecurePairingStore.savePairing] should do with the stored `deviceSecret`.
 */
```

### `class Wrapped(val secret: String, val keys: CredentialKeys, val salt: ByteArray) : SecretWrite {`
```
    /** Store it wrapped behind the PIN-derived credential key.
     *
     *  **Not a `data class`.** The generated `toString()` prints `secret=` followed by the pairing
     *  device secret in the clear, so one interpolation into a log line or an exception message
     *  puts this device's bearer credential in logcat. The generated `equals`/`hashCode` would also
     *  be identity-over-[ByteArray] on `salt`, which is the trap [org.kysecurity.mail.security.WrappedSecret]
     *  and [org.kysecurity.mail.security.PinHash] already refuse for the same reason. Nothing
     *  compares or prints these. */
```

### `class SecurePairingStore(context: Context) {`
```
/**
 * Holds pairing proof material (device secret, pairing token) in a Keystore-backed
 * EncryptedSharedPreferences file rather than the plaintext DataStore used for the rest of the
 * push state (history, sync status, server URL setting).
 */
```

### `@Volatile`
```
    /** The TOFU pin, cached because [currentTlsPin] is on the hot path of every HTTP request and
     *  the backing file costs four AES operations to read. **Invariant:** [saveTlsPin] and
     *  [clearPairing] are the only writers and both must update this. */
```

### `private val tlsPinTripwire =`
```
    /** Plain, unencrypted companion to [KEY_TLS_PIN] — see [tlsPinState]. Same shape and same
     *  reason as [org.kysecurity.mail.security.AppLockStore]'s tripwire: a marker that survives the
     *  encrypted file being reset, so "the pin vanished" is distinguishable from "there never was
     *  one". */
```

### `suspend fun savePairing(pairing: PairingData, secret: SecretWrite) {`
```
    /**
     * Writes the pairing, applying [secret] to the stored `deviceSecret`.
     *
     * The secret's fate is a [SecretWrite], not a nullable `String` plus a `preserveStoredSecret`
     * boolean. Those two encoded four intentions in two arguments, and two of them meant opposite
     * things: `deviceSecret = null` was "delete it" from one caller and "leave it alone" from
     * another, and getting that wrong destroyed a credential the user cannot get back — the server
     * had just minted a replacement and invalidated the previous one, leaving the device with no
     * usable secret, a UI still reading "Paired", and no repair path
     * ([org.kysecurity.mail.security.rewrapPairingIfNeeded] bails on a blank secret, and turning the
     * gate back off unwraps a value that is no longer there). A sealed type makes each intention
     * say its own name and makes the `when` exhaustive.
     */
```

### `suspend fun savePairing(`
```
    /** Convenience for the callers that hold a pairing and want its own secret written under the
     *  current gate posture: wrapped when keys are supplied, plaintext when they are not, and
     *  [SecretWrite.Clear] when the pairing carries no secret at all. */
```

### `fun hasStoredPairing(): Boolean = !prefs.getString(KEY_SUBSCRIBER_ID, null).isNullOrBlank()`
```
    /** Whether a pairing exists on disk at all, without decrypting anything. Distinguishes "there
     *  is no secret to strand" from "there is one and we cannot read it" — see
     *  [org.kysecurity.mail.security.SecuritySettingsActivity]'s unwrap path, where the two used to
     *  be conflated into a silent `return`. */
```

### `fun pairingSnapshot(credentialKeys: CredentialKeys?): PairingData? = readPairing(credentialKeys)`
```
    /** Reads pairing state, unwrapping `deviceSecret` with [credentialKeys] if it was stored
     *  wrapped. Returns the same shape either way; `deviceSecret` comes back `null` if it's
     *  wrapped and [credentialKeys] is null or wrong — never throws. */
```

### `fun needsCredentialRewrap(): Boolean {`
```
    /**
     * True when the stored `deviceSecret` is not wrapped under the current scheme while the
     * credential gate is on — either not wrapped at all (a background FCM token rotation ran in a
     * process that was never PIN-unlocked) or wrapped at [SECRET_VERSION_LEGACY], from before the
     * Keystore pepper existed. Both are closed by [org.kysecurity.mail.security.rewrapPairingIfNeeded].
     */
```

### `if (prefs.getString(KEY_SUBSCRIBER_ID, null).isNullOrBlank()) return false`
```
        // No pairing means no secret to wrap. Without this, an unpaired device answered "yes"
        // forever, so every PIN unlock ran the full rewrap dance — Keystore read, pairing snapshot,
        // AES — before bailing out at the first null. Cheapest possible check, and it is the same
        // field readPairing() treats as the pairing's existence.
```

### `suspend fun saveTlsPin(pin: TlsPin) {`
```
    /** Persists the TOFU TLS pin captured right after the first successful pairing, together with
     *  the host whose handshake produced it — never overwritten on later requests, only on a fresh
     *  pairing (initial or after [clearPairing] + re-pair). */
```

### `withContext(Dispatchers.IO + NonCancellable) {`
```
        // ORDER: marker, then pin, then cache. All three orderings fail at *something*; only
        // this one fails closed.
        //
        // Publishing the cache first — which is what this did, to close a window where
        // `currentTlsPin()` was null while the marker already read as captured — opens the mirror
        // window: the cache says Pinned while nothing is on disk. A process death in it (an OOM
        // kill, a force-stop, an OEM battery killer, all most likely on the memory-heavy pairing
        // screen) leaves no pin AND no marker, so the next launch reads `NeverPaired` and serves
        // every credential-bearing request over bare system-CA trust, permanently and silently.
        // That is the downgrade `TlsPinState.Lost` exists to refuse.
        //
        // With the marker first, the same interruption yields `Lost`: requests refuse, the user
        // re-pairs, and the failure is visible and recoverable.
```

### `fun currentTlsPin(): TlsPin? = cachedTlsPin`
```
    /** The currently enforced TLS pin, or null if this device has never captured one — including
     *  a pin stored without its host, which is ignored rather than applied to a host it may not
     *  have come from. */
```

### `fun tlsPinState(): TlsPinState {`
```
    /**
     * The pin, or why there isn't one. **"No pin yet" and "the pin is gone" are different answers
     * and must not be collapsed.**
     */
```

### `private fun buildEncryptedPrefs(appContext: Context): SharedPreferences =`
```
    /** See [openEncryptedPrefs]. A reset costs the pairing AND the TOFU TLS pin, so it happens only
     *  for an undecryptable keyset — never for a transient I/O failure, which is what the bare
     *  `catch (Exception)` this replaces treated identically. */
```

## app/src/main/java/org/kysecurity/mail/push/UnifiedPushRegistrar.kt

### `object UnifiedPushRegistrar {`
```
/**
 * Drives the UnifiedPush distributor selection + registration flow from an Activity.
 * Mirrors the flow used by the official UnifiedPush Android example: resolve first
 * to decide whether a confirmation prompt is needed, then let the library itself
 * show its own distributor picker when the choice is ambiguous (tryUseCurrentOrDefaultDistributor
 * launches that picker internally and reports the outcome via callback).
 */
```

### `fun beginRegistration(activity: Activity, onResult: (success: Boolean, error: String?) -> Unit) {`
```
    /**
     * Begins registration. [onResult] reports whether a distributor was selected
     * and registration was requested — the endpoint itself arrives later,
     * asynchronously, via KyPostUnifiedPushService.onNewEndpoint.
     */
```
