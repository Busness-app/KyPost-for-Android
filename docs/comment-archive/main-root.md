# Comment archive - main (root package)

## app/src/main/java/org/kysecurity/mail/Email.kt
### `val pgpEncrypted: Boolean = false`
```
    // PGP state carried through from the relay; see RelayEmailDto for the
    // encrypted-vs-failed-decrypt distinction and PgpMessageState for how it is
    // turned into something to render.
```

## app/src/main/java/org/kysecurity/mail/HttpExecute.kt
### `fun <T> Call.Factory.executeSync(request: Request, map: (Response) -> T): Result<T>`
```
/**
 * Runs [request] through this [Call.Factory] and applies [map] to the response inside the same
 * `use` block, so callers don't each write their own `runCatching { ... .execute().use { } }`.
 * The [Result] failure branch is a thrown network exception; body decoding stays the caller's job.
 */
```

## app/src/main/java/org/kysecurity/mail/ScopedValue.kt
### `class ScopedValue<T>`
```
/**
 * One subscriber-scoped value in a [Preferences] DataStore: [scopeKey] travels alongside
 * [valueKey] so a change of scope (e.g. re-pairing as a different subscriber) reads back null
 * instead of the previous scope's stale value.
 */
```

## app/src/main/java/org/kysecurity/mail/ForwardAttachmentHandoff.kt
### `object ForwardAttachmentHandoff : ProcessScopedState`
```
/**
 * Carries a forwarded message's attachments from [EmailDetailActivity] to [ComposeActivity].
 *
 * Not an Intent extra: attachments are base64 and capped at 25 MB total, while a Binder
 * transaction is limited to roughly 1 MB — putting them in the Intent throws
 * `TransactionTooLargeException` on any real attachment. Both Activities live in this process, so
 * a single-use handoff is both correct and cheaper than making Compose re-download what the detail
 * screen already has in hand.
 */
```

## app/src/main/java/org/kysecurity/mail/InMemoryPlaintext.kt
### `object InMemoryPlaintext`
```
/**
 * Destroys every process-scoped holder of message plaintext and account-scoped state.
 *
 * Process-scoped `object`s are not self-expiring: [org.kysecurity.mail.security.AppRestart.relaunch]
 * does not kill the process, so without this a security wipe would run to completion, remove the app
 * lock, relaunch into the same JVM and leave the victim's unsent message one tap away in a session
 * the attacker now controls. The same statics also crossed an unpair/re-pair, restoring one
 * account's draft inside another account's session.
 *
 * **Deliberately does not enumerate the holders.** A hand-maintained list went stale the first time
 * one was added — see [ProcessScopedState], which holders now register with instead.
 *
 * **Not called from `AppLockManager.lockNow()`:** the draft cache exists precisely so a
 * lock-interrupted composition survives, and clearing it there would discard the user's message on
 * every ordinary lock.
 */
```
### `fun clearAll(): List<String>`
```
    /** Returns the names of holders that failed to clear, so a caller that must report honestly
     *  ([org.kysecurity.mail.security.SecurityWipe]) can refuse to claim a clean wipe. Empty on success. */
```

## app/src/main/java/org/kysecurity/mail/EmailAdapter.kt
### `subjectTextView.contentDescription = when {`
```
            // The markers are emoji, which screen readers announce inconsistently or not at all,
            // so spell the state out instead of relying on them being read. A failed signature is
            // announced ahead of readability for the same reason it outranks it in the marker: the
            // row opens and reads normally, which is what makes an unflagged forgery dangerous.
```
### `signatureState == PgpSignatureState.KEY_CHANGED ->`
```
                // Unreachable today: signatureState comes from pgpSignatureStateOf, which cannot
                // produce KEY_CHANGED (that state comes only from a local decrypt). Kept so a
                // future row-level local verdict does not silently regress this branch.
```
### `val isUnread = email.status == "unread"`
```
            // Minor "unread" cue: a small accent dot plus a bolder, higher-contrast subject —
            // the same signal used for keyword pills with unread mail (InboxActivity.styleKeywordChip).
```
### `internal fun dispatchEmailListUpdate(`
```
/** Reports an inbox list change row by row.
 *
 *  Not `notifyDataSetChanged()`: that marks every attached ViewHolder invalid, so adapter positions
 *  read NO_POSITION until the next layout pass. ItemTouchHelper dispatches a completed swipe from a
 *  posted runnable that abandons the swipe permanently when it reads NO_POSITION, which strands the
 *  swipe's recover animation — the delete background then paints under the list until the process
 *  is killed, and the message is never deleted. Deleting several emails in a row is what lines a
 *  second swipe up with the first one's list update. */
```

## app/src/main/java/org/kysecurity/mail/MainActivity.kt
### `class MainActivity : LockedActivity()`
```
/**
 * Launcher and router: decides between the inbox and the pairing screen.
 *
 * Routing moved out of `onCreate` and into [onStart] so it happens strictly after
 * [LockedActivity]'s lock check — otherwise this Activity would launch the inbox and *then*
 * redirect itself to the unlock screen, racing two Activities into the task.
 */
```
### `private fun handleIntent(intent: Intent)`
```
            // No MFA routing here. This used to parse `type=mfa_challenge` out of its own extras and
            // forward to the approval screen; nothing in this app ever built such an intent, because
            // the MFA notification's PendingIntent targets MfaApprovalActivity directly.
```
### `private fun notificationExtras(intent: Intent): Bundle?`
```
    /**
     * The "open this message" extras, but only from an Intent this app actually built.
     *
     * This Activity is exported — the LAUNCHER filter requires it — so every extra on [intent] is
     * attacker-reachable by any co-installed app with no permissions at all. Forwarding them
     * unchecked let such an app drive the inbox to a message id of its choosing and put arbitrary
     * strings on screen in the position where a real sender and subject go. The token is the same
     * shape of fix as splitting `PushPairingLinkActivity` out of `PushPairingActivity`.
     */
```

## app/src/main/java/org/kysecurity/mail/AboutDialog.kt
### `const val APP_VERSION = BuildConfig.VERSION_NAME`
```
// -----------------------------------------------------------------------------
// App version shown on the About overlay and reported to the server on every device
// registration. Sourced from the build's versionName so there is one place to bump: the two used
```
### `fun showAboutDialog(activity: Activity)`
```
/** Shows the "About" overlay: app credit line plus a scrollable copy of the GPL v2. */
```
### `cornerRadius = dp(100).toFloat()`
```
            cornerRadius = dp(100).toFloat() // fully rounded pill
```
### `val divider = View(activity)`
```
    // Accent hairline separating the credit line from the license.
```
### `val boxHeight = ...`
```
    // Size the scroll box to a comfortable slice of the screen so it feels intentional on any device.
```
### `private fun formatLicenseText(raw: String): CharSequence`
```
/**
 * The bundled GPL text is print-formatted: paragraphs hard-wrapped at ~70 columns, headings padded
 * with leading spaces to fake centering. Dropped into a narrow monospace box each line wraps a
 * second time and it reads as a ragged mess. This reflows it for the screen without altering any
 * wording (the license itself stays verbatim on disk):
 *  - blank-line-separated blocks become paragraphs;
 *  - centered headings (deep leading indent) are bolded and center-aligned;
 *  - sample/notice blocks (indented, whitespace-significant) stay monospace and verbatim;
 *  - ordinary prose is unwrapped so it flows to the box width in a proportional font.
 */
```

## app/src/main/java/org/kysecurity/mail/KeywordSettings.kt
### `fun rememberKeywords(keywords: Set<String>)`
```
    /**
     * Merges newly-seen keywords into the remembered set, bounded on both axes.
     *
     * Keywords are the relay's per-message `label`, which is unvalidated server input, and this set
     * is rendered as one un-recycled `Chip` per entry during `InboxActivity.onCreate`. Unbounded,
     * a single inbox response could brick the app: ~50k labels reproducibly threw
     * `OutOfMemoryError` inside `onCreate` (measured: ~17k chips in ~14s before the throw), and one
     * 20MB label consumed most of the heap just loading this file. The Keyword Settings screen —
     * the only place a user could clean up — dies the same way, and this file outlives unpairing,
     * so there was no in-app recovery at all.
     *
     * Eviction is oldest-first, which keeps the labels the user has seen most recently.
     */
```
### `if (hostileLocationSettings.isEnabled()) return`
```
        // Server-assigned labels describe the user's mail, so under Hostile Location Protection
        // they must not be written to this plaintext file. Tabs still work for the session from
        // whatever the current fetch returned; only the accumulated history is skipped.
```
### `const val PREFS_NAME`
```
        /** Public so [org.kysecurity.mail.security.SecurityWipe] and
         *  [org.kysecurity.mail.push.PushRepository.clearPairing] can clear this file by name rather
         *  than repeating the literal. */
```

## app/src/main/java/org/kysecurity/mail/ProcessScopedState.kt
### `interface ProcessScopedState`
```
/**
 * State that lives in a process-scoped `object` and must not survive into a new session.
 *
 * [org.kysecurity.mail.security.AppRestart.relaunch] deliberately no longer kills the process, so
 * "process-scoped" stopped being its own expiry. Every static holder of message plaintext,
 * account-scoped state or notification bookkeeping therefore has to be reset by hand at a
 * session boundary — a security wipe, an unpair, or a re-pair.
 */
```
### `fun resetForNewSession()`
```
    /**
     * Drop everything held for the outgoing session.
     *
     * Must be safe to call from any thread, more than once, and while another thread is reading —
     * a wipe runs concurrently with whatever the UI is doing. Must not throw; [ProcessState.resetAll]
     * isolates failures but a holder that throws is one that did not clear.
     */
```
### `object ProcessState`
```
/**
 * The registry [ProcessScopedState] holders announce themselves to.
 *
 * Holders register from their `object` initialiser, which means a holder the process has never
 * touched is never registered — and that is correct rather than a gap: an uninitialised `object`
 * holds nothing to clear. What it buys is that *touching* a holder is what enrols it, so there is
 * no path where state exists and is unregistered.
 */
```
### `fun resetAll(): List<String>`
```
    /**
     * Resets every registered holder, isolating failures so one bad holder cannot leave the rest
     * of the session's plaintext in memory. Returns the holders that failed, so a caller that has
     * to report honestly (see [org.kysecurity.mail.security.SecurityWipe]) can.
     */
```

## app/src/main/java/org/kysecurity/mail/SingletonGraph.kt
### `interface ClosableGraph (misplaced SingletonGraph KDoc)`
```
/**
 * Thread-safe, context-scoped lazy holder shared by each package's `XGraph`/`XRuntime` pair
 * (mail/MailGraph, contacts/ContactsGraph, data/DataRuntime, push/PushRuntime) so the
 * double-checked-locking singleton logic lives in one place instead of four.
 */
```
### `interface ClosableGraph`
```
/**
 * A graph that owns something needing an orderly shutdown when it is dropped.
 */
```
### `fun invalidate()`
```
    /**
     * Drops the cached instance so the next [get] rebuilds it from scratch. Exists for settings
     * that change how a graph is constructed rather than how it behaves — Hostile Location
     * Protection picks disk-backed vs in-memory Room at [org.kysecurity.mail.data.DataGraph]
     * construction time, and a security wipe closes the database out from under the old graph.
     * Both used to require killing the process, which is why [org.kysecurity.mail.security.AppRestart]
     * no longer does.
     */
```
### `fun take(): T?`
```
    /**
     * Atomically removes and returns the cached instance, or null if one was never built.
     *
     * Taking it also means no later caller can be handed the instance that is about to be closed —
     * which `invalidate()` alone only guarantees for callers that arrive after it returns.
     */
```
### `fun peek(): T?`
```
    /**
     * The cached instance if one exists, without building it.
     *
     * For code that wants to act on a graph only when the process already has one. A plain [get]
     * during a security wipe rebuilt the graph the wipe had just torn down — and rebuilt it against
     * settings the wipe had already deleted, so [org.kysecurity.mail.data.DataGraph] read Hostile
     * Location Protection as off and recreated `kypost_mail.db` on disk.
     */
```

## app/src/main/java/org/kysecurity/mail/MailBackgroundExecutor.kt
### `private const val QUIESCE_TIMEOUT_MS`
```
/** How long [MailBackgroundExecutor.quiesce] waits for in-flight mail work to stop before giving
 *  up on it. Short: these tasks are network calls that may be blocked in a socket read, and the
 *  caller is a destructive teardown that must not be held up by an unreachable server. */
```
### `object MailBackgroundExecutor`
```
// State-changing mail actions (mark read, archive, delete, move) are fired here instead of an
// Activity-scoped executor so the IMAP round trip keeps running after the screen that triggered
// it finishes, letting the UI update optimistically instead of waiting on the network.
```
### `private val executor = AtomicReference<ExecutorService>`
```
    /**
     * [java.util.concurrent.atomic.AtomicReference], not `@Volatile` plus a plain assignment.
     */
```
### `fun quiesce(): Boolean`
```
    /**
     * Stops in-flight mail work and hands back a fresh pool.
     *
     * Called before the database is closed and deleted. `SingletonGraph.invalidate()` only makes the
     * *next* `get()` rebuild — every task already running holds the old `AppDatabase`, so closing it
     * out from under them threw `IllegalStateException` on a pool thread, which is an uncaught
     * exception on a non-UI thread, which is a process kill. This is the largest source of that:
     * these tasks are fired precisely so they outlive the screen that started them.
     *
     * Best-effort by construction. `shutdownNow` interrupts, and a thread blocked inside a socket
     * read does not observe an interrupt — hence the bounded wait and the unconditional rebuild.
     * What it buys is that the common case (a task between network calls, or queued and not yet
     * started) is torn down rather than left pointing at a closed database.
     */
```
### `val settled = try { previous.awaitTermination(...) }`
```
        // `awaitTermination` returns false on timeout and throws only on interruption, so wrapping
        // it in `runCatching` and inspecting only the failure branch discarded the one answer that
        // matters: "threads are still running against the database you are about to close". That is
        // the uncaught-exception-on-a-pool-thread process kill this function exists to prevent, and
        // it was being silently accepted. Report it instead — the caller still proceeds (a wipe
        // cannot be held hostage by a socket read), but it can now say so.
```
### `fun submitReporting(`
```
    /**
     * Runs a mail mutation and reports failure to the user.
     *
     * The toast is posted against the application context because the Activity that started this
     * has usually already finished — that is the whole reason this executor exists.
     */
```

## app/src/main/java/org/kysecurity/mail/ComposeDraftCache.kt
### `object ComposeDraftCache : ProcessScopedState`
```
/**
 * The in-progress composition, held for the life of the process so the app lock cannot destroy it.
 *
 * [org.kysecurity.mail.security.LockedActivity] *finishes* a gated screen rather than layering the
 * unlock prompt over it — which is what makes the lock unbypassable, and is worth keeping. The cost
 * was that any lock while composing discarded the message outright: recipients, subject, body and
 * every attachment already picked, with nothing to recover. The grace window in
 * [KyPostApp.onStop] stops the common case (a file-picker round trip) from locking at all; this
 * covers the rest.
 *
 * Deliberately in-memory and process-scoped, not on disk. The thing being survived is Activity
 * destruction, not process death — and a disk-backed draft would write message plaintext into the
 * app sandbox, which is exactly what Hostile Location Protection exists to prevent. A cache that
 * dies with the process needs no special-casing for that mode at all.
 */
```
### `private var sealed: Boolean = false`
```
    /**
     * Refuses writes until the next [take].
     *
     * `ComposeActivity.onStop` stashes the draft from `bodyEditor.exportHtml`, which is an
     * **asynchronous** callback on the main looper. A wipe clears this cache on an IO thread as
     * its very first step, and a callback already queued before that then landed afterwards and
     * put the victim's unsent message — recipients, body, attachments — straight back into a
     * static that survives [org.kysecurity.mail.security.AppRestart.relaunch]. Sealing on [clear]
     * makes the late write a no-op instead of a resurrection.
     */
```
### `fun take(): CachedDraft?`
```
    /**
     * Returns and clears — a restored draft is now owned by the screen that took it.
     *
     * Also unseals: a compose screen asking for the draft is a live session, and any callback left
     * over from the session that was wiped has long since been drained off the main looper (it was
     * queued strictly earlier than this Activity's `onCreate`).
     */
```
### `val encrypt: Boolean = false`
```
    /** The Encrypt and Sign toggles. Carried here because the compose form is excluded from the
     *  saved-state Bundle (see `ComposeActivity.onCreate`), and a fold that silently reset Encrypt
     *  to its unchecked layout default would send in the clear a message the user had asked to
     *  encrypt. Not part of [hasContent]: a toggle with nothing typed is not a draft. */
```

## app/src/main/java/org/kysecurity/mail/MemoryBudget.kt
### `internal object MemoryBudget`
```
/**
 * Every ceiling on attacker-influenced heap in this app, in one place, with the total stated.
 *
 * They live together because the sum is the number that matters: `minSdk 31`, no
 * `android:largeHeap`, and per-app limits routinely 128–192 MB. Split across three files, no one of
 * them could see more than its own third.
 *
 * **A limit is not a peak.** Some terms cost more than their bound at the instant they complete, so
 * each states its own multiplier and [WORST_CASE_PEAK_BYTES] is built from the peaks.
 *
 * **Static, not sized from `ActivityManager.getMemoryClass()`.** [PGP_PLAINTEXT_BYTES] is consumed
 * by [org.kysecurity.mail.pgp.PgpDecryptor], which has no Android imports so the same code runs in
 * a JVM test as on a device. There is also no smaller mail to fetch, so a runtime-measured budget
 * would buy a number the app cannot act on.
 */
```
### `const val RESPONSE_BYTES`
```
    /**
     * Any single HTTP response body. `/api/inbox` returns the full HTML body of every message in a
     * folder and is the largest response here; the attachment endpoint's own 25 MB cap sits under
     * this one.
     *
     * Multiplier 1x: [org.kysecurity.mail.BodySizeLimitInterceptor] counts bytes as they stream and
     * throws at the bound, so they never accumulate here. What the caller then materialises is
     * counted below rather than twice.
     */
```
### `const val PGP_PLAINTEXT_BYTES`
```
    /**
     * One decrypted OpenPGP message.
     *
     * An encrypted mail carries its attachments inline and base64-inflated, so the binding
     * constraint is the relay's 25 MB attachment cap: 25 MB of base64 is ~18 MB decoded, and the
     * surrounding MIME is small. A message that exceeds this is refused with `TooLarge`, a path the
     * UI already has.
     */
```
### `const val PGP_PLAINTEXT_PEAK_BYTES`
```
    /**
     * What [PGP_PLAINTEXT_BYTES] costs at the instant it completes.
     *
     * `PgpDecryptor.readAllWithLimit` accumulates chunks and then joins them into an exact-length
     * array; both are live when the first chunk is copied. That 2x is irreducible for any strategy
     * returning a `ByteArray` from a stream of unknown length, so it is stated rather than hidden
     * behind a limit that reads like a peak.
     */
```
### `const val PENDING_ATTACHMENT_BYTES`
```
    /**
     * Total decrypted attachment plaintext parked awaiting a viewer's read.
     *
     * The only *retained* term — up to a minute, across several attachments, while the other two are
     * transient — so it decides the realistic peak. 32 MB holds one attachment at the 25 MB relay
     * cap, which is the case that has to work; past that
     * [org.kysecurity.mail.security.EphemeralAttachmentBytes.register] refuses and the caller has a
     * "cannot serve this" path.
     *
     * Multiplier 1x: the bytes arrive already materialised and are stored by reference.
     */
```
### `const val WORST_CASE_PEAK_BYTES`
```
    /**
     * All three at their ceiling at once: 32 + 48 + 32 = **112 MB**.
     *
     * Reachable, and they genuinely overlap — an attachment parked for viewing from an earlier
     * decrypt, a big inbox refresh streaming on the mail executor, a second PGP message opening on
     * `Dispatchers.Default`. It fits a 128 MB heap with little room and a 192 MB heap comfortably.
     *
     * Raising any constant above means raising this, and this is the one that has to stay under a
     * mid-range device's heap.
     */
```

## app/src/main/java/org/kysecurity/mail/RecipientInputView.kt
### `class RecipientInputView`
```
/**
 * One TO/CC/BCC recipient field: an [AutoCompleteTextView] backed by a local-contact [Filter],
 * plus a [ChipGroup] of already-added recipient pills. ComposeActivity creates three instances.
 * Implements ContactAutocomplete.md sections 1, 2, and the "invalid formats"/"duplicate
 * prevention" parts of section 4 (the address-book modal itself is [org.kysecurity.mail.contacts.AddressBookSheet]).
 */
```
### `var onRecipientsChanged: (() -> Unit)? = null`
```
    /** Fires after a recipient is actually added or removed — i.e. once per committed change to
     *  [recipientEmails], never per keystroke. ComposeActivity uses this to re-run the encrypt
     *  preflight when the committed address set changes while Encrypt is checked. */
```
### `fun configure(search: ..., onOpenAddressBook: ...)`
```
    /** Wires local-contact search into the dropdown. Pass [onOpenAddressBook] on exactly one of
     *  the three TO/CC/BCC instances (ComposeActivity uses the TO row) — the address-book modal
     *  itself offers TO/CC/BCC actions per contact, so a single entry point covers all three
     *  fields; showing the icon on every field would just be three doors to the same room. */
```
### `fun addRecipient(email: String, displayName: String?): Boolean`
```
    /** Adds [email] as a chip if it isn't already present in this field. Returns false (and shows
     *  a duplicate toast) otherwise — [org.kysecurity.mail.contacts.AddressBookSheet] uses the return
     *  value to decide whether to flip its per-row checkmark. */
```
### `fun applyTheme()`
```
    /** Re-tints existing chips after a theme switch — call from the host Activity's onResume,
     *  alongside its other applyXTheme() calls. */
```
### `private inner class SuggestionAdapter`
```
    /**
     * Dropdown adapter. **No [Filterable], and no [Filter].**
     *
     * [debounceAndSearch] does it in the coroutine world instead, where cancelling the previous
     * job actually cancels it and the query never runs at all.
     */
```
### `override fun getFilter(): Filter`
```
        /**
         * [AutoCompleteTextView.setAdapter] requires a [Filterable], so one is provided — but it
         * does no work.
         *
         * All this does is hand back whatever [submit] last published, so the dropdown can size
         * itself. The searching happens in [debounceAndSearch], on a cancellable coroutine, because
         * `Filter`'s single serialised worker thread is the wrong place for a debounce and the
         * worst place for a blocking database call.
         */
```
### `private fun debounceAndSearch(`
```
    /**
     * A real debounce: the pending job is cancelled outright by the next keystroke, so a superseded
     * query never reaches the database.
     *
     * Scoped to the view's lifecycle via [findViewTreeLifecycleOwner], so a search in flight when
     * the screen goes away is cancelled with it rather than resuming against a closed database —
     * which the old `runBlocking` on a `Filter` thread had no way to avoid.
     */
```

## app/src/main/java/org/kysecurity/mail/ComposePgpController.kt
### `fun splitAddresses(vararg commaJoined: String): List<String>`
```
/**
 * Flattens the compose screen's three comma-joined recipient fields into one address list for the
 * preflight.
 *
 * Deduplicates case-insensitively: the same address in To and CC is one recipient to check, and
 * naming it twice in the confirmation dialog would read as two different people. The first spelling
 * wins, since that is the one the user typed and expects to see.
 */
```
### `class ComposePgpController(`
```
/**
 * The compose screen's PGP decisions, kept out of [ComposeActivity] so they are testable without a
 * Context and so the Activity stays a view.
 *
 * Nothing here decides whether to *send*. The confirmation is driven by the relay's 409, not by the
 * preflight — see [keylessRecipients].
 */
```
### `private val enrollmentProbe: suspend () -> Boolean`
```
    /** Whether this device still holds the account's private key. Injected so the controller stays
     *  Context-free and JVM-testable; the real one probes the Keystore via `probeEnrollment`. */
```
### `suspend fun composeState(): PgpComposeState`
```
    /**
     * Which PGP controls this account gets.
     *
     * The **bootstrap** is cached for the process on success only — caching a failure would disable
     * encryption for the rest of the session over one flaky request. Enrollment deliberately is
     * **not** cached: custody mode is fixed at key creation, but the user can enrol part-way through
     * a session and the OS can invalidate the Keystore key underneath us, so it is re-probed on
     * every call.
     *
     * Returns the everything-hidden state when the device is not paired or bootstrap fails:
     * couldn't-check is not "no".
     */
```
### `val pairing = withContext(Dispatchers.IO) { pairingProvider() }`
```
        // pairingProvider() reaches SecurePairingStore.pairingSnapshot(), which reads
        // Keystore-backed EncryptedSharedPreferences and does an AES unwrap — disk plus crypto —
        // so it must not run on the caller's dispatcher, which is Main for every call site today.
```
### `suspend fun keylessRecipients(addresses: List<String>): List<String>`
```
    /**
     * The addresses with no usable key **in the user's contacts**, for an inline warning.
     *
     * A lower bound, never a promise: the send path also runs WKD and keyserver discovery, so an
     * address here may still be encrypted to successfully. A failure yields an empty list — no
     * warning rather than a false one — which is safe because the relay's 409 is the actual gate,
     * so a failed preflight can never be the reason the pickup fallback gets used.
     */
```
### `private var cachedBootstrap: PgpBootstrapResult.Success? = null`
```
        /** Process-scoped, so a second compose in the same session costs no round trip. Not
         *  persisted: custody mode is fixed at key creation. An account switch does **not**
         *  restart the process — [org.kysecurity.mail.push.PushRepository.unpairDevice] only clears
         *  pairing and cancels the pull worker — so this cache has to be dropped at a session
         *  boundary via [ProcessScopedState]. Without that, a switch from a client-custody account
         *  to a server-custody one would keep hiding the Encrypt/Sign chips for the rest of the
         *  process.
         *
         *  Holds the **bootstrap**, not the composed state: enrollment is an input to that state
         *  and can change within one process, so it is re-probed rather than frozen here. */
```
### `fun from(context: Context): ComposePgpController`
```
        /** Wires the real, TLS-pinned clients. Mirrors [org.kysecurity.mail.pgp.hasPgpIdentity]'s
         *  Context-based default. */
```
### `enrollmentProbe = {`
```
            // Probes the Keystore rather than any bookkeeping of ours, so it stays honest across an
            // app reinstall or an OS key invalidation. Both the EncryptedSharedPreferences read and
            // the Keystore lookup touch disk, hence Dispatchers.IO.
```

## app/src/main/java/org/kysecurity/mail/PairingAuthHeaders.kt
### `const val HEADER_DEVICE_ID`
```
/**
 * **Why every credentialed client in this app takes an injected `okhttp3.Call.Factory`.**
 *
 * Two reasons, and this is the only place they are written down — the same five-line comment was
 * pasted into eleven client classes, which is a DRY violation whether the duplicated thing is code
 * or prose, and it drifted into four slightly different wordings.
 *
 * 1. `Call.Factory` rather than the concrete `OkHttpClient` so a test can inject a fake with no
 *    real network call and no MockWebServer dependency. `OkHttpClient` satisfies the interface, so
 *    production wiring is unaffected.
 * 2. There is deliberately **no default value** on any of those parameters. In production every one
 *    of them is a [org.kysecurity.mail.push.PinnedOrFallbackCallFactory], which re-reads the TLS pin
 *    per request and refuses outright once a pin that existed has gone; a default would let a new
 *    call site silently opt out of that. See [PinPosture].
 */
```
### `fun Request.Builder.pairingAuthHeaders(deviceId: String, deviceSecret: String)`
```
/**
 * Attaches this device's own pairing-auth credentials as headers. Replaces the old
 * account-wide shared subscriberId/subscriberHash headers (removed entirely — the server no
 * longer accepts them). deviceSecret is minted once per successful registration call and must
 * be persisted unconditionally by the caller (see SecurePairingStore), since each registration
 * mints a brand-new secret that invalidates the previous one.
 */
```
### `sealed interface PinPosture`
```
/**
 * Whether a client pins, stated rather than defaulted.
 *
 * [pairingHttpClient] used to take `pinnedSpkiSha256: String? = null, host: String? = null`, so
 * **the default posture was no pinning** and any call site that simply forgot got bare system-CA
 * trust for a request carrying this device's bearer credential. A sealed type with no default makes
 * the decision unskippable, and `grep TofuWindow` is now a complete audit of the unpinned surface —
 * which was previously not a question the source could answer.
 */
```
### `object TofuWindow : PinPosture`
```
    /**
     * No pin is enforced. Legitimate in exactly one situation: no pairing has ever completed, so
     * there is nothing to pin against yet. A pin that existed and is gone must NOT come here — see
     * [org.kysecurity.mail.push.TlsPinState.Lost], which fails closed instead.
     */
```
### `private val basePairingClient: OkHttpClient by lazy`
```
/**
 * The one client every request that carries [pairingAuthHeaders] is derived from.
 *
 * Actually shared, unlike the KDoc this replaces: [pairingHttpClient] used to claim to be a "shared
 * client" while being a factory that built a whole new [OkHttpClient] — its own dispatcher, thread
 * pool and connection pool — on every call, so nothing reused a connection and each re-pair
 * orphaned the pools of the client it replaced. `newBuilder()` below shares all three.
 *
 * Redirect-following is disabled: OkHttp only strips the standard Authorization header on a
 * cross-host redirect, not our custom device-id/secret headers, so a malicious or compromised
 * paired server could otherwise 3xx-redirect a request to an arbitrary host and receive the
 * device's bearer credential.
 */
```
### `fun pairingHttpClient(posture: PinPosture, callTimeoutMillis: Long?)`
```
/**
 * A client for [posture], sharing [basePairingClient]'s pools.
 *
 * [callTimeoutMillis] sets a hard ceiling on the *whole* call — connect, write, read, redirects —
 * rather than the per-phase defaults. Null keeps OkHttp's defaults, which is right for the
 * endpoints that stream up to 25 MB of attachment. It exists for the deregister call, where
 * `withTimeoutOrNull` could not deliver the bound its caller documented: coroutine cancellation
 * cannot interrupt a thread blocked inside a socket read, so the only thing that actually bounds a
 * blocking OkHttp call is OkHttp cancelling it. See [org.kysecurity.mail.security.SecurityWipe].
 */
```
### `private const val MAX_RESPONSE_BYTES`
```
/**
 * Hard ceiling on how many bytes any response body may yield, applied to every request this app
 * makes rather than to one endpoint at a time.
 *
 * `RelayMailSource.downloadAttachment` bounded its own read and documented why; every other
 * endpoint went through `response.body?.string()`, which materialises the whole body — and then
 * doubles it, since a Kotlin `String` is UTF-16. `/api/inbox` returns the full HTML body of every
 * message in the folder and is by far the largest response here, so the one place the bound was
 * missing was the place it mattered most: a hostile or compromised relay (or an active MITM before
 * the first TOFU pin exists) answering with a multi-hundred-megabyte body is an OOM kill, repeated
 * every 90 seconds by the inbox refresh cadence.
 *
 * Throws rather than truncating: a truncated JSON body fails to parse anyway, and callers map an
 * IOException to `UpstreamFailure` — a named failure beats a mystery parse error.
 *
 * The value lives in [MemoryBudget] with the app's other two heap ceilings, which it has to be read
 * against rather than on its own.
 */
```

## app/src/main/java/org/kysecurity/mail/KyPostApp.kt
### `class KyPostApp : Application(), DefaultLifecycleObserver`
```
/**
 * Process-level wiring for push/pull delivery. Observes the process lifecycle so that every time
 * the app foregrounds we re-read the authoritative delivery mode and, when in "App Pull" mode,
 * kick an immediate pull — complementing the WorkManager periodic baseline.
 */
```
### `runCatching { SecurityRuntime.graph(this@KyPostApp) }`
```
            // Build the security graph HERE, on IO, before any Activity asks for it.
            //
            // Constructing it forces AppLockStore's EncryptedSharedPreferences, which is a
            // MasterKey round trip into the AndroidKeyStore plus a Tink keyset load. The first
            // caller was LockedActivity.onCreate — via isLocked() — so that cost landed on the main
            // thread inside the first Activity of every cold start, including the FCM-woken process
            // that has to render MfaApprovalActivity promptly. SecurityGraph's own KDoc already
            // diagnosed this cost and fixed the *number* of times it was paid, not the thread.
```
### `val verdict = runCatching { SecurityWipe.enforceTripwire(...) }`
```
            // If the encrypted app-lock state vanished while the tripwire says a lock was
            // configured, the local database is destroyed rather than served up behind a lock that
            // now reports itself as disabled.
```
### `applyLockGrace()`
```
        // App moved to the foreground. The unlock screen is no longer launched from here: every
        // gated Activity now redirects to it in its own onCreate/onStart (see
        // org.kysecurity.mail.security.LockedActivity), which is what makes the lock unbypassable
        // rather than a screen laid on top of a live app.
```
### `if (SecurityWipe.blockedByAbandonedWipe(this)) return`
```
        // Nothing below runs while locked. These are credential-bearing network syncs; kicking
        // them off behind the unlock screen both leaks activity and pointlessly fails whenever
        // the credential gate is on and the device secret is still wrapped.
        //
        // isLockedNow(), not locked.value — AppLockManager's own contract says a security decision
        // must use the former, because the flow only changes when something calls lockNow() and a
        // background grace window may have expired with nothing having done so. applyLockGrace()
        // above happens to cover this today; relying on that made the correctness of these three
        // syncs depend on the order of two lines in this method.
        // The wipe verdict outranks the lock. `SecurityWipe.blockedByAbandonedWipe` exists for
        // "the non-Activity entry points that cannot go through LockedActivity's terminal block",
        // and this is one of them: with the lock off (the default) an abandoned wipe still left
        // every foreground kicking three credential-bearing syncs, which repopulated the OS
        // contacts provider and the mail cache the wipe was supposed to have destroyed — while
        // every screen sat on "manual recovery required".
```
### `if (!SecurityWipe.startupVerdict.isCompleted) return`
```
        // Likewise before the verdict is in at all: enforceTripwire may be mid-wipe on the IO
        // scope right now, and a sync racing it writes rows behind the deletion. onStart fires
        // again on the next foreground, by which time the verdict has landed.
```
### `private var backgroundedAtElapsedMs: Long = 0L`
```
    /**
     * When the app went to the background, on the monotonic timebase. Zero means "foreground, or
     * the grace window has already been resolved".
     */
```
### `override fun onStop(owner: LifecycleOwner)`
```
    /**
     * Locking is deferred by [AppLockSettings.graceMillis] rather than firing the instant the app
     * loses the foreground.
     *
     * Every outbound intent this app makes leaves the process: the attachment picker, the
     * attachment-viewer chooser, the QR scanner (a GMS process), the "Open in webmail" handoff.
     * Each one stops the last Activity, which fired `lockNow()` immediately — and because
     * [org.kysecurity.mail.security.LockedActivity] *finishes* rather than layering, coming back
     * destroyed the screen outright. Attaching a file to a message therefore deleted the message:
     * recipients, subject, body and every attachment already picked, with no draft to recover.
     *
     * The grace window is the standard resolution (every banking app does this) and is
     * user-configurable, defaulting to 30s — long enough for a file picker round trip, short
     * enough that a pocketed phone re-locks.
     */
```
### `appLockManager.scheduleLock(backgroundedAtElapsedMs + grace)`
```
        // Two mechanisms for one deadline, because neither is sufficient alone. The Handler is what
        // actually flips the lock state and drops the cached credential keys, but it runs on
        // `uptimeMillis`, which stops advancing in deep sleep. `scheduleLock` records the same
        // deadline on `elapsedRealtime`, so AppLockManager.isLockedNow() answers correctly even if
        // the callback has not fired — see that method.
```
### `private fun applyLockGrace()`
```
    /**
     * Resolves the grace window on the way back to the foreground, and cancels the pending
     * [engageLock] so returning inside the window doesn't re-lock a screen the user is looking at.
     *
     * Still re-checks the elapsed time itself rather than trusting the cancelled callback: a
     * `Handler` callback does not survive process death, and Doze can hold a non-exact
     * `postDelayed` past its deadline. Whichever of the two notices first, the app locks.
     */
```
### `override fun onTrimMemory(level: Int)`
```
    /**
     * Drops the opened PGP private key under real memory pressure.
     *
     * **[level] is load-bearing, and ignoring it undid the grace window.** `TRIM_MEMORY_UI_HIDDEN`
     * fires every time this app's UI goes away — the attachment picker, the QR scanner, the webmail
     * handoff, or the user glancing at a text message. Clearing on every trim signal therefore
     * meant a BiometricPrompt on return from each of those, on exactly the round trips [onStop]'s
     * grace window exists to make survivable, and it contradicted
     * [org.kysecurity.mail.pgp.EnrollmentSession]'s own contract that the key is "bound to the window
     * the user already configured at 'Lock after: …' rather than to a second concept of its own".
     *
     * `TRIM_MEMORY_RUNNING_LOW` and above are the levels that actually mean the process is a
     * candidate for a kill, which is the case worth paying a prompt for. The ordinary
     * background transition is [onStop]'s job, and it does it on the user's configured deadline.
     *
     * Deliberately NOT routed through `InMemoryPlaintext`. Its KDoc records that it is not called
     * from `AppLockManager.lockNow()` because the compose draft cache must survive an ordinary
     * lock; the key holder has the opposite requirement, so it gets its own call rather than a
     * change to that policy.
     */
```

## app/src/main/java/org/kysecurity/mail/InboxActivity.kt
### `private val pendingMessagePollRunnable`
```
    // The backend can take a few seconds to make a just-pushed email available via the inbox
    // fetch — a single refresh attempt right after the notification tap routinely misses it, so
    // this keeps polling (bounded by pendingMessageDeadlineMs) instead of giving up immediately.
```
### `val layoutManager = recyclerView.layoutManager as? LinearLayoutManager`
```
        // A still-unconsumed pending target wins over the live list, matching
        // ContactsListActivity: until the folder has loaded the RecyclerView is empty and
        // findFirstVisibleItemPosition() reports -1, so two folds inside the data-load window
```
### `swipeRefresh.setOnRefreshListener { refreshInbox(forceFullResync = true) }`
```
        // forceFullResync = true: the 90-second cadence sends the cursor and gets a delta, which
        // cannot repair a drifted cache. Someone pulling down is saying they think the list is
        // wrong, so this re-reads the folder rather than asking what changed.
```
### `intent.putExtra("email_pgp_signed", email.pgpSigned)`
```
        // Signature state is the only signal that separates an authentic signed message from an
        // impersonation. The relay computes it and it was persisted to Room behind its own
        // migration, but it stopped here — so a forged-signature message rendered with the
        // reassuring "this message was encrypted" bar and nothing else.
```
### `intent.putExtra("email_suspicious", isFlaggedPhishing(email.keywords))`
```
        // The $Phishing IMAP keyword the server sets on mail that impersonates
        // KyPost. See mail/PhishingFlag.kt for why the match is
        // case-insensitive.
```
### `val email = emails.find { it.id == id }`
```
        // Match by ID first, then fallback to fuzzy match by sender + subject if IDs don't match
        // (common in IMAP where push messageId might be a server UUID but email.id is header Message-ID).
        // The fallback requires a non-blank sender: `contains("")` is always true, so a push payload
        // with an empty senderName silently reduced this to subject-only matching and let whoever
        // composes the payload open — and mark read — an arbitrary other cached message whose
        // subject they could guess.
```
### `mainHandler.postDelayed(pendingMessagePollRunnable, ...)`
```
            // Not found on this attempt, but still within the deep-link wait window — the backend
            // may not have indexed the just-arrived email yet. Poll again shortly instead of
            // giving up after a single miss.
```
### `private fun refreshInbox(forceFullResync: Boolean = ...)`
```
    /**
     * [forceFullResync] is the difference between the 90-second cadence and a user pulling down.
     *
     * The automatic path sends the persisted cursor, so the relay answers with a delta — which is
     * right for a background poll and wrong for someone who just told the app they think it is out of
     * date. A delta cannot repair a cache that has drifted: `reconcileFetchResult` merges "updated"
     * entries over the existing row and skips entries it has never seen, so the states a user
     * actually pulls down about survive it. `since=0` re-reads the folder and prunes what is gone.
     *
     * There is already a daily forced resync for the same reason (`MailCursorStore`). A push tap
     * also forces one: opening its cached match would freeze stale body/bodyMode in the detail view.
     */
```
### `val showCacheFirst = ...`
```
        // No emails held in memory yet (cold open, or a just-switched-to folder) — render the
        // Room cache immediately so the list isn't empty while the network round trip is in
        // flight, then let the fetch below overwrite it with fresh data.
        //
        // Never on a pull: the gesture has its own spinner, and raising the full-screen overlay over
        // it would replace the list the user is looking at.
```
### `try { refreshInboxOnIo(...) } finally { ... }`
```
            // try/finally, not a call at the end of the happy path. cachedEmails and
            // rememberKeywords both touch Room and can throw, and a spinner that never stops is a
            // screen the user has to back out of to escape.
```
### `if (pendingMessageId == null) { loadingOverlay.visibility = GONE }`
```
                    // If we aren't waiting for a specific message (it was found in cache or 
                    // this isn't a deep link), we can hide the overlay now.
```
### `val discoveredThisBatch = KeywordTabs.buildTabs(emails)...`
```
        // Always show every allowed (visible-in-Keyword-Settings) keyword the app has ever seen,
        // not just ones present in the current email batch — a keyword tab shouldn't disappear
        // just because its last matching email got archived/deleted/filtered to another folder.
```
### `val dotSizePx = (7 * resources.displayMetrics.density).toInt()`
```
        // Unread state (bold text + a small leading accent dot, matching the same cue used on
        // inbox rows in EmailAdapter) tracks unread counts, which can change on a refresh even
        // when the keyword set itself doesn't, so refresh it unconditionally rather than folding
        // it into the rebuild check above.
```
### `val accent = Color.parseColor(getStoredThemePalette(this).accent)`
```
                // A checked chip is already accent-filled, so an accent-colored dot would
                // disappear into it — use the chip's own (contrasting) text color instead. This
                // has to be a ColorStateList (like chipBackgroundColor/chipStrokeColor already
                // are), not a one-off flat color: tapping a chip only toggles its checked state,
                // it doesn't re-run this loop, so a flat color baked in at whatever checked state
                // happened to be current here goes stale the moment the user selects a different
                // pill — which is exactly what showed as a dot stuck black in dark themes.
```
### `val cardRadius = resources.getDimension(R.dimen.card_corner_radius)`
```
        // Rounded on the same side as the row's own corners (item_email.xml's 14dp
        // cardCornerRadius) so the reveal doesn't show a sharp corner poking out from behind the
        // rounded card as it slides away.
```

## app/src/main/java/org/kysecurity/mail/AppTheme.kt
### `val avatarGradientStart: String`
```
    // Avatar gradient stops — mirrors web's ThemeVars newEmailStart/End/Border (used there for
    // the "compose" button gradient, reused here since .users-avatar/.contacts-avatar on web
    // draw from the same three fields).
```
### `activity.window.decorView.setBackgroundColor(bgColor)`
```
    // Every screen calls enableEdgeToEdge before setContentView, so the system bars are transparent
    // on every API level: what shows behind the status bar is the window background, and behind the
    // navigation bar the content background. Window.statusBarColor/navigationBarColor used to paint
```
### `activity.window.decorView.post { tintOverflowIcon(...) }`
```
    // The overflow ("more options") icon isn't part of the content view tree, so it never gets
    // painted by applyThemeToViewTree below. It defaults to a fixed light tint from the base
    // theme, which disappears against light accent colors (Sun, Sky, White Cliffs, ...). The menu
    // only exists once onCreateOptionsMenu has run, so defer the lookup by a frame.
```
### `fun applyKyPostTopBar(activity: Activity, subtitle: CharSequence)`
```
/** Top app bar brand treatment: KyPost name + launcher mark, with the screen/folder as subtitle. */
```
### `fun applyRailInsets(activity: Activity, view: View)`
```
/**
 * The rail equivalent of [applyBottomInset]. A vertical rail spans the full height at the start
 * edge, so the bottom-only padding that suits a bottom bar leaves its top item under the status bar
 * and its first icon under the gesture handle.
 */
```
### `val imeInset = insets.getInsets(WindowInsetsCompat.Type.ime()).bottom`
```
        // Under the enforced edge-to-edge of targetSdk 36, windowSoftInputMode="adjustResize" no
        // longer shrinks the window for the keyboard, so pad by the IME inset ourselves. It reads 0
        // whenever the keyboard is hidden, so screens without text fields are unaffected.
```
### `fun applyWarningCalloutTheme(context: Context, textView: TextView)`
```
/** Stroke + 12%-fill warning panel for non-interactive informational callouts — same stroke+fill
 *  shape as [applyDangerButtonTheme] (STYLE_GUIDE.md §4's danger-button pattern), but with the
 *  fixed warning yellow (STYLE_GUIDE.md §1) and applied to a TextView since callouts aren't
 *  buttons. Caller sets its own padding/margins; this only sets background + text color. */
```
### `fun applySuccessChipTheme(`
```
/** Success/"added" state for the address-book picker's TO/CC/BCC action chips — mirrors
 *  [applyDangerButtonTheme]'s stroke+fill shape (STYLE_GUIDE.md §4's danger-button pattern is the
 *  closest documented precedent for a colored actionable state) using [COLOR_SUCCESS_BORDER]/
 *  [COLOR_SUCCESS_TEXT] (STYLE_GUIDE.md §1) instead of the danger palette.
 *
 *  [animate], when true, cross-fades from the chip's current colors instead of snapping
 *  (STYLE_GUIDE.md §5/§7 — 120ms). Only pass true from the actual tap that adds a recipient;
 *  per-bind calls (recycled rows) must stay instant, so the default is false. */
```
### `private fun crossFadeChipColors(...)`
```
/** 120ms `FastOutSlowIn` cross-fade of a Chip's background/stroke/text colors — the shared motion
 *  timing all four sibling apps converged on independently (STYLE_GUIDE.md §5). Used for the one
 *  real color "snap" §7 calls out (the address-book chip's pill→success transition on tap); not
 *  wired into [applyPillChipTheme]'s checked/unchecked toggle, since Chip's own state machine
 *  already transitions that one and its colors are stateful `ColorStateList`s, not single values. */
```
### `fun applySectionLabelTheme(...)`
```
/** Small uppercase, letter-spaced, 72%-opacity `inkStrong` label — mirrors web's
 *  `.sidebar-section-label` / `.contact-details-section-title`. Group headers only, not body
 *  copy or per-field captions. */
```
### `fun applyPillChipTheme(...)`
```
/** Stadium pill chip per the style guide's filter-tab spec: inactive = transparent fill + `line`
 *  stroke; active/checked = `accent` fill + `readableOn(accent)` text. Shared by the inbox's
 *  keyword filter pills and the compose screen's formatting toolbar.
 *
 *  The inactive fill can't actually be [Color.TRANSPARENT]: Chip's underlying ChipDrawable paints
 *  a private `chipSurfaceColor` layer (sourced from the theme's `colorSurface`, which this app
 *  hardcodes dark for popup/dialog chrome — see themes.xml) *underneath* `chipBackgroundColor`,
 *  with no public setter to override it. A transparent fill let that dark layer show through,
 *  rendering near-black text on a near-black chip in light themes (invisible in dark themes purely
 *  by coincidence, since dark-on-dark still looked intentional there). Painting an opaque `panel`
 *  fill instead — matching the bar behind the pills — fully covers that layer and reads as "blank"
 *  against the matching bar. */
```
### `if (chip.chipIcon != null) { chip.chipIconTint = contentColors }`
```
    // Only tint, never clear: callers that pre-set `app:chipIcon` in XML (e.g. Compose's
    // icon-only formatting chips) want it recolored on every theme pass, same as the text color
    // above. Callers that never set one (the common case — keyword/attachment/plain-text pills)
    // are unaffected since chip.chipIcon stays null either way.
```
### `fun unreadDotDrawable(...)`
```
/** Small solid circle — a minor "has unread content" cue, reused for both inbox rows and keyword
 *  pills so the two surfaces read as the same signal. Defaults to `accent`, but callers placing
 *  it on an already-accent-filled surface (e.g. a checked pill) should pass a contrasting
 *  [color] instead, or the dot disappears into its own background. */
```
### `fun applyStatusBadgeTheme(...)`
```
/** Pill-outline status badge with a small leading dot — STYLE_GUIDE.md §4's "status badge + dot"
 *  component (iOS `StatusBadgeView.swift` / Linux `StatusBadge.qml`; previously missing on
 *  Android, §7 item 2). [active] = fixed success green ([COLOR_SUCCESS_BORDER]/[COLOR_SUCCESS_TEXT],
 *  §1); inactive = theme-derived `line`/`panel`/`ink`, never a fixed gray (§1: "inactive status
 *  uses line/panel/ink from the active palette, not a fixed color"). Non-interactive — this reports
 *  state, it doesn't toggle it. */
```
### `fun ibmPlexMonoFontFaceCss(context: Context): String`
```
/** Base64-inlined `@font-face` CSS for the bundled IBM Plex Mono Regular asset
 * (`assets/fonts/IBMPlexMono-Regular.ttf`), for injection into [EmailDetailActivity]'s WebView
 * HTML (STYLE_GUIDE.md §2/§7 item 1 — the email body previously rendered generic `monospace`).
 * Inlined rather than referenced via a `file:///android_asset/` base URL: that WebView renders
 * untrusted email HTML with JS enabled, and granting it `file://` origin access for a font is a
 * real security cost for a small convenience gain. Read once per process and cached — the ttf is
 * ~134KB, cheap to decode but no reason to repeat it on every email open.
```
### `val padH = (14 * density).toInt()`
```
            // A bare GradientDrawable carries no internal padding, so without this the text and
            // hint sit flush against the rounded border. Preserve any larger top padding a
            // multi-line field (e.g. the compose body) already declares.
```
### `val current = view.currentTextColor`
```
            // Hardcoded XML text colors in this app are always grayscale template leftovers
            // (black/white/mid-gray placeholders), never intentional brand colors, so any
            // grayscale color is safe to remap onto the active palette's ink tones.
```
### `if (view is androidx.recyclerview.widget.RecyclerView) { return }`
```
        // The inbox list themes its own item views (rounded CardViews) in the adapter. Recursing
        // into it here would overwrite each card's rounded background with a flat ColorDrawable,
        // and since only already-bound rows get hit the rounding ends up inconsistent. Skip its
        // whole subtree.
```
### `view.setBackgroundColor(panelColor)`
```
        // Keep panel containers in sync with the active palette. Always repaint (not just when
        // background == null) so switching themes without recreating the activity refreshes
        // containers that were already painted on a previous pass, not just newly-touched ones.
```
### `internal fun scalePxByDensity(value: Int, density: Float): Int`
```
/** Pure dp->px math, factored out of [dpToPx] so it's unit-testable without the Android
 *  framework (this project has no Robolectric setup) — [dpToPx] is the entry point every caller
 *  should use directly. */
```
### `fun LinearLayout.addViewSpaced(view: View, topDp: Int, bottomDp: Int)`
```
/** Adds [view] with vertical breathing room ([topDp]/[bottomDp], converted via [dpToPx]) instead
 *  of the zero-margin default plain `addView(view)` produces — the Security/Keyword settings
 *  screens build their layout by hand and need real gaps between sibling controls. */
```
### `fun applyPanelBackground(...)`
```
/**
 * Paints [view]'s background as a rounded, theme-`panel`-colored panel using the shared
 * STYLE_GUIDE.md §3 Card/panel radius (`@dimen/card_corner_radius`). For containers that need a
 * *rounded* panel fill rather than the flat fill `applyThemeToViewTree` gives generic ViewGroups.
 */
```
### `private fun applyButtonPadding(...)`
```
/**
 * Restores the inset a themed button loses.
 *
 * A `Button`'s default background is a nine-patch carrying its own padding, and that padding is where
 * the label's breathing room comes from. Replacing it with a [GradientDrawable] — which has none —
 * leaves the label flush against the rounded edge, and on a wide button with a long label it reads as
 * text running off the left side. Exactly the problem the [EditText] branch of [applyThemeToViewTree]
 * already documents and guards against; buttons had the same bug and no guard.
 *
 * `maxOf` so a view that declares larger padding in XML keeps it.
 */
```
### `private fun accentAffordanceColors(...)`
```
/**
 * The stroke/fill/text triple for a danger or warning affordance, resolved against the active theme.
 *
 * The constants in STYLE_GUIDE.md §1 are stated as pale tints — `#ffd8d3`, `#fff0b8` — which are
 * chosen to read as *light text on a dark panel*. On the light themes ("Light Matter" and friends,
 * panel `#fff8ee`) that same pale text lands on near-white, and the measured WCAG contrast is
 * **1.08:1 for the warning text and 1.24:1 for the danger text** — indistinguishable from the
 * background. That is what made the "remove key from this device" button and the push-relay warning
 * illegible on light themes.
 *
 * Rather than introduce new named colors, this keeps each affordance's documented hue
 * ([COLOR_DANGER] / [COLOR_WARNING]) and drives it toward black for light themes, so the guide's
 * palette still decides *what colour* the thing is and only the shade tracks the background. The
 * derived shades measure 5.84:1 (warning) and 9.57:1 (danger) on `#fff8ee`, both past WCAG AA;
 * the dark-theme path is byte-for-byte what it was (13.28:1 and 11.56:1 on `#252530`).
 */
```
### `fun isDarkTheme(palette: ThemePalette): Boolean`
```
/** True when [palette]'s background is dark enough that white text reads better on it than black —
 *  i.e. this is one of the app's "dark" themes (Dark Matter, Tropic Night, Ocean, ...) rather than a
 *  light one. Used by [org.kysecurity.mail.EmailDetailActivity] to decide whether rendered email HTML
 *  needs its own colors forcibly overridden: a light theme's palette already looks like a typical
 *  email's default white-background/dark-text design, so nothing needs overriding there, but a dark
 *  theme's palette does not, and most email HTML hardcodes its own light-mode colors regardless of
 *  the reader's OS/app theme. */
```

## app/src/main/java/org/kysecurity/mail/ComposeActivity.kt
### `private var handoffOnlyAccount = false`
```
    /** True once the PGP bootstrap has reported this account's key is held only by the user *and*
     *  this device is not enrolled. The Send action is withdrawn while it holds — see
     *  [applyPgpComposeState]. An enrolled device can encrypt locally, so this stays false there. */
```
### `private var sendJob: Job? = null`
```
    /** The in-flight client-encrypted send, if any. Guards against a double-tap starting two sends
     *  — the crypto plus the round trip leaves a wide window. Mirrors EmailDetailActivity's
     *  decryptJob. */
```
### `private var preflightJob: Job? = null`
```
    /** The in-flight preflight check, if any. Cancelled whenever a newer one supersedes it (a
     *  recipient change while Encrypt is checked) or Encrypt is switched off, so a late result
     *  can never re-show the "no key on file" warning after the toggle has already gone off. */
```
### `private var sentDraft: MailDraft? = null`
```
    /** The draft as it was actually sent, kept so the post-409 re-send reuses it byte-for-byte
     *  with only allowPickupFallback flipped. Re-exporting the editor HTML or re-encoding the
     *  attachments could produce a subtly different message. */
```
### `private var pgpChipListenersReady = false`
```
    /** Set by [applyPgpComposeState], which is where the chips' listeners are installed. The draft
     *  restore and that call can land in either order — `composeState()` only actually suspends on a
     *  cold bootstrap — so whichever is second is what applies the toggles. */
```
### `private fun applyRestoredPgpToggles() {`
```
    /**
     * Restores the Encrypt/Sign toggles a fold destroyed, once both halves are ready.
     */
```
### `rootView.isSaveFromParentEnabled = false`
```
        // Keeps the composition out of the saved-state Bundle, exactly as ContactEditActivity does
        // for the contact form. composeSubjectField and the recipient inputs freeze their own text,
        // so the framework's default view-hierarchy save would hand the subject and every address
        // to system_server, outside the app lock and outside SecurityWipe. ComposeDraftCache is
        // what carries the composition across a recreate instead.
```
### `bodyEditor.settings.apply {`
```
        // The editor ships with JavaScript on and a bound @JavascriptInterface, and it quotes
        // sender-authored markup. QuotedHtmlSanitizer is the primary control; these are the
        // independent second layer, and they close the leak that needs no script at all: without
        // blockNetworkLoads, merely pressing Reply or Forward fetched every remote image, iframe
        // and stylesheet the sender embedded, defeating the reader's "Show images" opt-in.
        //
        // Safe for the editor itself: its chrome is loaded from an inlined template, not over the
        // network, and on minSdk 31 file:///android_asset stays reachable regardless of
        // allowFileAccess.
```
### `val onRecipientsChanged = { if (encryptChip.isChecked) runPreflight() }`
```
        // Re-run the preflight whenever the committed recipient set changes, but only while
        // Encrypt is on — otherwise toggling Encrypt before any recipient is entered means
        // splitAddresses() sees an empty list, the initial check short-circuits, and the warning
        // never appears again no matter how many keyless addresses are added afterward.
```
### `rootView.setBackgroundColor(Color.parseColor(getStoredThemePalette(this).bg))`
```
        // applyThemeToViewTree paints every ViewGroup (root included) flat `panel`-colored by
        // default, so root and the cards below would otherwise be indistinguishable. Repaint the
        // root `bg`-colored (mirrors InboxActivity's recyclerView.setBackgroundColor(bg)) so the
        // rounded `panel` cards actually pop against it instead of blending in.
```
### `handoffOnlyAccount = state.handoffToWebmail`
```
        // On an UNENROLLED client-custody account the key is held only by the user, so this app
        // cannot encrypt or sign — and because both chips are GONE, sendEmail's
        // `isChecked && visibility == VISIBLE` computes both wire flags as false. The relay's own
        // client-custody guard is nested inside `if (sign || encrypt)`, so a flagless send skipped
        // it entirely and went out as plain MIME: a silent downgrade to cleartext on the one account
        // type configured for end-to-end encryption. Refuse instead, exactly as the web client does
        // ("quietly sending in the clear instead would be worse than failing") and route the user to
        // the handoff.
        //
        // On an ENROLLED one this no longer applies: the chips are VISIBLE, so the same expression
        // now computes a real user choice, and both unchecked is a deliberate plaintext send rather
        // than a silent downgrade. Send therefore stays available.
```
### `if (clientSideAccount) signChip.isChecked = false`
```
                // Sign-only is impossible on this path: the relay accepts multipart/encrypted and
                // rejects multipart/signed, so a signed-but-unencrypted delivery is refused
                // outright. Coupling the chips says so honestly; the web client papers over it by
                // silently encrypting anyway.
```
### `private fun runPreflight() {`
```
    /** Runs when Encrypt is switched on, and again on every committed recipient change while it
     *  stays on (see the onRecipientsChanged wiring in onCreate). Not debounced per keystroke:
     *  recipients are committed as chips by RecipientInputView rather than typed continuously, so
     *  this fires on a settled address list, never mid-keystroke.
     *
     *  Cancels any still-running preflight before starting a new one, so a recipient added a
     *  moment after a slow check started can't have its result clobbered by the earlier one
     *  landing late. */
```
### `private fun applyEditorThemeCss() {`
```
    /** Injects the active palette into the editor's WebView content so it doesn't render as a
     *  fixed light/dark WebView default regardless of the in-app theme. Passing the same [id] on
     *  every call replaces the previous tag rather than accumulating one per theme switch.
     *
     *  Also sets a floor on the document's own height: the editor watches
     *  `document.documentElement`'s resize and reports that height back to Android, which then
     *  becomes the WebView's *explicit* height (see the library's define_listeners.js /
     *  updateWebViewHeight) — overriding any Android-side match_parent/minHeight. Without a
     *  min-height here, an empty document reports only ~1rem, and the WebView shrinks to a single
     *  line no matter how much space its parent layout gives it. */
```
### `private fun addAttachments(uris: List<Uri>) {`
```
    /**
     * Adds the picked documents, one at a time.
     *
     * Sequential rather than a `forEach` of independent jobs: each one is checked against the
     * remaining budget, and concurrent checks would all see the same "before" total and every one
     * of them would pass.
     */
```
### `private suspend fun addAttachment(uri: Uri) {`
```
    /**
     * Reads one picked document on [Dispatchers.IO], enforces the 25 MB total cap (matching the
     * backend) **before** the bytes are in the heap, and renders a removable chip.
     *
     * Three things were wrong here. `OpenableColumns.SIZE` was read and then never used — the cap
     * was applied to `bytes.size`, i.e. after `readBytes()` had already materialised the entire
     * document, so picking a multi-gigabyte file from a cloud provider was an `OutOfMemoryError`
     * (which `runCatching` does not catch, so: a hard crash with an unsent message in flight, before
     * `onStop` could cache the draft). The read, the 33 MB base64 `String` and the whole thing again
     * for every file in a multi-select all ran on the main thread, from the picker callback — an ANR
     * on any real attachment. And the KDoc said "off the UI thread", which is where it was.
     */
```
### `if (isFinishing || isDestroyed) return@exportHtml`
```
            // exportHtml's callback runs on the main looper and can still fire after onDestroy has
            // called ioExecutor.shutdownNow() (e.g. app lock finishing this screen while the
            // export was pending) — dispatchSend below would then hit a shut-down executor and
            // throw RejectedExecutionException.
```
### `if (clientSideAccount && (draft.sign || draft.encrypt)) {`
```
            // A client-custody account encrypts here, not on the relay. Both chips unchecked is a
            // deliberate plaintext send and still goes down the ordinary path — which is what the
            // web client does, and what restores a capability the old withdraw-Send behaviour
```
### `private fun dispatchClientSend(draft: MailDraft) {`
```
    /**
     * The client-custody send: encrypt and sign on this device, then hand ciphertext to the relay.
     *
     * Threading mirrors [EmailDetailActivity]'s decrypt path. The sender is built on IO because the
     * pairing lookup reads Keystore-backed storage, and [ClientEncryptedSender.send] runs on
     * Default because Bouncy Castle is CPU-bound — on the main thread it is ANR-class. The biometric
     * prompt inside [AndroidVaultOpener] owns its own hop back to Main, so it must not be wrapped.
     */
```
### `private fun warnKeyChanged(addresses: List<String>) {`
```
    /**
     * A pinned key's fingerprint no longer matches what discovery returned.
     *
     * Deliberately louder and more specific than the missing-key case, and never merged into it:
     * this is what a key rotation looks like *and* what an interception attempt looks like, so the
     * user has to be told which it might be rather than "no key on file".
     */
```
### `.create()`
```
            // FLAG_SECURE on the dialog's own window: it enumerates recipient addresses, and the
            // Activity's own flag does not extend to a separate dialog window. Same precedent as
            // confirmPickupFallback.
```
### `private fun explainMissingKeys(addresses: List<String>) {`
```
    /**
     * No usable key for at least one recipient, and nothing was sent.
     *
     * There is no pickup fallback here and there must not be: the server-side one works by storing
     * the message plaintext, which is the thing client-side protection exists to prevent. So the
     * honest options are to add the key, or to continue in webmail — which has the browser-sealed
     * pickup path this app deliberately does not build.
     */
```
### `if (isFinishing || isDestroyed) return@runOnUiThread`
```
                // The round trip above can outlive the Activity: LockedActivity.onStart finishes
                // this screen outright if the app lock engages while a send is in flight, and
                // Activity.runOnUiThread still runs its Runnable after finish(). Building an
                // AlertDialog on a finishing/destroyed Activity throws BadTokenException (or, on a
                // merely-finishing one, succeeds and leaks the window) — bail before either dialog
                // branch runs.
```
### `val message = warning.ifBlank { getString(R.string.compose_send_success) }`
```
                        // The send already succeeded even when sentSaved is false or a pickup link
                        // failed — surface the warning as a notice, never as a failure, and never
                        // offer a retry that would duplicate the message. A non-blank warning (e.g.
                        // "failed to deliver a pickup link to 1 of 3 recipient(s)") is longer than
                        // the plain success message and shown right before finish(), so it needs
                        // LENGTH_LONG to have any chance of being read.
```
### `private fun confirmPickupFallback(keylessRecipients: List<String>) {`
```
    /**
     * Nothing was delivered when this fires — the relay refuses before any SMTP — so the re-send
     * cannot duplicate the message.
     *
     * The copy is the spec's, verbatim, because it is what makes the opt-in meaningful. Cancel is
     * the negative button and the dialog stays cancelable, so dismissing keeps the composition.
     */
```
### `.create()`
```
            // FLAG_SECURE on the dialog's own window. This one enumerates recipient addresses and is
            // the consent gate for storing the message plaintext on the server for seven days; the
            // Activity's own flag does not extend to a separate dialog window.
```
### `private fun handOffToWebmail() {`
```
    /**
     * Saves the composition as a draft and hands the Drafts URL to the **system**, so an installed
     * PWA or the user's browser opens it with the session it already has. Never an in-app WebView:
     * that shares no session and would put an account-password field inside this app.
     *
     * **Consent comes first.** `/api/mail/draft` writes plain MIME into the relay's IMAP store, so
     * this is the moment the message leaves the device unencrypted — on the one account type whose
     * configuration exists to stop exactly that. Saving first and asking afterwards, as this used to
     * do, meant the plaintext was already on the server before the dialog was drawn and Cancel
     * removed nothing (there is no delete path). The dialog now names the cost and the save only
     * happens if the user accepts it.
     *
     * The draft is saved without the PGP flags, since [MailDraft]'s sign/encrypt only apply to
     * /api/mail/send, not the plain /api/mail/draft endpoint.
     */
```
### `webmailChip.isEnabled = false`
```
        // Disabled for the whole in-flight window, starting before the async exportHtml/saveDraft
        // round trip even begins: a double-tap in that window would park two drafts and overwrite
        // activeDialog with the second dialog, orphaning the first. Re-enabled on every path that
        // doesn't end in finish() — the two failure toasts below, and the dialog's dismiss
        // listener, which covers Cancel and the no-handler case alike.
```
### `if (openWebmail(this, serverUrl, url)) {`
```
        // Prefers the installed PWA, then any browser — either way the browser session webmail
        // already holds comes with it, so the user is not asked to log in again just to press
        // send. Both land in another app's task, never this one's; see WebmailTab. Still no
```
### `override fun onStop() {`
```
    /**
     * Stashes the composition so the app lock cannot discard it.
     *
     * `onStop` (not `onDestroy`) because [bodyEditor]'s HTML export is asynchronous and needs a
     * live WebView to answer: the Activity is still fully alive here, and the lock's `finish()`
     * does not land until the following `onStart`.
     *
     * Only when the screen is going away for a reason the user did not choose. Pressing Back is a
     * deliberate discard, and resurrecting a message someone threw away is its own bug.
     */
```
### `if (isDestroyed) return@exportHtml`
```
            // Guarded like every other exportHtml callback in this file — this one had been missed,
            // and it is the one that writes into a process-scoped static. A security wipe clears
            // ComposeDraftCache as its first step on an IO thread; a callback already queued on the
```
### `internal fun readAtMost(input: InputStream, limit: Long, expectedSize: Long = -1L): ByteAr`
```
/**
 * Reads [input] fully, or throws [AttachmentTooLargeException] as soon as it has produced more than
 * [limit] bytes — never allocating the whole of an oversized source.
 *
 * `internal` rather than private so it is reachable from a plain JVM test — the bound is the whole
 * point of this function and the old code had none.
 */
```
### `val initial = expectedSize.takeIf { it in 0..limit }?.toInt() ?: ATTACHMENT_COPY_BUFFER_BY`
```
    // Pre-sized when the provider told us how big the document is, because ByteArrayOutputStream
    // grows by doubling and then `toByteArray()` copies the whole thing again. For a 25 MB
    // attachment that is ~32 MB of internal buffer plus a 25 MB copy, on the way to a ~34 MB base64
    // String — roughly triple the peak of a function whose entire purpose is bounding the heap.
    // Clamped to the budget so a provider that over-reports cannot make us allocate past it.
```

## app/src/main/java/org/kysecurity/mail/EmailDetailActivity.kt
### `private val ioExecutor = Executors.newFixedThreadPool(2)`
```
    // Two threads, not one. Every background task on this screen shared a single thread, so
    // downloading a 25 MB attachment blocked the body render — and the `Show images` reload, and
    // the quoted-HTML sanitize — behind it for the whole transfer.
```
### `private lateinit var replyForwardButtons: List<ImageButton>`
```
    /** [actionReply], [actionReplyAll] and [actionForward] — the subset of [actionButtons] that
     *  [applyReplyForwardAvailability] visually marks as unavailable for a
     *  [PgpMessageState.CLIENT_PROTECTED] message. Kept as its own field, rather than re-derived
     *  from [actionButtons] by position, so which three buttons this reaches cannot silently drift
     *  if [actionButtons]'s order ever changes. */
```
### `private var replyForwardState: PgpMessageState = PgpMessageState.CLIENT_PROTECTED`
```
    /**
     * The state Reply/Reply-All/Forward's click listeners check via [mayReplyOrForward] before
     * doing anything.
     *
     * Fail closed. [renderBody] runs on a background thread and, for an uncached message, makes a
     * network round trip before it can report a real [PgpMessageState] — see its own KDoc on
     * `bodyUnavailable` — and may never report one at all if it throws (caught by the `runCatching`
     * around its call site, which only toasts). Defaulting to [PgpMessageState.NONE] here would
     * leave Reply live for that entire window on exactly the messages this task exists to protect.
     * Set to the real, encrypted-or-not verdict as soon as the Intent extra is read in `onCreate`
     * (synchronous, no fetch involved), then overwritten with the definitive value once
     * [renderBody] resolves it.
     */
```
### `private var webmailUnavailable: Boolean = false`
```
    /** Set in the [PgpMessageState.CLIENT_PROTECTED] branch of [renderPgpBar] when no webmail URL
     *  could be resolved for this message. [showLocked] appends [R.string.email_pgp_no_webmail] in
     *  that case, since every [ReadOutcome] notice below was written assuming a webmail fallback
     *  exists — several end "...or open it in webmail" with no button and no address on screen when
     *  it does not. */
```
### `private var decryptJob: Job? = null`
```
    /** Guards [attemptDecrypt] against a second attempt landing while the first is still in flight
     *  — e.g. a tap on Decrypt while the automatic (unlockIfNeeded = false) attempt is still
     *  running. Without this, an outcome that resolves out of order (a stale [ReadOutcome.Cancelled]
     *  arriving after a real [ReadOutcome.Decrypted]) could regress a message already on screen back
     *  to the padlock. */
```
### `private var pgpSignatureState: PgpSignatureState = PgpSignatureState.NONE`
```
    /** The relay's verdict on this message's OpenPGP signature, from the detail Intent —
     *  initially. For a [PgpMessageState.CLIENT_PROTECTED] message this app can decrypt locally,
     *  it is overwritten with the local verdict from [displaySignatureVerdict] once that decrypt
     *  finishes, so it does not stay the relay's verdict for the message's whole lifetime on
     *  screen. Rendered by both [renderPgpBar] and [showLocked] — see [PgpSignatureState] for why
     *  it is separate from [PgpMessageState]. */
```
### `private val downloadedAttachments = linkedMapOf<Int, org.kysecurity.mail.mail.OutgoingAtta`
```
    /** Attachments downloaded on this screen, keyed by their listing index, so Forward can carry
     *  them. Populated lazily — only what the user actually opened is here, which is the honest
     *  limit of what this screen has without re-fetching every attachment on entry. */
```
### `replyForwardState = initialReplyForwardState(pgpEncrypted)`
```
        // Refines the fail-closed CLIENT_PROTECTED default above as soon as we synchronously know
        // better: an unencrypted message was never going to become CLIENT_PROTECTED, so there is no
        // reason to hold its Reply button hostage to the body fetch below. An encrypted one keeps
        // the fail-closed default until renderBody reports the real state. See
        // initialReplyForwardState's own KDoc for why this is a pure function rather than the
        // ternary it replaced.
```
### `phishingBar.visibility = if (phishingFlagged) View.VISIBLE else View.GONE`
```
        // Advisory only: the links this warns about are already refused by
        // SAFE_LINK_SCHEMES in shouldOverrideUrlLoading, whether or not the
        // server ever flagged the message.
```
### `if (!mayReplyOrForward(replyForwardState)) {`
```
            // Checked here, not via isEnabled = false: a disabled ImageButton's onTouchEvent
            // returns before performClick ever runs, which would make this very explanation
            // unreachable. See applyReplyForwardAvailability's KDoc for the rest of the reasoning
            // (fail-closed default, alpha-only visual signal, contentDescription for TalkBack).
```
### `allowContentAccess = false`
```
            // Defaults that are wrong for a renderer whose input is attacker-controlled HTML:
            // allowContentAccess defaults to true, which lets email markup reference this app's
            // own content:// providers, and DOM storage is state an email has no business
            // creating. allowFileAccess is already false on this minSdk but is pinned here so it
            // stays false if the default ever moves.
```
### `blockNetworkLoads = true`
```
            // Senders can embed tracking beacons — not just <img>, but <iframe>, <video>/<audio>
            // src or poster, <link rel="stylesheet">, and remote web fonts all fetch over the
            // network too, and blockNetworkImage only covers image-typed resources. Blocking all
            // network loads closes those too; loading them automatically would leak the reader's
            // IP and "message opened" status before they've decided whether to trust the sender.
            // btnShowImages lets them opt in per-message instead.
```
### `webView.webViewClient = object : WebViewClient() {`
```
        // Without a WebViewClient, WebView handles navigation itself: tapping a link in an email —
        // or a <meta http-equiv="refresh"> the sender planted — replaced this view's contents with
        // the target page, in-app, with no address bar for the user to check. That is a ready-made
        // phishing surface inside a trusted mail client. Hand every navigation to the system
        // instead, so it opens in a real browser with a visible URL.
```
### `if (!request.hasGesture()) return true`
```
                // Only act on a real tap. Sender HTML navigates on its own — an <iframe src> or a
                // <meta http-equiv="refresh"> fires this callback with hasGesture() false, needing
                // no JavaScript and no user interaction beyond opening the message. blockNetworkLoads
                // does not help: it gates resource loads, while this is a navigation throttle that
                // runs first, so a non-http scheme sails straight past it. Un-gestured, that gave a
                // remote sender one free implicit ACTION_VIEW per opened mail to any scheme on the
                // device — including this app's own kypost://native-pair, which conjures the pairing
                // dialog on top of the attacker's own pretext.
```
### `ioExecutor.execute {`
```
        // runCatching, not a bare block: an uncaught exception on an ExecutorService thread is a
        // process kill, and every input below is chosen by the sender — the body HTML, its length,
        // its CSS. `stripImportant` threw on a six-hex-digit CSS escape above the Unicode codespace
        // (fixed in decodeCssEscapes), which crashed the app on open and again on every reopen,
        // since the message stays in the mailbox. The decode bug is fixed; this makes the next one
        // an unreadable message rather than an unusable app.
```
### `private fun renderBody(`
```
    /** The body fetch, PGP-state resolution and HTML assembly for one message. Extracted from
     *  `onCreate` so the whole thing sits inside one `runCatching` on the executor thread — see the
     *  call site for why that matters. */
```
### `val serverUrl = if (pgpState == PgpMessageState.CLIENT_PROTECTED) {`
```
        // Resolved off the main thread with the URL it builds — pairingForAuthenticatedCall
        // reads Keystore-backed EncryptedSharedPreferences, which is disk I/O. Both are kept:
        // openWebmail re-derives the origin from serverUrl to check the URL it is handed.
```
### `fetchedBodyHtml = content?.html?.takeIf { pgpState != PgpMessageState.CLIENT_PROTECTED }`
```
            // Not `bodyToRender`: that is blanked for the PGP states with nothing to show. Enforced
            // here too, not just emergent from the server's empty CLIENT_PROTECTED body: the spec's
            // non-negotiable rule is that a local decrypt must never reach this property, and this
            // makes that explicit rather than relying on the server having nothing to assign.
```
### `private fun forwardMessage(`
```
    /**
     * Opens the composer with the whole message: the real body, and every attachment.
     */
```
### `quotedBodyHtmlAsync(emailPreview) { quoted ->`
```
                // Same sanitize-or-escape hop as the no-missing-attachments branch above. This one
                // used to interpolate `emailPreview` — 140 characters of the sender's raw HTML —
                // straight into the quote, which is the only path into the compose editor that did
```
### `private fun renderPgpBar(`
```
    /**
     * The only screen that tells the user what happened to an encrypted message. Silence here is
     * what the old build did, and it read as "this email is blank".
     *
     * [serverUrl] is passed in beside [webmailUrl] rather than read from a field so the two are
     * provably from the same render pass: the click listener below re-checks the link against the
     * origin it was built from, and a field could have been overwritten by a later render in
     * between.
     */
```
### `mailbox: String,`
```
        /** The account mailbox (IMAP folder) and message id this render is for, plus the sender
         *  exactly as displayed — needed only to kick off [attemptDecrypt] from the
         *  [PgpMessageState.CLIENT_PROTECTED] branch below. */
```
### `val signatureNotice = signatureNoticeFor(pgpSignatureState)`
```
        // A message can be perfectly readable and still be signed by someone other than who it
        // claims to be from, so the signature verdict is rendered even when there is no encryption
        // state to report. This was computed by the relay, carried through every layer and written
        // to Room behind its own migration — and then never shown, so a forged-signature message
        // displayed as ordinary mail while webmail flagged it.
```
### `val notice = signatureNotice`
```
            // The blank-screen case this function's KDoc warns about, still open for NONE after it
            // was closed for every encrypted state. An encrypted message the server has not warmed
            // arrives with pgpEncrypted false and no body, lands here, and rendered as silence.
            // A signature notice, where there is one, wins: it is a stronger statement than "nothing
            // to show" and the two would otherwise be concatenated into a contradiction.
```
### `if (serverUrl != null && webmailUrl != null) {`
```
                // Defer Open in Webmail visibility to renderReadOutcome to avoid a flash
                // of the fallback button before the on-device decrypt (attemptDecrypt with
                // unlockIfNeeded=false) resolves. The success path (Decrypted) and the
                // NeedsUnlock/Cancelled paths both hide webmail; only terminal failures
                // show it via showLocked's webmailUnavailable guard.
```
### `if (!openWebmail(this, serverUrl, webmailUrl)) {`
```
                        // The installed PWA, else the user's real browser — with the session
                        // webmail already holds, and in that app's own task. See WebmailTab for
                        // why this is neither an in-app WebView nor a Custom Tab.
```
### `pgpText.text = ""`
```
                // No pointless "This message is end-to-end encrypted..." paragraph — show only
                // actionable buttons (Decrypt Email vs Open in webmail). The signature badge,
                // if any, is rendered at the end of this function.
```
### `private fun applyReplyForwardAvailability(pgpState: PgpMessageState) {`
```
    /**
     * Records the definitive [PgpMessageState] for Reply/Reply-All/Forward's own click-time check
     * ([replyForwardState]) and updates the three buttons' visual state to match.
     *
     * `POST /api/mail/draft` uploads the draft to the server. Quoting a decrypted body into a
     * reply would hand the server the plaintext of a message this whole mode exists to keep from
     * it — at one tap, with no warning. There is no encrypted send path in the app yet, so there
     * is no safe destination for any of these three actions.
     *
     * Unconditional rather than gated on decrypt success — see [mayReplyOrForward] — so a button
     * never starts working once a message opens; that would teach the user a rule that is not
     * true.
     *
     * Deliberately does NOT set `isEnabled = false`. `View.onTouchEvent` returns before
     * `performClick()` ever runs on a disabled view, which would make the explanatory Toast in
     * each click listener unreachable dead code — a grey button the user taps for nothing. `alpha`
     * carries the visual signal instead, and [contentDescription][View.setContentDescription]
     * carries the same "why" to TalkBack that `isEnabled = false` would otherwise have announced
     * for free (as "disabled", with no reason) — the same substitution [EmailAdapter] already makes
     * for the inbox row's own PGP markers, and for the same reason: an emoji or a plain disabled
     * state tells a screen-reader user nothing a sighted user wouldn't also be missing.
     */
```
### `private fun signatureNoticeFor(state: PgpSignatureState): String? = when (state) {`
```
    /** The sentence for one [PgpSignatureState], or null when there is nothing to say. Shared by
     *  [renderPgpBar] (server-side verdicts) and [renderReadOutcome] (on-device verdicts) so the
     *  wording cannot drift between the two paths that can produce the same six states. */
```
### `opener = AndroidVaultOpener(this@EmailDetailActivity),`
```
            // No wrapper here: AndroidVaultOpener.open() owns its own dispatching now — IO for the
            // Keystore/prefs read, Main only for the BiometricPrompt itself — so nothing in this
            // caller needs to hop for it. See VaultOpenerAndroid.kt.
```
### `localSignerKeys = org.kysecurity.mail.pgp.RoomLocalSignerKeys(applicationContext),`
```
            // Wired, and load-bearing: without it the signature verdict is whatever the relay says
            // it is. Application context, because the reader outlives nothing but this screen and
            // the graph behind it is process-scoped.
```
### `private fun attemptDecrypt(mailbox: String, messageId: String, sender: String, unlockIfNee`
```
    /**
     * Automatic when the key is already held, explicit when it is not.
     *
     * The prompt stays tied to a deliberate tap so that a dismissal is always a response to
     * something the user just did, rather than a sheet that ambushed a message they opened by
     * accident.
     *
     * [EncryptedMessageReader.read] is deliberately Android-free — no `withContext` anywhere inside
     * it — which makes dispatching it off Main this caller's job. Left on the default
     * `Dispatchers.Main.immediate` of [lifecycleScope], the happy path (key already held, automatic
     * decrypt) would run a Keystore-backed disk read, the full BouncyCastle decrypt/verify and the
     * MIME parse all on the UI thread — ANR-class on a large message. Only [encryptedReader]'s own
     * pairing lookup goes on `Dispatchers.IO` (it is disk I/O, not CPU work); the reader's `read`
     * itself goes on `Dispatchers.Default`, matching the CPU-bound work inside it. The one exception
     * is the biometric prompt: `AndroidVaultOpener.open()` owns that hop back to Main itself, so
     * nothing here has to arrange it.
     *
     * [decryptJob] guards against a second attempt landing mid-flight — see its KDoc.
     */
```
### `lockedPlaceholder.visibility = View.GONE`
```
                // The one path that shows content. The body goes to the WebView and NOWHERE else:
                // not Room, and not fetchedBodyHtml, which feeds reply quoting into
                // ComposeDraftCache and on to POST /api/mail/draft — the server this message was
                // deliberately never readable by.
```
### `val palette = getStoredThemePalette(this)`
```
                // Routed through the same dark-theme override every other body gets — without it, a
                // sender who hardcodes their own colors (buildEmailBodyHtml's own KDoc: "virtually
                // all of them") renders black-on-black under a dark palette.
```
### `outcome.body.protectedSubject?.takeIf { it.isNotBlank() }?.let { subjectView.text = it }`
```
                // The real subject from the encrypted part's protected headers, when the sender used
                // them — the outer envelope subject is only ever a placeholder for this path. This is
                // the entire point of protected headers; leaving it unrendered defeats them.
```
### `if (verdict != PgpSignatureState.NONE) {`
```
                // Show the mailbox the verdict is ABOUT, not the header the sender wrote.
                //
                // `sender` and `resolvedSender` are separable by an attacker: a From whose display
                // name is `bob@example.com` and whose mailbox is `eve@evil.example` renders as
                // "bob@example.com <eve@evil.example>". The badge is computed against the resolved
                // mailbox, so putting the raw header beside it would let a badge earned by Eve's
                // key sit next to Bob's name. Wherever a verification verdict appears, the
                // resolved mailbox appears with it — and displaySignatureVerdict already guarantees
                // resolvedSender is non-blank whenever verdict is not NONE.
```
### `ReadOutcome.NoEncryptedContent -> {`
```
            // Terminal, unlike FetchFailed: the server answered, and its answer was that this
            // message carries no OpenPGP payload. Retrying cannot change that, so no Retry button —
            // offering one would invite the user to tap it forever.
```
### `btnRetryPayload.visibility = if (showsRetryButton(outcome)) View.VISIBLE else View.GONE`
```
        // Routed through the pure decision below rather than set inline per-branch, so the one
        // outcome that must never offer Retry (NoEncryptedContent — see showsRetryButton's KDoc)
        // cannot drift out of sync with a JVM test that has no Android framework to exercise the
        // branches above directly.
```
### `private fun showLocked(notice: String) {`
```
    /** The padlock and the webmail button always appear together: one says "not readable here",
     *  the other says "readable there" — except when [webmailUnavailable], where there is genuinely
     *  nowhere to send the user, and [R.string.email_pgp_no_webmail] is appended so the padlock does
     *  not sit next to a notice that dangles a webmail fallback with no button and no address on
     *  screen. */
```
### `setOnClickListener {`
```
                // A tap views; it never writes to disk. Saving into shared Downloads puts decrypted
                // mail outside the sandbox where no wipe reaches it, so it is a deliberate second
                // gesture with its own confirmation rather than the meaning of a single tap.
```
### `private fun downloadAttachment(`
```
    /**
     * Fetches an attachment and applies [action] to it.
     *
     * **Everything except the Toast and the chooser runs on [ioExecutor].** This used to hop back
     * to the main thread on completion and then do the whole of the save there: a base64 encode
     * for the forward cache plus a `ContentResolver` insert and a full stream write, of a payload
     * bounded only by the relay's 25 MB attachment ceiling. That is a guaranteed ANR on a large
     * attachment and a plausible OOM (base64 of 25 MB is a ~34 MB `String`, i.e. ~68 MB of UTF-16),
     * on the default code path.
     */
```
### `org.kysecurity.mail.security.AttachmentAction.VIEW_EPHEMERAL -> runOnUiThread {`
```
                // Deliberately NOT cached for forwarding on this path. rememberForForwarding
                // base64-encodes the plaintext into an immutable String that lives for the life
                // of this Activity — and, once forwarded, in the process-scoped
                // ForwardAttachmentHandoff. A String cannot be zeroed. That silently undid the
                // entire point of EphemeralAttachmentBytes, which goes to some trouble to
                // Arrays.fill(bytes, 0) on a timer. forwardMessage() already re-fetches anything it
                // does not have, so the cost is one extra download on a forward.
```
### `private fun confirmSaveToDownloads(emailId: String, emailFolder: String, info: AttachmentI`
```
    /**
     * Saving puts decrypted mail into shared storage, outside this app's sandbox, where no wipe
     * step can reach it except through [DownloadedAttachmentLedger]. That is a real decision, so it
     * gets a real prompt rather than being what an ordinary tap happens to mean.
     */
```
### `private fun saveToDownloads(name: String, mimeType: String, bytes: ByteArray): Boolean {`
```
    /**
     * Writes bytes into the shared Downloads collection via MediaStore (no storage permission
     * needed on the app's minSdk 31). Returns false if the insert or stream write fails.
     *
     * Name and type are sanitised on the way in, exactly as [viewAttachmentEphemerally] does.
     * Both come from the sender's `Content-Disposition`/`Content-Type`, which the relay passes
     * through unfiltered — and this is the branch taken when Hostile Location Protection is *off*,
     * i.e. by default, so it was the unhardened path that nearly everyone uses.
     */
```
### `org.kysecurity.mail.security.DownloadedAttachmentLedger.record(this, uri)`
```
            // Recorded so a later security wipe can delete it. This file is outside the app
            // sandbox, so nothing the wipe deletes reaches it — and the screen after a wipe tells
            // the user their local data has been erased.
```
### `setResult(RESULT_OK, Intent().putExtra(EXTRA_REMOVED_EMAIL_ID, emailId))`
```
        // Tell InboxActivity which row to drop immediately, mirroring its own swipe-to-archive/
        // delete optimistic removal. Without this, returning here re-triggers InboxActivity's
        // onStart refresh, which races the still-in-flight mutation above and can redraw the row
        // we just "removed" — the mutation still lands, it just looks like the button did nothing.
```
### `if (attachments.isNotEmpty()) ForwardAttachmentHandoff.put(attachments)`
```
        // Handed through the process-scoped cache rather than the Intent: a 25 MB base64 payload
        // in an Intent extra is well past Binder's ~1 MB transaction limit and would throw
        // TransactionTooLargeException. Both Activities are in this process, so a handoff object
        // is both correct and cheaper than re-downloading.
```
### `private fun openExternally(uri: android.net.Uri) {`
```
    /** Opens a link the user tapped inside an email in the system browser. Failure is silent-ish
     *  (a toast) rather than a crash: an email can name any scheme, including ones no app handles.
     *
     *  CATEGORY_BROWSABLE narrows resolution to components that accept being driven by untrusted
     *  content, which is what K-9 does on the same path — without it, an email link can reach an
     *  installed app's non-browsable exported activities. Callers must already have checked the
     *  scheme and the user gesture; see [SAFE_LINK_SCHEMES].
     *
     *  FLAG_ACTIVITY_NEW_TASK, so a sender-controlled page never renders inside this app's task:
     *  the address bar and the app switch are the cues that this is somewhere else, and this task's
     *  Recents card stays under this app's FLAG_SECURE. The webmail handoff in renderPgpBar reaches
     *  the same conclusion by a different route — see WebmailTab. */
```
### `private fun quotedBodyHtmlAsync(preview: String, then: (String) -> Unit) {`
```
    /**
     * The quoted original, as HTML, sanitized for the compose editor.
     *
     * Falls back to the escaped preview only when the body genuinely is not available (an
     * uncached message under Hostile Location Protection, or a client-protected one), which is the
     * same condition the PGP bar already reports to the user.
     *
     * Both quote builders go through here so the sanitize step cannot be forgotten on one of them.
     * The editor is a JavaScript-enabled WebView with a bound `@JavascriptInterface` and its
     * `setHtml` assigns to `innerHTML`, so an `onerror` attribute in a quoted message would execute
     * with the user's outgoing mail in reach — see [org.kysecurity.mail.mail.QuotedHtmlSanitizer].
     */
    /**
     * Sanitizes the quoted original off the UI thread, and refuses to try past a size bound.
     *
     * Both properties are load-bearing, and neither was present. `Jsoup.clean` costs time quadratic
     * in the sender's chosen nesting depth: measured against this exact function, 10k nested `<div>`
     * (50 KB) took 122 ms, 40k took 2.2 s, 80k (400 KB) took 12.7 s and 200k (1 MB) took 156 s, with
     * the output amplified up to 14.6x. This ran straight from the Reply/Reply-All/Forward click
     * listeners with no cap at all, so a message whose body is `"<div>".repeat(80000)` plus "please
     * reply to confirm" reliably ANR'd the app on a single natural tap, repeatable with every
     * message. The body is bounded only by the 32 MB response cap, so the tail is unbounded too.
     *
     * Run-2 found and fixed this same class in this same file — two quadratic regexes, closed with a
     * bounded pattern and a 512 KB cap — and the new sanitizer reintroduced it on the *main* thread.
     * The sibling jsoup call in this file, [stripImportant], was already on [ioExecutor]; now both
     * are. Past the cap the quote degrades to the escaped preview, which is the same fallback this
     * already used when the body is genuinely unavailable.
     */
```
### `private fun extractAddress(raw: String): String = addressFromHeader(raw)`
```
    // Delegates to mail/AddressText.kt so the rule is unit-tested and stays
    // identical to the webmail and Linux clients -- see AddressTextTest for why
    // a display name must never win over the real angle-addr.
```
### `private val SAFE_LINK_SCHEMES = setOf("http", "https", "mailto", "tel")`
```
        /** Schemes an email link may open. `intent:`, `file:`, `content:` and any third-party
         *  app's custom scheme are refused: routing untrusted sender content into an arbitrary
         *  installed app's deep link is not something a mail body gets to do. */
```
### `private val REMOTE_IMAGE_PATTERN = Regex(`
```
        /** Cheap heuristic for "does this body reference remote content" (images, iframes, media,
         *  stylesheets) — only used to decide whether the "Show images" bar is worth showing, not
         *  a security control itself (all network loads are blocked regardless via
         *  [android.webkit.WebSettings.setBlockNetworkLoads]).
         *
         *  The tag interior is bounded rather than `[^>]*`. Unbounded, this was quadratic on
         *  sender-chosen input and — unlike [stripImportant] — had no length cap and ran on every
         *  message on every theme: `[^>]*` scanned to end-of-body from each of the many `<img`
         *  positions, then backtracked looking for the attribute. Measured on-device at ~21.8s for
         *  a 128KB body of repeated `<img`, scaling 4x per doubling. 2KB is far past any real tag. */
```
### `internal fun buildEmailBodyHtml(bodyToRender: String, palette: ThemePalette, monoFontFace:`
```
/** Wraps [bodyToRender] (the email's own, untrusted HTML) in a themed document for [WebView].
 *  Pulled out of the `onCreate` body-loading callback so it's unit-testable without a
 *  Context-backed WebView/Activity (same extraction rationale as [mergedContactDto] in
 *  `ContactEditActivity`).
 *
 *  For a dark [palette], a plain `body` rule isn't enough: most email HTML hardcodes its own
 *  light-mode colors (inline `style="color:#000"`, legacy `bgcolor` attributes, or a `<style>`
 *  block of its own), and those win over `body`'s inherited color/background at every descendant
 *  that sets its own — producing exactly the reported bug (black text on the app's dark background
 *  where an email set its own text color but not a background, or black-on-white where it set
 *  both, depending on what that particular email happens to override). CSS `!important` beats a
 *  plain (non-`!important`) declaration regardless of origin or specificity, so a wildcard
 *  `!important` override here reliably wins over whatever the email brought — *unless* the email's
 *  own declaration is itself `!important` too, which real templates increasingly do specifically to
 *  defend their background/text colors against Gmail/Outlook/Apple Mail's own automatic dark-mode
 *  recoloring. When both sides are `!important`, the cascade falls back to specificity/origin, and
 *  an inline `style="...!important"` attribute always outranks any external stylesheet rule — no
 *  selector on our side, however specific, can out-rank it (that's exactly the residual bug: an
 *  email with an `!important`-marked white background stayed white-on-white, our forced light text
 *  landing on top of it unread). [stripImportant] removes every literal `!important` from the
 *  email's own markup first, so nothing in it can compete on importance at all — our `!important`
 *  rules then win unconditionally, regardless of what selector or attribute the email used, per the
 *  CSS cascade's origin/importance step being resolved before specificity is ever considered.
 *  Does not need JavaScript (disabled in this WebView) or WebView's own force-dark APIs (which
 *  follow the *system* day/night setting, not this app's independent, non-system-linked theme
 *  picker). Links are re-forced to the palette's accent color after the wildcard rule so they don't
 *  get flattened to the same color as body text.
 *
 *  [isDark] (from [isDarkPalette]) is a caller-supplied `Boolean` rather than computed in here from
 *  [palette] directly so this function stays free of any `android.graphics.Color` call — same
 *  reasoning as [mergedContactDto]'s extraction: a plain-JVM unit test can exercise it with no
 */
```
### `internal fun showsRetryButton(outcome: ReadOutcome): Boolean = outcome is ReadOutcome.Fetc`
```
/**
 * Whether [outcome] should offer a Retry button.
 *
 * True only for [ReadOutcome.FetchFailed] — a transport failure a second attempt might not repeat.
 * [ReadOutcome.NoEncryptedContent] looks similar at a glance (both leave the message unread) but is
 * terminal: the server answered, and its answer was that this message carries no OpenPGP payload,
 * so retrying cannot change it. Offering Retry there would invite the user to tap it forever.
 *
 * Pulled out as its own pure function — rather than left inline in [EmailDetailActivity]'s
 * `renderReadOutcome` `when` — so this one decision has a JVM test with no Android framework
 * involved, on a file where `isReturnDefaultValues = true` makes most other UI logic untestable.
 */
```
### `internal fun displaySignatureVerdict(outcome: ReadOutcome.Decrypted): PgpSignatureState =`
```
/**
 * The signature verdict actually safe to display for [outcome].
 *
 * [ReadOutcome.Decrypted.signature] can be non-[PgpSignatureState.NONE] — e.g.
 * [PgpSignatureState.SIGNER_UNKNOWN] — even when [ReadOutcome.Decrypted.resolvedSender] is blank:
 * [org.kysecurity.mail.pgp.PgpPayloadResult.resolvedSender]'s own KDoc documents this ("empty when the
 * server could not resolve one, e.g. a multi-mailbox From"), and a multi-mailbox `From` is exactly
 * the attacker-separable shape the resolved-vs-raw-sender display rule exists for in the first
 * place. Showing a verdict with no resolved mailbox to pin it to lets that verdict read as being
 * about whatever raw sender text the screen still has on it — so with no resolved mailbox to
 * display, this returns [PgpSignatureState.NONE]: there is nothing safe to say.
 */
```
### `internal fun mayReplyOrForward(state: PgpMessageState): Boolean = state != PgpMessageState`
```
/**
 * Whether Reply, Reply-All or Forward may be offered for a message in [state].
 *
 * False only for [PgpMessageState.CLIENT_PROTECTED] — see [EmailDetailActivity.applyReplyForwardAvailability]
 * for why that has to hold even once the message is decrypted on screen: `POST /api/mail/draft`
 * uploads to the server, so quoting a decrypted body into a reply would hand the server plaintext
 * this mode exists to keep from it, and there is no encrypted send path in the app to make that
 * safe.
 *
 * Pulled out as its own pure function for the same reason as [showsRetryButton] above: a JVM test
 * with no Android framework, on a file where `isReturnDefaultValues = true` makes the Activity's
 * own view-toggling logic untestable.
 */
```
### `internal fun initialReplyForwardState(pgpEncrypted: Boolean): PgpMessageState =`
```
/**
 * The [PgpMessageState] Reply/Reply-All/Forward should assume for [pgpEncrypted] before
 * `renderBody`'s background fetch — which may make a network round trip for an uncached message,
 * and may never complete at all if it throws — can report the real state.
 *
 * Fails closed: an encrypted message defaults to [PgpMessageState.CLIENT_PROTECTED], the one state
 * [mayReplyOrForward] refuses, rather than [PgpMessageState.NONE]. The alternative — assume
 * replyable until told otherwise — leaves the buttons live for the entire fetch on exactly the
 * messages this task exists to protect, and forever if the fetch throws. An unencrypted message
 * defaults to [PgpMessageState.NONE] since it was never going to become [PgpMessageState.CLIENT_PROTECTED]
 * regardless of how the fetch turns out, so there's no reason to hold it hostage to the same wait.
 *
 * Pulled out as its own pure function, rather than left as the ternary it replaced inline in
 * `onCreate`, so this specific fail-closed default has a JVM test independent of the Activity that
 * reads it — `EmailDetailActivity` itself can't be instantiated in this module's plain JUnit
 * tests (no Robolectric; see the other Android-framework-free notes throughout this file's test
 * class).
 */
```
### `internal fun safeFileName(raw: String, mimeType: String = ""): String {`
```
/**
 * The sender's filename, reduced to something safe to hand MediaStore.
 */
```
### `val expected = extensionForMimeType(mimeType)`
```
    // The extension comes from the type WE decided to declare, never from the sender's filename.
    // Sanitising the name and then trusting its suffix let `invoice.pdf.apk` through intact: the
    // MIME type handed to MediaStore was already reduced to application/octet-stream, but the name
    // on disk still read as an installer, and a name is what the user sees in a file picker.
```
### `private val EXTENSION_SUFFIX = Regex("""\.[A-Za-z0-9]{1,5}$""")`
```
/**
 * Removes every trailing segment that looks like a file extension, so exactly one — ours, or none
 * — is put back by [safeFileName].
 *
 * Repeated, not `substringBeforeLast('.')`: a single strip leaves `invoice.pdf.apk` as
 * `invoice.pdf`, which is still a name claiming a type this app did not declare. Shaped as "what
 * is an extension" rather than "which extensions are dangerous", because a denylist of risky
 * suffixes is exactly the control that goes stale.
 *
 * A dot-segment counts as an extension only if it is 1–5 characters and entirely alphanumeric, so
 * ordinary dotted names (`minutes.2026 Q1 final`) keep their text.
 */
```
### `internal fun extensionForMimeType(mimeType: String): String? = when (`
```
/** The one extension this app will put on a file, per type it is willing to declare. Null means
 *  "no extension" — which is what an unrecognised type gets, since octet-stream has no meaningful
 *  one and inventing the sender's is the bug above. */
```
### `private val VIEWABLE_MIME_TYPES = setOf(`
```
/**
 * MIME types this app will hand to another app as-declared. Anything else becomes
 * `application/octet-stream`, which every file handler competes for.
 *
 * The type comes from the sender's `Content-Type`, which the relay passes through unfiltered. An
 * obscure type like `application/vnd.kypost-x` lets a co-installed app guarantee itself
 * sole-resolver status for the attachment — so it applies on both the ephemeral-view path and the
 * save-to-Downloads path, not just the one that skips disk.
 */
```
### `private val CSS_COMMENT = Regex("""/\*[^*]*\*+(?:[^/*][^*]*\*+)*/""")`
```
// A CSS comment produces zero tokens during tokenization (CSS Syntax §4) and is fully transparent
// between any two other tokens — including between `!` and `important` — so it has to be removed
// before the token check rather than matched around.
```
### `private val CSS_ESCAPE = Regex("""\\([0-9a-fA-F]{1,6})\s?""")`
```
// A CSS escape sequence is a backslash followed by 1-6 hex digits and an optional whitespace
// terminator (CSS Syntax §4.3.7), so a sender can spell any letter of "important" as an escape
// (`!\49 mportant` decodes to `!Important`).
```
### `private fun decodeCssEscapes(candidate: String): String =`
```
/**
 * Decodes CSS escape sequences, leaving anything that is not a valid code point as literal text.
 *
 * [CSS_ESCAPE] matches up to six hex digits, which reaches 0xFFFFFF — past the 0x10FFFF ceiling of
 * the Unicode codespace — and `Character.toChars` throws on those. CSS treats an out-of-range escape
 * as a parse error rendering as U+FFFD, so it can never spell a letter of "important" either way.
 */
```
### `internal fun stripImportantFromCss(css: String): String =`
```
/**
 * Removes every `!important` from one CSS declaration block or stylesheet body.
 *
 * Tolerant of the two spec-legal ways a sender can split the token to dodge a plain text search: a
 * CSS comment inserted anywhere, and any letter written as an escape sequence.
 */
```
### `internal fun stripImportant(html: String): String {`
```
/**
 * Strips every `!important` the sender's markup can bring — see [buildEmailBodyHtml] for why that
 * is what actually closes the dark-mode override gap.
 *
 * Parsed with jsoup rather than pattern-matched over the raw body. The previous version was a
 * text-level regex sweep across the whole message, justified by "this app has no HTML parser
 * dependency" — which stopped being true when jsoup was added for [org.kysecurity.mail.mail.QuotedHtmlSanitizer].
 * Doing it structurally means the token patterns only ever run over a single `style` attribute or
 * `<style>` block, so the catastrophic-backtracking cases that needed a bounded whitespace run and a
 * 512 KB skip-the-whole-thing cap are no longer reachable from a message body at all — and CSS in
 * places CSS cannot apply (text, comments, attribute values) is no longer rewritten.
 *
 * Returns [html] byte-identical when nothing needed changing, so an unstyled message is not
 * re-serialised through the parser for no reason.
 */
```

