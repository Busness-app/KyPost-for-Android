# Comment archive - main/contacts, data, mail, ui

Comments removed from `app/src/main/java/org/kysecurity/mail/{contacts,data,mail,ui}` by the
Ponytail comment sweep. Each entry is the removed text verbatim, under the declaration it sat above.

## app/src/main/java/org/kysecurity/mail/contacts/AddressBookSheet.kt

### `class AddressBookSheet @JvmOverloads constructor(`

```
/** Address-book picker (ContactAutocomplete.md section 3): search bar + scrollable contact list
 *  with TO/CC/BCC action chips per row. Stays open across picks so the user can multi-select —
 *  [onPick] fires once per successful pick; see [RecipientRowAdapter] for the checkmark state. */
```

## app/src/main/java/org/kysecurity/mail/contacts/ContactAdapter.kt

### `var selfHasPgpIdentity: Boolean? = null`

```
    /** Whether the paired account has a PGP identity on the server (see [org.kysecurity.mail.pgp.hasPgpIdentity]),
     *  `null` while unknown/unchecked. The self-contact's own `pgpKey` field is a normal,
     *  independently-editable contact field with no connection to the account's real PGP identity
     *  (see that function's doc comment) — this is the account-level signal set from outside,
     *  since computing it needs a network call this per-row [bind] has no coroutine scope for. */
```

### `internal fun contactHasLinkedPgpKey(pgpKey: String?, isSelf: Boolean, selfHasPgpIdentity: Boolean?): Boolean =`

```
/** Whether a contact's "PGP" status badge should read as linked: either it has its own [pgpKey]
 *  field set (true for any contact, including self, whose key was actually attached — e.g. via the
 *  PGP QR scan flow), or — for the self-contact specifically ([isSelf]) — the account has a
 *  confirmed server PGP identity per [selfHasPgpIdentity]. `null` (unknown/unchecked) is treated as
 *  "no" here, same as a confirmed false — it only ever adds a second way to show "linked", never a
 *  way to hide the [pgpKey]-based one. Takes primitives rather than a [ContactEntity]/`ContactDto`
 *  directly so both (and [org.kysecurity.mail.contacts.ContactDetailActivity]'s own read model) can share
 *  it without a shared base type. */
```

## app/src/main/java/org/kysecurity/mail/contacts/ContactCursorStore.kt

### `class ContactCursorStore(context: Context, private val db: AppDatabase) {`

```
/**
 * Durable per-subscriber sync cursor, scoped to the subscriber so re-pairing as someone else
 * starts clean. The first read imports the legacy DataStore value; later updates stay in Room so
 * they can commit with the contact outbox acknowledgement.
 */
```

## app/src/main/java/org/kysecurity/mail/contacts/ContactDetailActivity.kt

### `class ContactDetailActivity : LockedActivity() {`

```
/** Read-only contact screen: what tapping a contact in [ContactsListActivity] opens (replacing the
 *  old direct-to-[ContactEditActivity] jump). Renders every field [ContactEditActivity] lets the
 *  user edit, minus none of them, as plain formatted text — plus tap-to-act rows for the field
 *  types that have an obvious action (email → compose, phone → dial, address → map, website →
 *  browser). An "Edit" action-bar item opens the real editor ([ContactEditActivity]) on the same
 *  contact; returning here re-loads and re-renders (see [onResume]) so edits show immediately. */
```

### `val selfHasPgpIdentity = if (dto.isSelf) hasPgpIdentity(this@ContactDetailActivity) else null`

```
            // Only the self-contact needs the extra (network) identity check — every other
            // contact's badge is fully determined by its own pgpKey field. See ContactAdapter's
            // contactHasLinkedPgpKey doc for why pgpKey alone isn't enough for the self-contact.
```

### `pgpBadge.text = when {`

```
            // "Key changed" must not be shown for an identity rebind: it sends the user to a QR
            // fingerprint comparison, which attests to the key and says nothing about the addresses
            // that actually changed.
```

### `private fun openUri(uri: String) {`

```
    /**
     * Contact field values are not trustworthy input: they arrive from the paired relay and from any
     * app holding WRITE_CONTACTS. Restrict the scheme, since a website field is free text that ends
     * up in an implicit ACTION_VIEW — a `file://` value crashes the app with
     * `FileUriExposedException` (which is not an `ActivityNotFoundException`, so the old catch missed
     * it), and any other scheme reaches whichever installed app claims it.
     *
     * The catch is widened to `RuntimeException` for the same reason: a tap on a contact row must not
     * be able to kill the process whatever the stored value is.
     */
```

### `internal fun contactSubtitle(dto: ContactDto): String =`

```
/** "Job title · Organization" — [ContactEditActivity]'s edit form keeps these as separate fields;
 *  the detail screen's subtitle line under the name joins whichever are present. */
```

### `internal fun formatAddress(address: ContactAddressDto): String {`

```
/** Multi-line "street, city, region postalCode, country" — blank components are dropped, not
 *  rendered as empty commas. Used both for on-screen display and as the query text for the
 *  tap-to-open-in-maps `geo:` intent, so it deliberately stays a single human-readable line rather
 *  than literal newlines a `geo:` query wouldn't understand anyway. */
```

### `internal fun urlWithScheme(value: String): String {`

```
/** Prefixes `https://` onto a bare `example.com`-style website value so [Uri.parse] + `ACTION_VIEW`
 *  resolves to a browser instead of failing to match any activity — contacts commonly store
 *  websites without a scheme (that's also all [ContactEditActivity]'s hint text asks for). Leaves
 *  an already-schemed value (`http://`, `https://`, or anything else with its own `scheme:`)
 *  untouched. */
```

## app/src/main/java/org/kysecurity/mail/contacts/ContactEditActivity.kt

### `class ContactEditActivity : LockedActivity() {`

```
/** Create/edit form, organized into collapsible sections (Name, Work, Contact, Addresses, Online,
 *  Personal, Notes, Other). Only fn is required per Mobile_Contact_Sync.md's field table; everything
 *  else is optional. Covers every contact field except photoRef/groupIDs (no UI yet) and isSelf/
 *  pgpKey (read-only badges — set only via the web app / PGP QR exchange respectively). */
```

### `private var loadedDto: ContactDto = ContactDto()`

```
    /** The full contact as loaded from Room, including every field this single-screen editor has
     *  no UI for (structured name parts, addresses, ims, websites, relations, events, phonetic
     *  names, department, customFields, pronouns, photoRef, groupIDs, pgpKey, isSelf, ...). [save]
     *  must `.copy()` off this rather than building a fresh [ContactDto], or every field not shown
     *  here gets silently wiped — locally immediately, and on the server too, since both the local
     *  upsert and the server's PUT/push handlers fully replace the stored contact rather than
     *  merging. Stays at [ContactDto]'s all-default value for new (not-yet-existing) contacts,
     *  which is correct: there's nothing prior to preserve. */
```

### `formRoot.isSaveFromParentEnabled = false`

```
        // Keeps this form out of the saved-state Bundle. Every EditText below freezes its own text,
        // so the framework's default view-hierarchy save writes the whole contact — names, numbers,
        // addresses, notes, birthday — into `ActivityRecord.mIcicle` over Binder, where the app
        // lock, SecurityWipe and ProcessState.resetAll() cannot reach it. A parent skips a child
        // with this cleared and does not descend into it, so the entire subtree stays out.
        // ContactEditDraftCache is what carries an in-progress edit across a recreate instead.
```

### `val emit: () -> Unit = {`

```
                // Both fields must read from each other's *live* text, not the bind-time item
                // snapshot — two separate listeners each doing item.copy(singleField = ...) would
                // silently drop whichever field was edited first the next time the other field
                // fires (each closes over the same stale item).
```

### `val emit: () -> Unit = {`

```
                // wireDatePicker's callback fires after field.setText(formatted) already ran (see
                // wireDatePicker below), so dateField.text is current by the time emit() reads it —
                // same live-read approach as every other multi-field row, avoiding the stale-item
                // closure bug (editing the label then picking a date must not drop the label edit).
```

### `val draft = ContactEditDraftCache.take(existingUid)`

```
        // A draft was .copy()-ed off the loaded contact, so it already carries every field the form
        // does not show and there is nothing left to read. Restoring it *instead of* loading keeps
        // the database read from landing afterwards and overwriting the user's edits: populateForm
        // only suspends for the self-contact, so "the draft writes last" is not a race worth having.
```

### `if (isFinishing) {`

```
        // Leaving this screen for good is not the "came back to a destroyed form" case this cache
        // exists for — a successful save already wrote to the database, and a back-out was
        // deliberate. Clearing matches ComposeActivity, and stops an earlier stash from
        // resurrecting one contact's PII into the next contact opened.
```

### `graph.repository.queueUpdate(dto, identityChanged = false)`

```
                // The user is editing this contact themselves, in this app, behind the app lock.
                // Their own edit to an address is not the silent third-party rebind that
                // pgpKeyNeedsReverification exists to catch.
```

### `private fun wireDatePicker(field: EditText, onPicked: (String) -> Unit) {`

```
    /** Wires [field] to open a [android.app.DatePickerDialog] on tap, pre-filled from [field]'s
     *  current `yyyy-MM-dd` text if present (else today), writing the picked date back as
     *  `yyyy-MM-dd` and invoking [onPicked]. [field] must have `focusable="false"` (see the row/
     *  section layouts) so tapping it opens the picker instead of the soft keyboard. */
```

### `private class SimpleTextWatcher(private val onChanged: () -> Unit) : android.text.TextWatcher {`

```
    /** [android.text.TextWatcher] that only cares about the end state, matching every row-field
     *  use in this Activity (none need before/during-change info). */
```

### `internal fun mergedContactDto(`

```
/** Pulled out of [ContactEditActivity.save] so it's unit-testable without a Context-backed Room/
 *  Activity. Applies real edits for every field the editor exposes UI for, while `.copy()`-ing off
 *  [loaded] so the handful of fields it doesn't (`photoRef`, `groupIDs`, `isSelf`, `pgpKey`) survive
 *  untouched instead of silently wiping on save (see [ContactEditActivity]'s `loadedDto` KDoc). */
```

## app/src/main/java/org/kysecurity/mail/contacts/ContactEditDraftCache.kt

### `object ContactEditDraftCache : ProcessScopedState {`

```
/**
 * The in-progress contact edit, held for the life of the process so a fold cannot destroy it.
 *
 * Unfolding a device is a configuration change, which destroys and recreates the Activity. This
 * screen carries the user's contact PII across roughly thirty fields, and discarding it because
 * someone opened their phone is data loss on a casual gesture.
 *
 * A saved-state Bundle is the wrong home for it: that is system-managed storage written outside
 * this app's control, and [ComposeDraftCache][org.kysecurity.mail.ComposeDraftCache] already
 * documents why message plaintext stays out of it. This holds the same line for contact plaintext —
 * in memory, process-scoped, and registered with [ProcessState] so a security wipe clears it.
 */
```

### `fun take(uid: String): ContactDto? {`

```
    /**
     * Returns the draft only if it belongs to [uid]; a mismatch drops it rather than holding it for
     * a later asker.
     *
     * The editor is finished outright by the app lock, and the unlock returns the user to the inbox
     * rather than to the contact they were editing. An identity-blind cache therefore had a live
     * path where the next contact opened inherited the previous one's name, emails and addresses —
     * and saved them over itself, locally and on the server. Dropping on mismatch keeps that to a
     * single missed restore instead of a draft that keeps hunting for a victim.
     *
     * Two successive *new* contacts share the empty uid and so can still restore into one another.
     * That duplicates the user's own unsaved typing rather than destroying a stored contact, and is
     * the likelier intent after being locked out mid-entry.
     */
```

### `private fun ContactDto.hasFormContent(): Boolean =`

```
/**
 * Whether the form behind this draft holds anything the user would miss.
 *
 * Gating on `fn` alone lost a new contact's phone, email and address if the name had not been typed
 * yet — data loss on a casual gesture, which is the harm this cache exists to prevent. Mirrors
 * [CachedDraft.hasContent][org.kysecurity.mail.CachedDraft.hasContent] by OR-ing across every field
 * the editor exposes; the repeatable lists are already blank-filtered by `RepeatableFieldList.items`,
 * so an untouched form still reads as empty.
 */
```

## app/src/main/java/org/kysecurity/mail/contacts/ContactMappers.kt

### `fun ContactDto.toEntity(`

```
/**
 * [previous] is the contact's existing row, if any, fetched by the caller before this sync
 * delta is applied. `pgpKey` arrives via ordinary two-way contact sync — unlike the QR
 * key-exchange flow, which independently recomputes and requires user confirmation of a
 * fingerprint before ever trusting a key — so this is the one place that same discipline is
 * applied to sync-derived keys: the fingerprint is (re)computed locally from the key bytes, and
 * a previously-verified fingerprint changing out from under the contact sets
 * [ContactEntity.pgpKeyNeedsReverification] instead of silently updating the trust badge.
 *
 * [verifiedInPerson] is set only by the QR key-exchange flow, where the user has just compared
 * this exact fingerprint out-of-band against the other person's device. That is the strongest
 * trust state the app can reach, so it must CLEAR the badge rather than raise it. Raising it
 * there — which is what happened when a contact legitimately rotated their key and the user
 * re-verified in person — trained users to dismiss the app's only TOFU alarm, and the badge is
 * plain text with no provenance, so a dismissed real key swap looks identical.
 */
```

### `val keyUnparseable = !verifiedInPerson && !pgpKey.isNullOrBlank() && newFingerprint == null`

```
    // [PgpFingerprint.compute] returns null for the shapes it refuses to vouch for — an appended
    // second key ring, a subkey bound by a foreign signature or by none — and its KDoc requires
    // callers to treat that as "reject this key". Reading it as "no information" meant a key the
    // local parser rejects raised nothing, which is the one alarm here that does not depend on the
    // relay's own verdict. It also cleared an outstanding alarm, because stillNeedsReverification
    // asks for newFingerprint == previousFingerprint and a null fingerprint never matches.
```

### `val identityRebound = (identityChanged || previous?.identityNeedsReview == true) &&`

```
    // The mirror of [keyRotated]: same person, different key vs. same key, different person. A
    // device-side merge carries pgpKey over untouched, so the fingerprint is unchanged and the
    // rotation check cannot fire — but ContactsContract has no per-account write ACL, so any app
```

### `identityNeedsReview = identityRebound,`

```
        // The IDENTITY alarm, in its own column so the ceremony cannot clear it. A fingerprint
        // comparison attests to the key; it says nothing about which addresses that key is displayed
        // beside, and the save path builds its DTO from the current — possibly already tampered —
        // Room row while the confirmation screen shows the scanned card's addresses.
```

## app/src/main/java/org/kysecurity/mail/contacts/ContactSyncClient.kt

### `private sealed class HttpMappedResult<out T> {`

```
/** Generic HTTP-status-to-result mapping shared by every `ContactSyncClient` endpoint. */
```

### `class ContactSyncClient(`

```
/**
 * Talks to `/api/contacts/sync`. Auth is sent as X-Kypost-Device-Id/X-Kypost-Device-Secret
 * headers (never query params/cookies), kept parallel to
 * [org.kysecurity.mail.push.PullNotificationClient] — same okhttp/serialization stack.
 */
```

### `private suspend fun <T> executeMapped(`

```
    /** Centralized HTTP status -> result mapping: 200 decodes via [decode], 400/401/503 map to their
     * respective variants, malformed bodies and anything else fall back to [HttpMappedResult.Retryable]. */
```

## app/src/main/java/org/kysecurity/mail/contacts/ContactSyncCoordinator.kt

### `class ContactSyncCoordinator(`

```
/** Mirrors push/PullSyncCoordinator.kt's fire-and-forget shape for foreground/post-edit syncs. */
```

### `fun syncNowAsync() {`

```
    /** Fire-and-forget sync, used on app foreground and immediately after any local edit. */
```

## app/src/main/java/org/kysecurity/mail/contacts/ContactSyncReconciliation.kt

### `object ContactSyncReconciliation {`

```
/**
 * Matches locally-created (not-yet-synced) contacts to their server-assigned uid in a push
 * response. The wire protocol has no client-supplied correlation id (Mobile_Contact_Sync.md
 * Part 2 explicitly calls this out), so this matches by content — a pending create's serialized
 * fn/org/emails/phones against each unclaimed entry in [changed] — in push order, claiming the
 * first unclaimed exact match per pending create.
 */
```

## app/src/main/java/org/kysecurity/mail/contacts/ContactSyncRepository.kt

### `sealed class ContactDedupeOutcome {`

```
/** Mirrors [ContactSyncOutcome]'s shape; kept as a parallel type (rather than a variant of
 * [ContactSyncOutcome]) because `Success` here needs to carry the dedupe report. */
```

### `class ContactSyncRepository(`

```
/**
 * Orchestrates contact sync: decides pull-vs-push based on the offline change queue, applies the
 * server delta (upsert changed, remove deleted, reconcile locally-created uids), and handles
 * tooOld by discarding the cursor and wiping the local cache for a full re-pull.
 */
```

### `val syncMutex = Mutex()`

```
    /** Guards the whole contacts table against concurrent sync writers: this repository and
     *  [org.kysecurity.mail.contacts.device.DeviceContactRepository] run on independent coroutine
     *  scopes with no other ordering between them, and [org.kysecurity.mail.data.ContactDao.upsertAll]
     *  replaces whole rows — so an interleaved read-modify-write from one side can silently
     *  overwrite a field (e.g. `isSelf`) the other side just wrote. Held by [sync] here and by
     *  `DeviceContactRepository.syncAll`. */
```

### `suspend fun dedupe(): ContactDedupeOutcome = resolveDedupeOutcome(pairingProvider) { pairing ->`

```
    /**
     * Calls the server-side dedupe endpoint. Deliberately does NOT call [sync] itself — mirrors
     * [sync]'s single-purpose shape; the caller is responsible for triggering a follow-up sync so
     * the merge's tombstones/survivor land locally.
     */
```

### `suspend fun queueUpdate(`

```
    /**
     * [verifiedInPerson] is passed only by the PGP QR flow, where the user has just compared this
     * fingerprint out-of-band.
     */
```

### `db.withTransaction {`

```
            // Non-destructive: reset the cursor so the next pull starts from 0 and rebuilds the
            // mirror from a full snapshot, but do NOT clear first. Clearing here used to return
            // before clearFlushed below, so the acknowledged pending changes were replayed — and
```

### `reconciled.forEach { (localUid, serverUid) ->`

```
                // The device link row keys on uid, so it has to follow this rename. Without it the
                // server-assigned uid looks unlinked, pushRoomChangesToDevice inserts a SECOND raw
                // contact, and the temp-uid link is orphaned forever (getByUid on a dead uid returns
                // null, so pullDeviceChangesForOwnAccount can never reclaim the first row).
```

### `internal suspend fun resolveDedupeOutcome(`

```
/**
 * Decides [ContactSyncRepository.dedupe]'s outcome: [ContactDedupeOutcome.NotPaired] if
 * [pairingProvider] yields no pairing, otherwise delegates to [dedupeCall] and maps its result via
 * [contactDedupeOutcomeOf]. Kept as a standalone function, independent of
 * [ContactSyncRepository]'s `AppDatabase`/`ContactCursorStore` dependencies, so it's testable in a
 * plain JVM unit test — mirrors [org.kysecurity.mail.mail.reconcileFetchResult]'s extraction for the
 * same reason.
 */
```

### `internal fun contactDedupeOutcomeOf(result: ContactDedupeResult): ContactDedupeOutcome = when (result) {`

```
/** Pure mapping from [ContactDedupeResult] to [ContactDedupeOutcome]; `BadRequest` folds into
 * [ContactDedupeOutcome.Retry], matching how [ContactSyncRepository.sync] folds
 * `ContactSyncResult.BadRequest` into `ContactSyncOutcome.Retry`. */
```

## app/src/main/java/org/kysecurity/mail/contacts/ContactsGraph.kt

### `private val pinnedCallFactory = pinnedPairingCallFactory(appContext)`

```
    // Shared with both clients below — see finding C2 of the 2026-07-22 security-hardening
    // spec's final-review fix round: contact/group sync used to default to the plain unpinned
    // pairingHttpClient() even though it sends the same deviceSecret bearer credential as mail.
```

### `fun invalidate() = holder.invalidate()`

```
    /** See [org.kysecurity.mail.SingletonGraph.invalidate] — used by
     *  [org.kysecurity.mail.security.AppRestart]. */
```

## app/src/main/java/org/kysecurity/mail/contacts/ContactsListActivity.kt

### `lifecycleScope.launch {`

```
            // Refreshed every time this screen becomes visible (not just once) so setting up a PGP
            // identity on the web app and coming back here picks it up without needing a full
            // contacts re-sync.
```

### `const val EXTRA_PICK_MODE = "pick_mode"`

```
        /** When set true on launch, tapping a contact returns its uid via [EXTRA_RESULT_UID]
         *  instead of opening [ContactEditActivity] — used by flows (e.g. PGP QR key exchange)
         *  that need the caller to pick an existing contact. */
```

## app/src/main/java/org/kysecurity/mail/contacts/ExpandableSectionView.kt

### `package org.kysecurity.mail.contacts`

```
// app/src/main/java/org/kysecurity/mail/contacts/ExpandableSectionView.kt
```

### `class ExpandableSectionView @JvmOverloads constructor(`

```
/**
 * Collapsible section container: a tappable header (title + item-count badge + chevron) that
 * toggles [body]'s visibility. Any children declared in XML inside this tag are automatically
 * moved into [body] (see [onFinishInflate]) so callers can populate a section's static fields
 * declaratively in the layout file; list-typed fields are added to [body] at runtime instead, via
 * [RepeatableFieldList]. Purely a layout primitive — knows nothing about contact fields.
 */
```

### `internal fun onFinishInflateForTest() = onFinishInflate()`

```
    /** Test-only: [onFinishInflate] is protected and only invoked by the inflater; this lets
     *  [ExpandableSectionViewTest] exercise the same move-children-into-body logic for a view built
     *  programmatically instead of from XML. */
```

## app/src/main/java/org/kysecurity/mail/contacts/GroupSyncRepository.kt

### `class GroupSyncRepository(`

```
/**
 * Full-refreshes the local [GroupEntity] cache from `GET /api/groups` on each sync cycle — no
 * delta cursor, mirroring [ContactSyncRepository]'s pairing/auth plumbing but simplified since
 * the groups list is small and has no offline-edit queue to reconcile (device never creates
 * groups; see `Client_Contact_Update.md` Part 2 point 3).
 */
```

## app/src/main/java/org/kysecurity/mail/contacts/GroupsSyncClient.kt

### `class GroupsSyncClient(`

```
/**
 * Talks to `GET /api/groups`. Pull-only (there is no delta cursor — the caller always fetches
 * the full list and full-refreshes its local cache), mirroring [ContactSyncClient]'s X-Kypost-Device-Id/X-Kypost-Device-Secret
 * header auth and HTTP-status-to-result mapping, minus the push/dedupe endpoints this
 * client has no need for. Two-way group *creation* sync (`POST /api/groups`) is out of scope for
 * this client — see `Client_Contact_Update.md` Part 2 point 3.
 */
```

## app/src/main/java/org/kysecurity/mail/contacts/RecipientMatching.kt

### `enum class RecipientField { TO, CC, BCC }`

```
/** Which composition field a picked contact should be appended to — shared between
 *  [org.kysecurity.mail.RecipientInputView] (single field) and [AddressBookSheet] (offers all three
 *  per row). */
```

### `fun ContactEntity.toRecipientCandidateOrNull(): RecipientCandidate? {`

```
/** Picks the contact's primary (first) email — same convention [ContactEditActivity] uses for its
 *  single-email field (see `loadExisting`). Returns null for contacts with no email at all —
 *  nothing usable to autocomplete to — and for one whose address carries a recipient separator.
 */
```

### `fun isDuplicateRecipient(existingEmails: List<String>, candidateEmail: String): Boolean =`

```
/** Case-insensitive duplicate check against a field's already-added recipient emails. */
```

### `fun matchRanges(text: String, query: String): List<IntRange> {`

```
/** Character range in [text] matching [query], case-insensitively — used to bold the matching
 *  substring in the autocomplete dropdown. Only the first occurrence is highlighted (dropdown rows
 *  are single-line; repeats aren't worth the extra spans). Empty when [query] is blank or absent. */
```

## app/src/main/java/org/kysecurity/mail/contacts/RecipientRowAdapter.kt

### `applySuccessChipTheme(chip.context, chip, animate = true)`

```
                // Animate only the tapped chip (STYLE_GUIDE.md §5/§7 — 120ms). A later rebind of
                // this row (scroll recycle) re-applies success instantly via bindActionButton
                // above, so this doesn't need a notifyItemChanged to stay correct.
```

## app/src/main/java/org/kysecurity/mail/contacts/RepeatableFieldList.kt

### `package org.kysecurity.mail.contacts`

```
// app/src/main/java/org/kysecurity/mail/contacts/RepeatableFieldList.kt
```

### `class RepeatableFieldList<T>(`

```
/**
 * Manages the "rows + Add button" pattern for one list-typed contact field inside an
 * [ExpandableSectionView]'s body. Each row is inflated from [rowLayoutRes] and wired by [bind];
 * [isBlank] decides which rows [items] drops (e.g. an "+Add" tapped but left empty); [default] is
 * what a fresh row starts as. [onChanged] fires after every add/remove/edit so callers can keep an
 * item-count badge live. Removal and edits look up the row's *current* index via
 * `container.indexOfChild(rowView)` rather than capturing a fixed index at add-time, so earlier
 * rows being removed doesn't corrupt later rows' bookkeeping. Purely a layout primitive — knows
 * nothing about contact fields; every DTO-specific mapping lives in [bind]/[isBlank]/[default].
 */
```

## app/src/main/java/org/kysecurity/mail/contacts/device/DeviceContactAccount.kt

### `fun accountExists(): Boolean = runCatching {`

```
    /**
     * Whether this app's sync account is currently on the device.
     *
     * Needs no permission: `getAccountsByType` always returns accounts whose authenticator is
     * signed by the caller, and this app ships that authenticator. That matters because the two
     * callers below run during teardown, after the contacts permissions may already be gone.
     *
     * This is also the only durable answer to "could this app have published rows into
     * ContactsContract" — every raw contact it writes is owned by this account, and CP2
     * hard-deletes an account's rows when the account goes. See [DeviceContactPurge].
     */
```

### `suspend fun ensureAccount(): Boolean = withContext(Dispatchers.IO) {`

```
    /**
     * Creates the sync account if it is not already there.
     *
     * Blocking AccountManager IPC, so callers must be on an IO dispatcher — the `suspend` marker
     * alone does not move work off the caller's thread, and this used to be awaited straight from
     * `lifecycleScope.launch`, i.e. on the main thread.
     */
```

### `fun removeAccountBlocking(): Boolean {`

```
    /**
     * Same work as [removeAccount] without the `suspend` marker, for callers already inside a
     * non-suspending block — see [org.kysecurity.mail.security.SecurityWipe.removeSyncedDeviceContacts].
     * `removeAccountExplicitly` is a synchronous AccountManager call either way.
     *
     * Removing the account is what makes CP2 hard-delete the raw contacts under it, so this is the
     * last line of defence for rows that live outside this app's sandbox. A failure here must reach
     * the caller — see [org.kysecurity.mail.security.SecurityWipe]'s `deviceContactAccount` step,
     * which turns a false into a reported incomplete wipe.
     */
```

## app/src/main/java/org/kysecurity/mail/contacts/device/DeviceContactFieldCoding.kt

### `object DeviceContactFieldCoding {`

```
/**
 * Pure label/type mappings between this app's freeform DTO label strings and the closed
 * `ContactsContract` `TYPE_*`/`PROTOCOL_*` vocabularies, kept out of [DeviceContactRepository]'s
 * `ContentProviderOperation`-building code so the mapping decisions are unit-testable without a
 * real `ContentResolver`.
 */
```

### `fun imCustomProtocolLabel(service: String?, label: String?): String = when (service) {`

```
    /** `whatsapp|signal|telegram|instagram|x|linkedin|facebook|mastodon|matrix|""` (=other) -> a
     *  human-readable display string, mirroring the web frontend's `IM_SERVICES` catalog
     *  (`kypost-server/frontend/src/api/contacts.ts`) so the two stay in sync. None of these map to
     *  a built-in `Im.PROTOCOL_*` constant, so every `ims` row is written as `PROTOCOL_CUSTOM` with
     *  this resolved string as `CUSTOM_PROTOCOL`. */
```

### `fun imServiceFromCustomProtocolLabel(label: String?): String = when (label) {`

```
    /** Inverse of [imCustomProtocolLabel]'s recognized-service branch: an on-device
     *  `Im.CUSTOM_PROTOCOL` display string read back from the phone's native Contacts app -> the
     *  closed `service` vocabulary word. Unrecognized display strings (including the "Other"
     *  fallback and any freeform label) collapse to `""`, matching the documented convention that
     *  `service == ""` means "other" and the display string is carried as the freeform `label`
     *  instead. */
```

### `fun relationType(label: String?): Int = when (label) {`

```
    /** `spouse|child|parent|partner|manager|assistant|friend|relative|other` -> the closest
     *  `Relation.TYPE_*` constant (values confirmed against the installed Android SDK's
     *  `android.jar`, not guessed); `"other"` and any unrecognized label fall back to
     *  `TYPE_CUSTOM`. */
```

### `fun relationLabelFromType(type: Int?): String = when (type) {`

```
    /** Inverse of [relationType]: an on-device `Relation.TYPE` read back from the phone's native
     *  Contacts app -> the closed vocabulary string. Unrecognized/`TYPE_CUSTOM` values collapse to
     *  `"other"` since [org.kysecurity.mail.contacts.ContactRelationDto.label] has no freeform slot to
     *  carry a native `Relation.LABEL` string through separately from the vocabulary word. */
```

## app/src/main/java/org/kysecurity/mail/contacts/device/DeviceContactMappers.kt

### `fun ContactEntity.toDto(): ContactDto = toCanonicalDto()`

```
    /**
     * Delegates to the canonical [org.kysecurity.mail.contacts.toDto] (in `ContactMappers.kt`) rather
     * than duplicating its JSON decode logic. This used to be its own partial implementation that
     * only carried the pre-Task-2 fields (fn/org/notes/birthday/emails/phones/addresses) — since
     * this function's result is the merge base in [DeviceContactRepository.pullDeviceChangesForOwnAccount]
     * and [DeviceContactRepository.pushRoomChangesToDevice] (`roomDto.copy(...)`/`entity.toDto()`),
     * that partial version silently dropped `groupIDs`/`photoRef`/`pgpKey`/`ims`/`websites`/
     * `relations`/`events`/phonetic names/`department`/`customFields`/`pronouns` on every device
     * sync pass — a real data-loss bug this task's device-provider wiring would otherwise inherit.
     */
```

## app/src/main/java/org/kysecurity/mail/contacts/device/DeviceContactMatcher.kt

### `class Index private constructor(private val byValue: Map<String, Match>) {`

```
    /**
     * Every normalized email and phone in [existing], mapped to the uid that owns it.
     *
     * Each value carries its owner's position in [existing], and [Index.findMatch] returns the
     * lowest-positioned match. That reproduces the old scan exactly — "the first contact in list
     * order that matches on either an email or a phone" — rather than quietly preferring whichever
     * field happens to be checked first.
     */
```

### `private fun emailKey(value: String): String? =`

```
    /**
     * Emails and phones share one map, so they are namespaced to keep a phone-shaped email from
     * matching a phone.
     */
```

## app/src/main/java/org/kysecurity/mail/contacts/device/DeviceContactModels.kt

### `data class DeviceRawContactSnapshot(`

```
/**
 * `groupIDs` deliberately has no field here — group membership only ever flows Room -> device
 * (see [DeviceGroupLinker]), never read back from `GroupMembership` rows into Room, per
 * `Client_Contact_Update.md` Part 2 point 3. `pgpKey`/`pronouns`/`customFields` are excluded too:
 * they have no `ContactsContract` data kind at all (Part 5) and stay Room-only.
 */
```

### `data class DeviceFieldSet(`

```
/**
 * The write-intention shape ([org.kysecurity.mail.contacts.device.DeviceContactMappers.toDeviceFieldSet]
 * converts a [org.kysecurity.mail.contacts.ContactDto] into this). Unlike [DeviceRawContactSnapshot],
 * this *does* carry [groupIDs] — group membership is write-only (Room -> device), so it belongs on
 * the write side, not the read side. `pgpKey`/`pronouns`/`customFields` are still excluded (Part 5).
 */
```

## app/src/main/java/org/kysecurity/mail/contacts/device/DeviceContactPurge.kt

### `object DeviceContactPurge {`

```
/**
 * Removes the raw contacts this app published into the OS contacts provider, **without touching any
 * graph**.
 *
 * [DeviceContactRepository.deleteAllSyncedDeviceContacts] does the same provider delete, but reaching
 * it means constructing [DeviceContactsGraph], whose constructor calls `DataRuntime.graph(...)`. On
 * the teardown paths that matters: during a security wipe the database has already been closed and
 * deleted, so building that graph recreates `kypost_mail.db` on disk — and with the hostile-location
 * flag file also already gone, it recreates it *disk-backed*. Teardown callers use this instead.
 *
 * The rows are the reason this exists at all: they live outside the app sandbox, so nothing the wipe
 * deletes from `/data/data` reaches them, and an unpair that cleared only the local link table left
 * the previous account's entire address book in ContactsContract with no index back to it.
 */
```

### `fun deleteSyncedRows(context: Context): Int {`

```
    /**
     * Deletes every raw contact under this app's sync account.
     *
     * `CALLER_IS_SYNCADAPTER` makes the delete immediate rather than leaving tombstoned rows that
     * still hold the contact data for an account that is about to be removed.
     *
     * Returns the number of rows deleted, or -1 if the rows could not be reached — whether the
     * provider refused outright or the contacts permission has since been revoked while this app's
     * sync account (and so its rows) is still on the device. Callers that must report failure (the
     * wipe) check the sign; callers that are best-effort ignore it.
     */
```

### `val accountExists = DeviceContactAccountManager(appContext).accountExists()`

```
            // A missing WRITE_CONTACTS does NOT mean this app never published a row: runtime
            // permissions are revocable, by the user and (since Android 11) by the OS auto-resetting
            // them for unused apps. Treating "cannot reach the provider" as "nothing to reach" is
            // how a wipe reported Complete over an address book still in ContactsContract.
            //
            // The account tells them apart. Every raw contact this app writes is owned by it, CP2
            // hard-deletes an account's rows when the account goes, and enumerating our own account
            // needs no permission -- so no account means no rows.
```

### `internal fun deniedPermissionRowOutcome(accountExists: Boolean): Int = if (accountExists) -1 else 0`

```
/**
 * What a provider [SecurityException] means, given whether this app's sync account is still present.
 *
 * Pure and Android-free so the decision has a plain JVM test: the surrounding function needs a real
 * ContentResolver and a revoked runtime permission, which no instrumented test can arrange.
 *
 * @return 0 when no rows can exist, or -1 when rows may exist and could not be reached.
 */
```

## app/src/main/java/org/kysecurity/mail/contacts/device/DeviceContactRepository.kt

### `private suspend fun stage(name: String, body: suspend () -> Unit): String? =`

```
    /**
     * Fault-isolates one sync stage, returning its name if it failed and null if it did not. Same
     * shape as [org.kysecurity.mail.security.SecurityWipe]'s `step`: a stage that cannot fail cannot
     * be reported.
     *
     * `CancellationException` is an `Exception`, so a broad catch here would let a cancelled sync
     * run its remaining stages holding [ContactSyncRepository.syncMutex] and writing to
     * ContactsContract. It is rethrown.
     */
```

### `suspend fun syncAll(): List<String> = syncRepository.syncMutex.withLock {`

```
    /**
     * Runs every sync stage, returning the names of those that failed — empty when all succeeded.
     * The stages are ordered and each builds on the last, so a non-empty list means the cycle is
     * incomplete, not that only those stages matter.
     *
     * Shares syncRepository.syncMutex with ContactSyncRepository.sync() — see that mutex's KDoc:
     * both sides read-modify-write the same contacts table from independent scopes.
     */
```

### `private suspend fun reconcileGroupRenames() = withContext(Dispatchers.IO) {`

```
    /**
     * Propagates a backend group rename to the on-device `Groups.TITLE` for every group that's
     * already linked (materialized on-device via a prior sync), not just groups referenced by a
     * brand-new not-yet-linked contact ([createRawContactForDto]'s own
     * `groupLinker.ensureAndroidGroupRowId` call already handles that narrower case). Runs on
     * every `syncAll()` cycle right after [groupSyncRepository]'s full refresh has updated the
     * Room [org.kysecurity.mail.data.GroupEntity] cache with the latest backend names.
     */
```

### `ContactsContract.RawContacts.DIRTY,`

```
            // DIRTY has to be read, not assumed. Treating every linked row as dirty meant
            // clearDirtyFlag issued a provider UPDATE per contact on every cycle; SQLite reports a
            // matched row as updated even when the value is unchanged, so CP2 marked the
            // transaction dirty and called notifyChange, which woke this app's own
            // DeviceContactObserver and re-triggered the sync — an ~8s loop for as long as the
            // contacts list stayed open, each iteration also making a credentialed network call.
```

### `val linksByRawContactId = db.deviceContactLinkDao().getAll().associateBy { it.rawContactId }`

```
        // Loaded once. `getByRawContactId` was called from inside the cursor loop, so a device with
        // N synced contacts issued N Room queries per sync cycle to read a table that is small
        // enough to hold entirely.
```

### `val existing = db.contactDao().getByUid(link.uid)`

```
                    // A device-side delete is a PROPOSAL, not an instruction. Any app holding
                    // WRITE_CONTACTS can set DELETED=1 on a row under our account type — CP2 has no
                    // per-account write ACL — and queueDelete drops the Room row *before* the
                    // tombstone is sent, so the contact's pgpKey, its fingerprint and its
                    // reverification flag are all destroyed locally, and the server's tombstone then
                    // clears PGPKey on its side too. One resolver.delete() per row therefore stripped
                    // every in-person-verified key pin on the device and on the server, silently,
                    // with no confirmation anywhere — while the in-app delete has one.
                    //
                    // So a contact holding a key (and the self contact, whose key is the user's own
                    // published one) is restored rather than tombstoned. Everything else still flows:
                    // an ordinary contact deleted on the phone is a delete the user meant.
```

### `syncRepository.queueUpdate(mergedDto, identityChanged = changed)`

```
                // A stored PGP key vouches for a person identified by these fields. ContactsContract
                // has no per-account write ACL, so any app holding WRITE_CONTACTS can rewrite them
                // under our account type, and this merge then uploads the result to the paired
                // server. The key itself is carried over untouched, so the rotation check in
                // toEntity cannot see it — re-arm on the identity instead.
                //
                // `changed`, not a two-field comparison. Restricting this to emails and fn left
                // phone, organisation, notes, websites, IMs, postal addresses, relations, events,
                // department and the phonetic names all rewritable under a pinned key with the trust
                // badge intact — and the rewritten phone is a live tel: tap target and the rewritten
                // website a live ACTION_VIEW. Any device-side change to a keyed contact is a change
                // to who that key is displayed beside.
```

### `private suspend fun restoreDeletedRawContact(rawContactId: Long) = withContext(Dispatchers.IO) {`

```
    /**
     * Undoes a device-side delete of a row we refuse to tombstone.
     */
```

### `val matchIndex = DeviceContactMatcher.Index.of(existing)`

```
        // Built once for the whole candidate loop. `findMatch(…, existing)` re-normalized and
        // rescanned every stored contact for every candidate, which is O(candidates x contacts)
        // string comparisons on a path that runs from a WorkManager job and from app foreground.
```

### `if (candidate.accountType == DeviceContactAccount.ACCOUNT_TYPE) {`

```
                // Deliberately do NOT link a uid to a raw contact owned by another account.
                // This query only ever returns foreign rows, and a match here is a single shared
                // email or phone with no name corroboration — but the link makes every later
                // updateRawContactForDto and deleteDeviceRawContact for that uid target the other
                // account's row, as a sync adapter. That bypasses the IS_READ_ONLY guard
                // ContactsProvider2 would otherwise apply, rewrites the row's structured name
                // (an unstructured-only DISPLAY_NAME update makes CP2 re-split and overwrite
                // GIVEN/FAMILY/etc), and hard-deletes it with no tombstone, so the owning
                // account's sync adapter never sees the change and cannot repair it.
                //
                // The match still does its job: we skip re-importing this contact. Room already
                // has it, so pushRoomChangesToDevice creates a raw contact under OUR account and
                // CP2 aggregates the two into one contact card — which is how every other sync
                // adapter behaves, and keeps our writes confined to rows we own.
```

### `val alreadyImported = existing.any { existingContact ->`

```
                // Compared against the contact's WHOLE email and phone lists, not `firstOrNull()`.
                // Matching only the head meant a contact whose shared address happened to sit
                // second in either list read as "not imported yet" and was queued as a create —
                // producing the duplicate this dedupe exists to prevent, decided by field order.
```

### `val existingEmails = existingContact.emails`

```
        // Blank normalized values are dropped on both sides, for the same reason
        // [DeviceContactMatcher.Index] drops them: a placeholder like "n/a" normalizes to the empty
        // string and would otherwise make every blank-valued candidate look like a match, silently
        // suppressing its import.
```

### `if (!syncPermitted()) return@withContext`

```
            // Policy can change mid-loop — the user can enable Hostile Location Protection while
            // this is running, and the purge that accompanies it does not cancel us. Publishing
            // after that point writes exactly the data the feature exists to withhold.
```

### `val androidGroupRowIds = dto.groupIDs.mapNotNull { groupId ->`

```
        // Group membership: find-or-create the on-device Groups row for each backend groupID
        // this contact belongs to (see DeviceGroupLinker). Resolved before the batch is built
        // since GROUP_ROW_ID is a plain value, not a withValueBackReference target. A groupID not
        // yet present in the local groups cache is silently skipped -- it will be picked up on a
        // future sync once GroupSyncRepository has pulled it down.
```

### `if (currentSnapshot.accountType != DeviceContactAccount.ACCOUNT_TYPE) {`

```
        // Defence in depth against a stale link row written by an older build: never write to a
        // raw contact another account owns. The write below goes out as a sync adapter, which
        // means CP2 skips the IS_READ_ONLY guard and leaves `dirty` unset, so the owning adapter
        // would neither notice nor repair the change.
```

### `if (!ownsRawContact(link.rawContactId)) {`

```
        // Same guard as updateRawContactForDto, and it matters more here: with
        // CALLER_IS_SYNCADAPTER, ContactsProvider2 takes deleteRawContactsImmediately rather than
        // markRawContactAsDeleted, so this is a hard delete with no tombstone. Against another
        // account's row that is unrecoverable local data loss from a "delete my KyPost contact" tap.
```

### `suspend fun deleteAllSyncedDeviceContacts() = syncRepository.syncMutex.withLock {`

```
    /**
     * Removes every raw contact this app owns from the OS contacts provider, plus the local link
     * rows that map them.
     *
     * Needed because those rows are not in this app's sandbox: enabling Hostile Location
     * Protection switches the local database to in-memory but does nothing about contacts already
     * published to the system provider, and [org.kysecurity.mail.security.SecurityWipe] has the same
     * problem in reverse. `CALLER_IS_SYNCADAPTER` makes the delete immediate rather than leaving
     * tombstoned rows that still hold the contact data.
     */
```

### `private suspend fun deleteAllSyncedDeviceContactsLocked() = withContext(Dispatchers.IO) {`

```
    /** Takes [ContactSyncRepository.syncMutex], which [syncAll] holds for its whole body. Without
     *  it the purge could interleave with `pushRoomChangesToDevice`, so rows written after the
     *  delete survived with no link entry — invisible to every later cleanup — after the user
     *  enabled the feature whose entire purpose is getting that data off the device. */
```

### `private suspend fun ownsRawContact(rawContactId: Long): Boolean = withContext(Dispatchers.IO) {`

```
    /** True only when [rawContactId] belongs to this app's sync account. Every provider write and
     *  delete this class performs carries `CALLER_IS_SYNCADAPTER`, which removes the read-only
     *  guard and turns deletes into immediate hard deletes, so the target's ownership has to be
     *  checked rather than assumed from a link row. */
```

### `private suspend fun pruneForeignLinks() = withContext(Dispatchers.IO) {`

```
    /** Sweeps link rows that point at raw contacts owned by another account. Older builds created
     *  these whenever a single email or phone matched a foreign contact, so installs upgrading to
     *  this build can already carry them; without the sweep the very first sync would rewrite the
     *  other account's rows before anything else got a chance to stop it. */
```

### `val customProtocol = data6?.takeIf { it.isNotBlank() }`

```
                                // Every ims row this app writes uses PROTOCOL_CUSTOM + a resolved
                                // display string (see DeviceContactFieldCoding.imCustomProtocolLabel).
                                // Map that display string back to its service code via the inverse
                                // catalog (imServiceFromCustomProtocolLabel) so a recognized service
                                // round-trips intact; only truly unrecognized strings fall back to
                                // the "other" bucket (service = "") with the string carried as the
                                // freeform label.
```

## app/src/main/java/org/kysecurity/mail/contacts/device/DeviceContactSyncCoordinator.kt

### `private val hostileLocationEnabled: () -> Boolean = { false },`

```
    /**
     * Hostile Location Protection makes Room in-memory so nothing reaches disk — but device
     * contact sync writes names, email addresses, phone numbers and PGP keys into the OS contacts
     * provider, which is not this app's storage and is not in-memory. Syncing while protection is
     * on published exactly the data the feature exists to withhold, so it is refused outright
     * rather than merely defaulted off.
     */
```

### `private suspend fun runBoundedSync(trigger: String) {`

```
    /**
     * One sync cycle under the 30-second ceiling, releasing [isSyncing] however it ends.
     *
     * Deliberately not `runCatching`, which catches **`Throwable`** and so would swallow the
     * `TimeoutCancellationException` that `withTimeoutOrNull` aborts with — eating the cancellation
     * of the very timeout that bounds it.
     */
```

## app/src/main/java/org/kysecurity/mail/contacts/device/DeviceContactSyncEnabler.kt

### `class DeviceContactSyncEnabler(`

```
/** Shared permission-check -> request -> enable sequence for device contact sync, used by both
 *  the Contacts screen's menu toggle and the pairing screen's first-scan intro popup so there's
 *  one canonical enable path instead of two copies of this logic. */
```

### `fun checkAndEnable(): Boolean {`

```
    /** Returns true if permissions had to be requested asynchronously — the caller must wait for
     *  the permission launcher's own callback (which should call [enableAfterPermissionGrant] on
     *  grant) before doing anything that assumes sync is now enabled. Returns false if it
     *  resolved synchronously because permissions were already granted. */
```

## app/src/main/java/org/kysecurity/mail/contacts/device/DeviceContactSyncSettings.kt

### `class DeviceContactSyncSettings(context: Context) {`

```
/**
 * Whether device-contact sync is on, plus its two bookkeeping timestamps.
 *
 * **Every write is `commit()`, never `apply()`**, for the same reason
 * [org.kysecurity.mail.security.AppLockStore] gives: `apply()` returns before the write reaches
 * disk, and this file is both written by, and deleted by, [org.kysecurity.mail.security.SecurityWipe].
 *
 * That combination resurrects data. `PushRepository.purgeAccountScopedData` calls [setEnabled]
 * during the wipe; with `apply()` the write was still queued when the wipe's `sharedPrefs` step
 * deleted this file, and the in-memory map it eventually flushed still held **every key the file
 * had before the wipe** — so the deleted file came back with its old contents, behind a wipe that
 * reported Complete. `SecurityWipeTest.wipeAndResetApp_removesEveryOwnedPreferencesFile` is the
 * assertion; it caught this on API 31.
 *
 * Durability is the second reason, independent of ordering: sync gates on this toggle and not on
 * having a pairing, so an unpair whose `setEnabled(false)` never reached disk leaves the device
 * still syncing contacts. The writes are one boolean or one long each.
 */
```

## app/src/main/java/org/kysecurity/mail/contacts/device/DeviceContactSyncWorker.kt

### `if (org.kysecurity.mail.security.SecurityWipe.blockedByAbandonedWipe(applicationContext)) {`

```
        // This worker calls the repository directly rather than going through the coordinator, so
        // the coordinator's Hostile Location Protection veto has to be repeated here — an already
        // enqueued periodic run would otherwise keep writing contacts to the OS provider after
        // protection was turned on.
        // Same shape as the protection veto below, and for a stronger reason: after an abandoned
        // wipe this worker would write the account's contacts back into the OS provider — outside
        // this app's sandbox — on a device the wipe had just tried to remove them from.
```

## app/src/main/java/org/kysecurity/mail/contacts/device/DeviceContactsGraph.kt

### `fun invalidate() = holder.invalidate()`

```
    /** See [org.kysecurity.mail.SingletonGraph.invalidate] — used by
     *  [org.kysecurity.mail.security.AppRestart]. */
```

## app/src/main/java/org/kysecurity/mail/contacts/device/DeviceGroupLinker.kt

### `class DeviceGroupLinker(`

```
/**
 * Bridges Room's local group cache ([org.kysecurity.mail.data.GroupEntity]) to Android's
 * `ContactsContract.Groups` rows scoped to this app's sync account, mirroring the remote-ID <->
 * local-row-ID bridging [org.kysecurity.mail.data.DeviceContactLinkEntity] already solves for contacts
 * themselves. Only ever materializes a *backend* group onto the device (find-or-create + rename
 * in place) — it never creates a backend group from a device-side one, matching
 * `Client_Contact_Update.md` Part 2 point 3's explicit one-direction (backend -> device) scoping
 * for group sync.
 */
```

### `suspend fun ensureAndroidGroupRowId(groupId: String, groupName: String): Long? = withContext(Dispatchers.IO) {`

```
    /**
     * Returns the Android `Groups._ID` row for [groupId]/[groupName]: reuses an existing
     * [GroupLinkEntity] if present (renaming the on-device `TITLE` in place if [groupName]
     * changed since the link was created), otherwise finds an existing on-device `Groups` row
     * matching by `TITLE == groupName` to avoid duplicating a group the user already has, and
     * only creates a new row as a last resort.
     */
```

### `suspend fun renameIfNeeded(androidGroupRowId: Long, groupName: String) = withContext(Dispatchers.IO) {`

```
    /**
     * Renames the on-device `Groups.TITLE` for [androidGroupRowId] to [groupName] in place, if
     * it differs from the current on-device title. Public (not just called from
     * [ensureAndroidGroupRowId]) so [org.kysecurity.mail.contacts.GroupSyncRepository]'s regular
     * full-refresh sync cycle can also invoke it for every *already-linked* group -- the plan's
     * Part 2 point 4 requires a backend group rename to reach the device on the next sync, not
     * only when a brand-new not-yet-linked contact happens to reference that group.
     */
```

### `internal fun groupRenameTargets(links: List<GroupLinkEntity>, groups: List<GroupEntity>): List<Pair<Long, String>> {`

```
/**
 * Pure join: for every [links] entry whose backend group still exists in the freshly-synced
 * [groups] cache, resolves the (androidGroupRowId, freshName) pair that should be passed to
 * [DeviceGroupLinker.renameIfNeeded]. A link whose group was deleted from the backend (and thus
 * dropped from [groups] by [org.kysecurity.mail.contacts.GroupSyncRepository]'s full refresh) is
 * skipped -- there's no fresh name to rename to. Extracted as a standalone pure function so the
 * "which already-linked groups need a rename pass" decision is unit-testable without a real
 * `ContentResolver`; the actual current-title comparison and write happen inside
 * [DeviceGroupLinker.renameIfNeeded] itself.
 */
```

### `internal fun findExistingGroupRowId(existingGroups: List<Pair<Long, String>>, groupName: String): Long? =`

```
/** Pure find-or-create decision: does any existing on-device group (scoped to our account)
 *  already have this exact title? Extracted so the matching rule is unit-testable without a real
 *  `ContentResolver`. */
```

## app/src/main/java/org/kysecurity/mail/data/AppDatabase.kt

### `val MIGRATION_7_8 = object : Migration(7, 8) {`

```
        // Defaults match a message with no OpenPGP content, which is what every
        // already-cached row is as far as this app has ever known — so existing
        // rows land in exactly the state they were already being rendered in.
```

### `val MIGRATION_9_10 = object : Migration(9, 10) {`

```
        /**
         * Splits the identity alarm out of `pgpKeyNeedsReverification`. Additive and defaulted, so
         * existing rows keep their key alarm and start with no identity alarm — the safe direction:
         * a missing identity alarm is re-raised by the next sync that observes a rebind, whereas
         * migrating every existing key alarm into both columns would show every user a review prompt
         * they cannot action.
         */
```

## app/src/main/java/org/kysecurity/mail/data/ContactDao.kt

### `@Dao`

```
/** suspend/Flow-based, matching the coroutine convention already used by push/PushRepository. */
```

### `@Upsert`

```
    // Deliberately no getSelf(): the account's own PGP identity is NOT in this table — the
    // self-contact's pgpKey is an ordinary contact field — so a "fetch my own row" helper only ever
    // served an answer this database cannot give. See pgp.ownFingerprintFromBootstrap.
```

### `suspend fun search(query: String): List<ContactEntity> = searchEscaped(query.escapeLikePattern())`

```
    /** Name-or-email substring match for the contact-autocomplete feature (spec:
     *  ContactAutocomplete.md). LIKE is case-insensitive for ASCII in SQLite by default, so no
     *  explicit COLLATE NOCASE is needed on the LIKE itself. Matches against the raw
     *  [ContactEntity.emailsJson] string rather than decoding it — the email address appears
     *  verbatim inside the encoded JSON, so a substring match is correct without a JOIN/decode;
     *  see RecipientMatching.kt for why only the *primary* email is ever displayed even though
     *  this query can match on a secondary one. Contacts with no email at all
     *  (`emailsJson = '[]'`) are excluded — nothing to autocomplete to. */
```

## app/src/main/java/org/kysecurity/mail/data/ContactEntity.kt

### `@Entity(tableName = "contacts")`

```
/**
 * Mirrors the `Contact` JSON shape in Mobile_Contact_Sync.md. [emailsJson]/[phonesJson]/
 * [addressesJson] hold pre-encoded kotlinx.serialization JSON for the field-entry lists — plain
 * String columns rather than a TypeConverter, since callers already have a Json instance handy
 * from decoding the sync response. The newer list columns ([groupIDsJson], [imsJson],
 * [websitesJson], [relationsJson], [eventsJson], [customFieldsJson]) carry an explicit
 * `@ColumnInfo(defaultValue = "[]")` — unlike the original three, they were added to an
 * already-populated table via [AppDatabase.MIGRATION_3_4], and SQLite requires a NOT NULL
 * column added by ALTER TABLE to declare a default so existing rows stay valid.
 */
```

### `val pgpKeyFingerprint: String? = null,`

```
    // Locally-computed OpenPGP fingerprint of [pgpKey] (see PgpFingerprint.compute) — never
    // trusts a server-supplied fingerprint string, same discipline as the QR key-exchange flow.
    // Used only to detect when a sync-delivered pgpKey silently changes; not synced to the server.
```

### `@ColumnInfo(defaultValue = "0") val identityNeedsReview: Boolean = false,`

```
    /**
     * The *identity* alarm, kept separate from [pgpKeyNeedsReverification] because they answer
     * different questions and are cleared by different evidence.
     */
```

## app/src/main/java/org/kysecurity/mail/data/ContactSyncStateDao.kt

### `@Query("DELETE FROM contact_sync_state")`

```
    /**
     * Drops every stored cursor.
     *
     * The cursor moved out of the `contacts_state` DataStore into this table, but the unpair purge
     * was not moved with it: it still deleted the DataStore file the cursor no longer lives in. Since
     * `subscriberId` is stable per account, a re-pair to the same account resumed from the stale
     * cursor, the server returned nothing changed since it, and the address book stayed empty
     * indefinitely with no error surfaced. Each ever-paired account also left a plaintext
     * `subscriberId` row behind -- the exact residue the purge deletes `contacts_state` to prevent.
     */
```

## app/src/main/java/org/kysecurity/mail/data/ContactSyncStateEntity.kt

### `@Entity(tableName = "contact_sync_state")`

```
/** Durable contact-sync cursor, kept beside the contact/outbox rows it acknowledges. */
```

## app/src/main/java/org/kysecurity/mail/data/DataRuntime.kt

### `val database: AppDatabase = if (HostileLocationSettings(appContext).isEnabled()) {`

```
    /**
     * In-memory when Hostile Location Protection is on (see the 2026-07-22 security-hardening
     * spec) — every repository/DAO is unchanged either way, since both builders produce the
     * same [AppDatabase] type; only where its rows live differs. Toggling the setting requires
     * an app relaunch ([org.kysecurity.mail.security.AppRestart]) since this decision is only made
     * once, at construction time.
     */
```

### `private fun encryptedOpenHelperFactory(appContext: Context): SupportOpenHelperFactory {`

```
    /**
     * SQLCipher, keyed from [DatabaseKey].
     *
     * Encryption at rest is unconditional. Hostile Location Protection remains the stronger mode,
     * where there is no file at all.
     *
     * The conversion of an existing plaintext file runs here, before Room opens it, because Room
     * would otherwise fail to open a database it cannot read. See [DatabaseMigration].
     */
```

### `if (!sqlCipherLoaded) throw DatabaseUnavailableException("libsqlcipher.so could not be loaded")`

```
        // Before anything touches SQLCipher. See [sqlCipherLoaded] — the library ships the .so and
        // loads it nowhere, so without this the first Room query throws UnsatisfiedLinkError on a
        // background thread.
```

### `if (!DatabaseMigration.encryptIfNeeded(appContext, DATABASE_NAME, passphrase)) {`

```
        // Checked. On false the file on disk is still plaintext, and building the factory anyway
        // hands a plaintext file to SQLCipher — which surfaces as SQLITE_NOTADB on the first query,
        // on a background thread, on every launch, with the cause nowhere near the symptom.
```

### `override fun closeGraph() {`

```
    /**
     * Closes the database when this graph is dropped.
     *
     * `SingletonGraph.invalidate()` alone only stopped handing this instance out; the database
     * stayed open, and [org.kysecurity.mail.security.AppRestart] does not kill the process. Under
     * Hostile Location Protection that leaked an in-memory database still holding every cached
     * message body.
     *
     * [org.kysecurity.mail.security.SecurityWipe.closeAndDeleteDatabase] still uses `takeGraph()` and
     * closes explicitly, because it also has to quiesce in-flight mail work first and then verify
     * the file is gone — this is the ordinary teardown, not that one.
     */
```

### `const val DATABASE_NAME = "kypost_mail.db"`

```
/** The one place the file name is written. [org.kysecurity.mail.security.SecurityWipe] deletes it and
 *  [DatabaseMigration] converts it, and a third spelling of the string is a bug waiting to happen. */
```

### `class DatabaseUnavailableException(message: String) : IllegalStateException(message)`

```
/**
 * The local database cannot be opened, and serving the app without it would mean presenting an
 * empty mailbox over data that is still on disk.
 *
 * Named rather than a bare `IllegalStateException` so the failure is greppable in a crash report
 * and distinguishable from a Room schema problem.
 */
```

### `object DataRuntime {`

```
/** Standalone singleton, kept independent of PushGraph/KyPostApp — mirrors how PushGraph itself
 *  stands alone rather than nesting inside another graph. */
```

### `fun invalidate() = holder.invalidate()`

```
    /** See [org.kysecurity.mail.SingletonGraph.invalidate] — used by
     *  [org.kysecurity.mail.security.AppRestart]. */
```

### `fun takeGraph(): DataGraph? = holder.take()`

```
    /** See [org.kysecurity.mail.SingletonGraph.take] — used by
     *  [org.kysecurity.mail.security.SecurityWipe.closeAndDeleteDatabase], which has to close the
     *  database instance that is actually in use, not a freshly built stand-in. */
```

### `fun peekGraph(): DataGraph? = holder.peek()`

```
    /** See [org.kysecurity.mail.SingletonGraph.peek] — used by
     *  [org.kysecurity.mail.push.PushRepository.purgeAccountScopedData], which must not resurrect a
     *  database that [org.kysecurity.mail.security.SecurityWipe] has already closed and deleted. */
```

## app/src/main/java/org/kysecurity/mail/data/DatabaseMigration.kt

### `internal val sqlCipherLoaded: Boolean by lazy {`

```
/**
 * Loads SQLCipher's native library, once. Nothing in the AAR does it, so `libsqlcipher.so` ships in
 * `jni/` and is never loaded unless the app loads it. Room opens the database lazily on a background
 * thread, so a missing load would otherwise surface as an `UnsatisfiedLinkError` on the first query.
 */
```

### `internal object DatabaseMigration {`

```
/**
 * One-time conversion of a pre-encryption `kypost_mail.db` into an encrypted one.
 *
 * The file is converted rather than discarded because `pending_contact_changes` holds contact edits
 * the user made offline that exist nowhere else.
 *
 * Crash safety rests on one property: the only step that changes which file *is* the database is a
 * single `rename(2)`, which the kernel applies atomically and which replaces the target. There is no
 * instant at which neither file is a usable database. [recoverInterrupted] additionally salvages the
 * temp file left by an earlier build that deleted the original before renaming.
 */
```

### `fun encryptIfNeeded(context: Context, databaseName: String, passphrase: String): Boolean {`

```
    /**
     * Converts [databaseName] in place if it is still plaintext. Safe to call on every launch.
     *
     * @return true if the database is now encrypted, or there was nothing to convert. **Callers must
     *   check this**: on false the file on disk is still plaintext, and handing it to SQLCipher
     *   produces an unopenable database rather than a reported failure.
     */
```

### `deleteJournals(plain)`

```
            // The plaintext journals belong to the file about to be replaced. `source.close()`
            // above checkpoints and removes them in the normal case; this covers the case where it
            // did not, and it runs before the rename so the encrypted file is never momentarily
            // paired with a foreign WAL. An interruption here still leaves the checkpointed
            // plaintext database in place, which the next launch converts again.
```

### `private fun recoverInterrupted(plain: File, temp: File, passphrase: String): Boolean {`

```
    /**
     * Adopts a converted database left stranded by an interrupted run.
     *
     * Builds up to and including 0.3.2 deleted the plaintext file before renaming the converted one
     * into place. A process death in that window left no database and an orphaned `.encrypting`
     * file holding the entire mailbox — which the old `if (!plain.exists()) return true` read as
     * "nothing to convert", so Room created an empty database over the top and the orphan was never
     * looked at again. Devices in that state are still out there; this is how they get their mail
     * back.
     *
     * @return true when [temp] is now the database.
     */
```

### `private fun exportToTemp(plain: File, temp: File, passphrase: String): Int {`

```
    /** Copies [plain] into a fresh encrypted [temp], returning the `user_version` it carried. */
```

### `source.rawExecSQL("ATTACH DATABASE ? AS encrypted KEY ?", temp.absolutePath, passphrase)`

```
            // rawExecSQL, because ATTACH and sqlcipher_export() are not statements the binder-based
            // API models. The key is BOUND, never interpolated — and DatabaseKey stores base64 so
            // the bytes SQLite sees for this text parameter are identical to the ones
            // SupportOpenHelperFactory is handed, making both derive the same key.
```

### `private fun versionUnder(file: File, passphrase: String): Int? = runCatching {`

```
    /** The `user_version` of [file] read under [passphrase], or null if it will not open. */
```

### `private fun isPlaintext(file: File): Boolean {`

```
    /**
     * Whether [file] is an unencrypted SQLite database.
     *
     * SQLCipher encrypts the whole file including SQLite's 16-byte header, so the magic's absence
     * identifies an already-converted database.
     *
     * Throws rather than guessing when the header cannot be read at all. Answering "encrypted" there
     * — which `runCatching { ... }.getOrDefault(false)` did, as did a short read whose count was
     * discarded — hands a plaintext file to SQLCipher and produces a database that never opens
     * again.
     */
```

## app/src/main/java/org/kysecurity/mail/data/DeviceContactLinkDao.kt

### `@Query("UPDATE device_contact_links SET uid = :serverUid WHERE uid = :localUid")`

```
    /** Reconciliation renames a locally-created contact's temp uid to the server-assigned one.
     *  The link row keys on uid, so it has to follow that rename — otherwise the new uid looks
     *  unlinked and [org.kysecurity.mail.contacts.device.DeviceContactRepository.pushRoomChangesToDevice]
     *  inserts a SECOND raw contact, while the old row is orphaned and can never be reclaimed
     *  (`getByUid` on the dead uid returns null forever). */
```

### `@Query("DELETE FROM device_contact_links WHERE rawContactId IN (:rawContactIds)")`

```
    /** Drops links pointing at raw contacts this app does not own. Older builds linked a uid to a
     *  raw contact belonging to another account (Google, Samsung) whenever a single email or phone
     *  matched, which made every later write and delete for that uid target the other account's
     *  row. Existing installs can already carry such rows, so they are swept on startup. */
```

### `@Query("DELETE FROM device_contact_links")`

```
    /** Used when every synced raw contact is removed at once — see
     *  [org.kysecurity.mail.contacts.device.DeviceContactRepository.deleteAllSyncedDeviceContacts]. */
```

## app/src/main/java/org/kysecurity/mail/data/EmailDao.kt

### `@Dao`

```
/**
 * Blocking (non-suspend) by design: callers already run on a background executor thread,
 * so there is no need to add coroutines to the mail path just for this cache.
 */
```

### `@Query("UPDATE emails SET body = '', preview = '' WHERE pgpEncrypted = 1 AND body IS NOT NULL AND body != ''")`

```
    /**
     * Drops the locally cached plaintext of mail the **server** decrypted.
     *
     * `pgpEncrypted = 1` with a non-empty body is exactly [PgpMessageState.DECRYPTED_BY_SERVER]: the
     * message was encrypted in the mailbox and the server opened it with an account key it held. Once
     * the account moves to a client-held key that plaintext is the one copy of the message the new
     * threat model does not account for — the server can no longer produce it, and nothing else on
     * the device would remove it until the next full snapshot up to 24 hours later.
     *
     * Ordinary unencrypted mail is untouched: `pgpEncrypted = 0` there, and clearing it would be
     * collateral for no privacy gain.
     *
     * `body IS NOT NULL` is not redundant. `body` is nullable and `body != ''` evaluates to NULL —
     * not true — for a null body, so the guard makes "no body to clear" explicit rather than relying
     * on three-valued logic to skip the row.
     *
     * Clears `preview` alongside `body` because the preview is derived from the decrypted text and
     * would otherwise leave the opening of every message readable. It does **not** clear `subject`:
     * a blanked subject leaves an unreadable inbox row until the next sync, and only the OpenPGP
     * protected-subject extension puts message content there. That case is left to the full snapshot.
     */
```

### `@Transaction`

```
    /** Reconciles a full-list fetch into the cache: upsert what came back, drop what didn't. */
```

## app/src/main/java/org/kysecurity/mail/data/EmailEntity.kt

### `@Entity(tableName = "emails")`

```
/**
 * Local cache row for one message, populated by [org.kysecurity.mail.mail.RelayMailSource].
 * This is the UI's read model — relay reconciles delta responses into it (new/updated/removed,
 * Mobile_Mail_Relay.md Part 5) rather than re-fetching everything on each screen visit.
 */
```

### `val pgpEncrypted: Boolean = false,`

```
    // Persisted because the inbox list renders from this cache: without them a
    // client-protected message would come back from Room indistinguishable from
    // one with a genuinely empty body. The server keeps these flags across
    // delta "updated" entries, so caching them does not go stale.
```

## app/src/main/java/org/kysecurity/mail/data/GroupDao.kt

### `@Dao`

```
/** Mirrors [ContactDao]'s suspend-based shape for the small, full-refreshed groups cache. */
```

## app/src/main/java/org/kysecurity/mail/data/GroupEntity.kt

### `@Entity(tableName = "groups")`

```
/**
 * Local cache of the backend's groups list (`GET /api/groups`), full-refreshed on each sync
 * cycle — small list, no delta cursor needed, mirrors [ContactEntity]'s `uid`/`rev` shape but
 * without the JSON-column machinery since a group has no list-valued fields.
 */
```

## app/src/main/java/org/kysecurity/mail/data/GroupLinkDao.kt

### `@Dao`

```
/** Mirrors [DeviceContactLinkDao]'s shape for the group remote-ID <-> Android-row-ID bridge. */
```

## app/src/main/java/org/kysecurity/mail/data/GroupLinkEntity.kt

### `@Entity(tableName = "group_links")`

```
/**
 * Bridges a backend group's [groupId] to the Android `ContactsContract.Groups._ID` row it was
 * lazily materialized as on-device, the same "remote ID <-> local row ID" problem
 * [DeviceContactLinkEntity] already solves for contacts themselves.
 */
```

## app/src/main/java/org/kysecurity/mail/data/PendingContactChangeEntity.kt

### `@Entity(tableName = "pending_contact_changes")`

```
/** Offline queue of not-yet-synced local contact edits, flushed by ContactSyncRepository.sync(). */
```

## app/src/main/java/org/kysecurity/mail/mail/AddressText.kt

### `fun addressFromHeader(raw: String): String {`

```
/**
 * The real address out of a raw From/To/Cc header value.
 *
 * A display name is attacker-controlled and authenticated by nothing: DKIM, SPF and DMARC validate
 * the domain a message was sent from, never the human-readable label in front of it. So this arrives
 * intact and aligned:
 *
 *     From: "Bob <bob@corp.com>" <evil@attacker.tld>
 *
 * Taking the *first* `<...>` group resolves that to Bob when the mail came from the attacker, and
 * Reply, Reply All and Forward all carry the quoted original — so a wrong answer here sends a thread
 * to someone who never sent it.
 *
 * The rule, shared verbatim with the webmail and Linux clients: the real address is the LAST
 * angle-addr, because RFC 5322 puts display-name first and addr-spec last. A bare value is the
 * address itself. Anything without an "@" yields "" rather than being passed through as a
 * pseudo-recipient.
 *
 * Deliberately not `android.text.util.Rfc822Tokenizer`: framework code would push these cases into
 * an instrumented test, where they would drift out of step with the other two clients' plain unit
 * tests against the same vectors.
 */
```

## app/src/main/java/org/kysecurity/mail/mail/MailCursorStore.kt

### `interface MailCursorProvider {`

```
/**
 * Blocking (non-suspend) by design, matching [MailSource] and [RelayMailSource]'s own
 * synchronous style — callers already run on a background executor thread. Backed by
 * [MailCursorStore] in production; tests inject an in-memory fake instead.
 */
```

### `class MailCursorStore(`

```
/**
 * Durable per-subscriber, per-folder delta-sync cursor for GET /api/inbox (Mobile_Mail_Relay.md
 * Part 5, v2), mirroring [org.kysecurity.mail.push.PushRepository]'s pull-cursor pattern exactly.
 * Scoped to subscriber+folder so re-pairing or switching mailboxes can't apply a stale/foreign
 * cursor. Cursors are opaque server-issued strings, not assumed to be numeric or ordered.
 */
```

### `private val inMemoryCursors = mutableMapOf<String, String>()`

```
    /**
     * Under Hostile Location Protection nothing about the user's mail may touch disk, and this
     * store's keys encode which folders exist and when each was last read. Held in memory instead,
     * matching [org.kysecurity.mail.push.PushRepository]'s in-memory push history — a cold process just
     * starts from since=0, which is correct, only less efficient.
     */
```

### `private fun resyncValue(folder: String) = ScopedValue(`

```
    /**
     * Its **own** scope key, not the cursor's.
     *
     * [ScopedValue.set] writes the scope alongside its value, so sharing one key meant writing the
     * resync stamp re-stamped the scope over a *stale cursor* and re-authorised it for the new
     * subscriber — precisely the opposite of ScopedValue's stated guarantee that "a change of scope
     * reads back null instead of the previous scope's stale value". After re-pairing, a relay that
     * answered the first `/api/inbox` with a blank cursor (a supported case the repo's own tests
     * exercise) skipped `saveCursor` while `recordFullResync` re-stamped the scope, and the next
     * refresh 90 seconds later put the *previous* relay's cursor token on the wire to the new one.
     */
```

### `private fun folderKey(folder: String): String {`

```
        /**
         * Hashes the folder into the key name instead of interpolating it, which fixes two things.
         *
         * It also stopped the key names from spelling out the user's folder taxonomy (`Archive/
         * Legal/Asylum-Case`) in a plaintext DataStore. The prefixes are now non-prefixing, so no
         * hash value can collide across the two roles either.
         *
         * Changing the scheme abandons existing cursors, which costs exactly one full resync.
         */
```

## app/src/main/java/org/kysecurity/mail/mail/MailGraph.kt

### `callFactory = pinnedPairingCallFactory(appContext),`

```
        // The one shared pinned-or-refuse factory, the same one the contacts graph uses. Building
        // a private PinnedCallFactoryProvider here and null-coalescing it against an unpinned
        // client is what let the mail endpoints downgrade silently.
```

### `fun invalidate() = holder.invalidate()`

```
    /** See [org.kysecurity.mail.SingletonGraph.invalidate] — used by
     *  [org.kysecurity.mail.security.AppRestart]. */
```

## app/src/main/java/org/kysecurity/mail/mail/MailRepository.kt

### `class MailRepository(`

```
/**
 * Uses relay [MailSource] exclusively. Writes fetch results into the Room cache (the UI's read model —
 * see data/EmailDao's replaceFolderSnapshot) and exposes the actions InboxActivity/EmailDetailActivity/
 * ComposeActivity call instead of instantiating sources directly.
 */
```

### `fun cachedEmails(folder: String): List<Email> = emailDao.getByFolder(folder).map { it.toUiEmail() }`

```
    /** Cached rows for [folder], available immediately (e.g. a fast cold-start render). */
```

### `fun refreshFolder(folder: String, limit: Int = 50, forceFullResync: Boolean = false): MailOutcome<MailFetchResult> {`

```
    /**
     * Fetches from relay source, reconciles into the Room cache, and returns the outcome.
     * [forceFullResync] requests since=0 on the relay source (see [MailSource.fetchInbox]) —
     * pass true for a user-initiated manual refresh; the daily self-heal cadence otherwise
     * applies automatically inside [RelayMailSource] regardless of this flag.
     */
```

### `fun fetchBody(id: String, folder: String): MailOutcome<MailMessageBody> {`

```
    /**
     * Returns the cached body, or a failure when we do not have this message at all.
     *
     * The distinction matters for PGP state. An empty body plus `pgpEncrypted` is the wire signature
     * of a client-protected message, so treating "we have no row for this id" the same way made the
     * detail view assert *"this message is end-to-end encrypted"* about mail the server had actually
     * decrypted — the wrong direction, since it hides server access from a user auditing what their
     * host can read. Under Hostile Location Protection that was the normal case, because Room is
     * in-memory and every cold process starts with no rows.
     *
     * A row that exists with no body is still reported as Success-with-empty: that is the server
     * genuinely having no body for us. (A delta "updated" entry for a message that was never cached
     * also lands in that shape — see [reconcileFetchResult], which now declines to create such a
     * row rather than inventing one with a body it was never sent.)
     */
```

### `internal fun reconcileFetchResult(emailDao: EmailDao, folder: String, mode: String, result: MailFetchResult) {`

```
/**
 * Reconciles one fetch outcome into [emailDao]: a full snapshot (isDelta=false) replaces the
 * folder wholesale as before; a delta upserts "new" entries, merges "updated" entries into the
 * existing row while preserving its body/preview (Mobile_Mail_Relay.md Part 5 — "updated" entries
 * never carry a body), and deletes `removed` ids. Kept as a standalone function, independent of
 * [MailSettings]/Context, so it's testable in a plain JVM unit test.
 */
```

### `val mergedEntities = updated.mapNotNull { email ->`

```
    // An "updated" entry never carries a body. With an existing row we merge, preserving the body we
    // already have. With NO existing row there is nothing to merge into, and storing the entry as-is
    // created a row whose empty body was indistinguishable from a client-protected message — so the
    // detail view claimed end-to-end encryption for mail the server had decrypted. Skip it instead:
    // we do not have this message, and a metadata-only delta is not a delivery of it. The next full
    // snapshot (forced daily, see MailCursorStore) brings it in properly.
```

### `if (result.isFullWindow) {`

```
    // On an older relay `removed` is delivered once and never repeated: it is computed against that
    // server's own prior window, which the same call then replaces, so a notification that went to
    // another device — or into a response this one never applied — is gone for good, and mail
    // deleted on the web sat in the inbox forever. A since=0 fetch is the whole window, so it can
    // say what is *absent*; pruning against it is the only self-heal for a removal we were never
    // told about, and it costs nothing against a relay that does retain removals. Partial (cursor)
    // deltas must not prune: they only describe what changed, and everything they omit is still
    // legitimately in the mailbox.
```

## app/src/main/java/org/kysecurity/mail/mail/MailSource.kt

### `data class ClientSideNeeded(val message: String) : MailOutcome<Nothing>()`

```
    /** Relay 409 on /api/mail/send with `clientSideNeeded` — the account's PGP key is
     *  end-to-end protected, so the server refuses to sign or encrypt on its behalf rather
     *  than silently sending in the clear. This app holds no private key, so the only ways
     *  forward are sending unencrypted or using webmail. Distinct from [BadRequest] because
     *  nothing about the request was malformed. */
```

### `data class PickupFallbackNeeded(`

```
    /** Relay 409 on /api/mail/send carrying `keylessRecipients` — one or more recipients have no
     *  usable PGP key, and the server refused rather than quietly falling back to a one-time link
     *  that stores this message's plaintext on the server for seven days. **Nothing was
     *  delivered:** the refusal happens before any SMTP, so re-sending the same draft with
     *  [MailDraft.allowPickupFallback] once the user has confirmed is safe and cannot duplicate. */
```

### `internal fun formatRetryAfter(seconds: Long): String = when {`

```
/** Whole minutes once past a minute, because a Retry-After of 900 read as "900 seconds" is
 *  not something a user can act on. */
```

### `val isFullWindow: Boolean = false,`

```
    // True when this response describes the server's entire window rather than just what changed
    // (i.e. we sent since=0). A relay predating the matching server fix labels such a response
    // `delta: true` all the same, so this — not the wire flag — is what tells us `messages` is
    // complete enough to prune the folder against. See [reconcileFetchResult], which needs it to
    // self-heal a removal we were never told about.
```

### `val encrypt: Boolean = false,`

```
    /** Server-side PGP encryption. */
```

### `val allowPickupFallback: Boolean = false,`

```
    /** Opt in to the one-time pickup link for recipients with no usable key. Meaningful only when
     *  [encrypt] is true, and only ever set after the user confirmed the dialog naming them: the
     *  fallback stores this message's plaintext on the server, unencrypted, for up to seven days.
     *  Per-message by design — never persisted as a preference. */
```

### `data class OutgoingAttachment(`

```
/** An attachment the user picked to send: raw base64 payload plus display metadata. */
```

### `data class ClientEncryptedDelivery(val recipients: List<String>, val ciphertext: String)`

```
/** One pre-built PGP/MIME message and the SMTP recipients it goes to. */
```

### `data class ClientEncryptedMessage(`

```
/**
 * A send whose PGP work already happened on this device, for `POST /api/mail/send-pgp`.
 *
 * [deliveries] is a list rather than one message because each BCC recipient needs their own
 * ciphertext — a shared one puts every BCC recipient's key id where the others can read it.
 *
 * [to]/[cc]/[bcc] stay in the clear deliberately: SMTP needs them, they are already the envelope,
 * and the Sent listing is unusable without them. Only the body and the real subject are protected.
 */
```

### `class DownloadedAttachment(val name: String, val mimeType: String, val bytes: ByteArray)`

```
/** A downloaded attachment's bytes plus the metadata needed to save it. */
/**
 * **Not a `data class`.** The generated `equals`/`hashCode` would compare [bytes] by identity while
 * looking structural, so a `Set<DownloadedAttachment>` or an `==` would silently never match — and
 * these are the values a de-duplicating forward cache is most likely to be built over.
 */
```

### `interface MailSource {`

```
/**
 * Blocking (non-suspend) by design: callers already run on a background executor thread,
 * so there is no need to introduce coroutines into the mail path just for this abstraction.
 */
```

### `fun sendClientEncrypted(message: ClientEncryptedMessage): MailOutcome<MailSendOutcome>`

```
    /** Relays ciphertext this device already built. Separate from [sendMail] rather than a flag on
     *  it: the request body, the endpoint and the failure modes all differ, and the two must not be
     *  able to drift into each other. */
```

## app/src/main/java/org/kysecurity/mail/mail/PhishingFlag.kt

### `const val PHISHING_KEYWORD = "\$Phishing"`

```
/**
 * The IMAP keyword the server sets on inbound mail that impersonates KyPost itself — see
 * `backend/internal/processor/phish_scan.go`.
 *
 * `$Phishing` is the reserved RFC 8621 keyword, so other mail clients understand it too. The message
 * is flagged in place: it stays in the inbox, stays unread, and keeps its body. Nothing here moves
 * or hides mail.
 *
 * A mirrored literal rather than a shared constant — the other clients are TypeScript and QML, with
 * no cross-repo artifact to share it through. The keyword string itself is the contract.
 */
```

## app/src/main/java/org/kysecurity/mail/mail/QuotedHtmlSanitizer.kt

### `object QuotedHtmlSanitizer {`

```
/**
 * Strips executable and resource-loading constructs out of a sender's message before it is quoted
 * into the compose editor.
 *
 * The reader ([org.kysecurity.mail.EmailDetailActivity]) renders sender HTML with JavaScript off,
 * network loads blocked and an opaque origin, so it is safe there. The **composer** is a different
 * WebView: `android-rich-html-editor` sets `setJavaScriptEnabled(true)` and
 * `addJavascriptInterface(jsBridge, "editor")`, and its `setHtml` assigns straight to `innerHTML`.
 * The library's own escaper handles a backtick, a backslash and a dollar sign — it is a JavaScript
 * string-literal escaper, not an HTML sanitizer, and does not claim to be.
 *
 * A `<script>` inserted via `innerHTML` does not execute, but **event handler content attributes on
 * inserted elements do**. Quoting a sender's `<img src=x onerror=...>` into a reply therefore gave
 * them script execution in the document holding the user's outgoing message, with the `editor`
 * bridge in reach.
 *
 * Allowlist-based and parser-backed rather than pattern-based: a regex over markup loses to mXSS and
 * to malformed tags the browser re-interprets. K-9 and FairEmail resolve this the same way.
 */
```

### `private val safelist: Safelist = Safelist.relaxed()`

```
    /**
     * [Safelist.relaxed] preserves formatting — headings, lists, tables, links — so a quoted reply
     * still looks like the message it quotes. Everything unnamed is dropped, which covers
     * `<script>`, `<iframe>`, `<object>`, `<embed>`, `<svg>` and every `on*` attribute, since
     * attributes are allowlisted per tag rather than denylisted. It also enforces a protocol
     * allowlist on `href`/`src` (removing `javascript:` and `data:`) and does not permit `style`.
     */
```

### `.removeTags("img")`

```
        // `relaxed()` permits <img src="http://…">, and the composer WebView has network access.
        // Quoting therefore fired the sender's tracking beacon while the reply was being written —
        // the exact leak the reader blocks with blockNetworkLoads and its opt-in "Show images" bar.
```

## app/src/main/java/org/kysecurity/mail/mail/RelayMailSource.kt

### `private const val CLIENT_SIDE_NEEDED_MARKER = "clientSideNeeded"`

```
/** Matches the JSON field the backend sets alongside its 409 on /api/mail/send, not the prose
 *  of the error message — the message is user-facing copy and may be reworded, the field is the
 *  contract. */
```

### `private class DownloadResponse(`

```
/**
 * Named rather than a 5-tuple: a Triple-of-Pairs made [downloadAttachment]'s call site unreadable
 * once Retry-After joined it.
 *
 * Read by property, never destructured, and deliberately **not** a `data class` — the generated
 * `equals`/`hashCode` would be identity-over-[ByteArray] behind a promise of structural equality,
 * which is the trap [org.kysecurity.mail.security.WrappedSecret] and
 * [org.kysecurity.mail.security.PinHash] each refuse in their own KDoc. Enforced by
 * `SourceRulesTest`; positional reads were what tied the two together.
 */
```

### `class RelayMailSource(`

```
/**
 * Talks to the six relay endpoints in Mobile_Mail_Relay.md. Blocking by design to match
 * [MailSource]'s synchronous interface — callers already run on a background executor thread.
 * Auth is sent as X-Kypost-Device-Id/X-Kypost-Device-Secret headers, sourced from the
 * pairing state (never query params/cookies).
 */
```

### `private val callFactory: Call.Factory,`

```
    /**
     * Injected `Call.Factory`; see `PairingAuthHeaders.kt` for why every credentialed client
     * takes one.
     *
     * **In production this is a [org.kysecurity.mail.push.PinnedOrFallbackCallFactory]**, which
     * re-reads the TLS pin per request and refuses outright once a pin that existed has gone. It
     * used to be a plain unpinned client plus a separate `pinnedCallFactory: () -> Call.Factory?`
     * that this class null-coalesced against — so the mail endpoints, which carry every message
     * body and this device's credential, fell back to bare system-CA trust for any reason the pin
     * could not be read, silently and permanently. There is one factory now and it owns that
     * decision; see [org.kysecurity.mail.push.TlsPinState].
     */
```

### `override fun sendClientEncrypted(message: ClientEncryptedMessage): MailOutcome<MailSendOutcome> {`

```
    /**
     * Relays ciphertext this device already built, via `POST /api/mail/send-pgp`.
     */
```

### `bytes = response.body?.let { readBounded(it, MAX_ATTACHMENT_DOWNLOAD_BYTES) } ?: ByteArray(0),`

```
                // Bounded read. `bytes()` materialises the whole body, and the advertised `size`
                // from the attachment listing was never enforced, so a relay could advertise a
                // kilobyte and stream hundreds of megabytes into the heap. Mirrors the 25MB
                // outbound cap in ComposeActivity, and matches the server's own message limit.
```

### `403 -> MailOutcome.BadRequest(rawBody.ifBlank { "Refused" })`

```
        // Plain text, and the prose is the whole value: it names an unauthorized From, which is the
        // one thing the user can act on. Without this branch it fell through to the generic
        // "Mail relay request failed (403)" and the sentence was discarded — for every endpoint,
        // not just the client-encrypted send that surfaced it.
```

### `private fun baseUrl(pairing: PairingData, path: String): HttpUrl? {`

```
    /**
     * The endpoint URL for [path], or null if the pairing's `serverUrl` is not one this app may send
     * credentials to.
     *
     * [pairingUrlHost] re-checks https (and rejects userinfo) at *request* time, not just at pairing
     * time. `toHttpUrlOrNull` accepts `http://` without complaint, and every request built here
     * carries `X-Kypost-Device-Secret`, so a pairing persisted by a build predating
     * `NativePairingDeepLinkParser`'s https gate reached this point looking valid.
     *
     * `sameOrigin` and `pairingUrlHost` both already carry doc comments about re-validating
     * persisted pairings; this was the one consumer that didn't.
     */
```

### `/** Same order of magnitude as the outbound cap in `ComposeActivity` and the server's own`

```
/** Pulls the filename out of a Content-Disposition header, honoring both the RFC 5987 `filename*`
 *  form and the plain quoted `filename=` form; empty when the header is absent or unparseable. */
```

### `internal fun readBounded(body: okhttp3.ResponseBody, limit: Long): ByteArray {`

```
/** Reads at most [limit] bytes, and throws [IOException] if the body had more to give — never
 *  allocating the whole of an oversized body, which is the out-of-memory kill this bound exists to
 *  prevent.
 *
 *  The unit tests could not see it: `FakeCalls.response()` builds a `Buffer`-backed body, and
 *  `Buffer.read` copies `min(byteCount, size)` from itself in one call with no segment limit. The
 *  fake took a fast path that does not exist on a socket, in exactly the dimension under test. See
 *  `RelayMailSourceTest.downloadAttachment_readsBodiesLargerThanOneOkioSegment`, which drives a
 */
```

### `keywords = (keywords + emailLabel).filter { it.isNotBlank() }.toSet(),`

```
        // Union of the wire keywords and the tab-derived label, not a
        // replacement: the label is what the keyword tabs filter on
        // (KeywordTabs), while the wire list is what carries server-set
        // keywords like the $Phishing anti-phishing flag. Dropping either
        // breaks one of the two.
```

## app/src/main/java/org/kysecurity/mail/mail/RelayModels.kt

### `@Serializable`

```
/** DTOs matching Mobile_Mail_Relay.md's JSON exactly. */
```

### `val keywords: List<String> = emptyList(),`

```
    // The message's real IMAP keywords. `omitempty` server-side, so an absent
    // key means none. Previously ignored entirely, which meant Email.keywords
    // was synthesised from `label` alone and a keyword the server actually set
```

### `val pgpEncrypted: Boolean = false,`

```
    // PGP state, all `omitempty` server-side (backend inboxEmail), so the defaults
    // below are the contract for a message with no OpenPGP content at all.
    //
    // pgpEncrypted with an EMPTY pgpDecryptError means the account is
    // client-protected: the server deliberately did not decrypt, there is no body
    // to render, and only the browser holds the key. A NON-empty pgpDecryptError
    // means the server tried and failed — a different condition with a real error
    // to show. See PgpMessageState.
```

### `@Serializable`

```
/**
 * POST /api/mail/send-pgp — a send whose PGP work already happened on this device.
 *
 * [subject] is accepted and deliberately IGNORED by the server: the real subject lives inside the
 * ciphertext as a protected header, so this carries the same fixed placeholder the server-side path
 * uses. Sending the real one here would hand the server the very thing this path exists to withhold.
 *
 * [sentCopyEncrypted] is an assertion *about the bytes* of [sentCopy]. A copy that does not claim it
 * is not stored at all, so this is hardcoded true at the call site rather than being a caller's
 * choice — see `RelayMailSource.sendClientEncrypted`.
 */
```

## app/src/main/java/org/kysecurity/mail/ui/SplitInitializer.kt

### `class SplitInitializer : Initializer<RuleController> {`

```
/**
 * Loads the split rules before the first Activity is created.
 *
 * Rules must be registered before the pair they describe is launched, and androidx.startup runs
 * this from the content-provider phase — earlier than Application.onCreate's own work and earlier
 * than any screen. On API 31, where embedding is unsupported, the rules are simply never applied.
 */
```

