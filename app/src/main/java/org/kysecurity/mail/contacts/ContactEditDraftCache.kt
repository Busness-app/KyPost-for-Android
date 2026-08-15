package org.kysecurity.mail.contacts

import org.kysecurity.mail.ProcessScopedState
import org.kysecurity.mail.ProcessState

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
object ContactEditDraftCache : ProcessScopedState {

    @Volatile
    private var draft: ContactDto? = null

    /** The uid the draft was being edited under — `""` for a not-yet-created contact. A draft is
     *  only ever handed back to the same contact, so one contact's PII cannot land in another's
     *  form and overwrite it on save. */
    @Volatile
    private var draftUid: String = ""

    /** Refuses writes until the next [take] — see ComposeDraftCache.sealed for the resurrection
     *  this prevents: a wipe clears the cache, and a write already queued lands afterwards. */
    @Volatile
    private var sealed: Boolean = false

    init {
        ProcessState.register(this)
    }

    fun save(uid: String, draft: ContactDto) {
        if (sealed) return
        // An untouched form is not worth restoring, and caching it would blank a later edit's
        // prefilled fields.
        val worthKeeping = draft.takeIf { it.hasFormContent() }
        this.draft = worthKeeping
        this.draftUid = if (worthKeeping == null) "" else uid
    }

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
    fun take(uid: String): ContactDto? {
        val matching = draft?.takeIf { draftUid == uid }
        draft = null
        draftUid = ""
        sealed = false
        return matching
    }

    fun clear() {
        draft = null
        draftUid = ""
        sealed = true
    }

    override fun resetForNewSession() = clear()
}

/**
 * Whether the form behind this draft holds anything the user would miss.
 *
 * Gating on `fn` alone lost a new contact's phone, email and address if the name had not been typed
 * yet — data loss on a casual gesture, which is the harm this cache exists to prevent. Mirrors
 * [CachedDraft.hasContent][org.kysecurity.mail.CachedDraft.hasContent] by OR-ing across every field
 * the editor exposes; the repeatable lists are already blank-filtered by `RepeatableFieldList.items`,
 * so an untouched form still reads as empty.
 */
private fun ContactDto.hasFormContent(): Boolean =
    fn.isNotBlank() || givenName != null || familyName != null || middleName != null ||
        prefix != null || suffix != null || nickname != null || org != null || title != null ||
        department != null || notes != null || birthday != null || pronouns != null ||
        phoneticGivenName != null || phoneticFamilyName != null ||
        emails.isNotEmpty() || phones.isNotEmpty() || addresses.isNotEmpty() ||
        websites.isNotEmpty() || ims.isNotEmpty() || relations.isNotEmpty() ||
        events.isNotEmpty() || customFields.isNotEmpty()
