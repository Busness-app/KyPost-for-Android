package org.kysecurity.mail.contacts

import org.kysecurity.mail.ProcessScopedState
import org.kysecurity.mail.ProcessState

// Deliberately not a saved-state Bundle: contact PII stays in-process and a wipe clears it.
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

    /** Returns the draft only if it belongs to [uid]; a mismatch drops it rather than re-offering it. */
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

// Gating on `fn` alone lost a new contact's phone, email and address before the name was typed.
private fun ContactDto.hasFormContent(): Boolean =
    fn.isNotBlank() || givenName != null || familyName != null || middleName != null ||
        prefix != null || suffix != null || nickname != null || org != null || title != null ||
        department != null || notes != null || birthday != null || pronouns != null ||
        phoneticGivenName != null || phoneticFamilyName != null ||
        emails.isNotEmpty() || phones.isNotEmpty() || addresses.isNotEmpty() ||
        websites.isNotEmpty() || ims.isNotEmpty() || relations.isNotEmpty() ||
        events.isNotEmpty() || customFields.isNotEmpty()
