package org.kysecurity.mail.contacts.device

import android.provider.ContactsContract.CommonDataKinds.Event
import android.provider.ContactsContract.CommonDataKinds.Relation

/**
 * Pure label/type mappings between this app's freeform DTO label strings and the closed
 * `ContactsContract` `TYPE_*`/`PROTOCOL_*` vocabularies, kept out of [DeviceContactRepository]'s
 * `ContentProviderOperation`-building code so the mapping decisions are unit-testable without a
 * real `ContentResolver`.
 */
object DeviceContactFieldCoding {
    /** `whatsapp|signal|telegram|instagram|x|linkedin|facebook|mastodon|matrix|""` (=other) -> a
     *  human-readable display string, mirroring the web frontend's `IM_SERVICES` catalog
     *  (`kypost-server/frontend/src/api/contacts.ts`) so the two stay in sync. None of these map to
     *  a built-in `Im.PROTOCOL_*` constant, so every `ims` row is written as `PROTOCOL_CUSTOM` with
     *  this resolved string as `CUSTOM_PROTOCOL`. */
    fun imCustomProtocolLabel(service: String?, label: String?): String = when (service) {
        "whatsapp" -> "WhatsApp"
        "signal" -> "Signal"
        "telegram" -> "Telegram"
        "instagram" -> "Instagram"
        "x" -> "X (Twitter)"
        "linkedin" -> "LinkedIn"
        "facebook" -> "Facebook"
        "mastodon" -> "Mastodon"
        "matrix" -> "Matrix"
        else -> label?.takeIf { it.isNotBlank() } ?: "Other"
    }

    /** Inverse of [imCustomProtocolLabel]'s recognized-service branch: an on-device
     *  `Im.CUSTOM_PROTOCOL` display string read back from the phone's native Contacts app -> the
     *  closed `service` vocabulary word. Unrecognized display strings (including the "Other"
     *  fallback and any freeform label) collapse to `""`, matching the documented convention that
     *  `service == ""` means "other" and the display string is carried as the freeform `label`
     *  instead. */
    fun imServiceFromCustomProtocolLabel(label: String?): String = when (label) {
        "WhatsApp" -> "whatsapp"
        "Signal" -> "signal"
        "Telegram" -> "telegram"
        "Instagram" -> "instagram"
        "X (Twitter)" -> "x"
        "LinkedIn" -> "linkedin"
        "Facebook" -> "facebook"
        "Mastodon" -> "mastodon"
        "Matrix" -> "matrix"
        else -> ""
    }

    /** `spouse|child|parent|partner|manager|assistant|friend|relative|other` -> the closest
     *  `Relation.TYPE_*` constant (values confirmed against the installed Android SDK's
     *  `android.jar`, not guessed); `"other"` and any unrecognized label fall back to
     *  `TYPE_CUSTOM`. */
    fun relationType(label: String?): Int = when (label) {
        "spouse" -> Relation.TYPE_SPOUSE
        "child" -> Relation.TYPE_CHILD
        "parent" -> Relation.TYPE_PARENT
        "partner" -> Relation.TYPE_PARTNER
        "manager" -> Relation.TYPE_MANAGER
        "assistant" -> Relation.TYPE_ASSISTANT
        "friend" -> Relation.TYPE_FRIEND
        "relative" -> Relation.TYPE_RELATIVE
        else -> Relation.TYPE_CUSTOM
    }

    /** The `Relation.LABEL` value to pair with [relationType] — only non-null when [relationType]
     *  resolved to `TYPE_CUSTOM`, matching the `TYPE_CUSTOM`+`LABEL` pairing convention. */
    fun relationCustomLabel(label: String?): String? =
        if (relationType(label) == Relation.TYPE_CUSTOM) label else null

    /** `label == "anniversary"` -> `Event.TYPE_ANNIVERSARY`; anything else -> `Event.TYPE_CUSTOM`.
     *  Birthday is unaffected — it stays the separate, existing `Event.TYPE_BIRTHDAY` row. */
    fun eventType(label: String?): Int = if (label == "anniversary") Event.TYPE_ANNIVERSARY else Event.TYPE_CUSTOM

    /** The `Event.LABEL` value to pair with [eventType] — only non-null when [eventType] resolved
     *  to `TYPE_CUSTOM`. */
    fun eventCustomLabel(label: String?): String? = if (eventType(label) == Event.TYPE_CUSTOM) label else null

    /** Inverse of [relationType]: an on-device `Relation.TYPE` read back from the phone's native
     *  Contacts app -> the closed vocabulary string. Unrecognized/`TYPE_CUSTOM` values collapse to
     *  `"other"` since [org.kysecurity.mail.contacts.ContactRelationDto.label] has no freeform slot to
     *  carry a native `Relation.LABEL` string through separately from the vocabulary word. */
    fun relationLabelFromType(type: Int?): String = when (type) {
        Relation.TYPE_SPOUSE -> "spouse"
        Relation.TYPE_CHILD -> "child"
        Relation.TYPE_PARENT -> "parent"
        Relation.TYPE_PARTNER -> "partner"
        Relation.TYPE_MANAGER -> "manager"
        Relation.TYPE_ASSISTANT -> "assistant"
        Relation.TYPE_FRIEND -> "friend"
        Relation.TYPE_RELATIVE -> "relative"
        else -> "other"
    }

    /** Inverse of [eventType] for the recognized (`TYPE_ANNIVERSARY`) case only; returns null for
     *  everything else so the caller falls back to the row's free-text `Event.LABEL` column. */
    fun eventLabelFromType(type: Int?): String? = if (type == Event.TYPE_ANNIVERSARY) "anniversary" else null
}
