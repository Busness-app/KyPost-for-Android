package org.kysecurity.mail.contacts.device

import android.provider.ContactsContract.CommonDataKinds.Event
import android.provider.ContactsContract.CommonDataKinds.Relation

object DeviceContactFieldCoding {
    /** Mirrors the web frontend's IM_SERVICES catalog; every `ims` row is PROTOCOL_CUSTOM. */
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

    /** Inverse of [imCustomProtocolLabel]; an unrecognized display string collapses to "" (other). */
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

    /** Constants confirmed against the SDK's android.jar; unrecognized labels give TYPE_CUSTOM. */
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

    /** Inverse of [relationType]; TYPE_CUSTOM collapses to "other" — the DTO has no freeform slot. */
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
