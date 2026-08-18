package org.kysecurity.mail.mail

import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.JsonDecoder
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonPrimitive

/** Some deployments may emit `cursor` as a bare JSON number rather than a quoted string; decode
 *  either shape into a plain string token so callers never need to care which one the server sent. */
private object FlexibleCursorSerializer : KSerializer<String> {
    override val descriptor = PrimitiveSerialDescriptor("Cursor", PrimitiveKind.STRING)

    override fun serialize(encoder: Encoder, value: String) = encoder.encodeString(value)

    override fun deserialize(decoder: Decoder): String {
        val element = (decoder as JsonDecoder).decodeJsonElement()
        return (element as? JsonPrimitive)?.takeIf { it !is JsonNull }?.content.orEmpty()
    }
}

/** DTOs matching Mobile_Mail_Relay.md's JSON exactly. */
@Serializable
data class RelayEmailDto(
    val messageId: String = "",
    val sender: String = "",
    val sentTo: String = "",
    val cc: String = "",
    val bcc: String = "",
    val subject: String = "",
    // Null (not "") distinguishes an omitted body (delta "updated" entries) from a genuinely
    // empty one, so callers know not to overwrite/clear a locally cached body.
    val body: String? = null,
    val bodyMode: String = "",
    val label: String = "",
    // The message's real IMAP keywords. `omitempty` server-side, so an absent
    // key means none. Previously ignored entirely, which meant Email.keywords
    // was synthesised from `label` alone and a keyword the server actually set
    val keywords: List<String> = emptyList(),
    val status: String = "unread",
    val atUtc: String? = null,
    // Warm-path hint for the inbox paperclip badge; false when the server
    // hasn't warmed the message yet (see backend mailcache.Entry).
    val hasAttachments: Boolean = false,
    // Only present when the parent response has "delta": true — "new" or "updated"
    // (Mobile_Mail_Relay.md Part 5, delta/cursor sync v2).
    val changeType: String? = null,
    // PGP state, all `omitempty` server-side (backend inboxEmail), so the defaults
    // below are the contract for a message with no OpenPGP content at all.
    //
    // pgpEncrypted with an EMPTY pgpDecryptError means the account is
    // client-protected: the server deliberately did not decrypt, there is no body
    // to render, and only the browser holds the key. A NON-empty pgpDecryptError
    // means the server tried and failed — a different condition with a real error
    // to show. See PgpMessageState.
    val pgpEncrypted: Boolean = false,
    val pgpSigned: Boolean = false,
    val pgpVerified: Boolean = false,
    val pgpSignerFingerprint: String = "",
    val pgpDecryptError: String = "",
)

@Serializable
data class RelayInboxResponseDto(
    val tabs: List<String> = emptyList(),
    val byTab: Map<String, List<RelayEmailDto>> = emptyMap(),
    @Serializable(with = FlexibleCursorSerializer::class)
    val cursor: String = "",
    val delta: Boolean = false,
    val removed: List<String> = emptyList(),
)

@Serializable
data class RelayFolderDto(val path: String, val deletable: Boolean = true)

@Serializable
data class RelayFolderListResponseDto(val parent: String = "", val folders: List<RelayFolderDto> = emptyList())

@Serializable
data class RelayFolderCreateRequestDto(val parent: String, val name: String)

@Serializable
data class RelayFolderRenameRequestDto(val folder: String, val name: String)

@Serializable
data class RelayActionRequestDto(
    val action: String,
    val messageIds: List<String>,
    val mailbox: String,
    val targetMailbox: String? = null,
)

@Serializable
data class RelayActionFailureDto(val messageId: String = "", val error: String = "")

@Serializable
data class RelayActionResponseDto(
    val ok: Boolean = false,
    val action: String = "",
    val processed: Int = 0,
    val failed: List<RelayActionFailureDto> = emptyList(),
    val targetMailbox: String = "",
)

/** `to`/`cc`/`bcc` are comma-separated strings here, not arrays — differs from /api/inbox's
 *  response shape and from contact sync's array-of-objects shape (Mobile_Mail_Relay.md Part 6). */
@Serializable
data class RelayMailRequestDto(
    val to: String,
    val cc: String = "",
    val bcc: String = "",
    val subject: String,
    val body: String,
    val mode: String = "plain",
    val attachments: List<RelayAttachmentDto> = emptyList(),
    /** Only /api/mail/send reads these three; /api/mail/draft ignores them, which is why
     *  [org.kysecurity.mail.mail.MailDraft] maps to this DTO through two different functions. */
    val sign: Boolean = false,
    val encrypt: Boolean = false,
    val allowPickupFallback: Boolean = false,
)

/** One pre-encrypted delivery for POST /api/mail/send-pgp. */
@Serializable
data class RelayClientEncryptedDeliveryDto(
    val recipients: List<String>,
    val ciphertext: String,
)

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
@Serializable
data class RelayClientEncryptedRequestDto(
    val from: String,
    val subject: String,
    val mode: String = "html",
    val to: List<String> = emptyList(),
    val cc: List<String> = emptyList(),
    val bcc: List<String> = emptyList(),
    val deliveries: List<RelayClientEncryptedDeliveryDto> = emptyList(),
    val sentCopy: String = "",
    val sentCopyEncrypted: Boolean = false,
)

/** Outgoing attachment wire shape accepted by /api/mail/send and /api/mail/draft. */
@Serializable
data class RelayAttachmentDto(
    val name: String,
    val mimeType: String,
    val dataBase64: String,
)

/** One received attachment's metadata from GET /api/mail/attachments. */
@Serializable
data class RelayAttachmentInfoDto(
    val index: Int = 0,
    val name: String = "",
    val mimeType: String = "",
    val size: Int = 0,
)

@Serializable
data class RelayAttachmentListResponseDto(
    val ok: Boolean = false,
    val attachments: List<RelayAttachmentInfoDto> = emptyList(),
)

@Serializable
data class RelaySendResponseDto(val ok: Boolean = false, val sentSaved: Boolean = false, val warning: String = "")

/** The 409 body /api/mail/send returns when recipients have no usable PGP key. Both PGP refusals
 *  are 409 and are told apart by which field is present, never by status or error prose — the
 *  prose is user-facing copy and may be reworded. */
@Serializable
data class RelayPickupFallbackDto(
    val error: String = "",
    val keylessRecipients: List<String> = emptyList(),
    val pickupFallbackAvailable: Boolean = false,
)
