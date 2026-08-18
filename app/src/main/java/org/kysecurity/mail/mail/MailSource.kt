package org.kysecurity.mail.mail

import org.kysecurity.mail.Email

sealed class MailOutcome<out T> {
    data class Success<T>(val value: T) : MailOutcome<T>()

    /** Relay 400 "imap configuration is required*" — direct the user to the web app, never a form. */
    data class NotConfigured(val message: String) : MailOutcome<Nothing>()

    /** Relay/pairing 401 — re-pair the device. */
    data class Unauthorized(val message: String) : MailOutcome<Nothing>()

    /** Relay 503 (either flavor: no PAIRING_SECRET, or IMAP client unavailable). */
    data class ServiceUnavailable(val message: String) : MailOutcome<Nothing>()

    /** Relay 502 upstream IMAP/SMTP failure — safe to retry with backoff. */
    data class UpstreamFailure(val message: String) : MailOutcome<Nothing>()

    /** Any other 400, or a local validation failure. */
    data class BadRequest(val message: String) : MailOutcome<Nothing>()

    /** TLS certificate didn't match the pin captured at pairing time — could be a legitimate
     *  cert rotation on the user's own server, or an active MITM; either way, do not silently
     *  fall back to trusting it. */
    data class CertificateMismatch(val message: String) : MailOutcome<Nothing>()

    /** Relay 409 on /api/mail/send with `clientSideNeeded` — the account's PGP key is
     *  end-to-end protected, so the server refuses to sign or encrypt on its behalf rather
     *  than silently sending in the clear. This app holds no private key, so the only ways
     *  forward are sending unencrypted or using webmail. Distinct from [BadRequest] because
     *  nothing about the request was malformed. */
    data class ClientSideNeeded(val message: String) : MailOutcome<Nothing>()

    /** Relay 409 on /api/mail/send carrying `keylessRecipients` — one or more recipients have no
     *  usable PGP key, and the server refused rather than quietly falling back to a one-time link
     *  that stores this message's plaintext on the server for seven days. **Nothing was
     *  delivered:** the refusal happens before any SMTP, so re-sending the same draft with
     *  [MailDraft.allowPickupFallback] once the user has confirmed is safe and cannot duplicate. */
    data class PickupFallbackNeeded(
        val keylessRecipients: List<String>,
        val message: String,
    ) : MailOutcome<Nothing>()

    /** Relay 429 with Retry-After — the server's per-device lockout after repeated bad
     *  credentials. [retryAfterSeconds] is null when the header was absent or unparseable;
     *  callers should still back off rather than retrying immediately. */
    data class RateLimited(val message: String, val retryAfterSeconds: Long?) : MailOutcome<Nothing>()
}

/** Wording tailored per failure kind, per Mobile_Mail_Relay.md's error table — never auto-clears
 *  pairing on 401/503, only points the user at the places that would (Settings/PushPairingActivity). */
fun MailOutcome<*>.userFacingMessage(): String? = when (this) {
    is MailOutcome.Success -> null
    is MailOutcome.NotConfigured -> "Set up your mail account on the web app first"
    is MailOutcome.Unauthorized -> "Device pairing expired or invalid — re-pair this device in Settings"
    is MailOutcome.ServiceUnavailable -> "Mail relay is unavailable: $message"
    is MailOutcome.UpstreamFailure -> "Couldn't reach the mail server: $message"
    is MailOutcome.BadRequest -> message
    is MailOutcome.CertificateMismatch -> "This server's certificate has changed since pairing — clear pairing and re-pair in Settings if you expect this (e.g. you rotated your server's certificate)"
    is MailOutcome.ClientSideNeeded -> "This account's PGP key is end-to-end protected, so signing and encryption aren't available on mobile. Send without them, or use webmail."
    is MailOutcome.PickupFallbackNeeded ->
        "No PGP key on file for ${keylessRecipients.joinToString(", ")} — nothing was sent."
    is MailOutcome.RateLimited -> retryAfterSeconds
        ?.let { "Too many failed attempts — try again in ${formatRetryAfter(it)}" }
        ?: "Too many failed attempts — try again later"
}

/** Whole minutes once past a minute, because a Retry-After of 900 read as "900 seconds" is
 *  not something a user can act on. */
internal fun formatRetryAfter(seconds: Long): String = when {
    seconds < 60 -> "$seconds seconds"
    seconds < 120 -> "a minute"
    else -> "${seconds / 60} minutes"
}

data class MailFetchResult(
    val tabs: List<String>,
    val messages: List<Email>,
    // The rest only matter when isDelta is true (Mobile_Mail_Relay.md Part 5 v2); a false/default
    // value means `messages` is a full snapshot, exactly like the pre-delta response shape.
    val isDelta: Boolean = false,
    val updatedMessageIds: Set<String> = emptySet(),
    val removedMessageIds: List<String> = emptyList(),
    // True when this response describes the server's entire window rather than just what changed
    // (i.e. we sent since=0). A relay predating the matching server fix labels such a response
    // `delta: true` all the same, so this — not the wire flag — is what tells us `messages` is
    // complete enough to prune the folder against. See [reconcileFetchResult], which needs it to
    // self-heal a removal we were never told about.
    val isFullWindow: Boolean = false,
)
data class FolderInfo(val path: String, val deletable: Boolean)
data class FolderListResult(val parent: String, val folders: List<FolderInfo>)

enum class MailAction { DELETE, ARCHIVE, SPAM, READ, MOVE }

data class MailActionOutcome(val processed: Int, val failed: List<Pair<String, String>>)

data class MailDraft(
    val to: String,
    val cc: String = "",
    val bcc: String = "",
    val subject: String,
    val body: String,
    val mode: String = "plain",
    val attachments: List<OutgoingAttachment> = emptyList(),
    /** Server-side PGP signing. Requires the account to have a PGP identity; the relay answers
     *  400 (plain text) if asked to sign without one. */
    val sign: Boolean = false,
    /** Server-side PGP encryption. */
    val encrypt: Boolean = false,
    /** Opt in to the one-time pickup link for recipients with no usable key. Meaningful only when
     *  [encrypt] is true, and only ever set after the user confirmed the dialog naming them: the
     *  fallback stores this message's plaintext on the server, unencrypted, for up to seven days.
     *  Per-message by design — never persisted as a preference. */
    val allowPickupFallback: Boolean = false,
) {
    /** Redacted: the body is the user's outgoing message. Enforced by `SourceRulesTest`. */
    override fun toString(): String = "MailDraft(redacted)"
}

/** An attachment the user picked to send: raw base64 payload plus display metadata. */
data class OutgoingAttachment(
    val name: String,
    val mimeType: String,
    val dataBase64: String,
    val size: Int,
)

data class MailSendOutcome(val sentSaved: Boolean, val warning: String)

/** One pre-built PGP/MIME message and the SMTP recipients it goes to. */
data class ClientEncryptedDelivery(val recipients: List<String>, val ciphertext: String)

/**
 * A send whose PGP work already happened on this device, for `POST /api/mail/send-pgp`.
 *
 * [deliveries] is a list rather than one message because each BCC recipient needs their own
 * ciphertext — a shared one puts every BCC recipient's key id where the others can read it.
 *
 * [to]/[cc]/[bcc] stay in the clear deliberately: SMTP needs them, they are already the envelope,
 * and the Sent listing is unusable without them. Only the body and the real subject are protected.
 */
data class ClientEncryptedMessage(
    val from: String,
    val to: List<String>,
    val cc: List<String>,
    val bcc: List<String>,
    val deliveries: List<ClientEncryptedDelivery>,
    /** The same message encrypted to the sender's own key. Never a plaintext body: the server
     *  refuses an unencrypted copy, and storing one would hand back in the clear exactly what the
     *  deliveries were protecting. */
    val sentCopy: String,
    val mode: String = "html",
)

data class MailMessageBody(
    val html: String,
    val bodyMode: String = "",
    val toAddresses: List<String>,
    val ccAddresses: List<String>,
) {
    /** Redacted: the html is message content. Enforced by `SourceRulesTest`. */
    override fun toString(): String = "MailMessageBody(redacted)"
}

/** One received attachment's metadata (no content), from GET /api/mail/attachments. */
data class AttachmentInfo(val index: Int, val name: String, val mimeType: String, val size: Int)

/** A downloaded attachment's bytes plus the metadata needed to save it. */
/**
 * **Not a `data class`.** The generated `equals`/`hashCode` would compare [bytes] by identity while
 * looking structural, so a `Set<DownloadedAttachment>` or an `==` would silently never match — and
 * these are the values a de-duplicating forward cache is most likely to be built over.
 */
class DownloadedAttachment(val name: String, val mimeType: String, val bytes: ByteArray)

/**
 * Blocking (non-suspend) by design: callers already run on a background executor thread,
 * so there is no need to introduce coroutines into the mail path just for this abstraction.
 */
interface MailSource {
    /** [forceFullResync] requests since=0 (full re-fetch reported in delta shape) regardless of
     *  any persisted cursor — the documented self-heal for a missed removal notification. */
    fun fetchInbox(mailbox: String, limit: Int, forceFullResync: Boolean = false): MailOutcome<MailFetchResult>
    fun listFolders(parent: String?): MailOutcome<FolderListResult>
    fun createFolder(parent: String, name: String): MailOutcome<Unit>
    fun renameFolder(folder: String, name: String): MailOutcome<Unit>
    fun deleteFolder(folder: String): MailOutcome<Unit>
    fun performAction(
        action: MailAction,
        messageIds: List<String>,
        mailbox: String,
        targetMailbox: String? = null,
    ): MailOutcome<MailActionOutcome>
    fun saveDraft(draft: MailDraft): MailOutcome<Unit>
    fun sendMail(draft: MailDraft): MailOutcome<MailSendOutcome>

    /** Relays ciphertext this device already built. Separate from [sendMail] rather than a flag on
     *  it: the request body, the endpoint and the failure modes all differ, and the two must not be
     *  able to drift into each other. */
    fun sendClientEncrypted(message: ClientEncryptedMessage): MailOutcome<MailSendOutcome>
    fun fetchMessageBody(messageId: String, folder: String): MailOutcome<MailMessageBody>
    fun listAttachments(messageId: String, folder: String): MailOutcome<List<AttachmentInfo>>
    fun downloadAttachment(messageId: String, folder: String, index: Int): MailOutcome<DownloadedAttachment>
}
