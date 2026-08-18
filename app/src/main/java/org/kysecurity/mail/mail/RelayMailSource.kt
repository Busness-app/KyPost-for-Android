package org.kysecurity.mail.mail

import org.kysecurity.mail.Email
import org.kysecurity.mail.executeSync
import org.kysecurity.mail.pairingAuthHeaders
import org.kysecurity.mail.pairingHttpClient
import org.kysecurity.mail.pgp.OUTER_PLACEHOLDER_SUBJECT
import org.kysecurity.mail.push.PairingData
import org.kysecurity.mail.push.pairingUrlHost
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import okhttp3.Call
import okhttp3.HttpUrl
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.io.IOException

private val JSON_MEDIA_TYPE = "application/json".toMediaType()
private const val NOT_CONFIGURED_PREFIX = "imap configuration is required"
private const val FULL_RESYNC_SINCE = "0"
private const val CHANGE_TYPE_UPDATED = "updated"
private const val HEADER_RETRY_AFTER = "Retry-After"

/** Matches the JSON field the backend sets alongside its 409 on /api/mail/send, not the prose
 *  of the error message — the message is user-facing copy and may be reworded, the field is the
 *  contract. */
private const val CLIENT_SIDE_NEEDED_MARKER = "clientSideNeeded"

/** Named rather than a 5-tuple because [downloadAttachment] destructures it positionally and a
 *  Triple-of-Pairs made the call site unreadable once Retry-After joined it. */
private data class DownloadResponse(
    val code: Int,
    val bytes: ByteArray,
    val name: String,
    val contentType: String,
    val retryAfter: String?,
)

/** Retry-After is seconds or an HTTP date (RFC 9110); this server sends seconds
 *  (wkd_ratelimit.go, device_auth.go). A date form, a negative value, or garbage all yield null,
 *  which callers render as a generic "try again later" — never as "retry now". */
internal fun parseRetryAfterSeconds(header: String?): Long? =
    header?.trim()?.toLongOrNull()?.takeIf { it >= 0 }

/**
 * Talks to the six relay endpoints in Mobile_Mail_Relay.md. Blocking by design to match
 * [MailSource]'s synchronous interface — callers already run on a background executor thread.
 * Auth is sent as X-Kypost-Device-Id/X-Kypost-Device-Secret headers, sourced from the
 * pairing state (never query params/cookies).
 */
class RelayMailSource(
    private val pairingProvider: () -> PairingData?,
    private val cursorProvider: MailCursorProvider,
    private val json: Json = Json { ignoreUnknownKeys = true },
    /**
     * Call.Factory (not the concrete OkHttpClient) so tests can inject a fake without a real
     * network call or a MockWebServer dependency; OkHttpClient itself satisfies this interface.
     *
     * **In production this is a [org.kysecurity.mail.push.PinnedOrFallbackCallFactory]**, which
     * re-reads the TLS pin per request and refuses outright once a pin that existed has gone. It
     * used to be a plain unpinned client plus a separate `pinnedCallFactory: () -> Call.Factory?`
     * that this class null-coalesced against — so the mail endpoints, which carry every message
     * body and this device's credential, fell back to bare system-CA trust for any reason the pin
     * could not be read, silently and permanently. There is one factory now and it owns that
     * decision; see [org.kysecurity.mail.push.TlsPinState].
     */
    private val callFactory: Call.Factory = pairingHttpClient(),
) : MailSource {

    private fun effectiveCallFactory(): Call.Factory = callFactory

    /** Attaches this device's own pairing credentials. A missing deviceId/deviceSecret (not yet
     *  registered) sends blank headers, which the server rejects with 401 — surfaced through the
     *  same [mapErrorCode] path as any other bad credential, rather than a special-cased result. */
    private fun Request.Builder.authed(pairing: PairingData): Request.Builder =
        pairingAuthHeaders(pairing.deviceId.orEmpty(), pairing.deviceSecret.orEmpty())

    override fun fetchInbox(mailbox: String, limit: Int, forceFullResync: Boolean): MailOutcome<MailFetchResult> {
        val pairing = pairingProvider() ?: return MailOutcome.Unauthorized("Device is not paired")
        val base = baseUrl(pairing, "/api/inbox") ?: return MailOutcome.BadRequest("Server URL is not valid")
        val since = sinceValue(pairing.subscriberId, mailbox, forceFullResync)
        val url = base.newBuilder()
            .addQueryParameter("limit", limit.toString())
            .addQueryParameter("mailbox", mailbox)
            .addQueryParameter("since", since)
            .build()
        val request = Request.Builder().url(url).get()
            .authed(pairing)
            .build()
        return execute(request) { code, body ->
            if (code != 200) return@execute mapErrorCode(code, body)
            val parsed = runCatching { json.decodeFromString<RelayInboxResponseDto>(body) }.getOrNull()
                ?: return@execute MailOutcome.UpstreamFailure("Malformed inbox response")
            if (parsed.cursor.isNotBlank()) {
                cursorProvider.saveCursor(pairing.subscriberId, mailbox, parsed.cursor)
            }
            if (since == FULL_RESYNC_SINCE) {
                cursorProvider.recordFullResync(pairing.subscriberId, mailbox)
            }
            // changeType is the source of truth for new-vs-updated, never whether `since` was sent
            // (Mobile_Mail_Relay.md Part 5) — read it straight off each entry, not derived state.
            val entries = parsed.byTab.flatMap { (tab, emails) -> emails.map { it.toUiEmail(tab) to it.changeType } }
            MailOutcome.Success(
                MailFetchResult(
                    tabs = parsed.tabs,
                    messages = entries.map { it.first },
                    isDelta = parsed.delta,
                    updatedMessageIds = entries.filter { it.second == CHANGE_TYPE_UPDATED }.map { it.first.id }.toSet(),
                    removedMessageIds = parsed.removed,
                    isFullWindow = since == FULL_RESYNC_SINCE,
                ),
            )
        }
    }

    /** since=0 when forced (explicitly, or the daily self-heal cadence is due), or no cursor is
     *  persisted yet (fresh pairing) — otherwise the persisted cursor (Mobile_Mail_Relay.md Part 5). */
    private fun sinceValue(subscriberId: String, folder: String, forceFullResync: Boolean): String {
        val forced = forceFullResync || cursorProvider.shouldForceFullResync(subscriberId, folder)
        return if (forced) FULL_RESYNC_SINCE else cursorProvider.cursor(subscriberId, folder) ?: FULL_RESYNC_SINCE
    }

    override fun listFolders(parent: String?): MailOutcome<FolderListResult> {
        val pairing = pairingProvider() ?: return MailOutcome.Unauthorized("Device is not paired")
        val base = baseUrl(pairing, "/api/inbox/folders") ?: return MailOutcome.BadRequest("Server URL is not valid")
        val urlBuilder = base.newBuilder()
        if (!parent.isNullOrBlank()) urlBuilder.addQueryParameter("parent", parent)
        val request = Request.Builder().url(urlBuilder.build()).get()
            .authed(pairing)
            .build()
        return execute(request) { code, body ->
            if (code != 200) return@execute mapErrorCode(code, body)
            val parsed = runCatching { json.decodeFromString<RelayFolderListResponseDto>(body) }.getOrNull()
                ?: return@execute MailOutcome.UpstreamFailure("Malformed folder list response")
            MailOutcome.Success(
                FolderListResult(parent = parsed.parent, folders = parsed.folders.map { FolderInfo(it.path, it.deletable) }),
            )
        }
    }

    override fun createFolder(parent: String, name: String): MailOutcome<Unit> {
        val pairing = pairingProvider() ?: return MailOutcome.Unauthorized("Device is not paired")
        val base = baseUrl(pairing, "/api/inbox/folders") ?: return MailOutcome.BadRequest("Server URL is not valid")
        val body = json.encodeToString(RelayFolderCreateRequestDto(parent = parent, name = name))
        val request = Request.Builder().url(base).post(body.toRequestBody(JSON_MEDIA_TYPE))
            .authed(pairing)
            .build()
        return execute(request) { code, rawBody -> mutationOutcome(code, rawBody) }
    }

    override fun renameFolder(folder: String, name: String): MailOutcome<Unit> {
        val pairing = pairingProvider() ?: return MailOutcome.Unauthorized("Device is not paired")
        val base = baseUrl(pairing, "/api/inbox/folders") ?: return MailOutcome.BadRequest("Server URL is not valid")
        val body = json.encodeToString(RelayFolderRenameRequestDto(folder = folder, name = name))
        val request = Request.Builder().url(base).put(body.toRequestBody(JSON_MEDIA_TYPE))
            .authed(pairing)
            .build()
        return execute(request) { code, rawBody -> mutationOutcome(code, rawBody) }
    }

    override fun deleteFolder(folder: String): MailOutcome<Unit> {
        val pairing = pairingProvider() ?: return MailOutcome.Unauthorized("Device is not paired")
        val base = baseUrl(pairing, "/api/inbox/folders") ?: return MailOutcome.BadRequest("Server URL is not valid")
        val url = base.newBuilder().addQueryParameter("folder", folder).build()
        val request = Request.Builder().url(url).delete()
            .authed(pairing)
            .build()
        return execute(request) { code, rawBody -> mutationOutcome(code, rawBody) }
    }

    override fun performAction(
        action: MailAction,
        messageIds: List<String>,
        mailbox: String,
        targetMailbox: String?,
    ): MailOutcome<MailActionOutcome> {
        val pairing = pairingProvider() ?: return MailOutcome.Unauthorized("Device is not paired")
        val base = baseUrl(pairing, "/api/inbox/actions") ?: return MailOutcome.BadRequest("Server URL is not valid")
        val requestDto = RelayActionRequestDto(
            action = action.wireValue(),
            messageIds = messageIds,
            mailbox = mailbox,
            targetMailbox = targetMailbox,
        )
        val body = json.encodeToString(requestDto)
        val request = Request.Builder().url(base).post(body.toRequestBody(JSON_MEDIA_TYPE))
            .authed(pairing)
            .build()
        return execute(request) { code, rawBody ->
            if (code != 200) return@execute mapErrorCode(code, rawBody)
            val parsed = runCatching { json.decodeFromString<RelayActionResponseDto>(rawBody) }.getOrNull()
                ?: return@execute MailOutcome.UpstreamFailure("Malformed action response")
            // ok:false with a non-empty failed[] is still a partial success — processed ids already
            // took effect (Mobile_Mail_Relay.md Part 2's explicit callout).
            MailOutcome.Success(
                MailActionOutcome(processed = parsed.processed, failed = parsed.failed.map { it.messageId to it.error }),
            )
        }
    }

    override fun saveDraft(draft: MailDraft): MailOutcome<Unit> {
        val pairing = pairingProvider() ?: return MailOutcome.Unauthorized("Device is not paired")
        val base = baseUrl(pairing, "/api/mail/draft") ?: return MailOutcome.BadRequest("Server URL is not valid")
        val body = json.encodeToString(draft.toWireDto())
        val request = Request.Builder().url(base).post(body.toRequestBody(JSON_MEDIA_TYPE))
            .authed(pairing)
            .build()
        return execute(request) { code, rawBody -> mutationOutcome(code, rawBody) }
    }

    override fun sendMail(draft: MailDraft): MailOutcome<MailSendOutcome> {
        val pairing = pairingProvider() ?: return MailOutcome.Unauthorized("Device is not paired")
        val base = baseUrl(pairing, "/api/mail/send") ?: return MailOutcome.BadRequest("Server URL is not valid")
        val body = json.encodeToString(draft.toSendWireDto())
        val request = Request.Builder().url(base).post(body.toRequestBody(JSON_MEDIA_TYPE))
            .authed(pairing)
            .build()
        return execute(request) { code, rawBody ->
            if (code != 200) return@execute mapErrorCode(code, rawBody)
            val parsed = runCatching { json.decodeFromString<RelaySendResponseDto>(rawBody) }.getOrNull()
                ?: return@execute MailOutcome.UpstreamFailure("Malformed send response")
            MailOutcome.Success(MailSendOutcome(sentSaved = parsed.sentSaved, warning = parsed.warning))
        }
    }

    /**
     * Relays ciphertext this device already built, via `POST /api/mail/send-pgp`.
     */
    override fun sendClientEncrypted(message: ClientEncryptedMessage): MailOutcome<MailSendOutcome> {
        val pairing = pairingProvider() ?: return MailOutcome.Unauthorized("Device is not paired")
        val base = baseUrl(pairing, "/api/mail/send-pgp")
            ?: return MailOutcome.BadRequest("Server URL is not valid")
        val body = json.encodeToString(
            RelayClientEncryptedRequestDto(
                from = message.from,
                subject = OUTER_PLACEHOLDER_SUBJECT,
                mode = message.mode,
                to = message.to,
                cc = message.cc,
                bcc = message.bcc,
                deliveries = message.deliveries.map {
                    RelayClientEncryptedDeliveryDto(recipients = it.recipients, ciphertext = it.ciphertext)
                },
                sentCopy = message.sentCopy,
                sentCopyEncrypted = true,
            ),
        )
        val request = Request.Builder().url(base).post(body.toRequestBody(JSON_MEDIA_TYPE))
            .authed(pairing)
            .build()
        return execute(request) { code, rawBody ->
            if (code != 200) return@execute mapErrorCode(code, rawBody)
            val parsed = runCatching { json.decodeFromString<RelaySendResponseDto>(rawBody) }.getOrNull()
                ?: return@execute MailOutcome.UpstreamFailure("Malformed send response")
            MailOutcome.Success(MailSendOutcome(sentSaved = parsed.sentSaved, warning = parsed.warning))
        }
    }

    override fun fetchMessageBody(messageId: String, folder: String): MailOutcome<MailMessageBody> {
        // /api/inbox already returns each message's full body inline (Mobile_Mail_Relay.md Part 2)
        // — there is no separate fetch-one-message endpoint. MailRepository.fetchBody serves this
        // from the Room cache instead of calling here; this only runs on an uncached cache miss.
        return MailOutcome.BadRequest("Relay mode has no separate message-body endpoint")
    }

    override fun listAttachments(messageId: String, folder: String): MailOutcome<List<AttachmentInfo>> {
        val pairing = pairingProvider() ?: return MailOutcome.Unauthorized("Device is not paired")
        val base = baseUrl(pairing, "/api/mail/attachments") ?: return MailOutcome.BadRequest("Server URL is not valid")
        val url = base.newBuilder()
            .addQueryParameter("mailbox", folder)
            .addQueryParameter("messageId", messageId)
            .build()
        val request = Request.Builder().url(url).get()
            .authed(pairing)
            .build()
        return execute(request) { code, body ->
            if (code != 200) return@execute mapErrorCode(code, body)
            val parsed = runCatching { json.decodeFromString<RelayAttachmentListResponseDto>(body) }.getOrNull()
                ?: return@execute MailOutcome.UpstreamFailure("Malformed attachment list response")
            MailOutcome.Success(parsed.attachments.map { AttachmentInfo(it.index, it.name, it.mimeType, it.size) })
        }
    }

    override fun downloadAttachment(messageId: String, folder: String, index: Int): MailOutcome<DownloadedAttachment> {
        val pairing = pairingProvider() ?: return MailOutcome.Unauthorized("Device is not paired")
        val base = baseUrl(pairing, "/api/mail/attachment") ?: return MailOutcome.BadRequest("Server URL is not valid")
        val url = base.newBuilder()
            .addQueryParameter("mailbox", folder)
            .addQueryParameter("messageId", messageId)
            .addQueryParameter("index", index.toString())
            .build()
        val request = Request.Builder().url(url).get()
            .authed(pairing)
            .build()
        // Binary response: read bytes and metadata headers inside the use block, not execute()'s
        // string() path.
        val result = effectiveCallFactory().executeSync(request) { response ->
            DownloadResponse(
                code = response.code,
                // Bounded read. `bytes()` materialises the whole body, and the advertised `size`
                // from the attachment listing was never enforced, so a relay could advertise a
                // kilobyte and stream hundreds of megabytes into the heap. Mirrors the 25MB
                // outbound cap in ComposeActivity, and matches the server's own message limit.
                bytes = response.body?.let { readBounded(it, MAX_ATTACHMENT_DOWNLOAD_BYTES) } ?: ByteArray(0),
                name = filenameFromDisposition(response.header("Content-Disposition")),
                contentType = response.header("Content-Type") ?: "application/octet-stream",
                retryAfter = response.header(HEADER_RETRY_AFTER),
            )
        }
        val downloadException = result.exceptionOrNull()
        if (downloadException is javax.net.ssl.SSLPeerUnverifiedException) {
            return MailOutcome.CertificateMismatch(downloadException.message ?: "Certificate pin mismatch")
        }
        val (code, bytes, name, contentType, retryAfter) = result.getOrNull()
            ?: return MailOutcome.UpstreamFailure(downloadException?.message ?: "Network error")
        if (code == 429) return rateLimited(bytes.toString(Charsets.UTF_8), retryAfter)
        if (code != 200) return mapErrorCode(code, bytes.toString(Charsets.UTF_8))
        return MailOutcome.Success(DownloadedAttachment(name = name.ifBlank { "attachment" }, mimeType = contentType.substringBefore(';').trim(), bytes = bytes))
    }

    private fun <T> rateLimited(rawBody: String, retryAfter: String?): MailOutcome<T> =
        MailOutcome.RateLimited(
            message = rawBody.ifBlank { "Too many requests" },
            retryAfterSeconds = parseRetryAfterSeconds(retryAfter),
        )

    private fun mutationOutcome(code: Int, rawBody: String): MailOutcome<Unit> =
        if (code == 200) MailOutcome.Success(Unit) else mapErrorCode(code, rawBody)

    // 429 is deliberately absent here: it needs the Retry-After header, which this signature
    // can't see, so it is short-circuited in [execute] and [downloadAttachment] instead.
    private fun <T> mapErrorCode(code: Int, rawBody: String): MailOutcome<T> = when (code) {
        400 -> if (rawBody.contains(NOT_CONFIGURED_PREFIX, ignoreCase = true)) {
            MailOutcome.NotConfigured(rawBody)
        } else {
            MailOutcome.BadRequest(rawBody.ifBlank { "Malformed request" })
        }
        401 -> MailOutcome.Unauthorized("Bad secret or unknown device")
        // Plain text, and the prose is the whole value: it names an unauthorized From, which is the
        // one thing the user can act on. Without this branch it fell through to the generic
        // "Mail relay request failed (403)" and the sentence was discarded — for every endpoint,
        // not just the client-encrypted send that surfaced it.
        403 -> MailOutcome.BadRequest(rawBody.ifBlank { "Refused" })
        // Two PGP refusals share this status. clientSideNeeded is checked first to match the
        // server's own precedence: a client-custody account cannot encrypt server-side at all, so
        // its keyless recipients are beside the point and a pickup dialog would be nonsense.
        409 -> when {
            rawBody.contains(CLIENT_SIDE_NEEDED_MARKER, ignoreCase = true) ->
                MailOutcome.ClientSideNeeded(rawBody)
            else -> {
                val parsed = runCatching { json.decodeFromString<RelayPickupFallbackDto>(rawBody) }.getOrNull()
                if (parsed != null && parsed.keylessRecipients.isNotEmpty()) {
                    MailOutcome.PickupFallbackNeeded(parsed.keylessRecipients, parsed.error)
                } else {
                    // Deliberately not rawBody: an unrecognized 409 body is JSON, and raw JSON in
                    // a toast is worse than a generic sentence.
                    MailOutcome.BadRequest("Conflicting request")
                }
            }
        }
        // Plain text, and it distinguishes "SMTP failed" from "every pickup link failed to
        // deliver; nothing was sent" — a distinction a fixed string throws away.
        502 -> MailOutcome.UpstreamFailure(rawBody.ifBlank { "Upstream IMAP/SMTP failure" })
        503 -> MailOutcome.ServiceUnavailable(rawBody.ifBlank { "Mail relay is temporarily unavailable" })
        else -> MailOutcome.UpstreamFailure("Mail relay request failed ($code)")
    }

    private fun <T> execute(request: Request, onResponse: (code: Int, body: String) -> MailOutcome<T>): MailOutcome<T> {
        val result = effectiveCallFactory().executeSync(request) { response ->
            Triple(response.code, response.body?.string().orEmpty(), response.header(HEADER_RETRY_AFTER))
        }
        val exception = result.exceptionOrNull()
        if (exception is javax.net.ssl.SSLPeerUnverifiedException) {
            return MailOutcome.CertificateMismatch(exception.message ?: "Certificate pin mismatch")
        }
        val (code, body, retryAfter) = result.getOrNull()
            ?: return MailOutcome.UpstreamFailure(exception?.message ?: "Network error")
        if (code == 429) return rateLimited(body, retryAfter)
        return onResponse(code, body)
    }

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
    private fun baseUrl(pairing: PairingData, path: String): HttpUrl? {
        if (pairingUrlHost(pairing.serverUrl) == null) return null
        return "${pairing.serverUrl.trimEnd('/')}$path".toHttpUrlOrNull()
    }
}

/** Pulls the filename out of a Content-Disposition header, honoring both the RFC 5987 `filename*`
 *  form and the plain quoted `filename=` form; empty when the header is absent or unparseable. */
/** Same order of magnitude as the outbound cap in `ComposeActivity` and the server's own
 *  `MaxInboundMessageBytes`, so no legitimate attachment is refused. */
private const val MAX_ATTACHMENT_DOWNLOAD_BYTES = 25L * 1024 * 1024

/** Reads at most [limit] bytes, and throws [IOException] if the body had more to give — never
 *  allocating the whole of an oversized body, which is the out-of-memory kill this bound exists to
 *  prevent.
 *
 *  The unit tests could not see it: `FakeCalls.response()` builds a `Buffer`-backed body, and
 *  `Buffer.read` copies `min(byteCount, size)` from itself in one call with no segment limit. The
 *  fake took a fast path that does not exist on a socket, in exactly the dimension under test. See
 *  `RelayMailSourceTest.downloadAttachment_readsBodiesLargerThanOneOkioSegment`, which drives a
 */
internal fun readBounded(body: okhttp3.ResponseBody, limit: Long): ByteArray {
    val source = body.source()
    val buffer = okio.Buffer()
    while (buffer.size < limit) {
        if (source.read(buffer, limit - buffer.size) == -1L) return buffer.readByteArray()
    }
    // Stopped on the bound, not on end-of-stream. One more byte available means the body was larger
    // than the limit and everything read so far is a prefix, not the attachment.
    if (!source.exhausted()) {
        throw IOException("Attachment is larger than the $limit byte download limit")
    }
    return buffer.readByteArray()
}

private fun filenameFromDisposition(header: String?): String {
    if (header.isNullOrBlank()) return ""
    Regex("filename\\*=(?:UTF-8'')?\"?([^\";]+)\"?", RegexOption.IGNORE_CASE).find(header)?.let {
        return runCatching { java.net.URLDecoder.decode(it.groupValues[1], "UTF-8") }.getOrDefault(it.groupValues[1])
    }
    Regex("filename=\"?([^\";]+)\"?", RegexOption.IGNORE_CASE).find(header)?.let {
        return it.groupValues[1]
    }
    return ""
}

private fun MailAction.wireValue(): String = when (this) {
    MailAction.DELETE -> "delete"
    MailAction.ARCHIVE -> "archive"
    MailAction.SPAM -> "spam"
    MailAction.READ -> "read"
    MailAction.MOVE -> "move"
}

private fun MailDraft.toWireDto(): RelayMailRequestDto =
    RelayMailRequestDto(
        to = to,
        cc = cc,
        bcc = bcc,
        subject = subject,
        body = body,
        mode = mode,
        attachments = attachments.map { RelayAttachmentDto(name = it.name, mimeType = it.mimeType, dataBase64 = it.dataBase64) },
    )

/** Send-only mapping. [toWireDto] stays flagless because /api/mail/draft ignores these fields —
 *  see [MailDraft.allowPickupFallback]. */
private fun MailDraft.toSendWireDto(): RelayMailRequestDto =
    toWireDto().copy(sign = sign, encrypt = encrypt, allowPickupFallback = allowPickupFallback)

private fun RelayEmailDto.toUiEmail(tab: String): Email {
    val emailLabel = label.ifBlank { tab }
    return Email(
        id = messageId,
        subject = subject,
        sender = sender,
        preview = body.orEmpty().take(140),
        // Union of the wire keywords and the tab-derived label, not a
        // replacement: the label is what the keyword tabs filter on
        // (KeywordTabs), while the wire list is what carries server-set
        // keywords like the $Phishing anti-phishing flag. Dropping either
        // breaks one of the two.
        keywords = (keywords + emailLabel).filter { it.isNotBlank() }.toSet(),
        sentTo = sentTo,
        cc = cc,
        bcc = bcc,
        body = body,
        bodyMode = bodyMode,
        label = emailLabel,
        status = status,
        atUtc = atUtc,
        hasAttachments = hasAttachments,
        sourceMode = "relay",
        pgpEncrypted = pgpEncrypted,
        pgpSigned = pgpSigned,
        pgpVerified = pgpVerified,
        pgpSignerFingerprint = pgpSignerFingerprint,
        pgpDecryptError = pgpDecryptError,
    )
}
