package com.urlxl.mail.mail

import com.urlxl.mail.Email
import com.urlxl.mail.data.EmailDao
import com.urlxl.mail.data.toEntity
import com.urlxl.mail.data.toUiEmail

/**
 * Uses relay [MailSource] exclusively. Writes fetch results into the Room cache (the UI's read model —
 * see data/EmailDao's replaceFolderSnapshot) and exposes the actions InboxActivity/EmailDetailActivity/
 * ComposeActivity call instead of instantiating sources directly.
 */
class MailRepository(
    private val emailDao: EmailDao,
    private val relaySource: MailSource,
) {
    /** Cached rows for [folder], available immediately (e.g. a fast cold-start render). */
    fun cachedEmails(folder: String): List<Email> = emailDao.getByFolder(folder).map { it.toUiEmail() }

    /**
     * Fetches from relay source, reconciles into the Room cache, and returns the outcome.
     * [forceFullResync] requests since=0 on the relay source (see [MailSource.fetchInbox]) —
     * pass true for a user-initiated manual refresh; the daily self-heal cadence otherwise
     * applies automatically inside [RelayMailSource] regardless of this flag.
     */
    fun refreshFolder(folder: String, limit: Int = 50, forceFullResync: Boolean = false): MailOutcome<MailFetchResult> {
        val outcome = relaySource.fetchInbox(folder, limit, forceFullResync)
        if (outcome is MailOutcome.Success) {
            reconcileFetchResult(emailDao, folder, "relay", outcome.value)
        }
        return outcome
    }

    fun markRead(id: String, folder: String): MailOutcome<Unit> {
        emailDao.updateStatus(id, "read")
        val outcome = relaySource.performAction(MailAction.READ, listOf(id), folder)
        return outcome.toUnitOutcome()
    }

    fun archive(id: String, folder: String): MailOutcome<Unit> = mutate(MailAction.ARCHIVE, id, folder)

    fun spam(id: String, folder: String): MailOutcome<Unit> = mutate(MailAction.SPAM, id, folder)

    fun delete(id: String, folder: String): MailOutcome<Unit> = mutate(MailAction.DELETE, id, folder)

    fun move(id: String, folder: String, targetFolder: String): MailOutcome<Unit> {
        val outcome = relaySource.performAction(MailAction.MOVE, listOf(id), folder, targetFolder)
        if (outcome is MailOutcome.Success) emailDao.deleteById(id)
        return outcome.toUnitOutcome()
    }

    private fun mutate(action: MailAction, id: String, folder: String): MailOutcome<Unit> {
        val outcome = relaySource.performAction(action, listOf(id), folder)
        if (outcome is MailOutcome.Success) emailDao.deleteById(id)
        return outcome.toUnitOutcome()
    }

    fun send(draft: MailDraft): MailOutcome<MailSendOutcome> = relaySource.sendMail(draft)

    fun listFolders(parent: String?): MailOutcome<FolderListResult> = relaySource.listFolders(parent)

    fun listAttachments(id: String, folder: String): MailOutcome<List<AttachmentInfo>> =
        relaySource.listAttachments(id, folder)

    fun downloadAttachment(id: String, folder: String, index: Int): MailOutcome<DownloadedAttachment> =
        relaySource.downloadAttachment(id, folder, index)

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
    fun fetchBody(id: String, folder: String): MailOutcome<MailMessageBody> {
        val cached = emailDao.getBody(id)
        if (!cached.isNullOrBlank()) {
            return MailOutcome.Success(MailMessageBody(html = cached, toAddresses = emptyList(), ccAddresses = emptyList()))
        }
        if (emailDao.getById(id) != null) {
            return MailOutcome.Success(MailMessageBody(html = "", toAddresses = emptyList(), ccAddresses = emptyList()))
        }
        return relaySource.fetchMessageBody(id, folder)
    }
}

/**
 * Reconciles one fetch outcome into [emailDao]: a full snapshot (isDelta=false) replaces the
 * folder wholesale as before; a delta upserts "new" entries, merges "updated" entries into the
 * existing row while preserving its body/preview (Mobile_Mail_Relay.md Part 5 — "updated" entries
 * never carry a body), and deletes `removed` ids. Kept as a standalone function, independent of
 * [MailSettings]/Context, so it's testable in a plain JVM unit test.
 */
internal fun reconcileFetchResult(emailDao: EmailDao, folder: String, mode: String, result: MailFetchResult) {
    if (!result.isDelta) {
        emailDao.replaceFolderSnapshot(folder, result.messages.map { it.toEntity(folder, mode) })
        return
    }
    val (updated, new) = result.messages.partition { it.id in result.updatedMessageIds }
    val newEntities = new.map { it.toEntity(folder, mode) }
    // An "updated" entry never carries a body. With an existing row we merge, preserving the body we
    // already have. With NO existing row there is nothing to merge into, and storing the entry as-is
    // created a row whose empty body was indistinguishable from a client-protected message — so the
    // detail view claimed end-to-end encryption for mail the server had decrypted. Skip it instead:
    // we do not have this message, and a metadata-only delta is not a delivery of it. The next full
    // snapshot (forced daily, see MailCursorStore) brings it in properly.
    val mergedEntities = updated.mapNotNull { email ->
        val incoming = email.toEntity(folder, mode)
        val existing = emailDao.getById(incoming.messageId) ?: return@mapNotNull null
        incoming.copy(body = existing.body, preview = existing.preview)
    }
    emailDao.upsertAll(newEntities + mergedEntities)
    result.removedMessageIds.forEach { emailDao.deleteById(it) }
}

private fun <T> MailOutcome<T>.toUnitOutcome(): MailOutcome<Unit> = when (this) {
    is MailOutcome.Success -> MailOutcome.Success(Unit)
    is MailOutcome.NotConfigured -> this
    is MailOutcome.Unauthorized -> this
    is MailOutcome.ServiceUnavailable -> this
    is MailOutcome.UpstreamFailure -> this
    is MailOutcome.BadRequest -> this
    is MailOutcome.CertificateMismatch -> this
    is MailOutcome.ClientSideNeeded -> this
    is MailOutcome.RateLimited -> this
}
