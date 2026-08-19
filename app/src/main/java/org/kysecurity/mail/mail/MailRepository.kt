package org.kysecurity.mail.mail

import org.kysecurity.mail.Email
import org.kysecurity.mail.data.EmailDao
import org.kysecurity.mail.data.toEntity
import org.kysecurity.mail.data.toUiEmail

class MailRepository(
    private val emailDao: EmailDao,
    private val relaySource: MailSource,
) {
    fun cachedEmails(folder: String): List<Email> = emailDao.getByFolder(folder).map { it.toUiEmail() }

    /** [forceFullResync] asks for since=0; the daily self-heal runs regardless of this flag. */
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

    /** The client-custody send: this device already encrypted and signed, the relay only forwards. */
    fun sendClientEncrypted(message: ClientEncryptedMessage): MailOutcome<MailSendOutcome> =
        relaySource.sendClientEncrypted(message)

    /** Used by the client-custody webmail handoff: the composition is parked as a draft so the
     *  browser has something to open. Drafts carry no crypto flags — see [MailDraft]. */
    fun saveDraft(draft: MailDraft): MailOutcome<Unit> = relaySource.saveDraft(draft)

    fun listFolders(parent: String?): MailOutcome<FolderListResult> = relaySource.listFolders(parent)

    fun listAttachments(id: String, folder: String): MailOutcome<List<AttachmentInfo>> =
        relaySource.listAttachments(id, folder)

    fun downloadAttachment(id: String, folder: String, index: Int): MailOutcome<DownloadedAttachment> =
        relaySource.downloadAttachment(id, folder, index)

    // "No row" must not look like an empty body: empty + pgpEncrypted is the client-protected shape.
    fun fetchBody(id: String, folder: String): MailOutcome<MailMessageBody> {
        val cached = emailDao.getBody(id)
        if (!cached.isNullOrBlank()) {
            return MailOutcome.Success(MailMessageBody(html = cached, bodyMode = emailDao.getById(id)?.bodyMode.orEmpty(), toAddresses = emptyList(), ccAddresses = emptyList()))
        }
        if (emailDao.getById(id) != null) {
            return MailOutcome.Success(MailMessageBody(html = "", bodyMode = emailDao.getById(id)?.bodyMode.orEmpty(), toAddresses = emptyList(), ccAddresses = emptyList()))
        }
        return relaySource.fetchMessageBody(id, folder)
    }
}

internal fun reconcileFetchResult(emailDao: EmailDao, folder: String, mode: String, result: MailFetchResult) {
    if (!result.isDelta) {
        emailDao.replaceFolderSnapshot(folder, result.messages.map { it.toEntity(folder, mode) })
        return
    }
    val (updated, new) = result.messages.partition { it.id in result.updatedMessageIds }
    val newEntities = new.map { it.toEntity(folder, mode) }
    // An "updated" entry never carries a body; with no existing row, skip rather than invent one.
    val mergedEntities = updated.mapNotNull { email ->
        val incoming = email.toEntity(folder, mode)
        val existing = emailDao.getById(incoming.messageId) ?: return@mapNotNull null
        incoming.copy(
            body = existing.body,
            preview = existing.preview,
            bodyMode = incoming.bodyMode.ifBlank { existing.bodyMode },
        )
    }
    emailDao.upsertAll(newEntities + mergedEntities)
    result.removedMessageIds.forEach { emailDao.deleteById(it) }
    // Only a full window can say what is absent; cursor deltas omit unchanged mail and must not prune.
    if (result.isFullWindow) {
        emailDao.pruneStaleInFolder(folder, result.messages.map { it.id })
    }
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
    is MailOutcome.PickupFallbackNeeded -> this
    is MailOutcome.RateLimited -> this
}
