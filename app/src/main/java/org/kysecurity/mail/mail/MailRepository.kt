package org.kysecurity.mail.mail

import org.kysecurity.mail.Email
import org.kysecurity.mail.splitAddresses
import org.kysecurity.mail.data.EmailDao
import org.kysecurity.mail.data.toEntity
import org.kysecurity.mail.data.toUiEmail

/** The one synchronization boundary: [MailSource] returns facts, this decides when they — and the
 *  checkpoint that skips them next time — become durable. */
class MailRepository(
    private val emailDao: EmailDao,
    private val relaySource: MailSource,
    private val cursorProvider: MailCursorProvider,
) {
    fun cachedEmails(folder: String): List<Email> = emailDao.getByFolder(folder).map { it.toUiEmail() }

    /** [forceFullResync] asks for since=0; the daily self-heal runs regardless of this flag. */
    fun refreshFolder(folder: String, limit: Int = 50, forceFullResync: Boolean = false): MailOutcome<MailFetchResult> {
        val outcome = relaySource.fetchInbox(folder, limit, forceFullResync)
        if (outcome is MailOutcome.Success) {
            // Order is the whole point: Room first, checkpoint second. Room and DataStore cannot
            // share a transaction, so a crash between them replays this window — upserts and
            // deletes are idempotent — whereas the old order dropped it.
            reconcileFetchResult(emailDao, folder, "relay", outcome.value)
            commitCheckpoint(folder, outcome.value.checkpoint)
        }
        return outcome
    }

    private fun commitCheckpoint(folder: String, checkpoint: MailCheckpoint?) {
        if (checkpoint == null) return
        if (checkpoint.cursor.isNotBlank()) {
            cursorProvider.saveCursor(checkpoint.subscriberId, folder, checkpoint.cursor)
        }
        if (checkpoint.wasFullResync) {
            cursorProvider.recordFullResync(checkpoint.subscriberId, folder)
        }
    }

    /** Server first, cache second. An optimistic local "read" bought nothing — the caller already
     *  runs on a background thread and shows the message regardless — and left the row lying about
     *  a state the server never reached. */
    fun markRead(id: String, folder: String): MailOutcome<Unit> {
        val outcome = relaySource.performAction(MailAction.READ, listOf(id), folder).appliedTo(id)
        if (outcome is MailOutcome.Success) emailDao.updateStatus(id, folder, "read")
        return outcome
    }

    fun archive(id: String, folder: String): MailOutcome<Unit> = mutate(MailAction.ARCHIVE, id, folder)

    fun spam(id: String, folder: String): MailOutcome<Unit> = mutate(MailAction.SPAM, id, folder)

    fun delete(id: String, folder: String): MailOutcome<Unit> = mutate(MailAction.DELETE, id, folder)

    fun move(id: String, folder: String, targetFolder: String): MailOutcome<Unit> =
        mutate(MailAction.MOVE, id, folder, targetFolder)

    /** The local row goes only when the relay says this id was processed — the message is gone from
     *  [folder] either way (deleted, or now living in another mailbox). */
    private fun mutate(
        action: MailAction,
        id: String,
        folder: String,
        targetFolder: String? = null,
    ): MailOutcome<Unit> {
        val outcome = relaySource.performAction(action, listOf(id), folder, targetFolder).appliedTo(id)
        if (outcome is MailOutcome.Success) emailDao.deleteById(id, folder)
        return outcome
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

    // "No row" must not look like an empty body: empty + pgpEncrypted is the client-protected
    // shape, and a blank body must NOT be re-routed to the relay — /api/inbox carries the body
    // inline, `fetchMessageBody` is a hard-fail stub, and its failure means BODY_UNAVAILABLE,
    // which would erase the client-protected state and its webmail handoff. See `fetchBody` tests.
    fun fetchBody(id: String, folder: String): MailOutcome<MailMessageBody> {
        val row = emailDao.getById(id, folder) ?: return relaySource.fetchMessageBody(id, folder)
        return MailOutcome.Success(
            MailMessageBody(
                html = row.body?.takeIf { it.isNotBlank() }.orEmpty(),
                bodyMode = row.bodyMode,
                // The cache is the only source of these: no relay response ever populates them, so
                // dropping them here is what makes Reply All reply to the sender alone.
                toAddresses = splitAddresses(row.sentTo),
                ccAddresses = splitAddresses(row.cc),
            ),
        )
    }
}

/** HTTP 200 is transport success, not operation success: `/api/inbox/actions` answers 200 with the
 *  requested id in `failed[]` (Mobile_Mail_Relay.md Part 2). Only an id the relay actually
 *  processed may be applied to the local cache. */
internal fun MailOutcome<MailActionOutcome>.appliedTo(id: String): MailOutcome<Unit> {
    if (this !is MailOutcome.Success) return toUnitOutcome()
    value.failed.firstOrNull { it.first == id }?.let { return MailOutcome.ActionRejected(id, it.second) }
    // `processed` is a count, not a list, so this is as close to "the id is in processed" as the
    // wire shape allows. Unknown counts as rejected: keeping a row the server may still hold costs
    // a redundant line in the list, whereas the other way round deletes mail that never moved.
    if (value.processed < 1) return MailOutcome.ActionRejected(id, "The server reported no change")
    return MailOutcome.Success(Unit)
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
        val existing = emailDao.getById(incoming.messageId, folder) ?: return@mapNotNull null
        incoming.copy(
            body = existing.body,
            preview = existing.preview,
            bodyMode = incoming.bodyMode.ifBlank { existing.bodyMode },
        )
    }
    emailDao.applyFolderDelta(
        folder = folder,
        upserts = newEntities + mergedEntities,
        removedIds = result.removedMessageIds,
        // Only a full window can say what is absent; cursor deltas omit unchanged mail and must not prune.
        pruneKeepIds = result.messages.map { it.id }.takeIf { result.isFullWindow },
    )
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
    is MailOutcome.ActionRejected -> this
    is MailOutcome.RateLimited -> this
}
