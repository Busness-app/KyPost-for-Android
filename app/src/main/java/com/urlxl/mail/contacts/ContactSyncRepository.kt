package com.urlxl.mail.contacts

import com.urlxl.mail.data.AppDatabase
import com.urlxl.mail.data.ContactEntity
import com.urlxl.mail.data.PendingContactChangeEntity
import com.urlxl.mail.push.PairingData
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import java.util.UUID

sealed class ContactSyncOutcome {
    object Success : ContactSyncOutcome()
    object NotPaired : ContactSyncOutcome()
    object Unauthorized : ContactSyncOutcome()
    data class ServiceUnavailable(val message: String) : ContactSyncOutcome()
    data class Retry(val message: String) : ContactSyncOutcome()
}

/** Mirrors [ContactSyncOutcome]'s shape; kept as a parallel type (rather than a variant of
 * [ContactSyncOutcome]) because `Success` here needs to carry the dedupe report. */
sealed class ContactDedupeOutcome {
    data class Success(val report: ContactDedupeReportDto) : ContactDedupeOutcome()
    object NotPaired : ContactDedupeOutcome()
    object Unauthorized : ContactDedupeOutcome()
    data class ServiceUnavailable(val message: String) : ContactDedupeOutcome()
    data class Retry(val message: String) : ContactDedupeOutcome()
}

/**
 * Orchestrates contact sync: decides pull-vs-push based on the offline change queue, applies the
 * server delta (upsert changed, remove deleted, reconcile locally-created uids), and handles
 * tooOld by discarding the cursor and wiping the local cache for a full re-pull.
 */
class ContactSyncRepository(
    private val db: AppDatabase,
    private val client: ContactSyncClient,
    private val cursorStore: ContactCursorStore,
    private val pairingProvider: suspend () -> PairingData?,
) {
    private val json = Json { ignoreUnknownKeys = true }

    /** Guards the whole contacts table against concurrent sync writers: this repository and
     *  [com.urlxl.mail.contacts.device.DeviceContactRepository] run on independent coroutine
     *  scopes with no other ordering between them, and [com.urlxl.mail.data.ContactDao.upsertAll]
     *  replaces whole rows — so an interleaved read-modify-write from one side can silently
     *  overwrite a field (e.g. `isSelf`) the other side just wrote. Held by [sync] here and by
     *  `DeviceContactRepository.syncAll`. */
    val syncMutex = Mutex()

    fun observeContacts(): Flow<List<ContactEntity>> = db.contactDao().observeAll()

    suspend fun sync(): ContactSyncOutcome = syncMutex.withLock {
        val pairing = pairingProvider() ?: return@withLock ContactSyncOutcome.NotPaired
        val deviceId = pairing.deviceId
        val deviceSecret = pairing.deviceSecret
        if (deviceId.isNullOrBlank() || deviceSecret.isNullOrBlank()) return@withLock ContactSyncOutcome.NotPaired
        val pendingChanges = db.pendingContactChangeDao().getAllPending()
        val cursor = cursorStore.cursor(pairing.subscriberId)

        val result = if (pendingChanges.isEmpty()) {
            client.pull(pairing.serverUrl, deviceId, deviceSecret, cursor)
        } else {
            client.push(
                serverUrl = pairing.serverUrl,
                deviceId = deviceId,
                deviceSecret = deviceSecret,
                baseCursor = cursor,
                changes = pendingChanges.map(::toWireDto),
            )
        }

        when (result) {
            is ContactSyncResult.Success -> {
                applyDelta(pairing.subscriberId, result.response, pendingChanges)
                ContactSyncOutcome.Success
            }
            is ContactSyncResult.Unauthorized -> ContactSyncOutcome.Unauthorized
            is ContactSyncResult.ServiceUnavailable -> ContactSyncOutcome.ServiceUnavailable(result.message)
            is ContactSyncResult.BadRequest -> ContactSyncOutcome.Retry(result.message)
            is ContactSyncResult.Retryable -> ContactSyncOutcome.Retry(result.message)
        }
    }

    /**
     * Calls the server-side dedupe endpoint. Deliberately does NOT call [sync] itself — mirrors
     * [sync]'s single-purpose shape; the caller is responsible for triggering a follow-up sync so
     * the merge's tombstones/survivor land locally.
     */
    suspend fun dedupe(): ContactDedupeOutcome = resolveDedupeOutcome(pairingProvider) { pairing ->
        val deviceId = pairing.deviceId
        val deviceSecret = pairing.deviceSecret
        if (deviceId.isNullOrBlank() || deviceSecret.isNullOrBlank()) {
            ContactDedupeResult.Unauthorized("Device is not registered yet")
        } else {
            client.dedupe(pairing.serverUrl, deviceId, deviceSecret)
        }
    }

    /** Creates locally under a temp uid and enqueues the create; reconciled to a server uid on sync. */
    suspend fun queueCreate(contact: ContactDto): String {
        val localUid = UUID.randomUUID().toString()
        val localCopy = contact.copy(uid = localUid)
        db.contactDao().upsertAll(listOf(localCopy.toEntity()))
        db.pendingContactChangeDao().enqueue(
            PendingContactChangeEntity(
                localUid = localUid,
                rev = 0,
                changeType = CHANGE_CREATE,
                payloadJson = json.encodeToString(contact.copy(uid = "")),
                createdAtEpochMs = System.currentTimeMillis(),
            ),
        )
        return localUid
    }

    /**
     * [verifiedInPerson] is passed only by the PGP QR flow, where the user has just compared this
     * fingerprint out-of-band.
     *
     * [identityChanged] has **no default on purpose**. It used to default to false, and the
     * device-contact merge was the only caller that passed it — so every other path (in-app edits,
     * the PGP QR save) silently answered "no, this does not rebind identity" on behalf of a contact
     * that may hold a pinned key. Whether an update moves the identity a key vouches for is a
     * question each call site has to answer for itself; see [com.urlxl.mail.contacts.toEntity].
     */
    suspend fun queueUpdate(
        contact: ContactDto,
        identityChanged: Boolean,
        verifiedInPerson: Boolean = false,
    ) {
        val previous = db.contactDao().getByUid(contact.uid)
        db.contactDao().upsertAll(listOf(contact.toEntity(previous, verifiedInPerson, identityChanged)))
        db.pendingContactChangeDao().enqueue(
            PendingContactChangeEntity(
                localUid = contact.uid,
                rev = contact.rev,
                changeType = CHANGE_UPDATE,
                payloadJson = json.encodeToString(contact),
                createdAtEpochMs = System.currentTimeMillis(),
            ),
        )
    }

    suspend fun queueDelete(uid: String, rev: Long) {
        db.contactDao().deleteByUids(listOf(uid))
        db.pendingContactChangeDao().enqueue(
            PendingContactChangeEntity(
                localUid = uid,
                rev = rev,
                changeType = CHANGE_DELETE,
                payloadJson = "",
                createdAtEpochMs = System.currentTimeMillis(),
            ),
        )
    }

    private fun toWireDto(change: PendingContactChangeEntity): ContactDto = when (change.changeType) {
        CHANGE_DELETE -> ContactDto(uid = change.localUid, rev = change.rev, deleted = true)
        CHANGE_CREATE -> decodePayload(change).copy(uid = "")
        else -> decodePayload(change).copy(uid = change.localUid, rev = change.rev)
    }

    private fun decodePayload(change: PendingContactChangeEntity): ContactDto =
        runCatching { json.decodeFromString<ContactDto>(change.payloadJson) }.getOrDefault(ContactDto())

    private suspend fun applyDelta(
        subscriberId: String,
        response: ContactSyncPullResponseDto,
        flushedChanges: List<PendingContactChangeEntity>,
    ) {
        if (response.tooOld) {
            // Non-destructive: reset the cursor so the next pull starts from 0 and rebuilds the
            // mirror from a full snapshot, but do NOT clear first. Clearing here used to return
            // before clearFlushed below, so the acknowledged pending changes were replayed — and
            // since toWireDto sends an empty uid for a create, the server minted a fresh uid per
            // replay, duplicating the contact on both sides. The server applies pushed changes
            // before it computes tooOld, so they are already persisted and must be flushed.
            cursorStore.resetCursor(subscriberId)
            if (flushedChanges.isNotEmpty()) {
                db.pendingContactChangeDao().clearFlushed(flushedChanges.map { it.id })
            }
            return
        }

        val pendingCreates = flushedChanges.filter { it.changeType == CHANGE_CREATE }
        val reconciled = ContactSyncReconciliation.reconcile(pendingCreates, response.changed)
        if (reconciled.isNotEmpty()) {
            // The device link row keys on uid, so it has to follow this rename. Without it the
            // server-assigned uid looks unlinked, pushRoomChangesToDevice inserts a SECOND raw
            // contact, and the temp-uid link is orphaned forever (getByUid on a dead uid returns
            // null, so pullDeviceChangesForOwnAccount can never reclaim the first row).
            reconciled.forEach { (localUid, serverUid) ->
                db.deviceContactLinkDao().remapUid(localUid, serverUid)
            }
            // Drop the temp-uid rows; the upsert below inserts the real, server-assigned rows.
            db.contactDao().deleteByUids(reconciled.keys.toList())
        }

        val incomingEntities = response.changed.map { dto ->
            dto.toEntity(previous = db.contactDao().getByUid(dto.uid))
        }
        db.contactDao().upsertAll(incomingEntities)
        db.contactDao().deleteByUids(response.deleted.map { it.uid })

        if (flushedChanges.isNotEmpty()) {
            db.pendingContactChangeDao().clearFlushed(flushedChanges.map { it.id })
        }
        cursorStore.advanceCursor(subscriberId, response.cursor)
    }

    companion object {
        const val CHANGE_CREATE = "create"
        const val CHANGE_UPDATE = "update"
        const val CHANGE_DELETE = "delete"
    }
}

/**
 * Decides [ContactSyncRepository.dedupe]'s outcome: [ContactDedupeOutcome.NotPaired] if
 * [pairingProvider] yields no pairing, otherwise delegates to [dedupeCall] and maps its result via
 * [contactDedupeOutcomeOf]. Kept as a standalone function, independent of
 * [ContactSyncRepository]'s `AppDatabase`/`ContactCursorStore` dependencies, so it's testable in a
 * plain JVM unit test — mirrors [com.urlxl.mail.mail.reconcileFetchResult]'s extraction for the
 * same reason.
 */
internal suspend fun resolveDedupeOutcome(
    pairingProvider: suspend () -> PairingData?,
    dedupeCall: suspend (PairingData) -> ContactDedupeResult,
): ContactDedupeOutcome {
    val pairing = pairingProvider() ?: return ContactDedupeOutcome.NotPaired
    return contactDedupeOutcomeOf(dedupeCall(pairing))
}

/** Pure mapping from [ContactDedupeResult] to [ContactDedupeOutcome]; `BadRequest` folds into
 * [ContactDedupeOutcome.Retry], matching how [ContactSyncRepository.sync] folds
 * `ContactSyncResult.BadRequest` into `ContactSyncOutcome.Retry`. */
internal fun contactDedupeOutcomeOf(result: ContactDedupeResult): ContactDedupeOutcome = when (result) {
    is ContactDedupeResult.Success -> ContactDedupeOutcome.Success(result.report)
    is ContactDedupeResult.Unauthorized -> ContactDedupeOutcome.Unauthorized
    is ContactDedupeResult.ServiceUnavailable -> ContactDedupeOutcome.ServiceUnavailable(result.message)
    is ContactDedupeResult.BadRequest -> ContactDedupeOutcome.Retry(result.message)
    is ContactDedupeResult.Retryable -> ContactDedupeOutcome.Retry(result.message)
}
