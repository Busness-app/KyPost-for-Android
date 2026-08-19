package org.kysecurity.mail.contacts

import org.kysecurity.mail.data.AppDatabase
import org.kysecurity.mail.data.GroupEntity
import org.kysecurity.mail.push.PairingData
import androidx.room.withTransaction

sealed class GroupSyncOutcome {
    object Success : GroupSyncOutcome()
    object NotPaired : GroupSyncOutcome()
    object Unauthorized : GroupSyncOutcome()
    data class ServiceUnavailable(val message: String) : GroupSyncOutcome()
    data class Retry(val message: String) : GroupSyncOutcome()
}

// Full refresh, no delta cursor and no offline queue: the device never creates groups.
class GroupSyncRepository(
    private val db: AppDatabase,
    private val client: GroupsSyncClient,
    private val pairingProvider: suspend () -> PairingData?,
) {
    suspend fun sync(): GroupSyncOutcome {
        val pairing = pairingProvider() ?: return GroupSyncOutcome.NotPaired
        val deviceId = pairing.deviceId
        val deviceSecret = pairing.deviceSecret
        if (deviceId.isNullOrBlank() || deviceSecret.isNullOrBlank()) return GroupSyncOutcome.NotPaired

        return when (val result = client.pull(pairing.serverUrl, deviceId, deviceSecret)) {
            is GroupsSyncResult.Success -> {
                applyFullRefresh(result.groups)
                GroupSyncOutcome.Success
            }
            is GroupsSyncResult.Unauthorized -> GroupSyncOutcome.Unauthorized
            is GroupsSyncResult.ServiceUnavailable -> GroupSyncOutcome.ServiceUnavailable(result.message)
            is GroupsSyncResult.BadRequest -> GroupSyncOutcome.Retry(result.message)
            is GroupsSyncResult.Retryable -> GroupSyncOutcome.Retry(result.message)
        }
    }

    private suspend fun applyFullRefresh(groups: List<GroupDto>) {
        val entities = groups.map { GroupEntity(id = it.id, name = it.name, rev = it.rev) }
        db.withTransaction {
            db.groupDao().upsertAll(entities)
            db.groupDao().deleteNotIn(entities.map { it.id })
        }
    }
}
