package org.kysecurity.mail.contacts

import org.kysecurity.mail.executeSync
import org.kysecurity.mail.pairingAuthHeaders
import org.kysecurity.mail.push.pairingEndpoint
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import okhttp3.Call
import okhttp3.Request

sealed class GroupsSyncResult {
    data class Success(val groups: List<GroupDto>) : GroupsSyncResult()
    data class Unauthorized(val message: String) : GroupsSyncResult()
    data class BadRequest(val message: String) : GroupsSyncResult()
    data class ServiceUnavailable(val message: String) : GroupsSyncResult()
    data class Retryable(val message: String) : GroupsSyncResult()
}

// Pull-only: group creation (POST /api/groups) is out of scope for this client.
class GroupsSyncClient(
    private val json: Json = Json { ignoreUnknownKeys = true },
    private val callFactory: Call.Factory,
) {
    suspend fun pull(serverUrl: String, deviceId: String, deviceSecret: String): GroupsSyncResult {
        val base = groupsUrl(serverUrl) ?: return GroupsSyncResult.BadRequest("Server URL is not valid")
        val request = Request.Builder().url(base).get()
            .pairingAuthHeaders(deviceId, deviceSecret)
            .build()

        val result = withContext(Dispatchers.IO) {
            callFactory.executeSync(request) { response -> response.code to response.body?.string().orEmpty() }
        }
        val (code, rawBody) = result.getOrNull()
            ?: return GroupsSyncResult.Retryable(result.exceptionOrNull()?.message ?: "Groups sync failed: network error")

        return when (code) {
            200 -> {
                val decoded = runCatching { json.decodeFromString<GroupsListResponseDto>(rawBody) }.getOrNull()
                decoded?.let { GroupsSyncResult.Success(it.groups) } ?: GroupsSyncResult.Retryable("Malformed groups sync response")
            }
            400 -> GroupsSyncResult.BadRequest(rawBody.ifBlank { "Malformed request" })
            401 -> GroupsSyncResult.Unauthorized("Bad secret or unknown device")
            503 -> GroupsSyncResult.ServiceUnavailable("Groups sync is not configured on the backend")
            else -> GroupsSyncResult.Retryable("Groups sync failed ($code)")
        }
    }

    private fun groupsUrl(serverUrl: String) = pairingEndpoint(serverUrl, "/api/groups")
}
