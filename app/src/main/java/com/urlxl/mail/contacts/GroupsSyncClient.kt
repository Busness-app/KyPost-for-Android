package com.urlxl.mail.contacts

import com.urlxl.mail.executeSync
import com.urlxl.mail.pairingAuthHeaders
import com.urlxl.mail.pairingHttpClient
import com.urlxl.mail.push.pairingEndpoint
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

/**
 * Talks to `GET /api/groups`. Pull-only (there is no delta cursor — the caller always fetches
 * the full list and full-refreshes its local cache), mirroring [ContactSyncClient]'s X-Kypost-Device-Id/X-Kypost-Device-Secret
 * header auth and HTTP-status-to-result mapping, minus the push/dedupe endpoints this
 * client has no need for. Two-way group *creation* sync (`POST /api/groups`) is out of scope for
 * this client — see `Client_Contact_Update.md` Part 2 point 3.
 */
class GroupsSyncClient(
    private val json: Json = Json { ignoreUnknownKeys = true },
    private val callFactory: Call.Factory = pairingHttpClient(),
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
