package org.kysecurity.mail.push

import org.kysecurity.mail.executeSync
import org.kysecurity.mail.pairingAuthHeaders
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import okhttp3.Call
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody

private val JSON_MEDIA_TYPE = "application/json".toMediaType()
private val EMPTY_JSON_BODY = "{}".toRequestBody(JSON_MEDIA_TYPE)

@Serializable
data class DeregisterResponse(
    @SerialName("ok") val ok: Boolean = false,
)

/** Mirrors [resolvePullEndpoint]/[resolveMfaRespondEndpoint] — always derived from the paired server URL. */
fun resolveDeregisterEndpoint(serverUrl: String): String =
    pairingEndpoint(serverUrl, "/api/notifications/native/deregister")?.toString().orEmpty()

sealed class DeregisterResult {
    object Success : DeregisterResult()
    data class Error(val message: String) : DeregisterResult()
}

/** [residue] is account-scoped data that survived the unpair purge; non-empty means the device
 *  must be wiped rather than left pairable, or the next account can read what is left. */
data class UnpairOutcome(val deregister: DeregisterResult, val residue: List<String>) {
    val cleanupIncomplete: Boolean get() = residue.isNotEmpty()
}

/** `POST /api/notifications/native/deregister` using device credentials, no session cookie. */
class DeregisterClient(
    private val json: Json = Json { ignoreUnknownKeys = true },
    // Injected Call.Factory; see PairingAuthHeaders.kt for why every credentialed client takes one.
    private val callFactory: Call.Factory,
) {
    suspend fun deregister(pairing: PairingData): DeregisterResult {
        val deviceId = pairing.deviceId
        val deviceSecret = pairing.deviceSecret
        if (deviceId.isNullOrBlank() || deviceSecret.isNullOrBlank()) {
            return DeregisterResult.Error("Device is not registered")
        }
        val endpoint = resolveDeregisterEndpoint(pairing.serverUrl)
        if (endpoint.isBlank()) return DeregisterResult.Error("Server URL is not valid")

        val httpRequest = Request.Builder()
            .url(endpoint)
            .post(EMPTY_JSON_BODY)
            .pairingAuthHeaders(deviceId, deviceSecret)
            .build()

        val result = withContext(Dispatchers.IO) {
            callFactory.executeSync(httpRequest) { response -> response.code to response.body?.string().orEmpty() }
        }
        val (code, rawBody) = result.getOrNull()
            ?: return DeregisterResult.Error(result.exceptionOrNull()?.message ?: "Failed to reach server")

        return when (code) {
            200 -> {
                val body = runCatching { json.decodeFromString<DeregisterResponse>(rawBody) }.getOrNull()
                if (body?.ok == true) DeregisterResult.Success else DeregisterResult.Error("Server did not confirm removal")
            }
            401 -> DeregisterResult.Error("Device credentials already invalid")
            else -> DeregisterResult.Error("Failed to unpair ($code)")
        }
    }
}
