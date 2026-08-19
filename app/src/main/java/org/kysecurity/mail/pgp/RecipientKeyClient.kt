package org.kysecurity.mail.pgp

import org.kysecurity.mail.executeSync
import org.kysecurity.mail.pairingAuthHeaders
import org.kysecurity.mail.push.pairingEndpoint
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import okhttp3.Call
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody

private val JSON_MEDIA_TYPE = "application/json".toMediaType()

/** [Failed] never means "everyone has a key" — a failed lookup is not `Success(emptyList())`. */
sealed class RecipientKeyResult {
    /** A lower bound from contacts only — the send path also runs WKD/keyserver. Never promise. */
    data class Success(val keyless: List<String>) : RecipientKeyResult()

    data class Failed(val message: String) : RecipientKeyResult()
}

@Serializable
private data class RecipientCheckRequestDto(val addresses: List<String>)

/** `revoked`/`expired`/`tier` are parsed but unused — do not re-derive keyless from them. */
@Serializable
private data class RecipientKeyStatusDto(
    val address: String = "",
    val hasKey: Boolean = false,
    val revoked: Boolean = false,
    val expired: Boolean = false,
    val tier: String = "",
)

@Serializable
private data class RecipientCheckResponseDto(val results: List<RecipientKeyStatusDto> = emptyList())

/** Cheap contacts-only preflight; [RecipientResolveClient] returns actual key material. */
class RecipientKeyClient(
    private val json: Json = Json { ignoreUnknownKeys = true },
    // Injected Call.Factory; see PairingAuthHeaders.kt for why every credentialed client takes one.
    private val callFactory: Call.Factory,
) {
    suspend fun check(
        serverUrl: String,
        deviceId: String,
        deviceSecret: String,
        addresses: List<String>,
    ): RecipientKeyResult {
        // No addresses is a local answer, not a round trip.
        if (addresses.isEmpty()) return RecipientKeyResult.Success(emptyList())
        val url = pairingEndpoint(serverUrl, "/api/pgp/recipients/check")
            ?: return RecipientKeyResult.Failed("Server URL is not valid")
        val payload = json.encodeToString(RecipientCheckRequestDto(addresses))
        val request = Request.Builder().url(url).post(payload.toRequestBody(JSON_MEDIA_TYPE))
            .pairingAuthHeaders(deviceId, deviceSecret)
            .build()

        val result = withContext(Dispatchers.IO) {
            callFactory.executeSync(request) { response -> response.code to response.body?.string().orEmpty() }
        }
        val (code, rawBody) = result.getOrNull()
            ?: return RecipientKeyResult.Failed(result.exceptionOrNull()?.message ?: "Network error")

        // Only 200 is JSON here; every other status returns plain text, so no decoder runs over it.
        if (code != 200) return RecipientKeyResult.Failed("Recipient key check failed ($code)")
        val parsed = runCatching { json.decodeFromString<RecipientCheckResponseDto>(rawBody) }.getOrNull()
            ?: return RecipientKeyResult.Failed("Malformed recipient key response")
        return RecipientKeyResult.Success(parsed.results.filter { !it.hasKey }.map { it.address })
    }
}
