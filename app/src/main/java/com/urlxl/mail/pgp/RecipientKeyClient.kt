package com.urlxl.mail.pgp

import com.urlxl.mail.executeSync
import com.urlxl.mail.pairingAuthHeaders
import com.urlxl.mail.pairingHttpClient
import com.urlxl.mail.push.pairingEndpoint
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

/**
 * Outcome of the recipient-key preflight.
 *
 * [Failed] is deliberately distinct from `Success(emptyList())`: a failed lookup must never read
 * as "everyone has a key", which would let the compose screen imply an encrypted send it knows
 * nothing about.
 */
sealed class RecipientKeyResult {
    /** [keyless] holds the addresses with no usable key **in the user's contacts**. This is a
     *  lower bound, not a prediction: the send path additionally runs WKD and keyserver discovery,
     *  so an address listed here may still be encrypted to successfully. Use it to warn, never to
     *  promise — the server's 409 is the real gate. */
    data class Success(val keyless: List<String>) : RecipientKeyResult()

    data class Failed(val message: String) : RecipientKeyResult()
}

@Serializable
private data class RecipientCheckRequestDto(val addresses: List<String>)

/** `revoked`, `expired` and `tier` are parsed but unused: the server already folds revoked and
 *  expired into [hasKey], and `tier` drives the web UI's per-recipient badges. They are declared
 *  only to document the shape — do not re-derive keyless from them. */
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

/**
 * Asks which recipients have a usable PGP key, via `POST /api/pgp/recipients/check`.
 *
 * **Not a replacement for [RecipientResolveClient], and not replaced by it.** This endpoint is the
 * cheap, contacts-only, no-network preflight behind the inline "no key on file" warning, and it
 * serves *both* send paths. `/api/pgp/recipients/resolve` hands back actual key material and runs
 * the full WKD and keyserver ladder; it is only meaningful when this device does the encrypting.
 *
 * An earlier revision of this comment said `/resolve` "refuses with 409 for any account that is not
 * client-protected — which is every account that can send encrypted from this app". The first half
 * is still true; the second stopped being true when the device enrollment ceremony gave this app the
 * account's private key, so a client-custody account can now encrypt here and `/resolve` is exactly
 * the right call for it.
 *
 * Kept parallel to [PgpQrClient]: same device-header auth, same injectable [Call.Factory].
 */
class RecipientKeyClient(
    private val json: Json = Json { ignoreUnknownKeys = true },
    // Call.Factory (not the concrete OkHttpClient) so tests can inject a fake without a real
    // network call or a MockWebServer dependency; OkHttpClient itself satisfies this interface.
    private val callFactory: Call.Factory = pairingHttpClient(),
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
