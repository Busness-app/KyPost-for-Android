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

/** [usable] already folds in revocation and expiry — do not re-derive it from [tier]. */
data class ResolvedRecipientKey(
    val address: String,
    val publicKey: String,
    val fingerprint: String,
    val tier: String,
    val usable: Boolean,
)

sealed class ResolveResult {
    data class Success(val results: List<ResolvedRecipientKey>) : ResolveResult()

    /** 409 — the account is not client-protected, so the server encrypts on its own and this
     *  endpoint is categorically the wrong one. No retry from this device changes it. */
    object NotClientProtected : ResolveResult()

    /** 413 — more addresses than the server's per-send cap. */
    data class TooMany(val message: String) : ResolveResult()

    data class Failed(val message: String) : ResolveResult()
}

@Serializable
private data class ResolveRequestDto(val addresses: List<String>)

@Serializable
private data class ResolvedKeyDto(
    val address: String = "",
    val publicKey: String = "",
    val fingerprint: String = "",
    val tier: String = "",
    val usable: Boolean = false,
)

@Serializable
private data class ResolveResponseDto(val results: List<ResolvedKeyDto> = emptyList())

@Serializable
private data class ResolveErrorDto(val error: String = "")

/** 200, 409 and 413 are JSON here; 400 and 500 are plain text — do not decode those. */
class RecipientResolveClient(
    private val json: Json = Json { ignoreUnknownKeys = true },
    // Injected Call.Factory; see PairingAuthHeaders.kt for why every credentialed client takes one.
    private val callFactory: Call.Factory,
) {
    suspend fun resolve(
        serverUrl: String,
        deviceId: String,
        deviceSecret: String,
        addresses: List<String>,
    ): ResolveResult {
        // No addresses is a local answer, not a round trip.
        if (addresses.isEmpty()) return ResolveResult.Success(emptyList())
        val url = pairingEndpoint(serverUrl, "/api/pgp/recipients/resolve")
            ?: return ResolveResult.Failed("Server URL is not valid")
        val payload = json.encodeToString(ResolveRequestDto(addresses))
        val request = Request.Builder().url(url).post(payload.toRequestBody(JSON_MEDIA_TYPE))
            .pairingAuthHeaders(deviceId, deviceSecret)
            .build()

        val result = withContext(Dispatchers.IO) {
            callFactory.executeSync(request) { response -> response.code to response.body?.string().orEmpty() }
        }
        val (code, rawBody) = result.getOrNull()
            ?: return ResolveResult.Failed(result.exceptionOrNull()?.message ?: "Network error")

        return when (code) {
            200 -> runCatching { json.decodeFromString<ResolveResponseDto>(rawBody) }.getOrNull()
                ?.let { parsed ->
                    ResolveResult.Success(
                        parsed.results.map {
                            ResolvedRecipientKey(
                                address = it.address,
                                publicKey = it.publicKey,
                                fingerprint = it.fingerprint,
                                tier = it.tier,
                                usable = it.usable,
                            )
                        },
                    )
                }
                ?: ResolveResult.Failed("Malformed recipient key response")

            409 -> ResolveResult.NotClientProtected
            413 -> ResolveResult.TooMany(errorMessage(rawBody) ?: "Too many recipients")
            else -> ResolveResult.Failed("Recipient key lookup failed ($code)")
        }
    }

    private fun errorMessage(rawBody: String): String? =
        runCatching { json.decodeFromString<ResolveErrorDto>(rawBody).error }.getOrNull()?.takeIf { it.isNotBlank() }
}
