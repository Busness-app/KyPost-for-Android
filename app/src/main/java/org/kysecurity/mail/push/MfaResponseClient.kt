package org.kysecurity.mail.push

import org.kysecurity.mail.executeSync
import org.kysecurity.mail.pairingAuthHeaders
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import okhttp3.Call
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody

private val JSON_MEDIA_TYPE = "application/json".toMediaType()

@Serializable
data class MfaRespondRequest(
    @SerialName("challengeId") val challengeId: String,
    @SerialName("approve") val approve: Boolean,
    /** The server verifies this; the on-device comparison is UX, not the control. */
    @SerialName("matchDigits") val matchDigits: String,
)

@Serializable
data class MfaRespondResponse(
    @SerialName("ok") val ok: Boolean = false,
    @SerialName("status") val status: String? = null,
    @SerialName("error") val error: String? = null,
)

/** Mirrors [resolvePullEndpoint] in NativeRegistration.kt — the respond endpoint has no server-provided override, it's always derived from the paired server URL. */
fun resolveMfaRespondEndpoint(serverUrl: String): String =
    pairingEndpoint(serverUrl, "/api/mfa/push/respond")?.toString().orEmpty()

sealed class MfaRespondResult {
    data class Success(val status: String) : MfaRespondResult()
    data class Error(val message: String) : MfaRespondResult()
}

class MfaResponseClient(
    private val json: Json = Json { ignoreUnknownKeys = true },
    // Injected Call.Factory; see PairingAuthHeaders.kt for why every credentialed client takes one.
    private val callFactory: Call.Factory,
) {
    suspend fun respond(
        pairing: PairingData,
        challengeId: String,
        approve: Boolean,
        matchDigits: String = "",
    ): MfaRespondResult {
        val deviceId = pairing.deviceId
        val deviceSecret = pairing.deviceSecret
        if (deviceId.isNullOrBlank() || deviceSecret.isNullOrBlank()) {
            return MfaRespondResult.Error("Device is not registered yet")
        }
        val endpoint = resolveMfaRespondEndpoint(pairing.serverUrl)
        if (endpoint.isBlank()) return MfaRespondResult.Error("Server URL is not valid")

        val request = MfaRespondRequest(
            challengeId = challengeId,
            approve = approve,
            // Never on a deny: the safe answer must not depend on reading a number.
            matchDigits = if (approve) matchDigits else "",
        )
        val httpRequest = Request.Builder()
            .url(endpoint)
            .post(json.encodeToString(request).toRequestBody(JSON_MEDIA_TYPE))
            .pairingAuthHeaders(deviceId, deviceSecret)
            .build()

        val result = withContext(Dispatchers.IO) {
            callFactory.executeSync(httpRequest) { response -> response.code to response.body?.string().orEmpty() }
        }
        val (code, rawBody) = result.getOrNull()
            ?: return MfaRespondResult.Error(result.exceptionOrNull()?.message ?: "Failed to reach server")

        return when (code) {
            200 -> {
                val body = runCatching { json.decodeFromString<MfaRespondResponse>(rawBody) }.getOrNull()
                if (body?.ok == true) {
                    MfaRespondResult.Success(body.status ?: "resolved")
                } else {
                    MfaRespondResult.Error("Server did not confirm response")
                }
            }
            // Still live and credentials fine — a re-prompt, not a re-pair. Prefer the server's wording.
            400 -> MfaRespondResult.Error(serverError(rawBody) ?: "That is not the number shown in the browser")
            401 -> MfaRespondResult.Error("Pairing is no longer valid")
            403 -> MfaRespondResult.Error("This device cannot approve sign-in")
            429 -> MfaRespondResult.Error(serverError(rawBody) ?: "Too many incorrect attempts; start the sign-in again")
            409 -> {
                val body = runCatching { json.decodeFromString<MfaRespondResponse>(rawBody) }.getOrNull()
                MfaRespondResult.Error("Already ${body?.status ?: "resolved"} on another device")
            }
            else -> MfaRespondResult.Error("Failed to respond ($code)")
        }
    }

    /** The server's `error` string, or null when the body is not the shape we expect. Length-capped
     *  because it reaches a Toast. */
    private fun serverError(rawBody: String): String? =
        runCatching { json.decodeFromString<MfaRespondResponse>(rawBody) }
            .getOrNull()
            ?.error
            ?.trim()
            ?.takeIf { it.isNotEmpty() }
            ?.take(200)
}
