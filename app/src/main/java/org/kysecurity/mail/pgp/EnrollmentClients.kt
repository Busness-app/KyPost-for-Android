package org.kysecurity.mail.pgp

import org.kysecurity.mail.executeSync
import org.kysecurity.mail.pairingAuthHeaders
import org.kysecurity.mail.push.pairingEndpoint
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
private data class PublishEnrollmentKeyRequest(@SerialName("publicKey") val publicKey: String)

@Serializable
private data class EnrollmentStateRequest(@SerialName("encryptionEnrolled") val encryptionEnrolled: Boolean)

@Serializable
private data class DeviceEnvelopeResponse(@SerialName("envelope") val envelope: String? = null)

internal sealed class EnrollmentCallResult {
    object Ok : EnrollmentCallResult()
    data class Envelope(val envelope: String) : EnrollmentCallResult()
    /** 404 covers both "never sealed" and "expired" — indistinguishable by design, and both mean
     *  re-run the ceremony. One result so a caller cannot accidentally split them. */
    object NotFound : EnrollmentCallResult()
    object Unauthorized : EnrollmentCallResult()
    data class RateLimited(val retryAfterSeconds: Long?) : EnrollmentCallResult()
    data class Failed(val message: String) : EnrollmentCallResult()
}

/**
 * The three device-authenticated enrollment calls.
 *
 * Endpoints are built from the paired origin, never from a server-supplied URL — the same rule
 * `PgpKeyActivity.renderQr` follows, and for the same reason: a tampered response must not be able
 * to point an authenticated call at another host, outside the TLS pin.
 *
 * JSON goes through kotlinx.serialization, not `org.json`. Under this module's
 * `isReturnDefaultValues = true`, `org.json` resolves to the stubbed `android.jar` in unit tests and
 * every call returns a default — so a client built on it parses nothing, encodes nothing, and its
 * tests still pass. That trap already cost this plan one green-but-empty suite in `DeviceEnvelope`.
 */
internal class EnrollmentClients(
    // Call.Factory (not the concrete OkHttpClient) so tests can inject a fake without a real network
    // call or a MockWebServer dependency. Mirrors MfaResponseClient.
    //
    private val callFactory: Call.Factory,
    private val json: Json = Json { ignoreUnknownKeys = true },
) {

    suspend fun publishKey(
        serverUrl: String,
        deviceId: String,
        deviceSecret: String,
        encodedPublicKey: String,
    ): EnrollmentCallResult {
        val body = json.encodeToString(PublishEnrollmentKeyRequest(encodedPublicKey))
        return call(serverUrl, "/api/pgp/device/enrollment-key", deviceId, deviceSecret, body) {
            EnrollmentCallResult.Ok
        }
    }

    suspend fun fetchEnvelope(
        serverUrl: String,
        deviceId: String,
        deviceSecret: String,
    ): EnrollmentCallResult =
        // No slot parameter: the server builds it from the verified credential, and a test there
        // asserts a ?slot= query is ignored so the route cannot quietly grow one.
        call(serverUrl, "/api/pgp/device/envelope", deviceId, deviceSecret, body = null) { raw ->
            val envelope = runCatching { json.decodeFromString<DeviceEnvelopeResponse>(raw).envelope }.getOrNull()
            if (envelope.isNullOrBlank()) EnrollmentCallResult.Failed("Malformed envelope response")
            else EnrollmentCallResult.Envelope(envelope)
        }

    suspend fun reportState(
        serverUrl: String,
        deviceId: String,
        deviceSecret: String,
        enrolled: Boolean,
    ): EnrollmentCallResult {
        // Always written explicitly. This route requires the field — unlike the tri-state pointer
        // on registration, an absent value here is a 400, not "no opinion".
        val body = json.encodeToString(EnrollmentStateRequest(enrolled))
        return call(serverUrl, "/api/pgp/device/enrollment-state", deviceId, deviceSecret, body) {
            EnrollmentCallResult.Ok
        }
    }

    private suspend fun call(
        serverUrl: String,
        path: String,
        deviceId: String,
        deviceSecret: String,
        body: String?,
        onSuccess: (String) -> EnrollmentCallResult,
    ): EnrollmentCallResult {
        val url = pairingEndpoint(serverUrl, path)
            ?: return EnrollmentCallResult.Failed("Server URL is not valid")
        val request = Request.Builder()
            .url(url)
            .apply { if (body == null) get() else post(body.toRequestBody(JSON_MEDIA_TYPE)) }
            .pairingAuthHeaders(deviceId, deviceSecret)
            .build()

        val result = withContext(Dispatchers.IO) {
            callFactory.executeSync(request) { response ->
                Triple(response.code, response.body?.string().orEmpty(), response.header("Retry-After"))
            }
        }
        val (code, raw, retryAfter) = result.getOrNull()
            ?: return EnrollmentCallResult.Failed(result.exceptionOrNull()?.message ?: "Request failed")

        return when (code) {
            200 -> onSuccess(raw)
            401 -> EnrollmentCallResult.Unauthorized
            404 -> EnrollmentCallResult.NotFound
            429 -> EnrollmentCallResult.RateLimited(retryAfter?.toLongOrNull())
            else -> EnrollmentCallResult.Failed("Request failed ($code)")
        }
    }
}
