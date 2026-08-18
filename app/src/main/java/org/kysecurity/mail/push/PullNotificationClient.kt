package org.kysecurity.mail.push

import org.kysecurity.mail.executeSync
import org.kysecurity.mail.pairingAuthHeaders
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import okhttp3.Call
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import okhttp3.Request

/** Outcome of a single GET against the pull endpoint. */
sealed class PullResult {
    /** 200 with a parsed body. */
    data class Success(val response: PullNotificationsResponse) : PullResult()

    /** 401: bad secret / unknown device. Credentials are wrong — stop hammering. */
    data class Unauthorized(val message: String) : PullResult()

    /** 400: missing pairing credentials. A client bug; don't tight-loop. */
    data class BadRequest(val message: String) : PullResult()

    /**
     * Transient: 5xx (incl. 503 "server pairing not configured") or a network error.
     * [retryAfterSeconds] carries the Retry-After header when present.
     */
    data class Retryable(val message: String, val retryAfterSeconds: Long? = null) : PullResult()
}

/**
 * Talks to `GET <pullEndpoint>?after=`. Auth is sent as X-Kypost-Device-Id/
 * X-Kypost-Device-Secret headers, never query params. Kept parallel to
 * [NativeRegistrationClient] — same okhttp/serialization stack, no session/bearer.
 */
class PullNotificationClient(
    private val json: Json = Json { ignoreUnknownKeys = true },
    // Injected Call.Factory; see PairingAuthHeaders.kt for why every credentialed client takes one.
    // Mirrors RelayMailSource/ContactSyncClient/GroupsSyncClient/PgpQrClient's callFactory pattern.
    private val callFactory: Call.Factory,
) {
    suspend fun pull(
        pullEndpoint: String,
        deviceId: String,
        deviceSecret: String,
        afterCursor: Long,
    ): PullResult {
        val base = pullEndpoint.takeIf { pairingUrlHost(it) != null }?.toHttpUrlOrNull()
            ?: return PullResult.BadRequest("Pull endpoint is not a valid URL")

        val url = base.newBuilder()
            .addQueryParameter("after", afterCursor.coerceAtLeast(0L).toString())
            .build()

        val httpRequest = Request.Builder().url(url).get()
            .pairingAuthHeaders(deviceId, deviceSecret)
            .build()

        val result = withContext(Dispatchers.IO) {
            callFactory.executeSync(httpRequest) { response ->
                Triple(response.code, response.body?.string().orEmpty(), response.header("Retry-After"))
            }
        }
        val (code, rawBody, retryAfter) = result.getOrNull()
            ?: return PullResult.Retryable(
                message = result.exceptionOrNull()?.message ?: "Network error while pulling",
            )

        return when (code) {
            200 -> {
                val body = runCatching { json.decodeFromString<PullNotificationsResponse>(rawBody) }.getOrNull()
                    ?: return PullResult.Retryable("Malformed pull response")
                PullResult.Success(body)
            }
            400 -> PullResult.BadRequest("Missing pairing credentials")
            401 -> PullResult.Unauthorized("Bad secret or unknown device")
            else -> PullResult.Retryable(
                message = "Pull failed ($code)",
                retryAfterSeconds = parseRetryAfterSeconds(retryAfter),
            )
        }
    }

    companion object {
        /** Retry-After may be delta-seconds; ignore HTTP-date form (uncommon for our server). */
        fun parseRetryAfterSeconds(value: String?): Long? =
            value?.trim()?.toLongOrNull()?.takeIf { it >= 0 }
    }
}
