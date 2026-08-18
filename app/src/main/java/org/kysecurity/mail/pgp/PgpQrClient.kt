package org.kysecurity.mail.pgp

import org.kysecurity.mail.executeSync
import org.kysecurity.mail.pairingAuthHeaders
import org.kysecurity.mail.push.pairingEndpoint
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import okhttp3.Call
import okhttp3.Request

/** Outcome of `GET /api/pgp/qr/token` (pairing-authenticated via X-Kypost-Device-Id/X-Kypost-Device-Secret headers). */
sealed class PgpQrTokenResult {
    data class Success(val token: PgpQrTokenDto) : PgpQrTokenResult()

    /** 400: caller has no PGP identity configured yet. There is no in-app fix — generating a PGP
     *  identity is a web-session-only action on the backend, so callers should point the user to
     *  the web app rather than any in-app settings screen. */
    data class NoIdentity(val message: String) : PgpQrTokenResult()

    /** 401: bad secret / unknown device. */
    data class Unauthorized(val message: String) : PgpQrTokenResult()

    /** 503: server's pairing subsystem isn't configured — a persistent ops issue, not something a
     *  client-side retry will resolve. */
    data class ServiceUnavailable(val message: String) : PgpQrTokenResult()

    /** Malformed body, network error, or any other unexpected status. */
    data class Retryable(val message: String) : PgpQrTokenResult()
}

/** Outcome of `GET /api/pgp/qr/key` (unauthenticated; the token itself is the credential). */
sealed class PgpQrKeyResult {
    data class Success(val key: PgpQrKeyDto) : PgpQrKeyResult()

    /** 403: token is invalid, expired, or has a tampered/mismatched signature. */
    data class Forbidden(val message: String) : PgpQrKeyResult()

    /** 404: the token owner has no PGP identity configured. */
    data class NotFound(val message: String) : PgpQrKeyResult()

    /** 503: server's pairing subsystem isn't configured — persistent, don't auto-retry. */
    data class ServiceUnavailable(val message: String) : PgpQrKeyResult()

    /** Malformed body, network error, or any other unexpected status. */
    data class Retryable(val message: String) : PgpQrKeyResult()
}

/**
 * Talks to the backend's PGP QR key-exchange endpoints. `mintToken` is pairing-authenticated
 * exactly like every other endpoint this app calls (X-Kypost-Device-Id/X-Kypost-Device-Secret
 * headers, never a session cookie — this app has no session-cookie concept). `fetchKey` is
 * unauthenticated; the token itself is the credential. Kept parallel to
 * [org.kysecurity.mail.contacts.ContactSyncClient] — same okhttp/serialization stack and
 * status-code-to-result mapping shape.
 */
class PgpQrClient(
    private val json: Json = Json { ignoreUnknownKeys = true },
    // Call.Factory (not the concrete OkHttpClient) so tests can inject a fake without a real
    // network call or a MockWebServer dependency; OkHttpClient itself satisfies this interface.
    private val callFactory: Call.Factory,
) {
    suspend fun mintToken(serverUrl: String, deviceId: String, deviceSecret: String): PgpQrTokenResult {
        val base = tokenUrl(serverUrl) ?: return PgpQrTokenResult.Retryable("Server URL is not valid")
        val request = Request.Builder().url(base).get()
            .pairingAuthHeaders(deviceId, deviceSecret)
            .build()

        val result = executeRequest(request)
        val (code, rawBody) = result.getOrNull()
            ?: return PgpQrTokenResult.Retryable(
                result.exceptionOrNull()?.message ?: "PGP QR token mint failed: network error",
            )

        return when (code) {
            200 -> runCatching { json.decodeFromString<PgpQrTokenDto>(rawBody) }.getOrNull()
                ?.let { PgpQrTokenResult.Success(it) }
                ?: PgpQrTokenResult.Retryable("Malformed PGP QR token response")
            400 -> PgpQrTokenResult.NoIdentity(rawBody.ifBlank { "No PGP identity configured yet" })
            401 -> PgpQrTokenResult.Unauthorized("Bad secret or unknown device")
            503 -> PgpQrTokenResult.ServiceUnavailable("PGP key exchange is not configured on the backend")
            else -> PgpQrTokenResult.Retryable("PGP QR token mint failed ($code)")
        }
    }

    suspend fun fetchKey(serverUrl: String, token: String): PgpQrKeyResult {
        val base = keyUrl(serverUrl) ?: return PgpQrKeyResult.Retryable("Server URL is not valid")
        val url = base.newBuilder().addQueryParameter("t", token).build()

        val result = executeRequest(Request.Builder().url(url).get().build())
        val (code, rawBody) = result.getOrNull()
            ?: return PgpQrKeyResult.Retryable(
                result.exceptionOrNull()?.message ?: "PGP key fetch failed: network error",
            )

        return when (code) {
            200 -> runCatching { json.decodeFromString<PgpQrKeyDto>(rawBody) }.getOrNull()
                ?.let { PgpQrKeyResult.Success(it) }
                ?: PgpQrKeyResult.Retryable("Malformed PGP key response")
            403 -> PgpQrKeyResult.Forbidden("Token expired or invalid")
            404 -> PgpQrKeyResult.NotFound("This person hasn't set up PGP encryption yet")
            503 -> PgpQrKeyResult.ServiceUnavailable("PGP key exchange is not configured on the backend")
            else -> PgpQrKeyResult.Retryable("PGP key fetch failed ($code)")
        }
    }

    private fun tokenUrl(serverUrl: String) = pairingEndpoint(serverUrl, "/api/pgp/qr/token")

    private fun keyUrl(serverUrl: String) = pairingEndpoint(serverUrl, "/api/pgp/qr/key")

    private suspend fun executeRequest(request: Request): Result<Pair<Int, String>> = withContext(Dispatchers.IO) {
        callFactory.executeSync(request) { response -> response.code to response.body?.string().orEmpty() }
    }
}
