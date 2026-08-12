package org.kysecurity.mail.pgp

import org.kysecurity.mail.executeSync
import org.kysecurity.mail.pairingAuthHeaders
import org.kysecurity.mail.pairingHttpClient
import org.kysecurity.mail.push.pairingEndpoint
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import okhttp3.Call
import okhttp3.Request

/**
 * The outcome of asking the relay for one message's OpenPGP payload.
 *
 * The three specific status codes are distinct cases rather than one [Failed], because each gets a
 * different exit-table row and a different sentence to the user. Collapsing them would tell someone
 * whose message is simply too large that the server could not be reached.
 */
internal sealed class PgpPayloadResult {
    data class Success(
        val encryptedPayload: String,
        val signaturePayload: String,
        /** The readable body of a signed-but-not-encrypted message, which the client needs
         *  alongside a detached signature in order to verify it. Empty when encrypted. */
        val body: String,
        /** Already narrowed by the server to [resolvedSender] — see [signatureStateFor]. */
        val signerKeys: List<SignerKey>,
        /** The raw From header as the server re-rendered it. Display only — never bind on it. */
        val sender: String,
        /** The addr-spec the server resolved and narrowed [signerKeys] to. The verdict is about
         *  THIS. Empty when the server could not resolve one, e.g. a multi-mailbox From. */
        val resolvedSender: String,
    ) : PgpPayloadResult()

    /** 409 — this account's key is not client-protected. A bug if it is ever seen here. */
    object NotClientProtected : PgpPayloadResult()

    /** 413 — larger than the server will hold in memory. */
    object TooLarge : PgpPayloadResult()

    /** 404 — no message, or it carries no OpenPGP payload. */
    object NoPayload : PgpPayloadResult()

    data class Failed(val message: String) : PgpPayloadResult()
}

@Serializable
private data class SignerKeyDto(
    val addresses: List<String> = emptyList(),
    val publicKey: String = "",
    // Both are `omitempty` server-side. The Kotlin defaults ARE the contract for an older server,
    // and false is the safe direction for each: it weakens a claim rather than inventing one.
    val verified: Boolean = false,
    val source: String = "",
    val conflict: Boolean = false,
)

/** `messageId` and `mailbox` echo the request and are not read here; the fields this app needs are
 *  the payload, its signature material, and the signer keys already narrowed to the sender. */
@Serializable
private data class PgpPayloadDto(
    val encryptedPayload: String = "",
    val signaturePayload: String = "",
    val body: String = "",
    val signerKeys: List<SignerKeyDto> = emptyList(),
    val sender: String = "",
    val resolvedSender: String = "",
)

private val JSON = Json { ignoreUnknownKeys = true }

/**
 * Reads one message's OpenPGP ciphertext via `GET /api/mail/pgp-payload`. Pairing-authenticated with
 * X-Kypost-Device-Id/X-Kypost-Device-Secret exactly like every other relay call this app makes.
 *
 * Kept parallel to [PgpBootstrapClient] and [RecipientKeyClient]: same injectable [Call.Factory] so
 * tests run without a real network call, same device-header auth.
 */
internal class PgpPayloadClient(
    // Call.Factory (not the concrete OkHttpClient) so tests can inject a fake without a real
    // network call or a MockWebServer dependency; OkHttpClient itself satisfies this interface.
    // Every real caller builds this on the pinned pairing call factory, like every other
    // credentialed request in this app — this default exists for tests only.
    private val callFactory: Call.Factory = pairingHttpClient(),
) {
    suspend fun fetch(
        serverUrl: String,
        deviceId: String,
        deviceSecret: String,
        mailbox: String,
        messageId: String,
    ): PgpPayloadResult {
        val base = pairingEndpoint(serverUrl, "/api/mail/pgp-payload")
            ?: return PgpPayloadResult.Failed("Server URL is not valid")
        val url = base.newBuilder()
            .addQueryParameter("mailbox", mailbox)
            .addQueryParameter("messageId", messageId)
            .build()
        val request = Request.Builder().url(url).get()
            .pairingAuthHeaders(deviceId, deviceSecret)
            .build()

        val result = withContext(Dispatchers.IO) {
            callFactory.executeSync(request) { response -> response.code to response.body?.string().orEmpty() }
        }
        val (code, rawBody) = result.getOrNull()
            ?: return PgpPayloadResult.Failed(result.exceptionOrNull()?.message ?: "Network error")

        return when (code) {
            409 -> PgpPayloadResult.NotClientProtected
            413 -> PgpPayloadResult.TooLarge
            404 -> PgpPayloadResult.NoPayload
            200 -> {
                val parsed = runCatching { JSON.decodeFromString<PgpPayloadDto>(rawBody) }.getOrNull()
                    ?: return PgpPayloadResult.Failed("Malformed PGP payload response")
                PgpPayloadResult.Success(
                    encryptedPayload = parsed.encryptedPayload,
                    signaturePayload = parsed.signaturePayload,
                    body = parsed.body,
                    signerKeys = parsed.signerKeys.map {
                        SignerKey(it.addresses, it.publicKey, it.verified, it.source, it.conflict)
                    },
                    sender = parsed.sender,
                    resolvedSender = parsed.resolvedSender,
                )
            }
            else -> PgpPayloadResult.Failed("PGP payload fetch failed ($code)")
        }
    }
}
