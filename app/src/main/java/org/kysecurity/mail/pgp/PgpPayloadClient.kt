package org.kysecurity.mail.pgp

import org.kysecurity.mail.executeDecoding
import org.kysecurity.mail.pairingAuthHeaders
import org.kysecurity.mail.push.pairingEndpoint
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import okhttp3.Call
import okhttp3.Request

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
    ) : PgpPayloadResult() {
        /** Redacted: the body and payload are message content. Enforced by `SourceRulesTest`. */
        override fun toString(): String = "Success(redacted)"
    }

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
) {
    /** Redacted: the body and payload are message content. Enforced by `SourceRulesTest`. */
    override fun toString(): String = "PgpPayloadDto(redacted)"
}

private val JSON = Json { ignoreUnknownKeys = true }

internal class PgpPayloadClient(
    // Injected Call.Factory; see PairingAuthHeaders.kt for why every credentialed client takes one.
    private val callFactory: Call.Factory,
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
            // Armored ciphertext inside JSON is the one reply that legitimately dwarfs the
            // JSON-sized default. See [org.kysecurity.mail.BodyLimit].
            .tag(
                org.kysecurity.mail.BodyLimit::class.java,
                org.kysecurity.mail.BodyLimit(org.kysecurity.mail.MemoryBudget.PGP_PAYLOAD_BYTES),
            )
            .build()

        // Streamed rather than read into a String first: `encryptedPayload` is the single largest
        // field this app decodes, and `.string()` held a UTF-16 copy of the whole body beside it.
        val result = withContext(Dispatchers.IO) {
            callFactory.executeDecoding(request, JSON, PgpPayloadDto.serializer())
        }
        val response = result.getOrNull()
            ?: return PgpPayloadResult.Failed(result.exceptionOrNull()?.message ?: "Network error")

        return when (response.code) {
            409 -> PgpPayloadResult.NotClientProtected
            413 -> PgpPayloadResult.TooLarge
            404 -> PgpPayloadResult.NoPayload
            200 -> {
                val parsed = response.decoded
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
            else -> PgpPayloadResult.Failed("PGP payload fetch failed (${response.code})")
        }
    }
}
