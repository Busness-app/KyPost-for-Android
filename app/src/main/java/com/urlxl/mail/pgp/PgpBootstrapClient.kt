package com.urlxl.mail.pgp

import com.urlxl.mail.executeSync
import com.urlxl.mail.pairingAuthHeaders
import com.urlxl.mail.pairingHttpClient
import com.urlxl.mail.push.pairingEndpoint
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import okhttp3.Call
import okhttp3.Request

/**
 * Outcome of `GET /api/pgp/bootstrap`.
 *
 * Two cases, not one per status code: the caller's response to *every* failure is identical — hide
 * the PGP controls, because couldn't-check is not "no" — so distinguishing 401 from 503 from a
 * malformed body would be a distinction nothing acts on.
 */
sealed class PgpBootstrapResult {
    /** [protection] is `"server"`, `"client"`, or `""` for an account with no identity. Passed
     *  through as the raw string; [pgpComposeStateOf] decides what it means, and treats anything
     *  unrecognized as "not server". [publicKey] is the account's own armored public key, `""`
     *  when it has no identity — the only device-reachable source for it, and what
     *  [ownFingerprintFromBootstrap] hashes to show the user their own fingerprint. */
    data class Success(
        val hasIdentity: Boolean,
        val protection: String,
        val publicKey: String,
        /** The account's own mail address, and the only device-reachable source for it —
         *  `GET /api/mail/send-as` is session-authenticated, so a paired device cannot ask.
         *
         *  Every client-encrypted delivery's `From` header must equal this exactly or the relay
         *  answers 403, and it is authoritative rather than inferred: the server builds
         *  `suggestedUserIDs[0]` from the same `strings.TrimSpace(payload.Username)` expression that
         *  `handleMailSendPGP` hands to `resolveMailFrom`. Blank when no mail account is configured,
         *  which means no valid `From` can be built at all. */
        val accountAddress: String = "",
    ) : PgpBootstrapResult()

    data class Failed(val message: String) : PgpBootstrapResult()
}

/** The three fields this app needs. The endpoint returns considerably more — wrappedPrivateKey,
 *  unlockRequired, signerPublicKeys, payloadEndpoint — all of it for the browser, none of it
 *  usable here, which is why the [Json] instance ignores unknown keys. The response's own
 *  `fingerprint` field is deliberately NOT among them: it is a claim sitting beside `publicKey`
 *  with no cryptographic tie to it, and [PgpFingerprint] exists precisely so the app hashes the
 *  key bytes itself instead of rendering a server-supplied label. */
@Serializable
private data class PgpBootstrapDto(
    val hasIdentity: Boolean = false,
    val protection: String = "",
    val publicKey: String = "",
    /** Primary address first, then every verified send-as alias. Only the first is used today. */
    val suggestedUserIDs: List<String> = emptyList(),
)

/**
 * Reads the account's PGP key-custody mode. Pairing-authenticated with
 * X-Kypost-Device-Id/X-Kypost-Device-Secret exactly like every other relay call this app makes —
 * there is no mobile login and no session cookie. Kept parallel to [PgpQrClient].
 */
class PgpBootstrapClient(
    private val json: Json = Json { ignoreUnknownKeys = true },
    // Call.Factory (not the concrete OkHttpClient) so tests can inject a fake without a real
    // network call or a MockWebServer dependency; OkHttpClient itself satisfies this interface.
    private val callFactory: Call.Factory = pairingHttpClient(),
) {
    suspend fun fetch(serverUrl: String, deviceId: String, deviceSecret: String): PgpBootstrapResult {
        val url = pairingEndpoint(serverUrl, "/api/pgp/bootstrap")
            ?: return PgpBootstrapResult.Failed("Server URL is not valid")
        val request = Request.Builder().url(url).get()
            .pairingAuthHeaders(deviceId, deviceSecret)
            .build()

        val result = withContext(Dispatchers.IO) {
            callFactory.executeSync(request) { response -> response.code to response.body?.string().orEmpty() }
        }
        val (code, rawBody) = result.getOrNull()
            ?: return PgpBootstrapResult.Failed(result.exceptionOrNull()?.message ?: "Network error")

        // Only 200 is JSON here; every other status returns plain text, so no decoder runs over it.
        if (code != 200) return PgpBootstrapResult.Failed("PGP bootstrap failed ($code)")
        val parsed = runCatching { json.decodeFromString<PgpBootstrapDto>(rawBody) }.getOrNull()
            ?: return PgpBootstrapResult.Failed("Malformed PGP bootstrap response")
        return PgpBootstrapResult.Success(
            hasIdentity = parsed.hasIdentity,
            protection = parsed.protection,
            publicKey = parsed.publicKey,
            accountAddress = parsed.suggestedUserIDs.firstOrNull().orEmpty(),
        )
    }
}
