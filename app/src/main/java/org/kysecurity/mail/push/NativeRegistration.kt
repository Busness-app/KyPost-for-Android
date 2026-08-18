package org.kysecurity.mail.push

import android.os.Build
import org.kysecurity.mail.APP_VERSION
import org.kysecurity.mail.executeSync
import org.kysecurity.mail.pairingAuthHeaders
import org.kysecurity.mail.security.SpkiPinner
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import okhttp3.Call
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody

private val JSON_MEDIA_TYPE = "application/json".toMediaType()

@Serializable
data class NativeRegistrationRequest(
    @SerialName("subscriberId") val subscriberId: String,
    @SerialName("pairingToken") val pairingToken: String,
    @SerialName("deviceToken") val deviceToken: String,
    @SerialName("deviceId") val deviceId: String?,
    @SerialName("platform") val platform: String,
    @SerialName("transport") val transport: String? = null,
    @SerialName("deviceName") val deviceName: String?,
    @SerialName("appVersion") val appVersion: String?,
    // WebPush encryption key material (RFC 8291), present only for transport="unifiedpush".
    // The server needs these to encrypt payloads so the UnifiedPush connector can decrypt them;
    // without them, messages arrive as undecryptable ciphertext.
    @SerialName("p256dh") val p256dh: String? = null,
    @SerialName("auth") val auth: String? = null,
)

@Serializable
data class NativeRegistrationResponse(
    @SerialName("ok") val ok: Boolean = false,
    @SerialName("synced") val synced: Boolean = false,
    @SerialName("deviceId") val deviceId: String? = null,
    // The raw per-device pairing secret, minted fresh on every successful registration and
    // returned only in this response — never retrievable again afterward. The caller must
    // persist it unconditionally, overwriting any prior value (see PushSyncCoordinator).
    @SerialName("deviceSecret") val deviceSecret: String? = null,
    // Current delivery mode for this user ("push" | "pull") and the endpoint to poll
    // when in pull mode. Both may be absent on older servers.
    @SerialName("deliveryMode") val deliveryMode: String? = null,
    @SerialName("pullEndpoint") val pullEndpoint: String? = null,
    // The transport the server actually stored ("fcm" | "apns" | "unifiedpush"), echoed back
    // so the client displays an authoritative value rather than just assuming its request won.
    // Absent on older servers.
    @SerialName("transport") val transport: String? = null,
)

/**
 * Resolves the pull endpoint: the server-provided value wins only if it shares the paired
 * server's scheme and host, otherwise it is derived from the paired server base URL. A
 * cross-origin value is rejected rather than trusted, since this endpoint is polled
 * automatically and carries the device's bearer credential on every request.
 * Mirrors [NativeRegistrationEndpointResolver] for the register endpoint.
 */
fun resolvePullEndpoint(serverUrl: String, provided: String?): String {
    val fallback = pairingEndpoint(serverUrl, "/api/notifications/native/pull")?.toString() ?: return ""
    val candidate = provided?.takeIf { it.isNotBlank() } ?: return fallback
    return if (pairingUrlHost(candidate) != null && sameOrigin(candidate, serverUrl)) {
        candidate
    } else {
        fallback
    }
}

/** The wire boundary keeps `String` — this is the JSON contract, and [PushTransport] is what every
 *  caller above it uses. */
object NativeRegistrationRequestMapper {
    fun map(
        pairing: PairingData,
        token: String,
        transport: String? = null,
        p256dh: String? = null,
        auth: String? = null,
    ): NativeRegistrationRequest {
        return NativeRegistrationRequest(
            subscriberId = pairing.subscriberId,
            pairingToken = pairing.pairingToken,
            deviceToken = token,
            deviceId = pairing.deviceId,
            platform = "android",
            transport = transport,
            deviceName = Build.MODEL,
            appVersion = "KyPost for Android v$APP_VERSION",
            p256dh = p256dh,
            auth = auth,
        )
    }
}

sealed class NativeRegistrationResult {
    data class Success(
        val syncedAtEpochMs: Long,
        val deviceId: String?,
        val deviceSecret: String?,
        val deliveryMode: DeliveryMode = DeliveryMode.PUSH,
        val pullEndpoint: String? = null,
        /** The transport the server confirmed, or null when it did not echo the field back (older
         *  servers) or sent something this client does not recognise. */
        val transport: PushTransport? = null,
        // TOFU (trust-on-first-use) SPKI pin of the leaf certificate seen on this successful
        // registration call's TLS handshake, paired with the host that handshake was with, or null
        // if the connection wasn't TLS or the handshake info wasn't available. Carrying the host
        // is what stops the pin being enforced against a different host later on — see
        // PinnedCallFactoryProvider. The caller decides whether to persist it.
        val tlsPin: TlsPin? = null,
    ) : NativeRegistrationResult()
    data class Error(val message: String, val expiredPairingToken: Boolean = false) : NativeRegistrationResult()
}

class NativeRegistrationClient(
    private val json: Json = Json { ignoreUnknownKeys = true },
    // Call.Factory (not the concrete OkHttpClient) so a pinned-or-fallback factory (see
    // PushGraph, finding C2 of the 2026-07-22 security-hardening spec's final-review fix round)
    // can be injected here the same way every other pairing client accepts one; OkHttpClient
    // itself still satisfies this interface, so the default below is unchanged behavior.
    private val callFactory: Call.Factory,
) {
    suspend fun register(
        pairing: PairingData,
        token: String,
        nowEpochMs: Long = System.currentTimeMillis(),
        transport: PushTransport? = null,
        p256dh: String? = null,
        auth: String? = null,
    ): NativeRegistrationResult {
        if (token.isBlank()) return NativeRegistrationResult.Error("FCM token is empty")
        if (pairingUrlHost(pairing.serverUrl) == null ||
            pairingUrlHost(pairing.registrationUrl) == null ||
            !sameOrigin(pairing.registrationUrl, pairing.serverUrl)
        ) {
            return NativeRegistrationResult.Error("Registration URL is not valid")
        }

        val request = NativeRegistrationRequestMapper.map(
            pairing = pairing,
            token = token,
            transport = transport?.wire,
            p256dh = p256dh,
            auth = auth,
        )
        val httpRequest = Request.Builder()
            .url(pairing.registrationUrl)
            .post(json.encodeToString(request).toRequestBody(JSON_MEDIA_TYPE))
            // Re-registration REBINDS an existing device row, and the server refuses that with 409
            // unless the current credential is presented: without the check, a stolen session could
            // take over a device row, keep its MFAApprover status and redirect that user's push.
            // The FCM-token-refresh flow re-registers, so this is the ordinary path.
            //
            // Both halves or neither. A first pairing has no secret yet — this call is what mints
            // one — and a device id sent alone reads to the server as a rebind attempt with no
            // credential, which is exactly the request it is designed to refuse. The credential gate
            // produces that shape whenever the app is locked.
            .apply {
                val deviceId = pairing.deviceId
                val deviceSecret = pairing.deviceSecret
                if (!deviceId.isNullOrBlank() && !deviceSecret.isNullOrBlank()) {
                    pairingAuthHeaders(deviceId, deviceSecret)
                }
            }
            .build()
        // The host this call's handshake will be with — the pin below is only meaningful together
        // with it, since it is this URL, not pairing.serverUrl, that the certificate belongs to.
        val registrationHost = pairing.registrationUrl.toHttpUrlOrNull()?.host

        val result = withContext(Dispatchers.IO) {
            // Captures the handshake alongside code/body (not just the mapped DTO) so a
            // successful call can seed the TOFU TLS pin — see the `tlsPin` computation below.
            callFactory.executeSync(httpRequest) { response ->
                Triple(response.code, response.body?.string().orEmpty(), response.handshake)
            }
        }
        val (code, rawBody, handshake) = result.getOrNull()
            ?: return NativeRegistrationResult.Error(result.exceptionOrNull()?.message ?: "Failed to register device")

        return when (code) {
            200 -> {
                val body = runCatching { json.decodeFromString<NativeRegistrationResponse>(rawBody) }.getOrNull()
                if (body?.ok == true && body.synced && body.deviceSecret.isNullOrBlank()) {
                    // A successful registration always mints a secret. Treating a 200 without one
                    // as success made savePairing erase the stored credential while leaving the rest
                    // of the pairing intact, so the UI kept reporting "Paired" while every
                    // authenticated call 401'd with nothing to explain why.
                    NativeRegistrationResult.Error("Registration did not return a device secret")
                } else if (body?.ok == true && body.synced) {
                    NativeRegistrationResult.Success(
                        syncedAtEpochMs = nowEpochMs,
                        deviceId = body.deviceId,
                        deviceSecret = body.deviceSecret,
                        deliveryMode = DeliveryMode.fromWire(body.deliveryMode),
                        pullEndpoint = body.pullEndpoint,
                        transport = PushTransport.fromWire(body.transport),
                        tlsPin = registrationHost?.let { host ->
                            handshake?.peerCertificates?.firstOrNull()?.let { TlsPin(host, SpkiPinner.pinFor(it)) }
                        },
                    )
                } else {
                    NativeRegistrationResult.Error("Registration did not confirm sync")
                }
            }
            400 -> NativeRegistrationResult.Error("Malformed request or missing fields")
            401 -> NativeRegistrationResult.Error(
                message = "Pairing token expired or invalid",
                expiredPairingToken = true,
            )
            503 -> NativeRegistrationResult.Error("Pairing not configured on backend")
            // The device row exists and belongs to a credential this call did not present. Not a
            // transport failure and not a retry: re-pairing is the only thing that resolves it.
            409 -> NativeRegistrationResult.Error(
                "This device is already registered with a different credential — re-pair it",
            )
            else -> NativeRegistrationResult.Error("Failed to register device ($code)")
        }
    }
}
