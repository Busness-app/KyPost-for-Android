package org.kysecurity.mail

import okhttp3.CertificatePinner
import okhttp3.Interceptor
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import okhttp3.ResponseBody
import okio.Buffer
import okio.BufferedSource
import okio.ForwardingSource
import okio.buffer
import java.io.IOException

/**
 * **Why every credentialed client in this app takes an injected `okhttp3.Call.Factory`.**
 *
 * Two reasons, and this is the only place they are written down — the same five-line comment was
 * pasted into eleven client classes, which is a DRY violation whether the duplicated thing is code
 * or prose, and it drifted into four slightly different wordings.
 *
 * 1. `Call.Factory` rather than the concrete `OkHttpClient` so a test can inject a fake with no
 *    real network call and no MockWebServer dependency. `OkHttpClient` satisfies the interface, so
 *    production wiring is unaffected.
 * 2. There is deliberately **no default value** on any of those parameters. In production every one
 *    of them is a [org.kysecurity.mail.push.PinnedOrFallbackCallFactory], which re-reads the TLS pin
 *    per request and refuses outright once a pin that existed has gone; a default would let a new
 *    call site silently opt out of that. See [PinPosture].
 */
const val HEADER_DEVICE_ID = "X-Kypost-Device-Id"
const val HEADER_DEVICE_SECRET = "X-Kypost-Device-Secret"

/**
 * Attaches this device's own pairing-auth credentials as headers. Replaces the old
 * account-wide shared subscriberId/subscriberHash headers (removed entirely — the server no
 * longer accepts them). deviceSecret is minted once per successful registration call and must
 * be persisted unconditionally by the caller (see SecurePairingStore), since each registration
 * mints a brand-new secret that invalidates the previous one.
 */
fun Request.Builder.pairingAuthHeaders(deviceId: String, deviceSecret: String): Request.Builder =
    header(HEADER_DEVICE_ID, deviceId).header(HEADER_DEVICE_SECRET, deviceSecret)

/**
 * Whether a client pins, stated rather than defaulted.
 *
 * [pairingHttpClient] used to take `pinnedSpkiSha256: String? = null, host: String? = null`, so
 * **the default posture was no pinning** and any call site that simply forgot got bare system-CA
 * trust for a request carrying this device's bearer credential. A sealed type with no default makes
 * the decision unskippable, and `grep TofuWindow` is now a complete audit of the unpinned surface —
 * which was previously not a question the source could answer.
 */
sealed interface PinPosture {
    data class Pinned(val host: String, val spkiSha256: String) : PinPosture

    /**
     * No pin is enforced. Legitimate in exactly one situation: no pairing has ever completed, so
     * there is nothing to pin against yet. A pin that existed and is gone must NOT come here — see
     * [org.kysecurity.mail.push.TlsPinState.Lost], which fails closed instead.
     */
    object TofuWindow : PinPosture
}

/**
 * The one client every request that carries [pairingAuthHeaders] is derived from.
 *
 * Actually shared, unlike the KDoc this replaces: [pairingHttpClient] used to claim to be a "shared
 * client" while being a factory that built a whole new [OkHttpClient] — its own dispatcher, thread
 * pool and connection pool — on every call, so nothing reused a connection and each re-pair
 * orphaned the pools of the client it replaced. `newBuilder()` below shares all three.
 *
 * Redirect-following is disabled: OkHttp only strips the standard Authorization header on a
 * cross-host redirect, not our custom device-id/secret headers, so a malicious or compromised
 * paired server could otherwise 3xx-redirect a request to an arbitrary host and receive the
 * device's bearer credential.
 */
private val basePairingClient: OkHttpClient by lazy {
    OkHttpClient.Builder()
        .followRedirects(false)
        .followSslRedirects(false)
        .addInterceptor(BodySizeLimitInterceptor())
        .build()
}

/**
 * A client for [posture], sharing [basePairingClient]'s pools.
 *
 * [callTimeoutMillis] sets a hard ceiling on the *whole* call — connect, write, read, redirects —
 * rather than the per-phase defaults. Null keeps OkHttp's defaults, which is right for the
 * endpoints that stream up to 25 MB of attachment. It exists for the deregister call, where
 * `withTimeoutOrNull` could not deliver the bound its caller documented: coroutine cancellation
 * cannot interrupt a thread blocked inside a socket read, so the only thing that actually bounds a
 * blocking OkHttp call is OkHttp cancelling it. See [org.kysecurity.mail.security.SecurityWipe].
 */
fun pairingHttpClient(posture: PinPosture, callTimeoutMillis: Long? = null): OkHttpClient {
    val builder = basePairingClient.newBuilder()
    when (posture) {
        is PinPosture.Pinned -> builder.certificatePinner(
            CertificatePinner.Builder().add(posture.host, posture.spkiSha256).build(),
        )
        PinPosture.TofuWindow -> Unit
    }
    if (callTimeoutMillis != null) {
        builder.callTimeout(callTimeoutMillis, java.util.concurrent.TimeUnit.MILLISECONDS)
    }
    return builder.build()
}

/**
 * Hard ceiling on how many bytes any response body may yield, applied to every request this app
 * makes rather than to one endpoint at a time.
 *
 * `RelayMailSource.downloadAttachment` bounded its own read and documented why; every other
 * endpoint went through `response.body?.string()`, which materialises the whole body — and then
 * doubles it, since a Kotlin `String` is UTF-16. `/api/inbox` returns the full HTML body of every
 * message in the folder and is by far the largest response here, so the one place the bound was
 * missing was the place it mattered most: a hostile or compromised relay (or an active MITM before
 * the first TOFU pin exists) answering with a multi-hundred-megabyte body is an OOM kill, repeated
 * every 90 seconds by the inbox refresh cadence.
 *
 * Throws rather than truncating: a truncated JSON body fails to parse anyway, and callers map an
 * IOException to `UpstreamFailure` — a named failure beats a mystery parse error.
 *
 * The value lives in [MemoryBudget] with the app's other two heap ceilings, which it has to be read
 * against rather than on its own.
 */
private const val MAX_RESPONSE_BYTES = MemoryBudget.RESPONSE_BYTES

internal class BodySizeLimitInterceptor(
    private val maxBytes: Long = MAX_RESPONSE_BYTES,
) : Interceptor {
    override fun intercept(chain: Interceptor.Chain): Response {
        val response = chain.proceed(chain.request())
        val body = response.body ?: return response
        // Content-Length, when the server bothers to send one, lets us refuse before reading a
        // single byte. An absent or lying header falls through to the streaming counter below.
        if (body.contentLength() > maxBytes) {
            body.close()
            throw IOException("Response body of ${body.contentLength()} bytes exceeds the $maxBytes byte limit")
        }
        return response.newBuilder().body(LimitedResponseBody(body, maxBytes)).build()
    }
}

private class LimitedResponseBody(
    private val delegate: ResponseBody,
    private val maxBytes: Long,
) : ResponseBody() {
    override fun contentType() = delegate.contentType()
    override fun contentLength() = delegate.contentLength()

    private val counting = object : ForwardingSource(delegate.source()) {
        private var seen = 0L
        override fun read(sink: Buffer, byteCount: Long): Long {
            val read = super.read(sink, byteCount)
            if (read != -1L) {
                seen += read
                if (seen > maxBytes) {
                    throw IOException("Response body exceeded the $maxBytes byte limit")
                }
            }
            return read
        }
    }

    private val limitedSource: BufferedSource = counting.buffer()

    override fun source(): BufferedSource = limitedSource
}
