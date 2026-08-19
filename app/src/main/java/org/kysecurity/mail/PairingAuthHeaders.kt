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

/** Credentialed clients take an injected `Call.Factory` with no default, so none skips pinning. */
const val HEADER_DEVICE_ID = "X-Kypost-Device-Id"
const val HEADER_DEVICE_SECRET = "X-Kypost-Device-Secret"

/** Each registration mints a new deviceSecret that invalidates the previous one; persist it. */
fun Request.Builder.pairingAuthHeaders(deviceId: String, deviceSecret: String): Request.Builder =
    header(HEADER_DEVICE_ID, deviceId).header(HEADER_DEVICE_SECRET, deviceSecret)

/** No default posture: `grep TofuWindow` is the complete audit of the unpinned surface. */
sealed interface PinPosture {
    /** [spkiSha256] is the whole observed chain, not just the leaf — see [org.kysecurity.mail.push.TlsPin]. */
    data class Pinned(val host: String, val spkiSha256: Set<String>) : PinPosture

    /** Only legitimate before any pairing completes; a pin that existed and is gone fails closed. */
    object TofuWindow : PinPosture
}

/** Redirects disabled: OkHttp does not strip our custom credential headers cross-host. */
private val basePairingClient: OkHttpClient by lazy {
    OkHttpClient.Builder()
        .followRedirects(false)
        .followSslRedirects(false)
        .addInterceptor(BodySizeLimitInterceptor())
        .build()
}

/** [callTimeoutMillis] bounds the whole call: cancellation cannot interrupt a socket read. */
fun pairingHttpClient(posture: PinPosture, callTimeoutMillis: Long? = null): OkHttpClient {
    val builder = basePairingClient.newBuilder()
    when (posture) {
        // `add` is vararg per host: every chain pin is registered, and CertificatePinner passes on
        // the first match, so a renewed leaf under an already-pinned issuer still validates.
        is PinPosture.Pinned -> {
            // Empty would configure no pin for the host, which CertificatePinner passes vacuously.
            // TlsPin makes that unrepresentable; this is the second half of the same guarantee.
            require(posture.spkiSha256.isNotEmpty()) { "Refusing to build a client that pins nothing" }
            builder.certificatePinner(
                CertificatePinner.Builder()
                    .apply { posture.spkiSha256.forEach { add(posture.host, it) } }
                    .build(),
            )
        }
        PinPosture.TofuWindow -> Unit
    }
    if (callTimeoutMillis != null) {
        builder.callTimeout(callTimeoutMillis, java.util.concurrent.TimeUnit.MILLISECONDS)
    }
    return builder.build()
}

/** Raises [BodySizeLimitInterceptor]'s ceiling for one request.
 *
 *  The default is sized for a JSON reply. Two routes legitimately carry far more — an attachment
 *  download and an armored OpenPGP payload — and before this existed a single constant had to be
 *  large enough for those, which meant every small JSON endpoint was also allowed to return tens
 *  of megabytes. Attach with `.tag(BodyLimit::class.java, BodyLimit(n))`. */
class BodyLimit(val maxBytes: Long)

internal class BodySizeLimitInterceptor(
    private val defaultMaxBytes: Long = MemoryBudget.JSON_RESPONSE_BYTES,
) : Interceptor {
    override fun intercept(chain: Interceptor.Chain): Response {
        val request = chain.request()
        val maxBytes = request.tag(BodyLimit::class.java)?.maxBytes ?: defaultMaxBytes
        val response = chain.proceed(request)
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
