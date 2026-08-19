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
    data class Pinned(val host: String, val spkiSha256: String) : PinPosture

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

/** Applied to every response; throws rather than truncating, so callers see UpstreamFailure. */
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
