package com.urlxl.mail

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
 * Shared client for every request that carries [pairingAuthHeaders]. Redirect-following is
 * disabled: OkHttp only strips the standard Authorization header on a cross-host redirect, not
 * our custom device-id/secret headers, so a malicious or compromised paired server could
 * otherwise 3xx-redirect a request to an arbitrary host and receive the device's bearer
 * credential.
 */
/** [pinnedSpkiSha256] + [host] both null (the default) matches every existing call site
 *  unchanged — no pin enforced, exactly today's behavior. Both non-null enables TOFU pinning
 *  for that host; see [com.urlxl.mail.security.SpkiPinner]. */
fun pairingHttpClient(pinnedSpkiSha256: String? = null, host: String? = null): OkHttpClient {
    val builder = OkHttpClient.Builder()
        .followRedirects(false)
        .followSslRedirects(false)
        .addInterceptor(BodySizeLimitInterceptor())
    if (pinnedSpkiSha256 != null && host != null) {
        builder.certificatePinner(
            CertificatePinner.Builder().add(host, pinnedSpkiSha256).build(),
        )
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
 * Enforced as an interceptor so no future client has to remember. The limit sits above
 * `MAX_ATTACHMENT_DOWNLOAD_BYTES` (25 MB) so a legitimate max-size attachment still succeeds; the
 * attachment path's own tighter bound stops reading long before this trips.
 *
 * Throws rather than truncating: a truncated JSON body fails to parse anyway, and callers map an
 * IOException to `UpstreamFailure` — a named failure beats a mystery parse error.
 */
private const val MAX_RESPONSE_BYTES = 32L * 1024 * 1024

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
