package org.kysecurity.mail

import kotlinx.serialization.DeserializationStrategy
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.decodeFromStream
import okhttp3.Call
import okhttp3.Request
import okhttp3.Response

/** [Result] failure is a thrown network exception; body decoding stays the caller's job. */
fun <T> Call.Factory.executeSync(request: Request, map: (Response) -> T): Result<T> = runCatching {
    newCall(request).execute().use(map)
}

/** How much of a failure response may be read. These strings reach a Toast; a hostile relay does
 *  not get to make one of them megabytes long just because the status code was not 200. */
private const val MAX_ERROR_BODY_BYTES = 4L * 1024

/** A consumed response: the decoded value on success, bounded text on failure. */
class DecodedResponse<T>(
    val code: Int,
    /** Non-null only when [code] was 200 and the body decoded. */
    val decoded: T?,
    /** Bounded failure text; empty on success. */
    val errorBody: String,
    val retryAfter: String?,
)

/**
 * Decodes a 200 body straight off the socket, without ever materialising it as a `String`.
 *
 * `ResponseBody.string()` costs two bytes of heap per byte of response — ART stores `String` as
 * UTF-16 — and that copy stays live while the object graph is decoded from it, so a JSON reply
 * peaked at roughly three times its wire size. Streaming removes the intermediate copy entirely;
 * only the decoded objects remain. See [MemoryBudget].
 */
@OptIn(ExperimentalSerializationApi::class)
fun <T> Call.Factory.executeDecoding(
    request: Request,
    json: Json,
    deserializer: DeserializationStrategy<T>,
    retryAfterHeader: String = "Retry-After",
): Result<DecodedResponse<T>> = runCatching {
    newCall(request).execute().use { response ->
        val retryAfter = response.header(retryAfterHeader)
        if (response.code != 200) {
            val text = runCatching { response.peekBody(MAX_ERROR_BODY_BYTES).string() }.getOrDefault("")
            return@use DecodedResponse(response.code, null, text, retryAfter)
        }
        val decoded = response.body?.byteStream()?.let { stream ->
            // Null on a malformed body, exactly as the decodeFromString callers treated it. The
            // stream is closed by `use` on the response either way.
            runCatching { json.decodeFromStream(deserializer, stream) }.getOrNull()
        }
        DecodedResponse(response.code, decoded, "", retryAfter)
    }
}
