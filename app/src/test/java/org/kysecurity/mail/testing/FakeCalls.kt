package org.kysecurity.mail.testing

import okhttp3.Call
import okhttp3.Callback
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.Protocol
import okhttp3.Request
import okhttp3.Response
import okhttp3.ResponseBody.Companion.asResponseBody
import okhttp3.ResponseBody.Companion.toResponseBody
import okio.Buffer
import okio.Timeout
import okio.buffer
import java.io.IOException

/** Shared OkHttp [Call.Factory] fakes; `internal` because top-level `private` still clashes. */
internal class FakeCallFactory(private val responder: (Request) -> Response) : Call.Factory {
    val requests = mutableListOf<Request>()

    override fun newCall(request: Request): Call {
        requests.add(request)
        return FakeCall(request, responder(request))
    }
}

/** [FakeCallFactory] that also captures bodies; separate because reading a body consumes it. */
internal class BodyRecordingCallFactory(private val responder: (Request) -> Response) : Call.Factory {
    val requests = mutableListOf<Request>()
    val bodies = mutableListOf<String>()

    override fun newCall(request: Request): Call {
        requests.add(request)
        val buffer = Buffer()
        request.body?.writeTo(buffer)
        bodies.add(buffer.readUtf8())
        return FakeCall(request, responder(request))
    }
}

/** A factory whose calls always fail, for verifying a client's exception-to-result mapping without
 *  a real network or TLS stack. */
internal class ThrowingCallFactory(private val exception: Exception) : Call.Factory {
    override fun newCall(request: Request): Call = ThrowingCall(request, exception)
}

private class FakeCall(private val req: Request, private val response: Response) : Call {
    private var executed = false
    private var canceled = false
    override fun request(): Request = req
    override fun execute(): Response {
        executed = true
        return response
    }
    override fun enqueue(responseCallback: Callback) = responseCallback.onResponse(this, response)
    override fun cancel() { canceled = true }
    override fun isExecuted(): Boolean = executed
    override fun isCanceled(): Boolean = canceled
    override fun timeout(): Timeout = Timeout.NONE
    override fun clone(): Call = FakeCall(req, response)
}

private class ThrowingCall(private val req: Request, private val exception: Exception) : Call {
    override fun request(): Request = req
    override fun execute(): Response = throw exception
    override fun enqueue(responseCallback: Callback) = responseCallback.onFailure(this, IOException(exception))
    override fun cancel() {}
    override fun isExecuted(): Boolean = false
    override fun isCanceled(): Boolean = false
    override fun timeout(): Timeout = Timeout.NONE
    override fun clone(): Call = ThrowingCall(req, exception)
}

/** Canned JSON response; [headers] carries meaning outside the body, e.g. `Retry-After`. */
internal fun response(
    request: Request,
    body: String,
    code: Int,
    message: String = "OK",
    headers: Map<String, String> = emptyMap(),
): Response =
    Response.Builder()
        .request(request)
        .protocol(Protocol.HTTP_1_1)
        .code(code)
        .message(message)
        .body(body.toResponseBody("application/json".toMediaType()))
        .apply { headers.forEach { (name, value) -> header(name, value) } }
        .build()

/** Body with real socket read semantics: one 8 KiB segment per read, unlike [response]'s Buffer. */
internal fun streamingResponse(
    request: Request,
    bytes: ByteArray,
    code: Int = 200,
    contentType: String = "application/octet-stream",
    headers: Map<String, String> = emptyMap(),
): Response {
    val backing = Buffer().write(bytes)
    val rawSource = object : okio.Source {
        override fun read(sink: Buffer, byteCount: Long): Long = backing.read(sink, byteCount)
        override fun timeout(): Timeout = Timeout.NONE
        override fun close() = backing.clear()
    }
    val builder = Response.Builder()
        .request(request)
        .protocol(Protocol.HTTP_1_1)
        .code(code)
        .message("OK")
        .body(
            rawSource.buffer().asResponseBody(contentType.toMediaType(), bytes.size.toLong()),
        )
    headers.forEach { (name, value) -> builder.header(name, value) }
    return builder.build()
}
