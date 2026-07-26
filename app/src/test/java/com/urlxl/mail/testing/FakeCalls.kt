package com.urlxl.mail.testing

import okhttp3.Call
import okhttp3.Callback
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.Protocol
import okhttp3.Request
import okhttp3.Response
import okhttp3.ResponseBody.Companion.toResponseBody
import okio.Buffer
import okio.Timeout
import java.io.IOException

/**
 * Shared hand-rolled fakes for OkHttp's [Call.Factory], so a client can be exercised without a real
 * network call. This repo has no mocking framework and no MockWebServer dependency, and injecting a
 * [Call.Factory] rather than a concrete `OkHttpClient` is the seam every client here is built around.
 *
 * These lived as `private` top-level copies in each test file, which worked only while no two files
 * in the same package needed them. Kotlin compiles a top-level `private` class to a package-level
 * JVM name — `private` restricts visibility, not the emitted class name — so the second test file in
 * `com.urlxl.mail.pgp` to declare `FakeCallFactory` failed to compile as a duplicate class. That was
 * papered over with per-file name prefixes (`BootstrapFakeCallFactory`, `RecipientKeyFakeCall`, …),
 * which left four near-identical copies under three naming conventions. One `internal` copy here
 * removes both problems: `internal` is module-wide, so any test in this source set can use it.
 */
internal class FakeCallFactory(private val responder: (Request) -> Response) : Call.Factory {
    val requests = mutableListOf<Request>()

    override fun newCall(request: Request): Call {
        requests.add(request)
        return FakeCall(request, responder(request))
    }
}

/**
 * [FakeCallFactory] that also captures each request body as a string.
 *
 * Separate from [FakeCallFactory] rather than folded into it because reading a body consumes it:
 * every GET-only test would pay for a capture it never inspects.
 */
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

/** Canned JSON response. Keeps the name the per-file copies used, so adopting this file is a
 *  deletion plus an import rather than a rewrite of every call site. */
internal fun response(request: Request, body: String, code: Int, message: String = "OK"): Response =
    Response.Builder()
        .request(request)
        .protocol(Protocol.HTTP_1_1)
        .code(code)
        .message(message)
        .body(body.toResponseBody("application/json".toMediaType()))
        .build()
