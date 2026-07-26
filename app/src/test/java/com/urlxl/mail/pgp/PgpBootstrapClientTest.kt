package com.urlxl.mail.pgp

import com.urlxl.mail.HEADER_DEVICE_SECRET
import com.urlxl.mail.HEADER_DEVICE_ID
import kotlinx.coroutines.runBlocking
import okhttp3.Call
import okhttp3.Callback
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.Protocol
import okhttp3.Request
import okhttp3.Response
import okhttp3.ResponseBody.Companion.toResponseBody
import okio.Timeout
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.IOException

/** Fakes OkHttp's [Call.Factory]; mirrors ContactSyncClientTest's hand-rolled-fake style (no
 *  mocking framework, no MockWebServer dependency in this repo).
 *
 *  Named with a `Bootstrap` prefix, unlike the otherwise-identical block in PgpQrClientTest.kt:
 *  both files share the `com.urlxl.mail.pgp` package, and Kotlin's top-level `private` is
 *  file-scoped only for visibility — the JVM class name is still bare (`FakeCall.class`), so two
 *  files in the same package cannot both declare a private top-level class of the same name. */
private class BootstrapFakeCallFactory(private val responder: (Request) -> Response) : Call.Factory {
    val requests = mutableListOf<Request>()

    override fun newCall(request: Request): Call {
        requests.add(request)
        return BootstrapFakeCall(request, responder(request))
    }
}

private class BootstrapThrowingCallFactory(private val exception: Exception) : Call.Factory {
    override fun newCall(request: Request): Call = BootstrapThrowingCall(request, exception)
}

private class BootstrapFakeCall(private val req: Request, private val response: Response) : Call {
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
    override fun clone(): Call = BootstrapFakeCall(req, response)
}

private class BootstrapThrowingCall(private val req: Request, private val exception: Exception) : Call {
    override fun request(): Request = req
    override fun execute(): Response = throw exception
    override fun enqueue(responseCallback: Callback) = responseCallback.onFailure(this, IOException(exception))
    override fun cancel() {}
    override fun isExecuted(): Boolean = false
    override fun isCanceled(): Boolean = false
    override fun timeout(): Timeout = Timeout.NONE
    override fun clone(): Call = BootstrapThrowingCall(req, exception)
}

private fun response(request: Request, body: String, code: Int, message: String = "OK"): Response = Response.Builder()
    .request(request)
    .protocol(Protocol.HTTP_1_1)
    .code(code)
    .message(message)
    .body(body.toResponseBody("application/json".toMediaType()))
    .build()

class PgpBootstrapClientTest {

    @Test
    fun parsesProtectionAndIdentity() = runBlocking {
        val callFactory = BootstrapFakeCallFactory { request ->
            response(request, """{"hasIdentity":true,"protection":"client"}""", 200)
        }
        val client = PgpBootstrapClient(callFactory = callFactory)

        val result = client.fetch("https://relay.example.com/", "device-1", "secret-1")

        assertEquals(PgpBootstrapResult.Success(hasIdentity = true, protection = "client"), result)
        val sent = callFactory.requests.single()
        assertEquals("https://relay.example.com/api/pgp/bootstrap", sent.url.toString())
        assertEquals("GET", sent.method)
        assertEquals("device-1", sent.header(HEADER_DEVICE_ID))
        assertEquals("secret-1", sent.header(HEADER_DEVICE_SECRET))
    }

    /** Bootstrap carries wrappedPrivateKey, unlockRequired, signerPublicKeys, payloadEndpoint and
     *  more, all of which exist for the browser. Unknown fields must not break parsing. */
    @Test
    fun ignoresTheBrowsersFields() = runBlocking {
        val body = """{"hasIdentity":false,"protection":"server","wrappedPrivateKey":"x","unlockRequired":true,"signerPublicKeys":[],"payloadEndpoint":"/x"}"""
        val client = PgpBootstrapClient(callFactory = BootstrapFakeCallFactory { request -> response(request, body, 200) })

        val result = client.fetch("https://relay.example.com", "device-1", "secret-1")

        assertEquals(PgpBootstrapResult.Success(hasIdentity = false, protection = "server"), result)
    }

    /** A failed bootstrap must be distinguishable from a successful "no identity", or the compose
     *  screen cannot honor couldn't-check-is-not-no. */
    @Test
    fun httpFailure_isFailedNotAnEmptySuccess() = runBlocking {
        val client = PgpBootstrapClient(callFactory = BootstrapFakeCallFactory { request -> response(request, "unavailable", 503) })

        val result = client.fetch("https://relay.example.com", "device-1", "secret-1")

        assertTrue("expected Failed, got $result", result is PgpBootstrapResult.Failed)
    }

    /** 503 and 401 bodies are plain text; a decoder run over them must not surface as a parse
     *  error, and a network throw must not escape. */
    @Test
    fun networkThrow_isFailed() = runBlocking {
        val client = PgpBootstrapClient(callFactory = BootstrapThrowingCallFactory(IOException("no route to host")))

        val result = client.fetch("https://relay.example.com", "device-1", "secret-1")

        assertTrue("expected Failed, got $result", result is PgpBootstrapResult.Failed)
    }

    @Test
    fun malformedBody_isFailed() = runBlocking {
        val client = PgpBootstrapClient(callFactory = BootstrapFakeCallFactory { request -> response(request, "not json", 200) })

        val result = client.fetch("https://relay.example.com", "device-1", "secret-1")

        assertTrue("expected Failed, got $result", result is PgpBootstrapResult.Failed)
    }

    @Test
    fun unusableServerUrl_isFailed() = runBlocking {
        val client = PgpBootstrapClient(callFactory = BootstrapFakeCallFactory { request -> response(request, "{}", 200) })

        val result = client.fetch("not a url", "device-1", "secret-1")

        assertTrue("expected Failed, got $result", result is PgpBootstrapResult.Failed)
    }
}
