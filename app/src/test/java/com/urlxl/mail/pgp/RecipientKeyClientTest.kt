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
 *  Named with a `RecipientKey` prefix, unlike the otherwise-identical block in PgpQrClientTest.kt
 *  and PgpBootstrapClientTest.kt: all three files share the `com.urlxl.mail.pgp` package, and
 *  Kotlin's top-level `private` is file-scoped only for visibility — the JVM class name is still
 *  bare (`FakeCall.class`), so two files in the same package cannot both declare a private
 *  top-level class of the same name. */
private class RecipientKeyFakeCallFactory(private val responder: (Request) -> Response) : Call.Factory {
    val requests = mutableListOf<Request>()

    override fun newCall(request: Request): Call {
        requests.add(request)
        return RecipientKeyFakeCall(request, responder(request))
    }
}

private class RecipientKeyThrowingCallFactory(private val exception: Exception) : Call.Factory {
    override fun newCall(request: Request): Call = RecipientKeyThrowingCall(request, exception)
}

private class RecipientKeyFakeCall(private val req: Request, private val response: Response) : Call {
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
    override fun clone(): Call = RecipientKeyFakeCall(req, response)
}

private class RecipientKeyThrowingCall(private val req: Request, private val exception: Exception) : Call {
    override fun request(): Request = req
    override fun execute(): Response = throw exception
    override fun enqueue(responseCallback: Callback) = responseCallback.onFailure(this, IOException(exception))
    override fun cancel() {}
    override fun isExecuted(): Boolean = false
    override fun isCanceled(): Boolean = false
    override fun timeout(): Timeout = Timeout.NONE
    override fun clone(): Call = RecipientKeyThrowingCall(req, exception)
}

/** Body-capturing factory for the POST-body assertion; `RecipientKeyFakeCallFactory` above only
 *  records requests, not bodies. Follows MfaResponseClientTest's `okio.Buffer` capture idiom. */
private class RecipientKeyBodyRecordingCallFactory(private val responder: (Request) -> Response) : Call.Factory {
    val requests = mutableListOf<Request>()
    val bodies = mutableListOf<String>()

    override fun newCall(request: Request): Call {
        requests.add(request)
        val buffer = okio.Buffer()
        request.body?.writeTo(buffer)
        bodies.add(buffer.readUtf8())
        return RecipientKeyFakeCall(request, responder(request))
    }
}

private fun response(request: Request, body: String, code: Int, message: String = "OK"): Response = Response.Builder()
    .request(request)
    .protocol(Protocol.HTTP_1_1)
    .code(code)
    .message(message)
    .body(body.toResponseBody("application/json".toMediaType()))
    .build()

class RecipientKeyClientTest {

    @Test
    fun reportsOnlyRecipientsWithNoUsableKey() = runBlocking {
        val body = """{"results":[
            {"address":"bob@example.com","hasKey":true,"revoked":false,"expired":false,"tier":"contact-verified"},
            {"address":"carol@example.com","hasKey":false,"revoked":false,"expired":false,"tier":"none"}
        ]}"""
        val client = RecipientKeyClient(callFactory = RecipientKeyFakeCallFactory { request -> response(request, body, 200) })

        val result = client.check(
            "https://relay.example.com", "d", "s", listOf("bob@example.com", "carol@example.com"),
        )

        assertEquals(listOf("carol@example.com"), (result as RecipientKeyResult.Success).keyless)
    }

    /** hasKey is already false for a revoked or expired key — the server sets it from its own
     *  usability check — so a revoked contact counts as keyless without this client re-deriving
     *  anything from the revoked/expired flags. */
    @Test
    fun revokedKeyCountsAsKeyless() = runBlocking {
        val body = """{"results":[{"address":"dave@example.com","hasKey":false,"revoked":true,"expired":false,"tier":"none"}]}"""
        val client = RecipientKeyClient(callFactory = RecipientKeyFakeCallFactory { request -> response(request, body, 200) })

        val result = client.check("https://relay.example.com", "d", "s", listOf("dave@example.com"))

        assertEquals(listOf("dave@example.com"), (result as RecipientKeyResult.Success).keyless)
    }

    @Test
    fun postsTheAddressesAndAuthHeaders() = runBlocking {
        val callFactory = RecipientKeyBodyRecordingCallFactory { request -> response(request, """{"results":[]}""", 200) }
        val client = RecipientKeyClient(callFactory = callFactory)

        client.check("https://relay.example.com/", "d", "s", listOf("bob@example.com"))

        val sent = callFactory.requests.single()
        assertEquals("https://relay.example.com/api/pgp/recipients/check", sent.url.toString())
        assertEquals("POST", sent.method)
        assertEquals("d", sent.header(HEADER_DEVICE_ID))
        assertEquals("s", sent.header(HEADER_DEVICE_SECRET))
        assertEquals("""{"addresses":["bob@example.com"]}""", callFactory.bodies.single())
    }

    /** A failed preflight must not read as "everyone has a key" — that would let the compose
     *  screen imply an encrypted send when it has no idea. */
    @Test
    fun httpFailureIsDistinctFromNoKeylessRecipients() = runBlocking {
        val client = RecipientKeyClient(callFactory = RecipientKeyFakeCallFactory { request -> response(request, "boom", 500) })

        val result = client.check("https://relay.example.com", "d", "s", listOf("bob@example.com"))

        assertTrue("expected Failed, got $result", result is RecipientKeyResult.Failed)
    }

    @Test
    fun networkThrowIsFailed() = runBlocking {
        val client = RecipientKeyClient(callFactory = RecipientKeyThrowingCallFactory(IOException("offline")))

        val result = client.check("https://relay.example.com", "d", "s", listOf("bob@example.com"))

        assertTrue("expected Failed, got $result", result is RecipientKeyResult.Failed)
    }

    /** No addresses to check is a local answer, not a round trip. */
    @Test
    fun emptyAddressListSkipsTheCall() = runBlocking {
        val callFactory = RecipientKeyFakeCallFactory { request -> response(request, """{"results":[]}""", 200) }
        val client = RecipientKeyClient(callFactory = callFactory)

        val result = client.check("https://relay.example.com", "d", "s", emptyList())

        assertEquals(emptyList<String>(), (result as RecipientKeyResult.Success).keyless)
        assertTrue("expected no request, sent ${callFactory.requests}", callFactory.requests.isEmpty())
    }
}
