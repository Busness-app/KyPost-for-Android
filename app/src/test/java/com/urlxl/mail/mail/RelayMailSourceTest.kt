package com.urlxl.mail.mail

import com.urlxl.mail.HEADER_DEVICE_ID
import com.urlxl.mail.HEADER_DEVICE_SECRET
import com.urlxl.mail.push.PairingData
import okhttp3.Call
import okhttp3.Callback
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.Protocol
import okhttp3.Request
import okhttp3.Response
import okhttp3.ResponseBody.Companion.toResponseBody
import okio.Timeout
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

private fun testPairing() = PairingData(
    subscriberId = "sub-1",
    serverUrl = "https://relay.example.com",
    registrationUrl = "",
    pairingToken = "",
    deviceId = "device-1",
    deviceSecret = "secret-1",
    pairedAtEpochMs = 0L,
)

/** In-memory fake matching this repo's hand-rolled-fake test style (no mocking framework). */
private class FakeMailCursorProvider(
    var storedCursor: String? = null,
    var forceDue: Boolean = false,
) : MailCursorProvider {
    var savedCursor: String? = null
        private set
    var fullResyncRecorded = false
        private set

    override fun cursor(subscriberId: String, folder: String): String? = storedCursor
    override fun saveCursor(subscriberId: String, folder: String, cursor: String) {
        savedCursor = cursor
        storedCursor = cursor
    }
    override fun shouldForceFullResync(subscriberId: String, folder: String): Boolean = forceDue
    override fun recordFullResync(subscriberId: String, folder: String) {
        fullResyncRecorded = true
    }
}

/** Fakes OkHttp's [Call.Factory] so RelayMailSource can be exercised without a real network call
 *  or a MockWebServer dependency — this repo has neither and prefers hand-rolled fakes. */
private class FakeCallFactory(private val responder: (Request) -> Response) : Call.Factory {
    val requests = mutableListOf<Request>()

    override fun newCall(request: Request): Call {
        requests.add(request)
        return FakeCall(request, responder(request))
    }
}

/** Records request bodies as well as requests — [FakeCallFactory] keeps only the latter, and the
 *  PGP send flags are body fields. Mirrors MfaResponseClientTest's body-capturing fake. */
private class BodyRecordingCallFactory(private val responder: (Request) -> Response) : Call.Factory {
    val bodies = mutableListOf<String>()

    override fun newCall(request: Request): Call {
        val buffer = okio.Buffer()
        request.body?.writeTo(buffer)
        bodies.add(buffer.readUtf8())
        return FakeCall(request, responder(request))
    }
}

/** A [Call.Factory] whose call always fails with [exception] — used to verify RelayMailSource's
 *  exception-to-[MailOutcome] mapping (e.g. a TLS pin mismatch) without a real network/TLS stack. */
private class ThrowingCallFactory(private val exception: Throwable) : Call.Factory {
    override fun newCall(request: Request): Call = object : Call {
        override fun request(): Request = request
        override fun execute(): Response = throw exception
        override fun enqueue(responseCallback: Callback) = responseCallback.onFailure(this, java.io.IOException(exception))
        override fun cancel() {}
        override fun isExecuted(): Boolean = false
        override fun isCanceled(): Boolean = false
        override fun timeout(): Timeout = Timeout.NONE
        override fun clone(): Call = this
    }
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

private fun jsonResponse(request: Request, body: String, code: Int = 200): Response = Response.Builder()
    .request(request)
    .protocol(Protocol.HTTP_1_1)
    .code(code)
    .message("OK")
    .body(body.toResponseBody("application/json".toMediaType()))
    .build()

class RelayMailSourceTest {

    @Test
    fun freshPairing_noPersistedCursor_sendsSinceZero() {
        val cursorProvider = FakeMailCursorProvider(storedCursor = null)
        val callFactory = FakeCallFactory { request ->
            jsonResponse(request, """{"tabs": [], "byTab": {}, "cursor": "c1", "delta": true, "removed": []}""")
        }
        val source = RelayMailSource(
            pairingProvider = { testPairing() },
            cursorProvider = cursorProvider,
            callFactory = callFactory,
        )

        val outcome = source.fetchInbox("INBOX", 50)

        assertTrue(outcome is MailOutcome.Success)
        assertEquals("0", callFactory.requests.single().url.queryParameter("since"))
        assertEquals("c1", cursorProvider.savedCursor)
    }

    @Test
    fun subsequentPoll_sendsPersistedCursor() {
        val cursorProvider = FakeMailCursorProvider(storedCursor = "cursor-42")
        val callFactory = FakeCallFactory { request ->
            jsonResponse(request, """{"tabs": [], "byTab": {}, "cursor": "cursor-43", "delta": true, "removed": []}""")
        }
        val source = RelayMailSource(
            pairingProvider = { testPairing() },
            cursorProvider = cursorProvider,
            callFactory = callFactory,
        )

        source.fetchInbox("INBOX", 50)

        assertEquals("cursor-42", callFactory.requests.single().url.queryParameter("since"))
        assertEquals("cursor-43", cursorProvider.savedCursor)
    }

    @Test
    fun deltaPoll_parsesNewUpdatedAndRemoved() {
        val cursorProvider = FakeMailCursorProvider(storedCursor = "cursor-1")
        val body = """
            {
              "tabs": ["Work"],
              "byTab": {
                "Work": [
                  {"messageId": "m1", "sender": "a@example.com", "subject": "New", "body": "Full body", "label": "Work", "status": "unread", "changeType": "new"},
                  {"messageId": "m2", "sender": "b@example.com", "subject": "Updated", "label": "Work", "status": "read", "changeType": "updated"}
                ]
              },
              "cursor": "cursor-2",
              "delta": true,
              "removed": ["m3"]
            }
        """.trimIndent()
        val callFactory = FakeCallFactory { request -> jsonResponse(request, body) }
        val source = RelayMailSource(
            pairingProvider = { testPairing() },
            cursorProvider = cursorProvider,
            callFactory = callFactory,
        )

        val outcome = source.fetchInbox("INBOX", 50)

        val result = (outcome as MailOutcome.Success).value
        assertTrue(result.isDelta)
        assertEquals(setOf("m2"), result.updatedMessageIds)
        assertEquals(listOf("m3"), result.removedMessageIds)
        assertEquals(2, result.messages.size)
        assertNull(result.messages.first { it.id == "m2" }.body)
        assertEquals("Full body", result.messages.first { it.id == "m1" }.body)
        assertEquals("cursor-2", cursorProvider.savedCursor)
    }

    @Test
    fun explicitForceFullResync_sendsSinceZero_regardlessOfPersistedCursor() {
        val cursorProvider = FakeMailCursorProvider(storedCursor = "cursor-99")
        val callFactory = FakeCallFactory { request ->
            jsonResponse(request, """{"tabs": [], "byTab": {}, "cursor": "cursor-100", "delta": true, "removed": []}""")
        }
        val source = RelayMailSource(
            pairingProvider = { testPairing() },
            cursorProvider = cursorProvider,
            callFactory = callFactory,
        )

        source.fetchInbox("INBOX", 50, forceFullResync = true)

        assertEquals("0", callFactory.requests.single().url.queryParameter("since"))
        assertTrue(cursorProvider.fullResyncRecorded)
    }

    @Test
    fun cadenceDue_sendsSinceZero_evenWithoutExplicitForce() {
        val cursorProvider = FakeMailCursorProvider(storedCursor = "cursor-5", forceDue = true)
        val callFactory = FakeCallFactory { request ->
            jsonResponse(request, """{"tabs": [], "byTab": {}, "cursor": "cursor-6", "delta": true, "removed": []}""")
        }
        val source = RelayMailSource(
            pairingProvider = { testPairing() },
            cursorProvider = cursorProvider,
            callFactory = callFactory,
        )

        source.fetchInbox("INBOX", 50)

        assertEquals("0", callFactory.requests.single().url.queryParameter("since"))
        assertTrue(cursorProvider.fullResyncRecorded)
    }

    @Test
    fun nonDeltaLegacyResponse_stillParsesAsFullSnapshot() {
        val cursorProvider = FakeMailCursorProvider(storedCursor = null)
        val body = """
            {
              "tabs": ["Work"],
              "byTab": {"Work": [{"messageId": "m1", "sender": "a@example.com", "subject": "S", "body": "B", "label": "Work", "status": "unread"}]}
            }
        """.trimIndent()
        val callFactory = FakeCallFactory { request -> jsonResponse(request, body) }
        val source = RelayMailSource(
            pairingProvider = { testPairing() },
            cursorProvider = cursorProvider,
            callFactory = callFactory,
        )

        val outcome = source.fetchInbox("INBOX", 50)

        val result = (outcome as MailOutcome.Success).value
        assertTrue(!result.isDelta)
        assertEquals(1, result.messages.size)
        assertNull(cursorProvider.savedCursor)
    }

    @Test
    fun fetchInbox_sendsPairingHeaders_notQueryParams() {
        val cursorProvider = FakeMailCursorProvider(storedCursor = null)
        val callFactory = FakeCallFactory { request ->
            jsonResponse(request, """{"tabs": [], "byTab": {}, "cursor": "c1", "delta": true, "removed": []}""")
        }
        val source = RelayMailSource(
            pairingProvider = { testPairing() },
            cursorProvider = cursorProvider,
            callFactory = callFactory,
        )

        source.fetchInbox("INBOX", 50)

        val sentRequest = callFactory.requests.single()
        assertEquals("device-1", sentRequest.header(HEADER_DEVICE_ID))
        assertEquals("secret-1", sentRequest.header(HEADER_DEVICE_SECRET))
        assertNull(sentRequest.url.queryParameter("sub"))
        assertNull(sentRequest.url.queryParameter("hash"))
    }

    @Test
    fun listFolders_sendsPairingHeaders_notQueryParams() {
        val callFactory = FakeCallFactory { request ->
            jsonResponse(request, """{"parent": null, "folders": []}""")
        }
        val source = RelayMailSource(
            pairingProvider = { testPairing() },
            cursorProvider = FakeMailCursorProvider(),
            callFactory = callFactory,
        )

        source.listFolders(null)

        val sentRequest = callFactory.requests.single()
        assertEquals("device-1", sentRequest.header(HEADER_DEVICE_ID))
        assertEquals("secret-1", sentRequest.header(HEADER_DEVICE_SECRET))
        assertNull(sentRequest.url.queryParameter("sub"))
        assertNull(sentRequest.url.queryParameter("hash"))
    }

    @Test
    fun createFolder_sendsPairingHeaders_notQueryParams() {
        val callFactory = FakeCallFactory { request -> jsonResponse(request, "", code = 200) }
        val source = RelayMailSource(
            pairingProvider = { testPairing() },
            cursorProvider = FakeMailCursorProvider(),
            callFactory = callFactory,
        )

        source.createFolder("INBOX", "New Folder")

        val sentRequest = callFactory.requests.single()
        assertEquals("device-1", sentRequest.header(HEADER_DEVICE_ID))
        assertEquals("secret-1", sentRequest.header(HEADER_DEVICE_SECRET))
        assertNull(sentRequest.url.queryParameter("sub"))
        assertNull(sentRequest.url.queryParameter("hash"))
    }

    @Test
    fun deleteFolder_sendsPairingHeaders_notQueryParams() {
        val callFactory = FakeCallFactory { request -> jsonResponse(request, "", code = 200) }
        val source = RelayMailSource(
            pairingProvider = { testPairing() },
            cursorProvider = FakeMailCursorProvider(),
            callFactory = callFactory,
        )

        source.deleteFolder("INBOX/Old")

        val sentRequest = callFactory.requests.single()
        assertEquals("device-1", sentRequest.header(HEADER_DEVICE_ID))
        assertEquals("secret-1", sentRequest.header(HEADER_DEVICE_SECRET))
        assertNull(sentRequest.url.queryParameter("sub"))
        assertNull(sentRequest.url.queryParameter("hash"))
        assertEquals("INBOX/Old", sentRequest.url.queryParameter("folder"))
    }

    @Test
    fun downloadAttachment_sendsPairingHeaders_notQueryParams() {
        val callFactory = FakeCallFactory { request ->
            Response.Builder()
                .request(request)
                .protocol(Protocol.HTTP_1_1)
                .code(200)
                .message("OK")
                .header("Content-Disposition", "attachment; filename=\"file.pdf\"")
                .header("Content-Type", "application/pdf")
                .body("bytes".toResponseBody("application/pdf".toMediaType()))
                .build()
        }
        val source = RelayMailSource(
            pairingProvider = { testPairing() },
            cursorProvider = FakeMailCursorProvider(),
            callFactory = callFactory,
        )

        source.downloadAttachment("m1", "INBOX", 0)

        val sentRequest = callFactory.requests.single()
        assertEquals("device-1", sentRequest.header(HEADER_DEVICE_ID))
        assertEquals("secret-1", sentRequest.header(HEADER_DEVICE_SECRET))
        assertNull(sentRequest.url.queryParameter("sub"))
        assertNull(sentRequest.url.queryParameter("hash"))
    }

    @Test
    fun tlsPinMismatch_mapsToCertificateMismatch_notGenericNetworkError() {
        val callFactory = ThrowingCallFactory(javax.net.ssl.SSLPeerUnverifiedException("pin mismatch"))
        val source = RelayMailSource(
            pairingProvider = { testPairing() },
            cursorProvider = FakeMailCursorProvider(),
            callFactory = callFactory,
        )

        val outcome = source.fetchInbox("INBOX", 50)

        assertTrue(outcome is MailOutcome.CertificateMismatch)
        assertEquals("pin mismatch", (outcome as MailOutcome.CertificateMismatch).message)
    }

    @Test
    fun tlsPinMismatch_onDownloadAttachment_alsoMapsToCertificateMismatch() {
        val callFactory = ThrowingCallFactory(javax.net.ssl.SSLPeerUnverifiedException("pin mismatch"))
        val source = RelayMailSource(
            pairingProvider = { testPairing() },
            cursorProvider = FakeMailCursorProvider(),
            callFactory = callFactory,
        )

        val outcome = source.downloadAttachment("m1", "INBOX", 0)

        assertTrue(outcome is MailOutcome.CertificateMismatch)
    }

    /** The backend returns this when a client-protected account asks the server to sign or
     *  encrypt. Before this mapping it fell through to "Mail relay request failed (409)". */
    @Test
    fun send409WithClientSideNeeded_mapsToClientSideNeeded() {
        val body = """{"error":"this account's PGP key is end-to-end protected, so the server cannot sign or encrypt on your behalf","clientSideNeeded":true}"""
        val source = RelayMailSource(
            pairingProvider = { testPairing() },
            cursorProvider = FakeMailCursorProvider(),
            callFactory = FakeCallFactory { request -> jsonResponse(request, body, code = 409) },
        )

        val outcome = source.sendMail(MailDraft(to = "a@example.com", subject = "s", body = "b"))

        assertTrue("expected ClientSideNeeded, got $outcome", outcome is MailOutcome.ClientSideNeeded)
    }

    /** A 409 without the marker must not inherit PGP wording — nothing else this app calls
     *  returns 409 today, but the mapping shouldn't assume that forever. */
    @Test
    fun send409WithoutMarker_staysBadRequest() {
        val source = RelayMailSource(
            pairingProvider = { testPairing() },
            cursorProvider = FakeMailCursorProvider(),
            callFactory = FakeCallFactory { request -> jsonResponse(request, """{"error":"conflict"}""", code = 409) },
        )

        val outcome = source.sendMail(MailDraft(to = "a@example.com", subject = "s", body = "b"))

        assertTrue("expected BadRequest, got $outcome", outcome is MailOutcome.BadRequest)
    }

    @Test
    fun rateLimit429_carriesRetryAfterSeconds() {
        val callFactory = FakeCallFactory { request ->
            Response.Builder()
                .request(request)
                .protocol(Protocol.HTTP_1_1)
                .code(429)
                .message("Too Many Requests")
                .header("Retry-After", "120")
                .body("too many requests".toResponseBody("text/plain".toMediaType()))
                .build()
        }
        val source = RelayMailSource(
            pairingProvider = { testPairing() },
            cursorProvider = FakeMailCursorProvider(),
            callFactory = callFactory,
        )

        val outcome = source.fetchInbox("INBOX", 50)

        assertTrue("expected RateLimited, got $outcome", outcome is MailOutcome.RateLimited)
        assertEquals(120L, (outcome as MailOutcome.RateLimited).retryAfterSeconds)
    }

    /** A missing or non-numeric Retry-After must not be reported as "retry now" — null means the
     *  caller renders a generic "try again later". */
    @Test
    fun rateLimit429_withoutUsableRetryAfter_hasNullDelay() {
        val callFactory = FakeCallFactory { request ->
            Response.Builder()
                .request(request)
                .protocol(Protocol.HTTP_1_1)
                .code(429)
                .message("Too Many Requests")
                .header("Retry-After", "Wed, 21 Oct 2026 07:28:00 GMT")
                .body("too many requests".toResponseBody("text/plain".toMediaType()))
                .build()
        }
        val source = RelayMailSource(
            pairingProvider = { testPairing() },
            cursorProvider = FakeMailCursorProvider(),
            callFactory = callFactory,
        )

        val outcome = source.fetchInbox("INBOX", 50)

        assertTrue("expected RateLimited, got $outcome", outcome is MailOutcome.RateLimited)
        assertNull((outcome as MailOutcome.RateLimited).retryAfterSeconds)
    }

    @Test
    fun rateLimit429_onDownloadAttachment_alsoMapsToRateLimited() {
        val callFactory = FakeCallFactory { request ->
            Response.Builder()
                .request(request)
                .protocol(Protocol.HTTP_1_1)
                .code(429)
                .message("Too Many Requests")
                .header("Retry-After", "30")
                .body("too many requests".toResponseBody("text/plain".toMediaType()))
                .build()
        }
        val source = RelayMailSource(
            pairingProvider = { testPairing() },
            cursorProvider = FakeMailCursorProvider(),
            callFactory = callFactory,
        )

        val outcome = source.downloadAttachment("m1", "INBOX", 0)

        assertTrue("expected RateLimited, got $outcome", outcome is MailOutcome.RateLimited)
        assertEquals(30L, (outcome as MailOutcome.RateLimited).retryAfterSeconds)
    }

    @Test
    fun inboxResponse_carriesPgpFieldsThroughToUiEmail() {
        val body = """
            {"tabs":["Inbox"],"byTab":{"Inbox":[
              {"messageId":"1","sender":"a@example.com","subject":"[Encrypted] Email Sent by KyPost",
               "pgpEncrypted":true,"pgpSigned":true,"pgpVerified":true,"pgpSignerFingerprint":"ABCD"},
              {"messageId":"2","sender":"b@example.com","subject":"plain"}
            ]},"cursor":"7"}
        """.trimIndent()
        val source = RelayMailSource(
            pairingProvider = { testPairing() },
            cursorProvider = FakeMailCursorProvider(),
            callFactory = FakeCallFactory { request -> jsonResponse(request, body) },
        )

        val outcome = source.fetchInbox("INBOX", 50)

        assertTrue("expected Success, got $outcome", outcome is MailOutcome.Success)
        val messages = (outcome as MailOutcome.Success).value.messages
        val encrypted = messages.first { it.id == "1" }
        assertTrue(encrypted.pgpEncrypted)
        assertTrue(encrypted.pgpSigned)
        assertTrue(encrypted.pgpVerified)
        assertEquals("ABCD", encrypted.pgpSignerFingerprint)
        assertEquals("", encrypted.pgpDecryptError)
        // Absent fields are omitempty server-side, so their defaults are the contract for
        // ordinary mail — not an unknown state.
        val plain = messages.first { it.id == "2" }
        assertEquals(false, plain.pgpEncrypted)
        assertEquals("", plain.pgpSignerFingerprint)
    }

    @Test
    fun sendMail_putsPgpFlagsOnTheWire() {
        val callFactory = BodyRecordingCallFactory { request ->
            jsonResponse(request, """{"ok":true,"sentSaved":true,"warning":""}""")
        }
        val source = RelayMailSource(
            pairingProvider = { testPairing() },
            cursorProvider = FakeMailCursorProvider(),
            callFactory = callFactory,
        )

        source.sendMail(
            MailDraft(
                to = "bob@example.com", subject = "hi", body = "hello",
                sign = true, encrypt = true, allowPickupFallback = true,
            ),
        )

        val sent = callFactory.bodies.single()
        assertTrue("expected sign in $sent", sent.contains("\"sign\":true"))
        assertTrue("expected encrypt in $sent", sent.contains("\"encrypt\":true"))
        assertTrue("expected allowPickupFallback in $sent", sent.contains("\"allowPickupFallback\":true"))
    }

    /** Drafts carry no crypto semantics — the server's draft handler ignores these fields — so
     *  sending them would claim a choice the user did not make at draft-save time. The webmail
     *  handoff saves a draft from a composition whose Encrypt toggle was on, so this is a live
     *  path, not a hypothetical. */
    @Test
    fun saveDraft_omitsPgpFlags() {
        val callFactory = BodyRecordingCallFactory { request -> jsonResponse(request, """{"ok":true}""") }
        val source = RelayMailSource(
            pairingProvider = { testPairing() },
            cursorProvider = FakeMailCursorProvider(),
            callFactory = callFactory,
        )

        source.saveDraft(
            MailDraft(to = "bob@example.com", subject = "hi", body = "hello", encrypt = true, sign = true),
        )

        val sent = callFactory.bodies.single()
        assertTrue("expected no encrypt in $sent", !sent.contains("encrypt"))
        assertTrue("expected no sign in $sent", !sent.contains("\"sign\""))
        assertTrue("expected no allowPickupFallback in $sent", !sent.contains("allowPickupFallback"))
    }
}
