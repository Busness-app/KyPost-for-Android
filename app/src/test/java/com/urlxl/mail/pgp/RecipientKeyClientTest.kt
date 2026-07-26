package com.urlxl.mail.pgp

import com.urlxl.mail.HEADER_DEVICE_SECRET
import com.urlxl.mail.HEADER_DEVICE_ID
import com.urlxl.mail.testing.BodyRecordingCallFactory
import com.urlxl.mail.testing.FakeCallFactory
import com.urlxl.mail.testing.ThrowingCallFactory
import com.urlxl.mail.testing.response
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.IOException

class RecipientKeyClientTest {

    @Test
    fun reportsOnlyRecipientsWithNoUsableKey() = runBlocking {
        val body = """{"results":[
            {"address":"bob@example.com","hasKey":true,"revoked":false,"expired":false,"tier":"contact-verified"},
            {"address":"carol@example.com","hasKey":false,"revoked":false,"expired":false,"tier":"none"}
        ]}"""
        val client = RecipientKeyClient(callFactory = FakeCallFactory { request -> response(request, body, 200) })

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
        val client = RecipientKeyClient(callFactory = FakeCallFactory { request -> response(request, body, 200) })

        val result = client.check("https://relay.example.com", "d", "s", listOf("dave@example.com"))

        assertEquals(listOf("dave@example.com"), (result as RecipientKeyResult.Success).keyless)
    }

    @Test
    fun postsTheAddressesAndAuthHeaders() = runBlocking {
        val callFactory = BodyRecordingCallFactory { request -> response(request, """{"results":[]}""", 200) }
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
        val client = RecipientKeyClient(callFactory = FakeCallFactory { request -> response(request, "boom", 500) })

        val result = client.check("https://relay.example.com", "d", "s", listOf("bob@example.com"))

        assertTrue("expected Failed, got $result", result is RecipientKeyResult.Failed)
    }

    @Test
    fun networkThrowIsFailed() = runBlocking {
        val client = RecipientKeyClient(callFactory = ThrowingCallFactory(IOException("offline")))

        val result = client.check("https://relay.example.com", "d", "s", listOf("bob@example.com"))

        assertTrue("expected Failed, got $result", result is RecipientKeyResult.Failed)
    }

    /** No addresses to check is a local answer, not a round trip. */
    @Test
    fun emptyAddressListSkipsTheCall() = runBlocking {
        val callFactory = FakeCallFactory { request -> response(request, """{"results":[]}""", 200) }
        val client = RecipientKeyClient(callFactory = callFactory)

        val result = client.check("https://relay.example.com", "d", "s", emptyList())

        assertEquals(emptyList<String>(), (result as RecipientKeyResult.Success).keyless)
        assertTrue("expected no request, sent ${callFactory.requests}", callFactory.requests.isEmpty())
    }
}
