package com.urlxl.mail.pgp

import com.urlxl.mail.HEADER_DEVICE_ID
import com.urlxl.mail.HEADER_DEVICE_SECRET
import com.urlxl.mail.testing.FakeCallFactory
import com.urlxl.mail.testing.ThrowingCallFactory
import com.urlxl.mail.testing.response
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.IOException

class PgpPayloadClientTest {

    private fun fetchWith(code: Int, body: String): PgpPayloadResult = runBlocking {
        val callFactory = FakeCallFactory { request -> response(request, body, code) }
        PgpPayloadClient(callFactory = callFactory)
            .fetch("https://relay.example", "dev-1", "secret", "INBOX", "42")
    }

    @Test
    fun parsesAPayloadWithItsSignerKeys() {
        val result = fetchWith(
            200,
            """
            {"messageId":42,"mailbox":"INBOX","encryptedPayload":"-----BEGIN PGP MESSAGE-----",
             "signaturePayload":"","body":"",
             "signerKeys":[{"addresses":["bob@example.com"],"publicKey":"KEY",
                            "verified":true,"source":"qr"}]}
            """.trimIndent(),
        )

        val ok = result as? PgpPayloadResult.Success
            ?: throw AssertionError("expected Success, got $result")
        assertEquals("-----BEGIN PGP MESSAGE-----", ok.encryptedPayload)
        assertEquals(1, ok.signerKeys.size)
        assertTrue(ok.signerKeys[0].verified)
        assertEquals("qr", ok.signerKeys[0].source)
    }

    @Test
    fun absentProvenanceFieldsDefaultToTheWeakerClaim() {
        // omitempty: an older server sends neither field. Defaulting verified to false is the safe
        // direction — it degrades a badge, where the opposite would invent a confirmation.
        val result = fetchWith(
            200,
            """{"encryptedPayload":"X","signaturePayload":"","body":"",
                "signerKeys":[{"addresses":["bob@example.com"],"publicKey":"KEY"}]}""",
        )

        val ok = result as PgpPayloadResult.Success
        assertEquals(false, ok.signerKeys[0].verified)
        assertEquals(false, ok.signerKeys[0].conflict)
    }

    @Test
    fun readsAConflictMarker() {
        val result = fetchWith(
            200,
            """{"encryptedPayload":"X","signaturePayload":"","body":"",
                "signerKeys":[{"addresses":["bob@example.com"],"publicKey":"","conflict":true}]}""",
        )

        assertTrue((result as PgpPayloadResult.Success).signerKeys[0].conflict)
    }

    @Test
    fun mapsTheThreeStatusCodesThatMeanSomethingSpecific() {
        assertTrue(fetchWith(409, "{}") is PgpPayloadResult.NotClientProtected)
        assertTrue(fetchWith(413, "{}") is PgpPayloadResult.TooLarge)
        assertTrue(fetchWith(404, "{}") is PgpPayloadResult.NoPayload)
    }

    @Test
    fun anyOtherErrorIsAPlainFailure() {
        assertTrue(fetchWith(500, "{}") is PgpPayloadResult.Failed)
    }

    /** A dropped or mistyped query parameter here would silently fetch the wrong message's
     *  ciphertext, and nothing else in this test class would notice. */
    @Test
    fun getsWithMailboxAndMessageIdQueryParamsAndAuthHeaders() = runBlocking {
        val callFactory = FakeCallFactory { request ->
            response(request, """{"encryptedPayload":"X","signaturePayload":"","body":"","signerKeys":[]}""", 200)
        }
        val client = PgpPayloadClient(callFactory = callFactory)

        client.fetch("https://relay.example.com/", "dev-1", "secret-1", "INBOX", "42")

        val sent = callFactory.requests.single()
        assertEquals("/api/mail/pgp-payload", sent.url.encodedPath)
        assertEquals("GET", sent.method)
        assertEquals("INBOX", sent.url.queryParameter("mailbox"))
        assertEquals("42", sent.url.queryParameter("messageId"))
        assertEquals("dev-1", sent.header(HEADER_DEVICE_ID))
        assertEquals("secret-1", sent.header(HEADER_DEVICE_SECRET))
    }

    @Test
    fun unusableServerUrlIsFailed() = runBlocking {
        val client = PgpPayloadClient(callFactory = FakeCallFactory { request -> response(request, "{}", 200) })

        val result = client.fetch("not a url", "d", "s", "INBOX", "42")

        assertTrue("expected Failed, got $result", result is PgpPayloadResult.Failed)
    }

    @Test
    fun networkThrowIsFailed() = runBlocking {
        val client = PgpPayloadClient(callFactory = ThrowingCallFactory(IOException("offline")))

        val result = client.fetch("https://relay.example.com", "d", "s", "INBOX", "42")

        assertTrue("expected Failed, got $result", result is PgpPayloadResult.Failed)
    }

    @Test
    fun malformedBodyIsFailed() = runBlocking {
        val client = PgpPayloadClient(callFactory = FakeCallFactory { request -> response(request, "not json", 200) })

        val result = client.fetch("https://relay.example.com", "d", "s", "INBOX", "42")

        assertTrue("expected Failed, got $result", result is PgpPayloadResult.Failed)
    }
}
