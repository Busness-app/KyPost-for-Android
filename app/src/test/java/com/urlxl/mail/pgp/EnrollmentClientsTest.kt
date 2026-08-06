package com.urlxl.mail.pgp

import com.urlxl.mail.testing.FakeCallFactory
import com.urlxl.mail.testing.response
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class EnrollmentClientsTest {

    @Test
    fun publishKey_sendsDeviceHeadersAndTheKey() = runBlocking {
        val factory = FakeCallFactory { req -> response(req, """{"ok":true}""", 200) }
        val clients = EnrollmentClients(callFactory = factory)

        val result = clients.publishKey("https://relay.example.com/", "dev-1", "secret-1", "BASE64KEY")

        assertEquals(EnrollmentCallResult.Ok, result)
        val sent = factory.requests.single()
        assertEquals("https://relay.example.com/api/pgp/device/enrollment-key", sent.url.toString())
        assertEquals("POST", sent.method)
        assertEquals("dev-1", sent.header("X-Kypost-Device-Id"))
        assertEquals("secret-1", sent.header("X-Kypost-Device-Secret"))
        val body = okio.Buffer().also { sent.body!!.writeTo(it) }.readUtf8()
        assertTrue("the key must actually be sent: $body", body.contains("\"publicKey\":\"BASE64KEY\""))
    }

    /** No slot parameter exists on this route — the server builds it from the verified credential.
     *  A client that invented one would be coding against a contract that does not exist. */
    @Test
    fun fetchEnvelope_takesNoSlotParameter() = runBlocking {
        val factory = FakeCallFactory { req ->
            response(req, """{"slot":"device:dev-1","envelope":"ENV"}""", 200)
        }
        val clients = EnrollmentClients(callFactory = factory)

        val result = clients.fetchEnvelope("https://relay.example.com", "dev-1", "secret-1")

        assertEquals(EnrollmentCallResult.Envelope("ENV"), result)
        val sent = factory.requests.single()
        assertEquals("https://relay.example.com/api/pgp/device/envelope", sent.url.toString())
        assertTrue("no query string may be sent", sent.url.querySize == 0)
    }

    /** 404 covers both "never sealed" and "expired", indistinguishable by design. Both mean
     *  re-run the ceremony, so they must map to one result the caller cannot accidentally split. */
    @Test
    fun fetchEnvelope_mapsNotFound() = runBlocking {
        val factory = FakeCallFactory { req ->
            response(req, """{"error":"no envelope sealed for this device"}""", 404)
        }

        assertEquals(
            EnrollmentCallResult.NotFound,
            EnrollmentClients(callFactory = factory).fetchEnvelope("https://relay.example.com", "d", "s"),
        )
    }

    /** A 200 that carries no envelope is a failure, not an empty success: treating it as one would
     *  hand the ceremony a blank string to open. */
    @Test
    fun fetchEnvelope_refusesAMalformedBody() = runBlocking {
        val factory = FakeCallFactory { req -> response(req, """{"slot":"device:dev-1"}""", 200) }

        assertTrue(
            EnrollmentClients(callFactory = factory)
                .fetchEnvelope("https://relay.example.com", "d", "s") is EnrollmentCallResult.Failed,
        )
    }

    @Test
    fun reportState_sendsTheBooleanAsRequired() = runBlocking {
        val factory = FakeCallFactory { req -> response(req, """{"ok":true}""", 200) }
        val clients = EnrollmentClients(callFactory = factory)

        clients.reportState("https://relay.example.com", "dev-1", "secret-1", enrolled = false)

        val sent = factory.requests.single()
        assertEquals("https://relay.example.com/api/pgp/device/enrollment-state", sent.url.toString())
        val body = okio.Buffer().also { sent.body!!.writeTo(it) }.readUtf8()
        assertTrue("must state an opinion explicitly: $body", body.contains("\"encryptionEnrolled\":false"))
    }

    /** Treated exactly as MfaResponseClient treats it — both come from the same shared
     *  writeDeviceAuthFailure on the server. */
    @Test
    fun rateLimited_carriesRetryAfter() = runBlocking {
        val factory = FakeCallFactory { req ->
            response(req, "", 429, headers = mapOf("Retry-After" to "42"))
        }

        assertEquals(
            EnrollmentCallResult.RateLimited(42L),
            EnrollmentClients(callFactory = factory).reportState("https://relay.example.com", "d", "s", true),
        )
    }

    @Test
    fun unauthorized_isDistinctFromAGenericFailure() = runBlocking {
        val factory = FakeCallFactory { req -> response(req, "", 401) }

        assertEquals(
            EnrollmentCallResult.Unauthorized,
            EnrollmentClients(callFactory = factory).reportState("https://relay.example.com", "d", "s", true),
        )
    }

    /** The endpoint is built from the paired origin. A URL that could not have come from a pairing
     *  must not reach the network carrying this device's credential. */
    @Test
    fun aNonHttpsServerUrlIsRefusedBeforeAnyCallIsMade() = runBlocking {
        val factory = FakeCallFactory { req -> response(req, """{"ok":true}""", 200) }

        val result = EnrollmentClients(callFactory = factory)
            .reportState("http://relay.example.com", "d", "s", true)

        assertTrue(result is EnrollmentCallResult.Failed)
        assertTrue("no request may be sent", factory.requests.isEmpty())
    }
}
