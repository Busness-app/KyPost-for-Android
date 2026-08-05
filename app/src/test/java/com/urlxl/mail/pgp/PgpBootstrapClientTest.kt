package com.urlxl.mail.pgp

import com.urlxl.mail.HEADER_DEVICE_SECRET
import com.urlxl.mail.HEADER_DEVICE_ID
import com.urlxl.mail.testing.FakeCallFactory
import com.urlxl.mail.testing.ThrowingCallFactory
import com.urlxl.mail.testing.response
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.IOException

class PgpBootstrapClientTest {

    @Test
    fun parsesProtectionAndIdentity() = runBlocking {
        val callFactory = FakeCallFactory { request ->
            response(request, """{"hasIdentity":true,"protection":"client"}""", 200)
        }
        val client = PgpBootstrapClient(callFactory = callFactory)

        val result = client.fetch("https://relay.example.com/", "device-1", "secret-1")

        assertEquals(
            PgpBootstrapResult.Success(hasIdentity = true, protection = "client", publicKey = ""),
            result,
        )
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
        val client = PgpBootstrapClient(callFactory = FakeCallFactory { request -> response(request, body, 200) })

        val result = client.fetch("https://relay.example.com", "device-1", "secret-1")

        assertEquals(
            PgpBootstrapResult.Success(hasIdentity = false, protection = "server", publicKey = ""),
            result,
        )
    }

    /** The PGP QR screen shows the user their own fingerprint beside the code they present, and
     *  computes it from these bytes rather than from the response's `fingerprint` claim. */
    @Test
    fun parsesTheOwnPublicKey() = runBlocking {
        val body = """{"hasIdentity":true,"protection":"client","publicKey":"-----BEGIN PGP PUBLIC KEY BLOCK-----\nabc\n-----END PGP PUBLIC KEY BLOCK-----"}"""
        val client = PgpBootstrapClient(callFactory = FakeCallFactory { request -> response(request, body, 200) })

        val result = client.fetch("https://relay.example.com", "device-1", "secret-1")

        assertEquals(
            "-----BEGIN PGP PUBLIC KEY BLOCK-----\nabc\n-----END PGP PUBLIC KEY BLOCK-----",
            (result as PgpBootstrapResult.Success).publicKey,
        )
    }

    /** A failed bootstrap must be distinguishable from a successful "no identity", or the compose
     *  screen cannot honor couldn't-check-is-not-no. */
    @Test
    fun httpFailure_isFailedNotAnEmptySuccess() = runBlocking {
        val client = PgpBootstrapClient(callFactory = FakeCallFactory { request -> response(request, "unavailable", 503) })

        val result = client.fetch("https://relay.example.com", "device-1", "secret-1")

        assertTrue("expected Failed, got $result", result is PgpBootstrapResult.Failed)
    }

    /** 503 and 401 bodies are plain text; a decoder run over them must not surface as a parse
     *  error, and a network throw must not escape. */
    @Test
    fun networkThrow_isFailed() = runBlocking {
        val client = PgpBootstrapClient(callFactory = ThrowingCallFactory(IOException("no route to host")))

        val result = client.fetch("https://relay.example.com", "device-1", "secret-1")

        assertTrue("expected Failed, got $result", result is PgpBootstrapResult.Failed)
    }

    @Test
    fun malformedBody_isFailed() = runBlocking {
        val client = PgpBootstrapClient(callFactory = FakeCallFactory { request -> response(request, "not json", 200) })

        val result = client.fetch("https://relay.example.com", "device-1", "secret-1")

        assertTrue("expected Failed, got $result", result is PgpBootstrapResult.Failed)
    }

    @Test
    fun unusableServerUrl_isFailed() = runBlocking {
        val client = PgpBootstrapClient(callFactory = FakeCallFactory { request -> response(request, "{}", 200) })

        val result = client.fetch("not a url", "device-1", "secret-1")

        assertTrue("expected Failed, got $result", result is PgpBootstrapResult.Failed)
    }
}
