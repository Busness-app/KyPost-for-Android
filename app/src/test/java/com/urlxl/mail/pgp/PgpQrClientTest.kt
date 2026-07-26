package com.urlxl.mail.pgp

import com.urlxl.mail.HEADER_DEVICE_SECRET
import com.urlxl.mail.HEADER_DEVICE_ID
import com.urlxl.mail.testing.FakeCallFactory
import com.urlxl.mail.testing.ThrowingCallFactory
import com.urlxl.mail.testing.response
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.IOException

class PgpQrClientTest {

    // ---- mintToken ----

    @Test
    fun mintToken_200_decodesTokenAndSendsExpectedRequest() = runBlocking {
        val callFactory = FakeCallFactory { request ->
            response(
                request,
                """{"token": "tok-1", "expiresAt": "2026-07-14T12:34:56Z", "url": "https://relay.example.com/api/pgp/qr/key?t=tok-1"}""",
                200,
            )
        }
        val client = PgpQrClient(callFactory = callFactory)

        val result = client.mintToken("https://relay.example.com/", "device-1", "secret-1")

        assertTrue(result is PgpQrTokenResult.Success)
        val token = (result as PgpQrTokenResult.Success).token
        assertEquals("tok-1", token.token)
        assertEquals("2026-07-14T12:34:56Z", token.expiresAt)
        assertEquals("https://relay.example.com/api/pgp/qr/key?t=tok-1", token.url)

        val sentRequest = callFactory.requests.single()
        assertEquals(
            "https://relay.example.com/api/pgp/qr/token",
            sentRequest.url.newBuilder().query(null).build().toString(),
        )
        assertEquals("device-1", sentRequest.header(HEADER_DEVICE_ID))
        assertEquals("secret-1", sentRequest.header(HEADER_DEVICE_SECRET))
        assertNull(sentRequest.url.queryParameter("sub"))
        assertNull(sentRequest.url.queryParameter("hash"))
        assertEquals("GET", sentRequest.method)
    }

    @Test
    fun mintToken_400_mapsToNoIdentity() = runBlocking {
        val callFactory = FakeCallFactory { request -> response(request, "no PGP identity configured yet", 400) }
        val client = PgpQrClient(callFactory = callFactory)

        val result = client.mintToken("https://relay.example.com", "device-1", "secret-1")

        assertTrue(result is PgpQrTokenResult.NoIdentity)
        assertEquals("no PGP identity configured yet", (result as PgpQrTokenResult.NoIdentity).message)
    }

    @Test
    fun mintToken_401_mapsToUnauthorized() = runBlocking {
        val callFactory = FakeCallFactory { request -> response(request, "", 401) }
        val client = PgpQrClient(callFactory = callFactory)

        val result = client.mintToken("https://relay.example.com", "device-1", "secret-1")

        assertTrue(result is PgpQrTokenResult.Unauthorized)
    }

    @Test
    fun mintToken_503_mapsToServiceUnavailable() = runBlocking {
        val callFactory = FakeCallFactory { request -> response(request, "", 503) }
        val client = PgpQrClient(callFactory = callFactory)

        val result = client.mintToken("https://relay.example.com", "device-1", "secret-1")

        assertTrue(result is PgpQrTokenResult.ServiceUnavailable)
    }

    @Test
    fun mintToken_malformedBody_mapsToRetryable() = runBlocking {
        val callFactory = FakeCallFactory { request -> response(request, "not json", 200) }
        val client = PgpQrClient(callFactory = callFactory)

        val result = client.mintToken("https://relay.example.com", "device-1", "secret-1")

        assertTrue(result is PgpQrTokenResult.Retryable)
    }

    @Test
    fun mintToken_networkError_mapsToRetryable() = runBlocking {
        val callFactory = ThrowingCallFactory(IOException("boom"))
        val client = PgpQrClient(callFactory = callFactory)

        val result = client.mintToken("https://relay.example.com", "device-1", "secret-1")

        assertTrue(result is PgpQrTokenResult.Retryable)
        assertEquals("boom", (result as PgpQrTokenResult.Retryable).message)
    }

    @Test
    fun mintToken_unexpectedStatusCode_mapsToRetryable() = runBlocking {
        val callFactory = FakeCallFactory { request -> response(request, "", 500) }
        val client = PgpQrClient(callFactory = callFactory)

        val result = client.mintToken("https://relay.example.com", "device-1", "secret-1")

        assertTrue(result is PgpQrTokenResult.Retryable)
    }

    // ---- fetchKey ----

    @Test
    fun fetchKey_200_decodesKeyAndSendsExpectedRequest_noAuthParams() = runBlocking {
        val callFactory = FakeCallFactory { request ->
            response(
                request,
                """{"name": "Alice", "fingerprint": "A1B2C3D4E5F6", "publicKey": "-----BEGIN PGP PUBLIC KEY BLOCK-----..."}""",
                200,
            )
        }
        val client = PgpQrClient(callFactory = callFactory)

        val result = client.fetchKey("https://relay.example.com", "tok-1")

        assertTrue(result is PgpQrKeyResult.Success)
        val key = (result as PgpQrKeyResult.Success).key
        assertEquals("Alice", key.name)
        assertEquals("A1B2C3D4E5F6", key.fingerprint)
        assertEquals("-----BEGIN PGP PUBLIC KEY BLOCK-----...", key.publicKey)

        val sentRequest = callFactory.requests.single()
        assertEquals(
            "https://relay.example.com/api/pgp/qr/key",
            sentRequest.url.newBuilder().query(null).build().toString(),
        )
        assertEquals("tok-1", sentRequest.url.queryParameter("t"))
        assertNull(sentRequest.url.queryParameter("sub"))
        assertNull(sentRequest.url.queryParameter("hash"))
        assertEquals("GET", sentRequest.method)
    }

    @Test
    fun fetchKey_200_withContactCard_decodesCardFields() = runBlocking {
        val callFactory = FakeCallFactory { request ->
            response(
                request,
                """
                {
                  "name": "Alice",
                  "fingerprint": "A1B2C3D4E5F6",
                  "publicKey": "-----BEGIN PGP PUBLIC KEY BLOCK-----...",
                  "contactCard": {
                    "fn": "Alice Example",
                    "org": "Example Corp",
                    "emails": [{"label": "work", "value": "alice@example.com"}],
                    "phones": [{"value": "+1-555-0100"}]
                  }
                }
                """.trimIndent(),
                200,
            )
        }
        val client = PgpQrClient(callFactory = callFactory)

        val result = client.fetchKey("https://relay.example.com", "tok-1")

        assertTrue(result is PgpQrKeyResult.Success)
        val card = (result as PgpQrKeyResult.Success).key.contactCard
        assertEquals("Alice Example", card?.fn)
        assertEquals("Example Corp", card?.org)
        assertEquals("alice@example.com", card?.emails?.single()?.value)
        assertEquals("+1-555-0100", card?.phones?.single()?.value)
    }

    @Test
    fun fetchKey_200_withoutContactCard_decodesNullCard() = runBlocking {
        val callFactory = FakeCallFactory { request ->
            response(
                request,
                """{"name": "Alice", "fingerprint": "A1B2C3D4E5F6", "publicKey": "-----BEGIN PGP PUBLIC KEY BLOCK-----..."}""",
                200,
            )
        }
        val client = PgpQrClient(callFactory = callFactory)

        val result = client.fetchKey("https://relay.example.com", "tok-1")

        assertTrue(result is PgpQrKeyResult.Success)
        assertNull((result as PgpQrKeyResult.Success).key.contactCard)
    }

    @Test
    fun fetchKey_403_mapsToForbidden() = runBlocking {
        val callFactory = FakeCallFactory { request -> response(request, "", 403) }
        val client = PgpQrClient(callFactory = callFactory)

        val result = client.fetchKey("https://relay.example.com", "tok-1")

        assertTrue(result is PgpQrKeyResult.Forbidden)
    }

    @Test
    fun fetchKey_404_mapsToNotFound() = runBlocking {
        val callFactory = FakeCallFactory { request -> response(request, "", 404) }
        val client = PgpQrClient(callFactory = callFactory)

        val result = client.fetchKey("https://relay.example.com", "tok-1")

        assertTrue(result is PgpQrKeyResult.NotFound)
    }

    @Test
    fun fetchKey_503_mapsToServiceUnavailable() = runBlocking {
        val callFactory = FakeCallFactory { request -> response(request, "", 503) }
        val client = PgpQrClient(callFactory = callFactory)

        val result = client.fetchKey("https://relay.example.com", "tok-1")

        assertTrue(result is PgpQrKeyResult.ServiceUnavailable)
    }

    @Test
    fun fetchKey_malformedBody_mapsToRetryable() = runBlocking {
        val callFactory = FakeCallFactory { request -> response(request, "not json", 200) }
        val client = PgpQrClient(callFactory = callFactory)

        val result = client.fetchKey("https://relay.example.com", "tok-1")

        assertTrue(result is PgpQrKeyResult.Retryable)
    }

    @Test
    fun fetchKey_networkError_mapsToRetryable() = runBlocking {
        val callFactory = ThrowingCallFactory(IOException("boom"))
        val client = PgpQrClient(callFactory = callFactory)

        val result = client.fetchKey("https://relay.example.com", "tok-1")

        assertTrue(result is PgpQrKeyResult.Retryable)
        assertEquals("boom", (result as PgpQrKeyResult.Retryable).message)
    }

    @Test
    fun fetchKey_unexpectedStatusCode_mapsToRetryable() = runBlocking {
        val callFactory = FakeCallFactory { request -> response(request, "", 500) }
        val client = PgpQrClient(callFactory = callFactory)

        val result = client.fetchKey("https://relay.example.com", "tok-1")

        assertTrue(result is PgpQrKeyResult.Retryable)
    }
}
