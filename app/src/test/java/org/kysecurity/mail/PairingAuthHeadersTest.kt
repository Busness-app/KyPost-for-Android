package org.kysecurity.mail

import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.Request
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class PairingAuthHeadersTest {

    @Test
    fun pairingAuthHeaders_setsBothHeadersOnTheRequest() {
        val request = Request.Builder()
            .url("https://relay.example.com/api/inbox".toHttpUrl())
            .get()
            .pairingAuthHeaders("device-1", "secret-1")
            .build()

        assertEquals("device-1", request.header(HEADER_DEVICE_ID))
        assertEquals("secret-1", request.header(HEADER_DEVICE_SECRET))
    }

    @Test
    fun pairingAuthHeaders_doesNotAddQueryParams() {
        val request = Request.Builder()
            .url("https://relay.example.com/api/inbox".toHttpUrl())
            .get()
            .pairingAuthHeaders("device-1", "secret-1")
            .build()

        assertNull(request.url.queryParameter("device"))
        assertNull(request.url.queryParameter("secret"))
    }
}
