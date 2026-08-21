package org.kysecurity.mail.push

import org.kysecurity.mail.HEADER_DEVICE_ID
import org.kysecurity.mail.HEADER_DEVICE_SECRET
import org.kysecurity.mail.testing.FakeCallFactory
import org.kysecurity.mail.testing.response
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class NativeRegistrationClientTest {

    private val paired = PairingData(
        subscriberId = "sub-1",
        serverUrl = "https://relay.example.com",
        registrationUrl = "https://relay.example.com/api/notifications/native/register",
        pairingToken = "tok",
        deviceId = "dev-1",
        deviceSecret = "secret-1",
        pairedAtEpochMs = 0L,
    )

    private val success =
        """{"ok":true,"synced":true,"deviceId":"dev-1","deviceSecret":"secret-2"}"""

    /** The tag is what makes PinnedOrFallbackCallFactory pin the request that discloses the
     *  pairing token, so its absence is the whole bug, not a detail. */
    @Test
    fun aLinkPinIsTaggedOntoTheRegistrationRequest() = runBlocking {
        val pin = "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        val factory = FakeCallFactory { req -> response(req, success, 200) }

        NativeRegistrationClient(callFactory = factory)
            .register(paired.copy(deviceId = null, deviceSecret = null, spkiPin = pin), token = "fcm-token")

        val tag = factory.requests.single().tag(org.kysecurity.mail.LinkPin::class.java)
        assertEquals(org.kysecurity.mail.LinkPin("relay.example.com", pin), tag)
    }

    @Test
    fun withNoLinkPin_theRequestCarriesNoTag() = runBlocking {
        val factory = FakeCallFactory { req -> response(req, success, 200) }

        NativeRegistrationClient(callFactory = factory).register(paired, token = "fcm-token")

        assertNull(factory.requests.single().tag(org.kysecurity.mail.LinkPin::class.java))
    }

    @Test
    fun aReRegistrationCarriesTheCurrentDeviceCredential() = runBlocking {
        val factory = FakeCallFactory { req -> response(req, success, 200) }

        NativeRegistrationClient(callFactory = factory).register(paired, token = "fcm-token")

        val sent = factory.requests.single()
        assertEquals("dev-1", sent.header(HEADER_DEVICE_ID))
        assertEquals("secret-1", sent.header(HEADER_DEVICE_SECRET))
    }

    @Test
    fun aFirstPairingSendsNoDeviceCredential() = runBlocking {
        val factory = FakeCallFactory { req -> response(req, success, 200) }
        val unpaired = paired.copy(deviceId = null, deviceSecret = null)

        NativeRegistrationClient(callFactory = factory).register(unpaired, token = "fcm-token")

        val sent = factory.requests.single()
        assertNull(sent.header(HEADER_DEVICE_ID))
        assertNull(sent.header(HEADER_DEVICE_SECRET))
    }

    @Test
    fun anIdWithNoSecretSendsNeitherHeader() = runBlocking {
        val factory = FakeCallFactory { req -> response(req, success, 200) }
        val gated = paired.copy(deviceSecret = null)

        NativeRegistrationClient(callFactory = factory).register(gated, token = "fcm-token")

        val sent = factory.requests.single()
        assertNull(sent.header(HEADER_DEVICE_ID))
        assertNull(sent.header(HEADER_DEVICE_SECRET))
    }

    @Test
    fun aRebindRejectionIsReportedAsItsOwnError() = runBlocking {
        val factory = FakeCallFactory { req -> response(req, "", 409) }

        val result = NativeRegistrationClient(callFactory = factory)
            .register(paired, token = "fcm-token")

        assertTrue(result is NativeRegistrationResult.Error)
        assertTrue(
            "the message must name the rebind: ${(result as NativeRegistrationResult.Error).message}",
            result.message.contains("already registered", ignoreCase = true),
        )
    }
}
