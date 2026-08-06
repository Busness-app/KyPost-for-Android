package com.urlxl.mail.push

import com.urlxl.mail.HEADER_DEVICE_ID
import com.urlxl.mail.HEADER_DEVICE_SECRET
import com.urlxl.mail.testing.FakeCallFactory
import com.urlxl.mail.testing.response
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Test 7, carried over from the original 2b handoff and finally placed.
 *
 * Rebinding an existing `deviceId` returns **409** unless the current device secret is sent, and the
 * reason the server requires it is not cosmetic: without it a stolen session could take over an
 * existing device row, keeping its `MFAApprover` status and redirecting that user's push. The
 * FCM-token-refresh flow re-registers, so this is the ordinary path, not an edge case.
 *
 * It also matters to enrollment specifically. The server carries `enrollmentPublicKey` and
 * `encryptionEnrolled` forward across re-registration on both branches — which is worth nothing if
 * re-registration itself 409s.
 */
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

    @Test
    fun aReRegistrationCarriesTheCurrentDeviceCredential() = runBlocking {
        val factory = FakeCallFactory { req -> response(req, success, 200) }

        NativeRegistrationClient(callFactory = factory).register(paired, token = "fcm-token")

        val sent = factory.requests.single()
        assertEquals("dev-1", sent.header(HEADER_DEVICE_ID))
        assertEquals("secret-1", sent.header(HEADER_DEVICE_SECRET))
    }

    /**
     * A first pairing has no secret yet — it is what this call mints. Sending an empty or absent
     * credential must not be confused with sending a wrong one.
     */
    @Test
    fun aFirstPairingSendsNoDeviceCredential() = runBlocking {
        val factory = FakeCallFactory { req -> response(req, success, 200) }
        val unpaired = paired.copy(deviceId = null, deviceSecret = null)

        NativeRegistrationClient(callFactory = factory).register(unpaired, token = "fcm-token")

        val sent = factory.requests.single()
        assertNull(sent.header(HEADER_DEVICE_ID))
        assertNull(sent.header(HEADER_DEVICE_SECRET))
    }

    /** A half-known pairing — an id with no readable secret, which the credential gate produces
     *  while the app is locked — must not send a device id on its own. The server reads that as a
     *  rebind attempt with no credential. */
    @Test
    fun anIdWithNoSecretSendsNeitherHeader() = runBlocking {
        val factory = FakeCallFactory { req -> response(req, success, 200) }
        val gated = paired.copy(deviceSecret = null)

        NativeRegistrationClient(callFactory = factory).register(gated, token = "fcm-token")

        val sent = factory.requests.single()
        assertNull(sent.header(HEADER_DEVICE_ID))
        assertNull(sent.header(HEADER_DEVICE_SECRET))
    }

    /** 409 is a distinct, actionable outcome — "this device row belongs to a credential you did not
     *  send" — and must not read as a generic transport failure. */
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
