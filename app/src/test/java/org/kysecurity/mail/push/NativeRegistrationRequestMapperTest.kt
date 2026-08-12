package org.kysecurity.mail.push

import android.os.Build
import org.kysecurity.mail.APP_VERSION
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class NativeRegistrationRequestMapperTest {

    @Test
    fun map_usesSubscriberIdPairingTokenDeviceIdAndPlatform() {
        val pairing = PairingData(
            subscriberId = "subscriber-id",
            serverUrl = "https://server.example.com",
            registrationUrl = "https://server.example.com/api/notifications/native/register",
            pairingToken = "pairing-token",
            deviceId = "last-known-device-id",
            deviceSecret = "last-known-device-secret",
            pairedAtEpochMs = 100L,
        )

        val request = NativeRegistrationRequestMapper.map(pairing = pairing, token = "fcm-token")

        assertEquals("subscriber-id", request.subscriberId)
        assertEquals("pairing-token", request.pairingToken)
        assertEquals("fcm-token", request.deviceToken)
        assertEquals("last-known-device-id", request.deviceId)
        assertEquals("android", request.platform)
        assertEquals(Build.MODEL, request.deviceName)
        assertEquals("KyPost for Android v$APP_VERSION", request.appVersion)
    }

    @Test
    fun map_withWebPushKeys_includesP256dhAndAuth() {
        val pairing = PairingData(
            subscriberId = "subscriber-id",
            serverUrl = "https://server.example.com",
            registrationUrl = "https://server.example.com/api/notifications/native/register",
            pairingToken = "pairing-token",
            deviceId = "last-known-device-id",
            deviceSecret = "last-known-device-secret",
            pairedAtEpochMs = 100L,
        )

        val request = NativeRegistrationRequestMapper.map(
            pairing = pairing,
            token = "https://distributor.example.com/endpoint",
            transport = "unifiedpush",
            p256dh = "p256dh-key",
            auth = "auth-secret",
        )

        assertEquals("p256dh-key", request.p256dh)
        assertEquals("auth-secret", request.auth)
    }

    @Test
    fun map_withoutWebPushKeys_leavesThemNull() {
        val pairing = PairingData(
            subscriberId = "subscriber-id",
            serverUrl = "https://server.example.com",
            registrationUrl = "https://server.example.com/api/notifications/native/register",
            pairingToken = "pairing-token",
            deviceId = "last-known-device-id",
            deviceSecret = "last-known-device-secret",
            pairedAtEpochMs = 100L,
        )

        val request = NativeRegistrationRequestMapper.map(pairing = pairing, token = "fcm-token")

        assertNull(request.p256dh)
        assertNull(request.auth)
    }
}
