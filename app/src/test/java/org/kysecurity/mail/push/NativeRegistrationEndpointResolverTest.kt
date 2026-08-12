package org.kysecurity.mail.push

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class NativeRegistrationEndpointResolverTest {

    @Test
    fun resolve_regPresent_winsOverSrv() {
        val result = NativeRegistrationEndpointResolver.resolve(
            qrReg = "https://server.example.com/api/notifications/native/register",
            qrServerUrl = "https://server.example.com",
        )

        val resolved = result as NativeRegistrationEndpointResolver.Resolution.Resolved
        assertEquals("https://server.example.com/api/notifications/native/register", resolved.registrationUrl)
    }

    @Test
    fun resolve_regMissing_derivesFromSrv() {
        val result = NativeRegistrationEndpointResolver.resolve(
            qrReg = null,
            qrServerUrl = "https://server.example.com/",
        )

        val resolved = result as NativeRegistrationEndpointResolver.Resolution.Resolved
        assertEquals("https://server.example.com/api/notifications/native/register", resolved.registrationUrl)
    }

    @Test
    fun resolve_regAndSrvMissing_blocksPairing() {
        val result = NativeRegistrationEndpointResolver.resolve(qrReg = null, qrServerUrl = null)

        assertTrue(result is NativeRegistrationEndpointResolver.Resolution.MissingServerUrl)
    }
}
