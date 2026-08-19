package org.kysecurity.mail.security

import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test
import org.kysecurity.mail.push.TlsPin

/** The deregister client is built from a pin captured before the wipe clears the pairing. */
class WipeDeregisterPinningTest {

    @Test
    fun noCapturedPinMeansNoDeregisterClient() {
        // Fails closed. A pairing with no captured pin is `TlsPinState.Lost`, which every ordinary
        // request already refuses; the wipe must not be the one caller that downgrades instead.
        assertNull(SecurityWipe.pinnedDeregisterClient(null))
    }

    @Test
    fun aCapturedPinProducesAClient() {
        val client = SecurityWipe.pinnedDeregisterClient(
            TlsPin(host = "relay.example.com", spkiSha256 = setOf("sha256/${"A".repeat(43)}=")),
        )
        assertNotNull("a captured pin must still produce a working deregister path", client)
    }
}
