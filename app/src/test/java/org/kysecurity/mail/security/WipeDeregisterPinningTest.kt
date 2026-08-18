package org.kysecurity.mail.security

import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test
import org.kysecurity.mail.push.TlsPin

/**
 * The wipe's one outbound request must be pinned or must not happen.
 *
 * It went out **unpinned**. The wipe clears the pairing — and with it `KEY_TLS_PIN` and the pin
 * tripwire — before the deregister runs, so by the time
 * [org.kysecurity.mail.push.PinnedOrFallbackCallFactory] was asked for a client it read
 * `TlsPinState.NeverPaired`, the one state that legitimately falls back to bare system-CA trust.
 * `X-Kypost-Device-Secret` then travelled over an unpinned connection during the operation whose
 * whole premise is that the device is in hostile hands, quite possibly on the attacker's network.
 *
 * A JVM test, which is the point: the fix is that the client is built from a pin captured up front
 * rather than resolved from state that no longer exists, and "built from what, exactly" is
 * answerable without a device.
 */
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
            TlsPin(host = "relay.example.com", spkiSha256 = "sha256/${"A".repeat(43)}="),
        )
        assertNotNull("a captured pin must still produce a working deregister path", client)
    }
}
