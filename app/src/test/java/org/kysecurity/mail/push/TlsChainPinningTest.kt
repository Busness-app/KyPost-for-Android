package org.kysecurity.mail.push

import org.kysecurity.mail.PinPosture
import org.kysecurity.mail.pairingHttpClient
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * The pin captured at pairing time used to be the leaf certificate alone. Certificate renewal mints
 * a new leaf key, so every renewal left a pin nothing in the chain matched, every call failed
 * closed, and the only recovery was unpairing — which deletes the local mailbox.
 *
 * These pin down the two halves of the fix: the whole chain is pinned, and an empty pin set — which
 * `CertificatePinner` would pass vacuously — cannot be built at all.
 */
class TlsChainPinningTest {

    private val host = "relay.example.com"

    /** A real 32-byte SHA-256 pin. Repeating one base64 character does not round-trip: the trailing
     *  bits must be zero, so OkHttp normalises the last character and the constant stops matching. */
    private fun pin(seed: Byte): String =
        "sha256/" + java.util.Base64.getEncoder().encodeToString(ByteArray(32) { seed })

    private val leaf = pin(1)
    private val intermediate = pin(2)
    private val root = pin(3)

    @Test
    fun everyChainPinIsRegisteredForTheHost() {
        val client = pairingHttpClient(PinPosture.Pinned(host, setOf(leaf, intermediate, root)))

        val matched = client.certificatePinner.findMatchingPins(host)

        // Three, not one: `add` was called per pin. Registering only the first is exactly the
        // regression that made a renewed leaf unverifiable.
        assertEquals(3, matched.size, "every captured chain pin must be registered for the host")
    }

    /** The point of pinning the issuers: a renewed leaf is unknown, its issuer is not. */
    @Test
    fun aRenewedLeafStillMatchesThroughItsIssuer() {
        val renewedLeaf = pin(4)
        val client = pairingHttpClient(PinPosture.Pinned(host, setOf(leaf, intermediate, root)))

        // Pin.toString() is the "sha256/BASE64" form CertificatePinner.pin() produces.
        val pinned = client.certificatePinner.findMatchingPins(host).map { it.toString() }

        assertTrue(renewedLeaf !in pinned, "the renewed leaf is genuinely unknown")
        assertTrue(
            intermediate in pinned,
            "so validation has to survive on the issuer pin, which must be present",
        )
    }

    @Test
    fun aPinnedPostureWithNoPinsIsRefused() {
        // CertificatePinner passes vacuously when no pin is configured for the host, so building
        // this client would silently unpin the connection.
        assertFailsWith<IllegalArgumentException> {
            pairingHttpClient(PinPosture.Pinned(host, emptySet()))
        }
    }

    @Test
    fun aTlsPinWithNoPinsCannotBeConstructed() {
        assertFailsWith<IllegalArgumentException> { TlsPin(host, emptySet()) }
    }

    /** TofuWindow is still the only unpinned posture, and only before a first pairing. */
    @Test
    fun theTofuWindowRemainsUnpinned() {
        val client = pairingHttpClient(PinPosture.TofuWindow)

        assertEquals(0, client.certificatePinner.findMatchingPins(host).size)
    }
}
