package org.kysecurity.mail.push

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * The stored pin set used to hold every certificate in the observed chain except its trust anchor,
 * which for the ordinary deployment meant a public CA intermediate — a pin that admits every
 * certificate that CA issues. Sets written before the leaf-only rule must therefore be REPLACED on
 * the next capture, not merged into, or an install whose certificate happens not to rotate would
 * carry the intermediate in its rolling window forever.
 */
@RunWith(AndroidJUnit4::class)
class TlsPinNarrowingTest {
    private val context = ApplicationProvider.getApplicationContext<Context>()
    private val host = "relay.test.invalid"

    private fun pin(seed: Byte): String =
        "sha256/" + java.util.Base64.getEncoder().encodeToString(ByteArray(32) { seed })

    @Before
    fun clearStore() {
        runBlocking { SecurePairingStore(context).clearPairing() }
        context.getSharedPreferences(TLS_PIN_TRIPWIRE_PREFS, Context.MODE_PRIVATE).edit().clear().commit()
    }

    @Test
    fun aFreshlyClearedStoreIsNotMarkedLeafOnly() {
        assertFalse(SecurePairingStore(context).tlsPinIsLeafOnly())
    }

    @Test
    fun savingAPinMarksTheStoredSetAsLeafOnly() = runBlocking {
        val store = SecurePairingStore(context)

        store.saveTlsPin(TlsPin(host, setOf(pin(1))))

        assertTrue(store.tlsPinIsLeafOnly())
        assertEquals(setOf(pin(1)), store.currentTlsPin()?.spkiSha256)
    }

    /** The rolling window, which is what replaced pinning the issuers: a leaf rotated between two
     *  resyncs is carried alongside the fresh one so the renewal is not an outage. */
    @Test
    fun aRotatedLeafIsCarriedAlongsideTheFreshOne() = runBlocking {
        val store = SecurePairingStore(context)
        store.saveTlsPin(TlsPin(host, setOf(pin(1))))

        val rolled = org.kysecurity.mail.security.SpkiPinner.rollingPins(
            fresh = setOf(pin(2)),
            history = store.currentTlsPin()!!.spkiSha256,
        )
        store.saveTlsPin(TlsPin(host, rolled))

        assertEquals(listOf(pin(2), pin(1)), store.currentTlsPin()!!.spkiSha256.toList())
    }

    /** And the window is bounded, so pins cannot accumulate until every certificate the server has
     *  ever presented — including a stolen one — stays valid forever. */
    @Test
    fun theWindowNeverGrowsPastTheCap() = runBlocking {
        val store = SecurePairingStore(context)
        store.saveTlsPin(TlsPin(host, setOf(pin(1))))

        repeat(5) { round ->
            val rolled = org.kysecurity.mail.security.SpkiPinner.rollingPins(
                fresh = setOf(pin((round + 2).toByte())),
                history = store.currentTlsPin()!!.spkiSha256,
            )
            store.saveTlsPin(TlsPin(host, rolled))
        }

        val stored = store.currentTlsPin()!!.spkiSha256
        assertEquals(org.kysecurity.mail.security.SpkiPinner.MAX_PINNED_LEAVES, stored.size)
        assertTrue("the freshest observation must survive", pin(6) in stored)
        assertFalse("the original must have aged out", pin(1) in stored)
    }

    @Test
    fun clearingThePairingAlsoClearsTheLeafOnlyMarker() = runBlocking {
        val store = SecurePairingStore(context)
        store.saveTlsPin(TlsPin(host, setOf(pin(1))))
        assertTrue(store.tlsPinIsLeafOnly())

        store.clearPairing()

        assertFalse(SecurePairingStore(context).tlsPinIsLeafOnly())
    }
}
